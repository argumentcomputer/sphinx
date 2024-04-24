use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::{fmt::Debug, marker::PhantomData};

use hybrid_array::{typenum::Unsigned, Array};
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use wp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, SP1AirBuilder},
    bytes::ByteLookupEvent,
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::{
        field_op::{FieldOpCols, FieldOperation},
        params::{Limbs, WORDS_FIELD_ELEMENT},
    },
    runtime::{ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, SyscallCode},
    syscall::precompiles::SyscallContext,
    utils::{
        bytes_to_words_le,
        ec::field::{FieldParameters, FieldType, WithFieldMultiplication},
        limbs_from_prev_access, pad_vec_rows,
    },
};

/// A set of columns to compute field element multiplication where p, q are in some prime field `Fp`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldMulCols<T, FP: FieldParameters> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub(crate) p_mul_q: FieldOpCols<T, FP::NB_LIMBS>,
}

#[derive(Default)]
pub struct FieldMulChip<FP: FieldParameters> {
    _marker: PhantomData<FP>,
}

impl<FP: FieldParameters> FieldMulChip<FP> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

/// Fp multiplication event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMulEvent<FP: FieldParameters> {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p: Array<u32, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub q_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q: Array<u32, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p_memory_records: Array<MemoryWriteRecord, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q_memory_records: Array<MemoryReadRecord, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
}

pub fn create_fp_mul_event<FP: FieldParameters>(
    rt: &mut SyscallContext<'_>,
    arg1: u32,
    arg2: u32,
) -> FieldMulEvent<FP> {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    let q_ptr = arg2;
    assert!(p_ptr % 4 == 0);
    assert!(q_ptr % 4 == 0);

    let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;

    let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, words_len);
    let q_memory_records = (&q_memory_records_vec[..]).try_into().unwrap();
    let q: Array<u32, _> = (&q_vec[..]).try_into().unwrap();
    let q_int = BigUint::from_slice(&q);

    let p: Array<u32, _> = (&rt.slice_unsafe(p_ptr, words_len)[..]).try_into().unwrap();
    let p_int = BigUint::from_slice(&p);
    let result_int = (p_int * q_int) % FP::modulus();
    let result_bytes = FP::to_limbs(&result_int);
    let result_words = bytes_to_words_le::<WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>(&result_bytes);

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;
    let p_memory_records = (&rt.mw_slice(p_ptr, &result_words.into())[..])
        .try_into()
        .unwrap();

    FieldMulEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
    }
}

impl<F: PrimeField32, FP: FieldParameters + WithFieldMultiplication> MachineAir<F>
    for FieldMulChip<FP>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match FP::FIELD_TYPE {
            FieldType::Bls12381 => "Bls12381FieldMul".to_string(),
            _ => panic!("Unsupported field"),
        }
    }

    #[instrument(name = "generate field mul trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the field type.
        let events = FP::mul_events(input);

        let (mut rows, new_byte_lookup_events): (Vec<_>, Vec<Vec<ByteLookupEvent>>) = events
            .par_iter()
            .map(|event| {
                let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
                let mut row = vec![F::zero(); size_of::<FieldMulCols<u8, FP>>()];
                let cols: &mut FieldMulCols<F, FP> = row.as_mut_slice().borrow_mut();

                // Populate basic columns.
                cols.is_real = F::one();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                // Decode field elements.
                let p = &event.p;
                let q = &event.q;
                let p_int = BigUint::from_slice(p);
                let q_int = BigUint::from_slice(q);
                cols.p_mul_q
                    .populate::<FP>(&p_int, &q_int, FieldOperation::Mul);

                // Populate the memory access columns.
                let mut new_byte_lookup_events = Vec::new();
                for i in 0..words_len {
                    cols.q_access[i]
                        .populate(event.q_memory_records[i], &mut new_byte_lookup_events);
                }
                for i in 0..words_len {
                    cols.p_access[i]
                        .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                }

                (row, new_byte_lookup_events)
            })
            .unzip();

        for byte_lookup_events in new_byte_lookup_events {
            output.add_byte_lookup_events(byte_lookup_events);
        }

        pad_vec_rows(&mut rows, || {
            let mut row = vec![F::zero(); size_of::<FieldMulCols<u8, FP>>()];
            let cols: &mut FieldMulCols<F, FP> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            cols.p_mul_q
                .populate::<FP>(&zero, &zero, FieldOperation::Mul);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<FieldMulCols<u8, FP>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match FP::FIELD_TYPE {
            FieldType::Bls12381 => !shard.bls12381_fp_mul_events.is_empty(),
            _ => panic!("Unsupported field"),
        }
    }
}

impl<F, FP: FieldParameters> BaseAir<F> for FieldMulChip<FP> {
    fn width(&self) -> usize {
        size_of::<FieldMulCols<u8, FP>>()
    }
}

impl<AB, FP: FieldParameters> Air<AB> for FieldMulChip<FP>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
        let main = builder.main();
        let local = main.row_slice(0);
        let row: &FieldMulCols<AB::Var, FP> = (*local).borrow();

        let p: Limbs<_, FP::NB_LIMBS> = limbs_from_prev_access(&row.p_access[0..words_len]);
        let q: Limbs<_, FP::NB_LIMBS> = limbs_from_prev_access(&row.q_access[0..words_len]);

        row.p_mul_q
            .eval::<AB, FP, _, _>(builder, &p, &q, FieldOperation::Mul);

        // Constraint self.p_access.value = [self.p_mul_q.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..FP::NB_LIMBS::USIZE {
            builder
                .when(row.is_real)
                .assert_eq(row.p_mul_q.result[i], row.p_access[i / 4].value()[i % 4]);
        }

        for i in 0..words_len {
            builder.eval_memory_access(
                row.shard,
                row.clk, // clk + 0 -> Memory
                row.q_ptr + AB::F::from_canonical_u32(i as u32 * 4),
                &row.q_access[i],
                row.is_real,
            );
        }
        for i in 0..words_len {
            builder.eval_memory_access(
                row.shard,
                row.clk + AB::F::from_canonical_u32(1), // The clk for p is moved by 1.
                row.p_ptr + AB::F::from_canonical_u32(i as u32 * 4),
                &row.p_access[i],
                row.is_real,
            );
        }

        // Fetch the syscall id for the field type.
        let syscall_id_fe = match FP::FIELD_TYPE {
            FieldType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_MUL.syscall_id())
            }
            _ => panic!("Unsupported field"),
        };

        builder.receive_syscall(
            row.shard,
            row.clk,
            syscall_id_fe,
            row.p_ptr,
            row.q_ptr,
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{utils, utils::tests::BLS12381_FP_MUL_ELF, Program};

    #[test]
    fn test_bls12381_fp_mul_simple() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_MUL_ELF);
        utils::run_test(program).unwrap();
    }
}