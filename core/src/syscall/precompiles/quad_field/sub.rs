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
use sphinx_derive::AlignedBorrow;
use tracing::instrument;

use crate::{
    air::{AluAirBuilder, EventLens, EventMutLens, MachineAir, MemoryAirBuilder, WithEvents},
    bytes::ByteLookupEvent,
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::{
        extensions::quadratic::{QuadFieldOpCols, QuadFieldOperation},
        params::{
            FieldParameters, FieldType, Limbs, WORDS_FIELD_ELEMENT, WORDS_QUAD_EXT_FIELD_ELEMENT,
        },
    },
    runtime::{ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, SyscallCode},
    syscall::precompiles::SyscallContext,
    utils::{bytes_to_words_le, limbs_from_prev_access, pad_vec_rows},
};

/// A set of columns to compute field element subtraction where p, q are in the quadratic field extension of some prime field `Fp`.
/// See additional documentation for `QuadFieldOpCols` for information on the specific quadratic field extensions supported.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct QuadFieldSubCols<T, FP: FieldParameters> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_QUAD_EXT_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_QUAD_EXT_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub(crate) p_sub_q: QuadFieldOpCols<T, FP>,
}

#[derive(Default)]
pub struct QuadFieldSubChip<FP: FieldParameters> {
    _marker: PhantomData<FP>,
}

impl<FP: FieldParameters> QuadFieldSubChip<FP> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

/// Fp2 subtraction event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuadFieldSubEvent<FP: FieldParameters> {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p0: Array<u32, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p1: Array<u32, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub q_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q0: Array<u32, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q1: Array<u32, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p_memory_records: Array<MemoryWriteRecord, WORDS_QUAD_EXT_FIELD_ELEMENT<FP::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q_memory_records: Array<MemoryReadRecord, WORDS_QUAD_EXT_FIELD_ELEMENT<FP::NB_LIMBS>>,
}

pub fn create_fp2_sub_event<FP: FieldParameters>(
    rt: &mut SyscallContext<'_>,
    arg1: u32,
    arg2: u32,
) -> QuadFieldSubEvent<FP> {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    let q_ptr = arg2;
    assert!(p_ptr % 4 == 0);
    assert!(q_ptr % 4 == 0);

    let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;

    let p: Array<u32, WORDS_QUAD_EXT_FIELD_ELEMENT<FP::NB_LIMBS>> = (&rt
        .slice_unsafe(p_ptr, 2 * words_len)[..])
        .try_into()
        .unwrap();
    let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, 2 * words_len);

    let p0 = &p[..words_len];
    let p1 = &p[words_len..];

    let q0 = &q_vec[..words_len];
    let q1 = &q_vec[words_len..];

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;

    let p0_int = BigUint::from_slice(p0);
    let p1_int = BigUint::from_slice(p1);
    let q0_int = BigUint::from_slice(q0);
    let q1_int = BigUint::from_slice(q1);
    let result0_int = (FP::modulus() + p0_int - q0_int) % FP::modulus();
    let result1_int = (FP::modulus() + p1_int - q1_int) % FP::modulus();

    let result0_bytes = FP::to_limbs(&result0_int);
    let result0_words = bytes_to_words_le::<WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>(&result0_bytes);
    let result1_bytes = FP::to_limbs(&result1_int);
    let result1_words = bytes_to_words_le::<WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>(&result1_bytes);

    let result_words: Vec<u32> = vec![result0_words, result1_words]
        .into_iter()
        .flatten()
        .collect();

    let p_memory_records = (&rt.mw_slice(p_ptr, &result_words)[..]).try_into().unwrap();

    QuadFieldSubEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        p_ptr,
        p0: p0.try_into().unwrap(),
        p1: p1.try_into().unwrap(),
        q_ptr,
        q0: q0.try_into().unwrap(),
        q1: q1.try_into().unwrap(),
        p_memory_records,
        q_memory_records: (&q_memory_records_vec[..]).try_into().unwrap(),
    }
}

impl<'a, FP: FieldParameters> WithEvents<'a> for QuadFieldSubChip<FP> {
    type InputEvents = &'a [QuadFieldSubEvent<FP>];
    type OutputEvents = &'a [ByteLookupEvent];
}

impl<F: PrimeField32, FP: FieldParameters> MachineAir<F> for QuadFieldSubChip<FP>
where
    ExecutionRecord: EventLens<QuadFieldSubChip<FP>> + EventMutLens<QuadFieldSubChip<FP>>,
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match FP::FIELD_TYPE {
            FieldType::Bls12381 => "Bls12381QuadFieldSub".to_string(),
            _ => panic!("Unsupported field"),
        }
    }

    #[instrument(name = "generate bls12381 fp2 sub trace", level = "debug", skip_all)]
    fn generate_trace<EL: EventLens<Self>, OL: EventMutLens<Self>>(
        &self,
        input: &EL,
        output: &mut OL,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the field type.
        let events = input.events();

        let (mut rows, new_byte_lookup_events): (Vec<_>, Vec<Vec<ByteLookupEvent>>) = events
            .par_iter()
            .map(|event| {
                let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
                let mut row = vec![F::zero(); size_of::<QuadFieldSubCols<u8, FP>>()];
                let cols: &mut QuadFieldSubCols<F, FP> = row.as_mut_slice().borrow_mut();

                // Decode field elements.
                let p0 = &event.p0;
                let p1 = &event.p1;
                let q0 = &event.q0;
                let q1 = &event.q1;
                let p0_int = BigUint::from_slice(p0);
                let p1_int = BigUint::from_slice(p1);
                let q0_int = BigUint::from_slice(q0);
                let q1_int = BigUint::from_slice(q1);

                // Populate basic columns.
                cols.is_real = F::one();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                let mut new_byte_lookup_events = Vec::new();

                cols.p_sub_q.populate(
                    &mut new_byte_lookup_events,
                    event.shard,
                    &[p0_int, p1_int],
                    &[q0_int, q1_int],
                    QuadFieldOperation::Sub,
                );

                // Populate the memory access columns.
                for i in 0..(2 * words_len) {
                    cols.q_access[i]
                        .populate(event.q_memory_records[i], &mut new_byte_lookup_events);
                }
                for i in 0..(2 * words_len) {
                    cols.p_access[i]
                        .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                }

                (row, new_byte_lookup_events)
            })
            .unzip();

        for byte_lookup_events in new_byte_lookup_events {
            output.add_events(&byte_lookup_events);
        }

        pad_vec_rows(&mut rows, || {
            let mut row = vec![F::zero(); size_of::<QuadFieldSubCols<u8, FP>>()];
            let cols: &mut QuadFieldSubCols<F, FP> = row.as_mut_slice().borrow_mut();
            let zero = [BigUint::zero(), BigUint::zero()];
            cols.p_sub_q
                .populate(&mut vec![], 0, &zero, &zero, QuadFieldOperation::Sub);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<QuadFieldSubCols<u8, FP>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match FP::FIELD_TYPE {
            FieldType::Bls12381 => !shard.bls12381_fp2_sub_events.is_empty(),
            _ => panic!("Unsupported field"),
        }
    }
}

impl<F, FP: FieldParameters> BaseAir<F> for QuadFieldSubChip<FP> {
    fn width(&self) -> usize {
        size_of::<QuadFieldSubCols<u8, FP>>()
    }
}

impl<AB, FP: FieldParameters> Air<AB> for QuadFieldSubChip<FP>
where
    AB: AluAirBuilder + MemoryAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
        let main = builder.main();
        let local = main.row_slice(0);
        let row: &QuadFieldSubCols<AB::Var, FP> = (*local).borrow();

        let p0: Limbs<_, FP::NB_LIMBS> = limbs_from_prev_access(&row.p_access[..words_len]);
        let p1: Limbs<_, FP::NB_LIMBS> = limbs_from_prev_access(&row.p_access[words_len..]);
        let q0: Limbs<_, FP::NB_LIMBS> = limbs_from_prev_access(&row.q_access[..words_len]);
        let q1: Limbs<_, FP::NB_LIMBS> = limbs_from_prev_access(&row.q_access[words_len..]);

        row.p_sub_q.eval(
            builder,
            &[p0, p1],
            &[q0, q1],
            QuadFieldOperation::Sub,
            row.shard,
            row.is_real,
        );

        // Constraint self.p_access.value = [self.p_sub_q.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..FP::NB_LIMBS::USIZE {
            builder
                .when(row.is_real)
                .assert_eq(row.p_sub_q.result[0][i], row.p_access[i / 4].value()[i % 4]);
            builder.when(row.is_real).assert_eq(
                row.p_sub_q.result[1][i],
                row.p_access[words_len + (i / 4)].value()[i % 4],
            );
        }

        for i in 0..(2 * words_len) {
            builder.eval_memory_access(
                row.shard,
                row.clk, // clk + 0 -> Memory
                row.q_ptr + AB::F::from_canonical_u32(i as u32 * 4),
                &row.q_access[i],
                row.is_real,
            );
        }
        for i in 0..(2 * words_len) {
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
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_SUB.syscall_id())
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
    use crate::{utils, utils::tests::BLS12381_FP2_SUB_ELF, Program};

    #[test]
    fn test_bls12381_fp2_sub_simple() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP2_SUB_ELF);
        utils::run_test(program).unwrap();
    }
}
