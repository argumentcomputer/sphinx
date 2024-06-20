use crate::air::{AluAirBuilder, EventLens, MachineAir, MemoryAirBuilder, Polynomial, WithEvents};
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::params::{FieldParameters, FieldType, WORDS_FIELD_ELEMENT};
use crate::runtime::SyscallContext;
use crate::runtime::{ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, SyscallCode};
use crate::utils::{bytes_to_words_le, pad_vec_rows};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use num::Zero;
use num_bigint::BigUint;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sphinx_derive::AlignedBorrow;
use std::marker::PhantomData;
use tracing::instrument;

#[derive(Default)]
pub struct FieldChip<FP: FieldParameters> {
    _marker: PhantomData<FP>,
}

impl<FP: FieldParameters> FieldChip<FP> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct FieldAddSyscall<FP: FieldParameters> {
    _marker: PhantomData<FP>,
}

impl<FP: FieldParameters> FieldAddSyscall<FP> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct FieldSubSyscall<FP: FieldParameters> {
    _marker: PhantomData<FP>,
}

impl<FP: FieldParameters> FieldSubSyscall<FP> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct FieldMulSyscall<FP: FieldParameters> {
    _marker: PhantomData<FP>,
}

impl<FP: FieldParameters> FieldMulSyscall<FP> {
    pub fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}

/// Fp subtraction event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEvent<FP: FieldParameters> {
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub op: FieldOperation,
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

impl<'a, FP: FieldParameters> WithEvents<'a> for FieldChip<FP> {
    type Events = &'a [FieldEvent<FP>];
}

pub fn create_fp_event<FP: FieldParameters>(
    rt: &mut SyscallContext<'_>,
    op: FieldOperation,
    arg1: u32,
    arg2: u32,
) -> FieldEvent<FP> {
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
    let result_int = match op {
        FieldOperation::Add => (p_int + q_int) % FP::modulus(),
        FieldOperation::Sub => (FP::modulus() + p_int - q_int) % FP::modulus(),
        FieldOperation::Mul => (p_int * q_int) % FP::modulus(),
        _ => panic!("unsupported field operation in FieldChip"),
    };
    let result_bytes = FP::to_limbs(&result_int);
    let result_words = bytes_to_words_le::<WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>(&result_bytes);

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;
    let p_memory_records = (&rt.mw_slice(p_ptr, &result_words.into())[..])
        .try_into()
        .unwrap();

    FieldEvent {
        shard: rt.current_shard(),
        channel: rt.current_channel(),
        clk: start_clk,
        op,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
    }
}

/// A set of columns to compute field element subtraction where p, q are in some prime field `Fp`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldCols<T, FP: FieldParameters> {
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub shard: T,
    pub channel: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryReadWriteCols<T>, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,

    pub op_cols: FieldOpCols<T, FP>,
}

impl<AB, FP: FieldParameters> Air<AB> for FieldChip<FP>
where
    AB: AluAirBuilder + MemoryAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let row: &FieldCols<AB::Var, FP> = (*local).borrow();

        builder.assert_bool(row.is_add);
        builder.assert_bool(row.is_sub);
        builder.assert_bool(row.is_mul);
        let is_real = row.is_add + row.is_sub + row.is_mul;
        builder.assert_bool(is_real.clone());

        let p: Vec<AB::Expr> = row
            .p_access
            .iter()
            .flat_map(|x| x.prev_value().0)
            .map(Into::into)
            .collect();
        let q: Vec<AB::Expr> = row
            .q_access
            .iter()
            .flat_map(|x| x.prev_value().0)
            .map(Into::into)
            .collect();
        let r: Vec<AB::Expr> = row
            .p_access
            .iter()
            .flat_map(|x| x.value().0)
            .map(Into::into)
            .collect();

        // let op = (&p * &q - &r) * row.is_mul.into()
        //     + (p.clone() + &q - &r) * row.is_add.into()
        //     + (r.clone() + &q - &p) * row.is_sub.into();

        // let a: Polynomial<AB::Expr> = zip(p.into_iter(), r.into_iter())
        //     .map(|(a, r)| (row.is_add + row.is_mul) * a + row.is_sub * r)
        //     .collect();
        // let r: Polynomial<AB::Expr> = zip(p.into_iter(), r.into_iter())
        //     .map(|(a, r)| (row.is_add + row.is_mul) * r + row.is_sub * a)
        //     .collect();
        let a: Polynomial<AB::Expr> = p.clone().into_iter().collect();
        let b: Polynomial<AB::Expr> = q.clone().into_iter().collect();
        let res: Polynomial<AB::Expr> = r.clone().into_iter().collect();

        // let a_add_b: Polynomial<AB::Expr> = a.clone() + &b;
        // let a_mul_b: Polynomial<AB::Expr> = a * b;

        // let a_op_b: Polynomial<AB::Expr> =
        //     a_add_b * (row.is_add.into() + row.is_sub.into()) + a_mul_b * row.is_mul.into();

        //r=a-b => r+b=a
        let a_op_b: Polynomial<AB::Expr> = (&a + &b) * row.is_add.into()
            + (res + &b) * row.is_sub.into()
            + (a * b) * row.is_mul.into();

        let p_limbs = FP::modulus_field_iter::<AB::F>()
            .map(AB::Expr::from)
            .collect::<Polynomial<_>>();
        row.op_cols.eval_any_with_modulus(
            builder,
            a_op_b,
            p_limbs,
            row.shard,
            row.channel,
            is_real.clone(),
        );

        // Constraint self.p_access.value = [self.p_add_q.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..FP::NB_LIMBS::USIZE {
            let result = (row.is_add + row.is_mul) * r[i].clone() + row.is_sub * p[i].clone();
            builder
                .when(is_real.clone())
                .assert_eq(row.op_cols.result[i], result);
        }

        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk, // clk + 0 -> Memory
            row.q_ptr,
            &row.q_access,
            is_real.clone(),
        );
        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk + AB::F::from_canonical_u32(1), // The clk for p is moved by 1.
            row.p_ptr,
            &row.p_access,
            is_real.clone(),
        );

        // Fetch the syscall id for the field type.
        let syscall_id_fe = match FP::FIELD_TYPE {
            FieldType::Bls12381 => {
                AB::Expr::from_canonical_u32(SyscallCode::BLS12381_FP_ADD.syscall_id())
                    * row.is_add.into()
                    + AB::Expr::from_canonical_u32(SyscallCode::BLS12381_FP_SUB.syscall_id())
                        * row.is_sub.into()
                    + AB::Expr::from_canonical_u32(SyscallCode::BLS12381_FP_MUL.syscall_id())
                        * row.is_mul.into()
            }
            _ => panic!("Unsupported field"),
        };

        builder.receive_syscall(
            row.shard,
            row.channel,
            row.clk,
            syscall_id_fe,
            row.p_ptr,
            row.q_ptr,
            is_real,
        );
    }
}

impl<F: PrimeField32, FP: FieldParameters> MachineAir<F> for FieldChip<FP>
where
    ExecutionRecord: EventLens<FieldChip<FP>>,
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match FP::FIELD_TYPE {
            FieldType::Bls12381 => "Bls12381Field".to_string(),
            _ => panic!("Unsupported field"),
        }
    }

    #[instrument(name = "generate field trace", level = "debug", skip_all)]
    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.events();

        let (mut rows, new_byte_lookup_events): (Vec<_>, Vec<Vec<ByteLookupEvent>>) = events
            .into_par_iter()
            .map(|event| {
                let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
                let mut row = vec![F::zero(); size_of::<FieldCols<u8, FP>>()];
                let cols: &mut FieldCols<F, FP> = row.as_mut_slice().borrow_mut();

                // Populate basic columns.
                match event.op {
                    FieldOperation::Add => cols.is_add = F::one(),
                    FieldOperation::Mul => cols.is_mul = F::one(),
                    FieldOperation::Sub => cols.is_sub = F::one(),
                    FieldOperation::Div => {
                        unreachable!()
                    }
                }
                cols.shard = F::from_canonical_u32(event.shard);
                cols.channel = F::from_canonical_u32(event.channel);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                // Decode field elements.
                let p = &event.p;
                let q = &event.q;
                let p_int = BigUint::from_slice(p);
                let q_int = BigUint::from_slice(q);

                let mut new_byte_lookup_events = Vec::new();
                cols.op_cols.populate(
                    &mut new_byte_lookup_events,
                    event.shard,
                    event.channel,
                    &p_int,
                    &q_int,
                    event.op,
                );

                // Populate the memory access columns.
                for i in 0..words_len {
                    cols.q_access[i].populate(
                        event.channel,
                        event.q_memory_records[i],
                        &mut new_byte_lookup_events,
                    );
                }
                for i in 0..words_len {
                    cols.p_access[i].populate(
                        event.channel,
                        event.p_memory_records[i],
                        &mut new_byte_lookup_events,
                    );
                }

                (row, new_byte_lookup_events)
            })
            .unzip();

        for byte_lookup_events in new_byte_lookup_events {
            output.add_byte_lookup_events(byte_lookup_events);
        }

        pad_vec_rows(&mut rows, || {
            let mut row = vec![F::zero(); size_of::<FieldCols<u8, FP>>()];
            let cols: &mut FieldCols<F, FP> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            cols.op_cols
                .populate(&mut vec![], 0, 0, &zero, &zero, FieldOperation::Add);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<FieldCols<u8, FP>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match FP::FIELD_TYPE {
            FieldType::Bls12381 => !shard.bls12381_fp_events.is_empty(),
            _ => panic!("Unsupported field"),
        }
    }
}

impl<F, FP: FieldParameters> BaseAir<F> for FieldChip<FP> {
    fn width(&self) -> usize {
        size_of::<FieldCols<u8, FP>>()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        utils,
        utils::tests::{BLS12381_FP_ADD_ELF, BLS12381_FP_MUL_ELF, BLS12381_FP_SUB_ELF},
        Program,
    };

    #[test]
    fn test_bls12381_fp_add_simple() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_ADD_ELF);
        utils::run_test(program).unwrap();
    }

    #[test]
    fn test_bls12381_fp_mul_simple() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_MUL_ELF);
        utils::run_test(program).unwrap();
    }

    #[test]
    fn test_bls12381_fp_sub_simple() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_SUB_ELF);
        utils::run_test(program).unwrap();
    }
}
