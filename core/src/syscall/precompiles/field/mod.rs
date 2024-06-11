use crate::air::{AluAirBuilder, MachineAir, MemoryAirBuilder, Polynomial};
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::{MemoryCols, MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::params::{
    FieldParameters, FieldType, Limbs, WithFieldAddition, WithFieldMultiplication,
    WithFieldSubtraction, WITNESS_LIMBS, WORDS_FIELD_ELEMENT,
};
use crate::operations::field::util_air::eval_field_operation;
use crate::runtime::{ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, SyscallCode};
use crate::stark::FieldAddChip;
use crate::syscall::precompiles::field::add::FieldAddCols;
use crate::utils::{limbs_from_access, limbs_from_prev_access, pad_vec_rows};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use itertools::{chain, Itertools};
use num::Zero;
use num_bigint::BigUint;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::iter::zip;
use std::marker::PhantomData;
use tracing::instrument;
use wp1_derive::AlignedBorrow;

pub mod add;
pub mod mul;
pub mod sub;

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

/// Fp subtraction event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEvent<FP: FieldParameters> {
    pub shard: u32,
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

/// A set of columns to compute field element subtraction where p, q are in some prime field `Fp`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldCols<T, FP: FieldParameters> {
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_FIELD_ELEMENT<FP::NB_LIMBS>>,

    pub op_cols: FieldOpCols<T, FP>,
}

impl<AB, FP: FieldParameters> Air<AB> for FieldChip<FP>
where
    AB: AluAirBuilder + MemoryAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
        let main = builder.main();
        let local = main.row_slice(0);
        let row: &FieldCols<AB::Var, FP> = (*local).borrow();

        builder.assert_bool(row.is_add);
        builder.assert_bool(row.is_sub);
        builder.assert_bool(row.is_mul);
        let is_real = row.is_add + row.is_sub + row.is_mul;
        builder.assert_bool(is_real.clone());

        let p: Polynomial<AB::Expr> = row
            .p_access
            .iter()
            .flat_map(|a| a.prev_value().0)
            .map(Into::into)
            .collect();
        let q: Polynomial<AB::Expr> = row
            .q_access
            .iter()
            .flat_map(|a| a.prev_value().0)
            .map(Into::into)
            .collect();
        let r: Polynomial<AB::Expr> = row
            .p_access
            .iter()
            .flat_map(|a| a.value().0)
            .map(Into::into)
            .collect();

        let op = (p.clone() * &q - &r) * row.is_mul.into()
            + (p.clone() + &q - &r) * row.is_add.into()
            + (r.clone() + &q - &p) * row.is_sub.into();

        let a: Polynomial<AB::Expr> = zip(&p, &r)
            .map(|(&a, &r)| (row.is_add + row.is_mul) * a + row.is_sub * r)
            .collect();
        let r: Polynomial<AB::Expr> = zip(&p, &r)
            .map(|(&a, &r)| (row.is_add + row.is_mul) * r + row.is_sub * a)
            .collect();
        let b: Polynomial<AB::Expr> = q.into_iter().map(Into::into).collect();

        let a_add_b: Polynomial<AB::Expr> = a.clone() + &b;
        let a_mul_b: Polynomial<AB::Expr> = a * b;

        let a_op_b: Polynomial<AB::Expr> =
            a_add_b * row.is_add.into() + a_sub_b * row.is_sub.into() + a_mul_b * row.is_mul.into();

        row.op_cols
            .eval_any(builder, a_op_b, row.shard, is_real.clone());

        // Constraint self.p_access.value = [self.p_add_q.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..FP::NB_LIMBS::USIZE {
            builder
                .when(is_real.clone())
                .assert_eq(row.op_cols.result[i], row.p_access[i / 4].value()[i % 4]);
        }

        for i in 0..words_len {
            builder.eval_memory_access(
                row.shard,
                row.clk, // clk + 0 -> Memory
                row.q_ptr + AB::F::from_canonical_u32(i as u32 * 4),
                &row.q_access[i],
                is_real.clone(),
            );
        }
        for i in 0..words_len {
            builder.eval_memory_access(
                row.shard,
                row.clk + AB::F::from_canonical_u32(1), // The clk for p is moved by 1.
                row.p_ptr + AB::F::from_canonical_u32(i as u32 * 4),
                &row.p_access[i],
                is_real.clone(),
            );
        }

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
            row.clk,
            syscall_id_fe,
            row.p_ptr,
            row.q_ptr,
            is_real,
        );
    }
}

impl<
        F: PrimeField32,
        FP: FieldParameters + WithFieldAddition + WithFieldSubtraction + WithFieldMultiplication,
    > MachineAir<F> for FieldChip<FP>
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
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the field type.
        let add_events = FP::add_events(input);
        let sub_events = FP::sub_events(input);
        let mul_events = FP::mul_events(input);

        let events = add_events
            .par_iter()
            .map(|add_event| FieldEvent {
                shard: add_event.shard,
                clk: add_event.shard,
                op: FieldOperation::Add,
                p_ptr: add_event.p_ptr,
                p: add_event.p.clone(),
                q_ptr: add_event.q_ptr,
                q: add_event.q.clone(),
                p_memory_records: add_event.p_memory_records.clone(),
                q_memory_records: add_event.q_memory_records.clone(),
            })
            .chain(sub_events.par_iter().map(|sub_event| FieldEvent {
                shard: sub_event.shard,
                clk: sub_event.shard,
                op: FieldOperation::Sub,
                p_ptr: sub_event.p_ptr,
                p: sub_event.p.clone(),
                q_ptr: sub_event.q_ptr,
                q: sub_event.q.clone(),
                p_memory_records: sub_event.p_memory_records.clone(),
                q_memory_records: sub_event.q_memory_records.clone(),
            }))
            .chain(mul_events.par_iter().map(|mul_event| FieldEvent {
                shard: mul_event.shard,
                clk: mul_event.shard,
                op: FieldOperation::Mul,
                p_ptr: mul_event.p_ptr,
                p: mul_event.p.clone(),
                q_ptr: mul_event.q_ptr,
                q: mul_event.q.clone(),
                p_memory_records: mul_event.p_memory_records.clone(),
                q_memory_records: mul_event.q_memory_records.clone(),
            }));

        let (mut rows, new_byte_lookup_events): (Vec<_>, Vec<Vec<ByteLookupEvent>>) = events
            .into_par_iter()
            .map(|event| {
                let words_len = WORDS_FIELD_ELEMENT::<FP::NB_LIMBS>::USIZE;
                let mut row = vec![F::zero(); size_of::<FieldAddCols<u8, FP>>()];
                let cols: &mut FieldCols<F, FP> = row.as_mut_slice().borrow_mut();

                // Populate basic columns.
                match event.op {
                    FieldOperation::Add => cols.is_add = F::one(),
                    FieldOperation::Mul => cols.is_sub = F::one(),
                    FieldOperation::Sub => cols.is_mul = F::one(),
                    FieldOperation::Div => {
                        unreachable!()
                    }
                }
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                // Decode field elements.
                let p = &event.p;
                let q = &event.q;
                let p_int = BigUint::from_slice(p);
                let q_int = BigUint::from_slice(q);

                let mut new_byte_lookup_events = Vec::new();
                cols.p_add_q.populate(
                    &mut new_byte_lookup_events,
                    event.shard,
                    &p_int,
                    &q_int,
                    FieldOperation::Add,
                );

                // Populate the memory access columns.
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
            let mut row = vec![F::zero(); size_of::<FieldCols<u8, FP>>()];
            let cols: &mut FieldCols<F, FP> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            cols.p_add_q
                .populate(&mut vec![], 0, &zero, &zero, FieldOperation::Add);
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
            FieldType::Bls12381 => {
                !shard.bls12381_fp_add_events.is_empty()
                    && !shard.bls12381_fp_sub_events.is_empty()
                    && !shard.bls12381_fp_mul_events.is_empty()
            }
            _ => panic!("Unsupported field"),
        }
    }
}

impl<F, FP: FieldParameters> BaseAir<F> for FieldChip<FP> {
    fn width(&self) -> usize {
        size_of::<FieldCols<u8, FP>>()
    }
}
