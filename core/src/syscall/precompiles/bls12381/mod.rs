use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::bytes::ByteLookupEvent;
use crate::memory::MemoryCols;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::params::Limbs;
use crate::runtime::ExecutionRecord;
use crate::runtime::MemoryReadRecord;
use crate::runtime::MemoryWriteRecord;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::bytes_to_words_le;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::weierstrass::bls12381::Bls12381BaseField;
use crate::utils::ec::weierstrass::bls12381::Bls12381Parameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::EllipticCurve;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::instrument;
use wp1_derive::AlignedBorrow;
use wp1_zkvm::syscalls::BLS12381_FP_ADD;

pub const NUM_BLS12381_FP_ADD_COLS: usize = size_of::<Bls12381FpAddCols<u8>>();

/// A set of columns to compute `Bls12381FpAdd` where p, q are field elements.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bls12381FpAddCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: [MemoryWriteCols<T>; 12],
    pub q_access: [MemoryReadCols<T>; 12],
    pub(crate) p_add_q: FieldOpCols<T, <Bls12381BaseField as FieldParameters>::NB_LIMBS>,
}

#[derive(Default)]
pub struct Bls12381FpAddChip {}

impl Bls12381FpAddChip {
    pub fn new() -> Self {
        Self {}
    }
    fn populate_field_ops<F: PrimeField32>(
        cols: &mut Bls12381FpAddCols<F>,
        p: BigUint,
        q: BigUint,
    ) {
        let populate = cols
            .p_add_q
            .populate::<Bls12381BaseField>(&p, &q, FieldOperation::Add);
    }
}

/// Bls12381 Fp addition event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bls12381FpAddEvent {
    pub shard: u32,
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 12],
    pub q_ptr: u32,
    pub q: [u32; 12],
    pub p_memory_records: [MemoryWriteRecord; 12],
    pub q_memory_records: [MemoryReadRecord; 12],
}

pub fn create_bls_fp_add_event(
    rt: &mut SyscallContext,
    arg1: u32,
    arg2: u32,
) -> Bls12381FpAddEvent {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }
    let q_ptr = arg2;
    if q_ptr % 4 != 0 {
        panic!();
    }

    let p: [u32; 12] = rt.slice_unsafe(p_ptr, 12).try_into().unwrap();
    let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, 12);
    let q_memory_records = q_memory_records_vec.try_into().unwrap();
    let q: [u32; 12] = q_vec.try_into().unwrap();
    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;

    let p_bytes = p[0..p.len()]
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect::<Vec<_>>();
    let p_int = BigUint::from_bytes_le(p_bytes.as_slice());
    let q_bytes = q[0..q.len()]
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect::<Vec<_>>();
    let q_int = BigUint::from_bytes_le(q_bytes.as_slice());
    let result_int = (p_int + q_int) % Bls12381BaseField::modulus();

    let result_words: [u32; 12] = bytes_to_words_le(&result_int.to_bytes_le());

    let p_memory_records = rt.mw_slice(p_ptr, &result_words).try_into().unwrap();

    Bls12381FpAddEvent {
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

impl Syscall for Bls12381FpAddChip {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_bls_fp_add_event(rt, arg1, arg2);
        rt.record_mut().bls12381_fp_add_events.push(event);
        None
    }
}

impl<F: PrimeField32> MachineAir<F> for Bls12381FpAddChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "Bls12381FpAdd".to_string()
    }

    #[instrument(name = "generate ed add trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (mut rows, new_byte_lookup_events): (
            Vec<[F; NUM_BLS12381_FP_ADD_COLS]>,
            Vec<Vec<ByteLookupEvent>>,
        ) = input
            .ed_add_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BLS12381_FP_ADD_COLS];
                let cols: &mut Bls12381FpAddCols<F> = row.as_mut_slice().borrow_mut();

                // Decode field elements.
                let p = &event.p;
                let p_bytes = p[0..p.len()]
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect::<Vec<_>>();
                let p_int = BigUint::from_bytes_le(p_bytes.as_slice());
                let q = &event.q;
                let q_bytes = q[0..q.len()]
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect::<Vec<_>>();
                let q_int = BigUint::from_bytes_le(q_bytes.as_slice());
                // FIXME

                // Populate basic columns.
                cols.is_real = F::one();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                Self::populate_field_ops(cols, p_int, q_int);

                // Populate the memory access columns.
                let mut new_byte_lookup_events = Vec::new();
                for i in 0..12 {
                    cols.q_access[i]
                        .populate(event.q_memory_records[i], &mut new_byte_lookup_events);
                }
                for i in 0..12 {
                    cols.p_access[i]
                        .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                }

                (row, new_byte_lookup_events)
            })
            .unzip();

        for byte_lookup_events in new_byte_lookup_events {
            output.add_byte_lookup_events(byte_lookup_events);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_BLS12381_FP_ADD_COLS];
            let cols: &mut Bls12381FpAddCols<F> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(cols, zero.clone(), zero);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLS12381_FP_ADD_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.ed_add_events.is_empty()
    }
}

impl<F> BaseAir<F> for Bls12381FpAddChip {
    fn width(&self) -> usize {
        NUM_BLS12381_FP_ADD_COLS
    }
}

impl<AB> Air<AB> for Bls12381FpAddChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &Bls12381FpAddCols<AB::Var> = main.row_slice(0).borrow();

        let p: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> = limbs_from_prev_access(&row.p_access[0..12]);
        let q: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> = limbs_from_prev_access(&row.q_access[0..12]);

        // p_add_q = p + q
        row.p_add_q
            .eval::<AB, Bls12381BaseField, _, _>(builder, &p, &q, FieldOperation::Add);

        // Constraint self.p_access.value = [self.p_add_q.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..48 {
            builder
                .when(row.is_real)
                .assert_eq(row.p_add_q.result[i], row.p_access[i / 4].value()[i % 4]);
        }

        for i in 0..12 {
            builder.constraint_memory_access(
                row.shard,
                row.clk, // clk + 0 -> Memory
                row.q_ptr + AB::F::from_canonical_u32(i * 4),
                &row.q_access[i as usize],
                row.is_real,
            );
        }
        for i in 0..12 {
            builder.constraint_memory_access(
                row.shard,
                row.clk + AB::F::from_canonical_u32(1), // The clk for p is moved by 1.
                row.p_ptr + AB::F::from_canonical_u32(i * 4),
                &row.p_access[i as usize],
                row.is_real,
            );
        }

        builder.receive_syscall(
            row.shard,
            row.clk,
            AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_ADD.syscall_id()),
            row.p_ptr,
            row.q_ptr,
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::utils;
    use crate::utils::tests::BLS12381_FP_ADD_ELF;
    use crate::Program;

    #[test]
    fn test_bls12381_fp_add_simple() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_ADD_ELF);
        utils::run_test(program).unwrap();
    }

    // #[test]
    // fn test_ed25519_program() {
    //     utils::setup_logger();
    //     let program = Program::from(ED25519_ELF);
    //     utils::run_test(program).unwrap();
    // }
}
