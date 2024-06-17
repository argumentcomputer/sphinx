use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::{fmt::Debug, marker::PhantomData};

use hybrid_array::{typenum::Unsigned, Array};
use num::BigUint;
use num::Zero;

use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use sphinx_derive::AlignedBorrow;

use crate::air::BaseAirBuilder;
use crate::{bytes::event::ByteRecord, utils::limbs_from_access};
use crate::bytes::ByteLookupEvent;
use crate::memory::MemoryCols;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_den::FieldDenCols;
use crate::operations::field::field_inner_product::FieldInnerProductCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::Limbs;
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::create_ec_add_event;
use crate::syscall::precompiles::SyscallContext;
use crate::syscall::precompiles::DEFAULT_NUM_LIMBS_T;
use crate::syscall::precompiles::WORDS_CURVEPOINT;
use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
use crate::utils::ec::edwards::EdwardsParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::BaseLimbWidth;
use crate::utils::ec::EllipticCurve;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;
use crate::{air::MachineAir, utils::ec::EllipticCurveParameters};
use crate::{
    air::{AluAirBuilder, EventLens, MemoryAirBuilder, WithEvents},
    syscall::precompiles::ECAddEvent,
};

pub const NUM_ED_ADD_COLS: usize = size_of::<EdAddAssignCols<u8, Ed25519BaseField>>();

/// A set of columns to compute `EdAdd` where a, b are field elements.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T, P: FieldParameters> {
    pub is_real: T,
    pub shard: T,
    pub channel: T,
    pub clk: T,
    pub nonce: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_CURVEPOINT<P::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_CURVEPOINT<P::NB_LIMBS>>,
    pub(crate) x3_numerator: FieldInnerProductCols<T, P>,
    pub(crate) y3_numerator: FieldInnerProductCols<T, P>,
    pub(crate) x1_mul_y1: FieldOpCols<T, P>,
    pub(crate) x2_mul_y2: FieldOpCols<T, P>,
    pub(crate) f: FieldOpCols<T, P>,
    pub(crate) d_mul_f: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldDenCols<T, P>,
    pub(crate) y3_ins: FieldDenCols<T, P>,
}

#[derive(Default)]
pub struct EdAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + EdwardsParameters> EdAddAssignChip<E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u32,
        cols: &mut EdAddAssignCols<F, <E as EllipticCurveParameters>::BaseField>,
        p_x: &BigUint,
        p_y: &BigUint,
        q_x: &BigUint,
        q_y: &BigUint,
    ) {
        let x3_numerator = cols.x3_numerator.populate(
            record,
            shard,
            channel,
            &[p_x.clone(), q_x.clone()],
            &[q_y.clone(), p_y.clone()],
        );
        let y3_numerator = cols.y3_numerator.populate(
            record,
            shard,
            channel,
            &[p_y.clone(), p_x.clone()],
            &[q_y.clone(), q_x.clone()],
        );
        let x1_mul_y1 =
            cols.x1_mul_y1
                .populate(record, shard, channel, p_x, p_y, FieldOperation::Mul);
        let x2_mul_y2 =
            cols.x2_mul_y2
                .populate(record, shard, channel, q_x, q_y, FieldOperation::Mul);
        let f = cols.f.populate(
            record,
            shard,
            channel,
            &x1_mul_y1,
            &x2_mul_y2,
            FieldOperation::Mul,
        );

        let d = E::d_biguint();
        let d_mul_f = cols
            .d_mul_f
            .populate(record, shard, channel, &f, &d, FieldOperation::Mul);

        cols.x3_ins
            .populate(record, shard, channel, &x3_numerator, &d_mul_f, true);
        cols.y3_ins
            .populate(record, shard, channel, &y3_numerator, &d_mul_f, false);
    }
}

// Specialized to 32-bit limb field representations, extensible generically if
// the receiver ed_add_events matches the desired limb length
impl<
        F: FieldParameters<NB_LIMBS = DEFAULT_NUM_LIMBS_T>,
        E: EllipticCurve<BaseField = F> + EdwardsParameters,
    > Syscall for EdAddAssignChip<E>
{
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_ec_add_event::<E>(rt, arg1, arg2);
        rt.record_mut().ed_add_events.push(event);
        None
    }
}

impl<'a, E: EllipticCurve + EdwardsParameters> WithEvents<'a> for EdAddAssignChip<E> {
    type Events = &'a [ECAddEvent];
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> MachineAir<F> for EdAddAssignChip<E>
where
    ExecutionRecord: EventLens<EdAddAssignChip<E>>,
{
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (mut rows, new_byte_lookup_events): (Vec<Vec<F>>, Vec<Vec<ByteLookupEvent>>) = input
            .events()
            .par_iter()
            .map(|event| {
                let mut row = vec![F::zero(); size_of::<EdAddAssignCols<u8, E::BaseField>>()];
                let cols: &mut EdAddAssignCols<F, E::BaseField> = row.as_mut_slice().borrow_mut();

                // Decode affine points.
                let p = &event.p;
                let q = &event.q;
                let p = AffinePoint::<E>::from_words_le(p);
                let (p_x, p_y) = (p.x, p.y);
                let q = AffinePoint::<E>::from_words_le(q);
                let (q_x, q_y) = (q.x, q.y);

                // Populate basic columns.
                cols.is_real = F::one();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.channel = F::from_canonical_u32(event.channel);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                let mut new_byte_lookup_events = Vec::new();
                Self::populate_field_ops(
                    &mut new_byte_lookup_events,
                    event.shard,
                    event.channel,
                    cols,
                    &p_x,
                    &p_y,
                    &q_x,
                    &q_y,
                );

                // Populate the memory access columns.
                for i in 0..WORDS_CURVEPOINT::<BaseLimbWidth<E>>::USIZE {
                    cols.q_access[i].populate(
                        event.channel,
                        event.q_memory_records[i],
                        &mut new_byte_lookup_events,
                    );
                }
                for i in 0..WORDS_CURVEPOINT::<BaseLimbWidth<E>>::USIZE {
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

        pad_rows(&mut rows, || {
            let mut row = vec![F::zero(); size_of::<EdAddAssignCols<u8, E::BaseField>>()];
            let cols: &mut EdAddAssignCols<F, E::BaseField> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(&mut vec![], 0, 0, cols, &zero, &zero, &zero, &zero);
            row
        });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_ADD_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut EdAddAssignCols<F, E::BaseField> =
                trace.values[i * NUM_ED_ADD_COLS..(i + 1) * NUM_ED_ADD_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.ed_add_events.is_empty()
    }
}

impl<F, E: EllipticCurve + EdwardsParameters> BaseAir<F> for EdAddAssignChip<E> {
    fn width(&self) -> usize {
        size_of::<EdAddAssignCols<u8, E::BaseField>>()
    }
}

impl<AB, E: EllipticCurve + EdwardsParameters> Air<AB> for EdAddAssignChip<E>
where
    AB: AluAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &EdAddAssignCols<AB::Var, E::BaseField> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &EdAddAssignCols<AB::Var, E::BaseField> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let x1 = limbs_from_prev_access(&local.p_access[0..8]);
        let x2 = limbs_from_prev_access(&local.q_access[0..8]);
        let y1 = limbs_from_prev_access(&local.p_access[8..16]);
        let y2 = limbs_from_prev_access(&local.q_access[8..16]);

        // x3_numerator = x1 * y2 + x2 * y1.
        local.x3_numerator.eval(
            builder,
            &[x1.clone(), x2.clone()],
            &[y2.clone(), y1.clone()],
            local.shard,
            local.channel,
            local.is_real,
        );

        // y3_numerator = y1 * y2 + x1 * x2.
        local.y3_numerator.eval(
            builder,
            &[y1.clone(), x1.clone()],
            &[y2.clone(), x2.clone()],
            local.shard,
            local.channel,
            local.is_real,
        );

        // f = x1 * x2 * y1 * y2.
        local.x1_mul_y1.eval(
            builder,
            &x1,
            &y1,
            FieldOperation::Mul,
            local.shard,
            local.channel,
            local.is_real,
        );
        local.x2_mul_y2.eval(
            builder,
            &x2,
            &y2,
            FieldOperation::Mul,
            local.shard,
            local.channel,
            local.is_real,
        );

        let x1_mul_y1 = &local.x1_mul_y1.result;
        let x2_mul_y2 = &local.x2_mul_y2.result;
        local.f.eval(
            builder,
            x1_mul_y1,
            x2_mul_y2,
            FieldOperation::Mul,
            local.shard,
            local.channel,
            local.is_real,
        );

        // d * f.
        let f = &local.f.result;
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::F>(&d_biguint);
        local.d_mul_f.eval(
            builder,
            f,
            &d_const,
            FieldOperation::Mul,
            local.shard,
            local.channel,
            local.is_real,
        );

        let d_mul_f = &local.d_mul_f.result;

        // x3 = x3_numerator / (1 + d * f).
        local.x3_ins.eval(
            builder,
            &local.x3_numerator.result,
            d_mul_f,
            true,
            local.shard,
            local.channel,
            local.is_real,
        );

        // y3 = y3_numerator / (1 - d * f).
        local.y3_ins.eval(
            builder,
            &local.y3_numerator.result,
            d_mul_f,
            false,
            local.shard,
            local.channel,
            local.is_real,
        );

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        let p_access_vec: Limbs<_, DEFAULT_NUM_LIMBS_T> = limbs_from_access(&local.p_access);
        builder
            .when(local.is_real)
            .assert_all_eq(local.x3_ins.result.clone(), p_access_vec[0..DEFAULT_NUM_LIMBS_T::USIZE].to_vec());
        builder.when(local.is_real).assert_all_eq(
            local.y3_ins.result.clone(),
            p_access_vec[DEFAULT_NUM_LIMBS_T::USIZE..DEFAULT_NUM_LIMBS_T::USIZE * 2].to_vec(),
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk.into(),
            local.q_ptr,
            &local.q_access,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk + AB::F::from_canonical_u32(1),
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::ED_ADD.syscall_id()),
            local.p_ptr,
            local.q_ptr,
            local.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        utils,
        utils::tests::{ED25519_ELF, ED_ADD_ELF},
        Program,
    };

    #[test]
    fn test_ed_add_simple() {
        utils::setup_logger();
        let program = Program::from(ED_ADD_ELF);
        utils::run_test(program).unwrap();
    }

    #[test]
    fn test_ed25519_program() {
        utils::setup_logger();
        let program = Program::from(ED25519_ELF);
        utils::run_test(program).unwrap();
    }
}
