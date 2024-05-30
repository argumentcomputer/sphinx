use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::{fmt::Debug, marker::PhantomData};

use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sphinx_derive::AlignedBorrow;

use crate::air::{AluAirBuilder, EventLens, MachineAir, MemoryAirBuilder, WithEvents};
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::MemoryCols;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::params::{FieldParameters, Limbs, WORDS_FIELD_ELEMENT};
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::{ECAddEvent, WORDS_CURVEPOINT};
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::BaseLimbWidth;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurve;
use crate::utils::{limbs_from_prev_access, pad_rows};

pub const fn num_weierstrass_add_cols<P: FieldParameters>() -> usize {
    size_of::<WeierstrassAddAssignCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassAdd` that add two points on a Weierstrass curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignCols<T, P: FieldParameters> {
    pub is_real: T,
    pub shard: T,
    pub channel: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_CURVEPOINT<P::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_CURVEPOINT<P::NB_LIMBS>>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct WeierstrassAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassAddAssignChip<E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        channel: u32,
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        p_x: &BigUint,
        p_y: &BigUint,
        q_x: &BigUint,
        q_y: &BigUint,
    ) {
        // This populates necessary field operations to calculate the addition of two points on a
        // Weierstrass curve.

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator = cols.slope_numerator.populate(
                blu_events,
                shard,
                channel,
                q_y,
                p_y,
                FieldOperation::Sub,
            );

            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                shard,
                channel,
                q_x,
                p_x,
                FieldOperation::Sub,
            );

            cols.slope.populate(
                blu_events,
                shard,
                channel,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared = cols.slope_squared.populate(
                blu_events,
                shard,
                channel,
                &slope,
                &slope,
                FieldOperation::Mul,
            );
            let p_x_plus_q_x = cols.p_x_plus_q_x.populate(
                blu_events,
                shard,
                channel,
                p_x,
                q_x,
                FieldOperation::Add,
            );
            cols.x3_ins.populate(
                blu_events,
                shard,
                channel,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x_3n) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate(blu_events, shard, channel, p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                shard,
                channel,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                shard,
                channel,
                &slope_times_p_x_minus_x,
                p_y,
                FieldOperation::Sub,
            );
        }
    }
}

impl<'a, E: EllipticCurve + WeierstrassParameters> WithEvents<'a> for WeierstrassAddAssignChip<E> {
    type Events = &'a [ECAddEvent<<E::BaseField as FieldParameters>::NB_LIMBS>];
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassAddAssignChip<E>
where
    ExecutionRecord: EventLens<WeierstrassAddAssignChip<E>>,
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            CurveType::Bn254 => "Bn254AddAssign".to_string(),
            CurveType::Bls12381 => "Bls12381AddAssign".to_string(),
            _ => unreachable!("Unsupported curve"),
        }
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the curve type.
        let events = input.events();

        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let event = &events[i];
            let mut row = vec![F::zero(); num_weierstrass_add_cols::<E::BaseField>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();

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
            for i in 0..cols.q_access.len() {
                cols.q_access[i].populate(
                    event.channel,
                    event.q_memory_records[i],
                    &mut new_byte_lookup_events,
                );
            }
            for i in 0..cols.p_access.len() {
                cols.p_access[i].populate(
                    event.channel,
                    event.p_memory_records[i],
                    &mut new_byte_lookup_events,
                );
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = vec![F::zero(); num_weierstrass_add_cols::<E::BaseField>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(&mut vec![], 0, 0, cols, &zero, &zero, &zero, &zero);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<WeierstrassAddAssignCols<u8, E::BaseField>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => !shard.secp256k1_add_events.is_empty(),
            CurveType::Bn254 => !shard.bn254_add_events.is_empty(),
            CurveType::Bls12381 => !shard.bls12381_g1_add_events.is_empty(),
            _ => panic!("Unsupported curve"),
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassAddAssignChip<E> {
    fn width(&self) -> usize {
        size_of::<WeierstrassAddAssignCols<u8, E::BaseField>>()
    }
}

impl<AB, E: EllipticCurve> Air<AB> for WeierstrassAddAssignChip<E>
where
    AB: MemoryAirBuilder + AluAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &WeierstrassAddAssignCols<AB::Var, E::BaseField> = (*row).borrow();

        let nw_field_elt = WORDS_FIELD_ELEMENT::<BaseLimbWidth<E>>::USIZE;
        let p_x: Limbs<_, BaseLimbWidth<E>> =
            limbs_from_prev_access(&row.p_access[0..nw_field_elt]);
        let p_y: Limbs<_, BaseLimbWidth<E>> = limbs_from_prev_access(&row.p_access[nw_field_elt..]);

        let q_x: Limbs<_, BaseLimbWidth<E>> =
            limbs_from_prev_access(&row.q_access[0..nw_field_elt]);
        let q_y: Limbs<_, BaseLimbWidth<E>> = limbs_from_prev_access(&row.q_access[nw_field_elt..]);

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            row.slope_numerator.eval(
                builder,
                &q_y,
                &p_y,
                FieldOperation::Sub,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.slope_denominator.eval(
                builder,
                &q_x,
                &p_x,
                FieldOperation::Sub,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.slope.eval(
                builder,
                &row.slope_numerator.result,
                &row.slope_denominator.result,
                FieldOperation::Div,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.slope.result.clone()
        };

        // x = slope * slope - self.x - other.x.
        let x = {
            row.slope_squared.eval(
                builder,
                &slope,
                &slope,
                FieldOperation::Mul,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.p_x_plus_q_x.eval(
                builder,
                &p_x,
                &q_x,
                FieldOperation::Add,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.x3_ins.eval(
                builder,
                &row.slope_squared.result,
                &row.p_x_plus_q_x.result,
                FieldOperation::Sub,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.x3_ins.result.clone()
        };

        // y = slope * (p.x - x_3n) - q.y.
        {
            row.p_x_minus_x.eval(
                builder,
                &p_x,
                &x,
                FieldOperation::Sub,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.slope_times_p_x_minus_x.eval(
                builder,
                &slope,
                &row.p_x_minus_x.result,
                FieldOperation::Mul,
                row.shard,
                row.channel,
                row.is_real,
            );

            row.y3_ins.eval(
                builder,
                &row.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
                row.shard,
                row.channel,
                row.is_real,
            );
        }

        let words_field_elt = WORDS_FIELD_ELEMENT::<BaseLimbWidth<E>>::USIZE;
        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..BaseLimbWidth::<E>::USIZE {
            builder
                .when(row.is_real)
                .assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value()[i % 4]);
            builder.when(row.is_real).assert_eq(
                row.y3_ins.result[i],
                row.p_access[words_field_elt + i / 4].value()[i % 4],
            );
        }

        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk.into(),
            row.q_ptr,
            &row.q_access,
            row.is_real,
        );
        builder.eval_memory_access_slice(
            row.shard,
            row.channel,
            row.clk + AB::F::from_canonical_u32(1), // We read p at +1 since p, q could be the same.
            row.p_ptr,
            &row.p_access,
            row.is_real,
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_fe = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id())
            }
            CurveType::Bn254 => AB::F::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()),
            CurveType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_G1_ADD.syscall_id())
            }
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            row.shard,
            row.channel,
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

    use crate::{
        runtime::Program,
        utils::{
            run_test, setup_logger,
            tests::{
                BLS12381_G1_ADD_ELF, BLS12381_G1_SCALARMUL_ELF, BN254_ADD_ELF, BN254_MUL_ELF,
                SECP256K1_ADD_ELF, SECP256K1_MUL_ELF,
            },
        },
    };

    #[test]
    fn test_secp256k1_add_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_ADD_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bn254_add_simple() {
        setup_logger();
        let program = Program::from(BN254_ADD_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bn254_mul_simple() {
        setup_logger();
        let program = Program::from(BN254_MUL_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_secp256k1_mul_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_MUL_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bls12381_g1_add_simple() {
        setup_logger();
        let program = Program::from(BLS12381_G1_ADD_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bls12381_mul_simple() {
        setup_logger();
        let program = Program::from(BLS12381_G1_SCALARMUL_ELF);
        run_test(program).unwrap();
    }
}
