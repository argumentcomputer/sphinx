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

use crate::air::{AluAirBuilder, MachineAir, MemoryAirBuilder};
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
use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignCols;
use crate::syscall::precompiles::WORDS_CURVEPOINT;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::BaseLimbWidth;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurve;
use crate::utils::ec::WithAddition;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_vec_rows;

pub const fn num_weierstrass_add_cols<P: FieldParameters>() -> usize {
    size_of::<WeierstrassAddAssignCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassAdd` that add two points on a Weierstrass curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignCols<T, P: FieldParameters> {
    pub is_add: T,
    pub is_double: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_CURVEPOINT<P::NB_LIMBS>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_CURVEPOINT<P::NB_LIMBS>>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) p_x_squared: FieldOpCols<T, P>,         //
    pub(crate) p_x_squared_times_3: FieldOpCols<T, P>, //
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, P>,
    pub(crate) p_x_plus_p_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct WeierstrassAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassAddAssignChip<E> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops_add<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
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
            let slope_numerator =
                cols.slope_numerator
                    .populate(blu_events, shard, q_y, p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator
                    .populate(blu_events, shard, q_x, p_x, FieldOperation::Sub);

            cols.slope.populate(
                blu_events,
                shard,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, shard, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x
                    .populate(blu_events, shard, p_x, q_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                shard,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x_3n) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate(blu_events, shard, p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                shard,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                shard,
                &slope_times_p_x_minus_x,
                p_y,
                FieldOperation::Sub,
            );
        }
    }

    fn populate_field_ops_dbl<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        p_x: &BigUint,
        p_y: &BigUint,
    ) {
        // This populates necessary field operations to double a point on a Weierstrass curve.

        let a = E::a_int();

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared
                        .populate(blu_events, shard, p_x, p_x, FieldOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    blu_events,
                    shard,
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FieldOperation::Mul,
                );
                cols.slope_numerator.populate(
                    blu_events,
                    shard,
                    &a,
                    &p_x_squared_times_3,
                    FieldOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                shard,
                &BigUint::from(2u32),
                p_y,
                FieldOperation::Mul,
            );

            cols.slope.populate(
                blu_events,
                shard,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, shard, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x
                    .populate(blu_events, shard, p_x, p_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                shard,
                &slope_squared,
                &p_x_plus_p_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate(blu_events, shard, p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                shard,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                shard,
                &slope_times_p_x_minus_x,
                p_y,
                FieldOperation::Sub,
            );
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters + WithAddition> MachineAir<F>
    for WeierstrassAddAssignChip<E>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            CurveType::Bn254 => "Bn254AddAssign".to_string(),
            CurveType::Bls12381 => "Bls12381AddAssign".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the curve type.
        let events = E::add_events(input);

        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let event = &events[i];

            let mut row = vec![F::zero(); size_of::<WeierstrassAddAssignCols<u8, E::BaseField>>()];
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
            cols.clk = F::from_canonical_u32(event.clk);
            cols.p_ptr = F::from_canonical_u32(event.p_ptr);
            cols.q_ptr = F::from_canonical_u32(event.q_ptr);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.shard,
                cols,
                &p_x,
                &p_y,
                &q_x,
                &q_y,
            );

            // Populate the memory access columns.
            for i in 0..WORDS_CURVEPOINT::<BaseLimbWidth<E>>::USIZE {
                cols.q_access[i].populate(event.q_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..WORDS_CURVEPOINT::<BaseLimbWidth<E>>::USIZE {
                cols.p_access[i].populate(event.p_memory_records[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_vec_rows(&mut rows, || {
            let mut row = vec![F::zero(); size_of::<WeierstrassAddAssignCols<u8, E::BaseField>>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops_add(&mut vec![], 0, cols, &zero, &zero, &zero, &zero);
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

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassAddAssignChip<E>
where
    AB: MemoryAirBuilder + AluAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &WeierstrassAddAssignCols<AB::Var, E::BaseField> = (*row).borrow();

        let is_add = row.is_add;
        let is_dbl = row.is_double;
        let is_real = is_add + is_dbl;
        builder.assert_bool(is_add);
        builder.assert_bool(is_dbl);
        builder.assert_bool(is_real.clone());

        // a in the Weierstrass form: y^2 = x^3 + a * x + b.
        let a = E::BaseField::to_limbs_field::<AB::F>(&E::a_int());

        let nw_field_elt = WORDS_FIELD_ELEMENT::<BaseLimbWidth<E>>::USIZE;
        let p_x: Limbs<_, BaseLimbWidth<E>> =
            limbs_from_prev_access(&row.p_access[0..nw_field_elt]);
        let p_y: Limbs<_, BaseLimbWidth<E>> = limbs_from_prev_access(&row.p_access[nw_field_elt..]);

        let q_x: Limbs<_, BaseLimbWidth<E>> =
            limbs_from_prev_access(&row.q_access[0..nw_field_elt]);
        let q_y: Limbs<_, BaseLimbWidth<E>> = limbs_from_prev_access(&row.q_access[nw_field_elt..]);

        let slope = {
            // slope_add = (q.y - p.y) / (q.x - p.x).
            {
                row.slope_numerator.eval(
                    builder,
                    &q_y,
                    &p_y,
                    FieldOperation::Sub,
                    row.shard,
                    row.is_add,
                );

                row.slope_denominator.eval(
                    builder,
                    &q_x,
                    &p_x,
                    FieldOperation::Sub,
                    row.shard,
                    row.is_add,
                );
            }

            // slope_dbl = a + (p.x * p.x) * 3. / 2 * y.
            {
                // slope_numerator = a + (p.x * p.x) * 3.
                {
                    row.p_x_squared.eval(
                        builder,
                        &p_x,
                        &p_x,
                        FieldOperation::Mul,
                        row.shard,
                        row.is_double,
                    );

                    row.p_x_squared_times_3.eval(
                        builder,
                        &row.p_x_squared.result,
                        &E::BaseField::to_limbs_field::<AB::F>(&BigUint::from(3u32)),
                        FieldOperation::Mul,
                        row.shard,
                        row.is_double,
                    );

                    row.slope_numerator.eval(
                        builder,
                        &a,
                        &row.p_x_squared_times_3.result,
                        FieldOperation::Add,
                        row.shard,
                        row.is_double,
                    );
                };

                // slope_denominator = 2 * y.
                row.slope_denominator.eval(
                    builder,
                    &E::BaseField::to_limbs_field::<AB::F>(&BigUint::from(2u32)),
                    &p_y,
                    FieldOperation::Mul,
                    row.shard,
                    row.is_double,
                );
            }

            row.slope.eval(
                builder,
                &row.slope_numerator.result,
                &row.slope_denominator.result,
                FieldOperation::Div,
                row.shard,
                is_real.clone(),
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
                is_real.clone(),
            );

            row.p_x_plus_q_x.eval(
                builder,
                &p_x,
                &q_x,
                FieldOperation::Add,
                row.shard,
                is_real.clone(),
            );

            row.x3_ins.eval(
                builder,
                &row.slope_squared.result,
                &row.p_x_plus_q_x.result,
                FieldOperation::Sub,
                row.shard,
                is_real.clone(),
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
                is_real.clone(),
            );

            row.slope_times_p_x_minus_x.eval(
                builder,
                &slope,
                &row.p_x_minus_x.result,
                FieldOperation::Mul,
                row.shard,
                is_real.clone(),
            );

            row.y3_ins.eval(
                builder,
                &row.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
                row.shard,
                is_real.clone(),
            );
        }

        let words_field_elt = WORDS_FIELD_ELEMENT::<BaseLimbWidth<E>>::USIZE;
        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..BaseLimbWidth::<E>::USIZE {
            builder
                .when(is_real.clone())
                .assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value()[i % 4]);
            builder.when(is_real.clone()).assert_eq(
                row.y3_ins.result[i],
                row.p_access[words_field_elt + i / 4].value()[i % 4],
            );
        }

        builder.eval_memory_access_slice(
            row.shard,
            row.clk.into(),
            row.q_ptr,
            &row.q_access,
            row.is_add,
        );
        builder.eval_memory_access_slice(
            row.shard,
            row.clk + AB::F::from_canonical_u32(1), // We read p at +1 since p, q could be the same.
            row.p_ptr,
            &row.p_access,
            is_real.clone(),
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_fe = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::Expr::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id()) * row.is_add
                    + AB::Expr::from_canonical_u32(SyscallCode::SECP256K1_DOUBLE.syscall_id())
                        * row.is_double
            }
            CurveType::Bn254 => {
                AB::Expr::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()) * row.is_add
                    + AB::Expr::from_canonical_u32(SyscallCode::BN254_DOUBLE.syscall_id())
                        * row.is_double
            }
            CurveType::Bls12381 => {
                AB::Expr::from_canonical_u32(SyscallCode::BLS12381_G1_ADD.syscall_id()) * row.is_add
                    + AB::Expr::from_canonical_u32(SyscallCode::BLS12381_G1_DOUBLE.syscall_id())
                        * row.is_double
            }
            _ => panic!("Unsupported curve"),
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
