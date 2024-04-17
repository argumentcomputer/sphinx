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
use wp1_derive::AlignedBorrow;

use crate::{
    air::{MachineAir, SP1AirBuilder},
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::{
        field_op::{FieldOpCols, FieldOperation},
        params::{LimbWidth, Limbs, DEFAULT_NUM_LIMBS_T, WORDS_CURVEPOINT, WORDS_FIELD_ELEMENT},
    },
    runtime::{ExecutionRecord, Program, SyscallCode},
    utils::{
        ec::{
            weierstrass::WeierstrassParameters, AffinePoint, BaseLimbWidth, CurveType,
            EllipticCurve, WithAddition,
        },
        limbs_from_prev_access, pad_vec_rows,
    },
};

/// A set of columns to compute `WeierstrassAdd` that add two points on a Weierstrass curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignCols<T, U: LimbWidth = DEFAULT_NUM_LIMBS_T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: Array<MemoryWriteCols<T>, WORDS_CURVEPOINT<U>>,
    pub q_access: Array<MemoryReadCols<T>, WORDS_CURVEPOINT<U>>,
    pub(crate) slope_denominator: FieldOpCols<T, U>,
    pub(crate) slope_numerator: FieldOpCols<T, U>,
    pub(crate) slope: FieldOpCols<T, U>,
    pub(crate) slope_squared: FieldOpCols<T, U>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, U>,
    pub(crate) x3_ins: FieldOpCols<T, U>,
    pub(crate) p_x_minus_x: FieldOpCols<T, U>,
    pub(crate) y3_ins: FieldOpCols<T, U>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, U>,
}

#[derive(Default)]
pub struct WeierstrassAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassAddAssignChip<E> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops<F: PrimeField32>(
        cols: &mut WeierstrassAddAssignCols<F, BaseLimbWidth<E>>,
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
                    .populate::<E::BaseField>(q_y, p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator
                    .populate::<E::BaseField>(q_x, p_x, FieldOperation::Sub);

            cols.slope.populate::<E::BaseField>(
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate::<E::BaseField>(&slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x
                    .populate::<E::BaseField>(p_x, q_x, FieldOperation::Add);
            cols.x3_ins
                .populate::<E::BaseField>(&slope_squared, &p_x_plus_q_x, FieldOperation::Sub)
        };

        // y = slope * (p.x - x_3n) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate::<E::BaseField>(p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate::<E::BaseField>(
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate::<E::BaseField>(
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

            let mut row =
                vec![F::zero(); size_of::<WeierstrassAddAssignCols<u8, BaseLimbWidth<E>>>()];
            let cols: &mut WeierstrassAddAssignCols<F, BaseLimbWidth<E>> =
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

            Self::populate_field_ops(cols, &p_x, &p_y, &q_x, &q_y);

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
            let mut row =
                vec![F::zero(); size_of::<WeierstrassAddAssignCols<u8, BaseLimbWidth<E>>>()];
            let cols: &mut WeierstrassAddAssignCols<F, BaseLimbWidth<E>> =
                row.as_mut_slice().borrow_mut();
            let zero = &BigUint::zero();
            Self::populate_field_ops(cols, zero, zero, zero, zero);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<WeierstrassAddAssignCols<u8, BaseLimbWidth<E>>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => !shard.secp256k1_add_events.is_empty(),
            CurveType::Bn254 => !shard.bn254_add_events.is_empty(),
            CurveType::Bls12381 => !shard.bls12381_add_events.is_empty(),
            _ => panic!("Unsupported curve"),
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassAddAssignChip<E> {
    fn width(&self) -> usize {
        size_of::<WeierstrassAddAssignCols<u8, BaseLimbWidth<E>>>()
    }
}

impl<AB, E: EllipticCurve> Air<AB> for WeierstrassAddAssignChip<E>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &WeierstrassAddAssignCols<AB::Var, BaseLimbWidth<E>> = (*row).borrow();

        let nw_field_elt = WORDS_FIELD_ELEMENT::<BaseLimbWidth<E>>::USIZE;
        let p_x: Limbs<_, BaseLimbWidth<E>> =
            limbs_from_prev_access(&row.p_access[0..nw_field_elt]);
        let p_y: Limbs<_, BaseLimbWidth<E>> = limbs_from_prev_access(&row.p_access[nw_field_elt..]);

        let q_x: Limbs<_, BaseLimbWidth<E>> =
            limbs_from_prev_access(&row.q_access[0..nw_field_elt]);
        let q_y: Limbs<_, BaseLimbWidth<E>> = limbs_from_prev_access(&row.q_access[nw_field_elt..]);

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            row.slope_numerator.eval::<AB, E::BaseField, _, _>(
                builder,
                &q_y,
                &p_y,
                FieldOperation::Sub,
            );

            row.slope_denominator.eval::<AB, E::BaseField, _, _>(
                builder,
                &q_x,
                &p_x,
                FieldOperation::Sub,
            );

            row.slope.eval::<AB, E::BaseField, _, _>(
                builder,
                &row.slope_numerator.result,
                &row.slope_denominator.result,
                FieldOperation::Div,
            );

            row.slope.result.clone()
        };

        // x = slope * slope - self.x - other.x.
        let x = {
            row.slope_squared.eval::<AB, E::BaseField, _, _>(
                builder,
                &slope,
                &slope,
                FieldOperation::Mul,
            );

            row.p_x_plus_q_x.eval::<AB, E::BaseField, _, _>(
                builder,
                &p_x,
                &q_x,
                FieldOperation::Add,
            );

            row.x3_ins.eval::<AB, E::BaseField, _, _>(
                builder,
                &row.slope_squared.result,
                &row.p_x_plus_q_x.result,
                FieldOperation::Sub,
            );

            row.x3_ins.result.clone()
        };

        // y = slope * (p.x - x_3n) - q.y.
        {
            row.p_x_minus_x
                .eval::<AB, E::BaseField, _, _>(builder, &p_x, &x, FieldOperation::Sub);

            row.slope_times_p_x_minus_x.eval::<AB, E::BaseField, _, _>(
                builder,
                &slope,
                &row.p_x_minus_x.result,
                FieldOperation::Mul,
            );

            row.y3_ins.eval::<AB, E::BaseField, _, _>(
                builder,
                &row.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
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
            row.clk.into(),
            row.q_ptr,
            &row.q_access,
            row.is_real,
        );
        builder.eval_memory_access_slice(
            row.shard,
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
                AB::F::from_canonical_u32(SyscallCode::BLS12381_ADD.syscall_id())
            }
            _ => panic!("Unsupported curve"),
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

    use crate::{
        runtime::Program,
        utils::{
            run_test, setup_logger,
            tests::{
                BLS12381_ADD_ELF, BLS12381_MUL_ELF, BN254_ADD_ELF, BN254_MUL_ELF,
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
    fn test_bls12381_add_simple() {
        setup_logger();
        let program = Program::from(BLS12381_ADD_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bls12381_mul_simple() {
        setup_logger();
        let program = Program::from(BLS12381_MUL_ELF);
        run_test(program).unwrap();
    }
}
