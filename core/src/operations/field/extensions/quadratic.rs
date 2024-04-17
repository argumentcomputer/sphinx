use crate::air::Polynomial;
use crate::air::SP1AirBuilder;
use crate::operations::field::params::LimbWidth;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::DEFAULT_NUM_LIMBS_T;
use crate::operations::field::params::WITNESS_LIMBS;
use crate::operations::field::util::{
    compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs,
};
use crate::operations::field::util_air::eval_field_operation;
use crate::utils::ec::field::FieldParameters;
use hybrid_array::{typenum::Unsigned, Array};
use num::{BigUint, Integer, One, Zero};
use p3_air::AirBuilder;
use p3_field::{AbstractField, PrimeField32};
use std::fmt::Debug;
use wp1_derive::AlignedBorrow;

/// Quadratic field operation for a field extension where `\beta = -1`, i.e. over
/// `(1 + u)` where `u^2 + 1 = 0`
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum QuadFieldOperation {
    Add,
    Mul,
    Sub,
    Div, // We don't constrain that the divisor is non-zero.
}

/// A set of columns to compute `QuadFieldOperation(a, b)` where a, b are field elements.
/// This specialization is for quadratic field extensions where `\beta = 1`.
///
/// Additionally, this requires that `2*N` for the emulated field modulus `N` fits in
/// `LimbWidth` limbs (i.e. the field representation has at least one "spare" bit).
/// This is true for BLS12-381, which is the interest of this implementation.
///
/// This can be checked by adding the field parameter to the `test_check_fields()` test below.
/// If the field does not pass the `check_quad_extension_preconditions` check, it is currently
/// unsafe to use with this implementation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct QuadFieldOpCols<T, U: LimbWidth = DEFAULT_NUM_LIMBS_T> {
    /// The result of `a op b`, where a, b are quadratic extension field elements
    pub result: [Limbs<T, U>; 2],
    pub(crate) carry: [Limbs<T, U>; 2],
    pub(crate) witness_low: [Array<T, WITNESS_LIMBS<U>>; 2],
    pub(crate) witness_high: [Array<T, WITNESS_LIMBS<U>>; 2],
}
// TODO(wwared): we want to generalize this to an arbitrary compile time constant `beta` value
//               ideally by adding a proper trait encapsulating the quadratic field parameters

impl<F: PrimeField32, U: LimbWidth> QuadFieldOpCols<F, U> {
    pub fn populate<P: FieldParameters<NB_LIMBS = U>>(
        &mut self,
        a: &[BigUint; 2],
        b: &[BigUint; 2],
        op: QuadFieldOperation,
    ) -> [BigUint; 2] {
        if b[0] == BigUint::zero() && b[1] == BigUint::zero() && op == QuadFieldOperation::Div {
            // Division by 0 is allowed only when dividing 0 so that padded rows can be all 0.
            assert!(
                a[0].is_zero() && a[1].is_zero(),
                "division by zero is allowed only when dividing zero"
            );
        }

        let modulus = &P::modulus();

        // If doing the subtraction operation, a - b = result, equivalent to a = result + b.
        if op == QuadFieldOperation::Sub {
            let result = [
                (modulus + &a[0] - &b[0]) % modulus,
                (modulus + &a[1] - &b[1]) % modulus,
            ];
            // We populate the carry, witness_low, witness_high as if we were doing an addition with result + b.
            // But we populate `result` with the actual result of the subtraction because those columns are expected
            // to contain the result by the user.
            // Note that this reversal means we have to flip result, a correspondingly in
            // the `eval` function.
            self.populate::<P>(&result, b, QuadFieldOperation::Add);
            self.result = result.each_ref().map(|r| P::to_limbs_field::<F>(r));
            return result;
        }

        let modulus_minus_one = modulus - BigUint::one();

        // a / b = result is equivalent to a = result * b.
        if op == QuadFieldOperation::Div {
            // a / b = result => result = a * (1/b)
            // We wish to find the multiplicative inverse of a nonzero
            // element b0 + b1u in Fp2. We leverage an identity
            //
            // (b0 + b1u)(b0 - b1u) = b0^2 + b1^2
            //
            // which holds because u^2 = -1. This can be rewritten as
            //
            // (b0 + b1u)(b0 - b1u)/(b0^2 + b1^2) = 1
            //
            // because b0^2 + b1^2 = 0 has no nonzero solutions for (b0, b1).
            // This gives that (b0 - b1u)/(b0^2 + b1^2) is the inverse
            // of (b0 + b1u). Importantly, this can be computing using
            // only a single inversion in Fp.
            // Inversions in Fp can be calculated as x^-1 = x^(p-2)
            // Negations in Fp can be calculated as -x = p - x
            let x = &b[0] * &b[0] + &b[1] * &b[1];
            let inv = x.modpow(&(&modulus_minus_one - BigUint::one()), modulus);
            let b_inv = [
                (&b[0] * &inv) % modulus,
                (&b[1] * (modulus - &inv)) % modulus,
            ];
            // Here we manually calculate a*b_inv
            let result = {
                let v0 = &a[0] * &b_inv[0];
                let v1 = &a[1] * &b_inv[1];
                let t0 = &a[0] + &a[1];
                let t1 = &b_inv[0] + &b_inv[1];
                let c0 = modulus * modulus_minus_one + &v0 - &v1;
                let c1 = (t0 * t1) - (v0 + v1);
                [c0 % modulus, c1 % modulus]
            };

            // We populate the carry, witness_low, witness_high as if we were doing a multiplication
            // with result * b. But we populate `result` with the actual result of the
            // multiplication because those columns are expected to contain the result by the user.
            // Note that this reversal means we have to flip result, a correspondingly in the `eval`
            // function.
            self.populate::<P>(&result, b, QuadFieldOperation::Mul);
            self.result = result.each_ref().map(|r| P::to_limbs_field::<F>(r));
            return result;
        }

        let unreduced_result = match op {
            // Compute field addition in the integers.
            QuadFieldOperation::Add => [&a[0] + &b[0], &a[1] + &b[1]],
            QuadFieldOperation::Mul => {
                // Following the textbook Karatsuba expansion:
                let v0 = &a[0] * &b[0];
                let v1 = &a[1] * &b[1];
                let t0 = &a[0] + &a[1];
                let t1 = &b[0] + &b[1];
                // Worst case scenario, v0 is 0 and v1 is (modulus-1)*(modulus-1)
                // to ensure this is all positive, we add modulus*(modulus-1)
                let c0 = modulus * &modulus_minus_one + &v0 - &v1;
                let c1 = (t0 * t1) - (v0 + v1);
                [c0, c1]
            }
            QuadFieldOperation::Sub | QuadFieldOperation::Div => unreachable!(),
        };
        let (result, carry) = {
            let (c0d, c0r) = unreduced_result[0].div_rem(modulus);
            let (c1d, c1r) = unreduced_result[1].div_rem(modulus);
            ([c0r, c1r], [c0d, c1d])
        };

        debug_assert!(&result[0] < modulus);
        debug_assert!(&result[1] < modulus);
        if op == QuadFieldOperation::Mul {
            // In the worst case scenario, the carry for each of the terms is at most modulus,
            // but we add them together
            debug_assert!(carry[0] < BigUint::from(2u32) * modulus);
            debug_assert!(carry[1] < BigUint::from(2u32) * modulus);
        } else {
            debug_assert!(&carry[0] < modulus);
            debug_assert!(&carry[1] < modulus);
        }

        debug_assert_eq!(&carry[0] * modulus, &unreduced_result[0] - &result[0]);
        debug_assert_eq!(&carry[1] * modulus, &unreduced_result[1] - &result[1]);

        // Make little endian polynomial limbs.
        let p_a: [Polynomial<F>; 2] = a.each_ref().map(|a| P::to_limbs_field::<F>(a).into());
        let p_b: [Polynomial<F>; 2] = b.each_ref().map(|b| P::to_limbs_field::<F>(b).into());
        let p_modulus: Polynomial<F> = P::to_limbs_field::<F>(modulus).into();
        let p_modulus_minus_one: Polynomial<F> = P::to_limbs_field::<F>(&modulus_minus_one).into();
        let p_result: [Polynomial<F>; 2] =
            result.each_ref().map(|r| P::to_limbs_field::<F>(r).into());
        let p_carry: [Polynomial<F>; 2] = carry.map(|c| P::to_limbs_field::<F>(&c).into());

        // Compute the vanishing polynomial.
        let p_op = match op {
            QuadFieldOperation::Add => [&p_a[0] + &p_b[0], &p_a[1] + &p_b[1]],
            QuadFieldOperation::Mul => {
                let v0 = &p_a[0] * &p_b[0];
                let v1 = &p_a[1] * &p_b[1];
                let t0 = &p_a[0] + &p_a[1];
                let t1 = &p_b[0] + &p_b[1];
                let c0 = &p_modulus * &p_modulus_minus_one + &v0 - &v1;
                let c1 = (t0 * t1) - (v0 + v1);
                [c0, c1]
            }
            QuadFieldOperation::Sub | QuadFieldOperation::Div => unreachable!(),
        };
        let p_vanishing: [Polynomial<F>; 2] = [
            &p_op[0] - &p_result[0] - &p_carry[0] * &p_modulus,
            &p_op[1] - &p_result[1] - &p_carry[1] * &p_modulus,
        ];
        debug_assert_eq!(p_vanishing[0].degree(), WITNESS_LIMBS::<U>::USIZE);
        debug_assert_eq!(p_vanishing[1].degree(), WITNESS_LIMBS::<U>::USIZE);

        let p_witness = p_vanishing.map(|v| {
            compute_root_quotient_and_shift(&v, P::WITNESS_OFFSET, P::NB_BITS_PER_LIMB as u32)
        });
        let p_witness_split = p_witness.map(|w| split_u16_limbs_to_u8_limbs(&w));

        self.result = p_result.map(|r| r.try_into().unwrap());
        self.carry = p_carry.map(|c| c.try_into().unwrap());
        self.witness_low = [
            (&p_witness_split[0].0[..]).try_into().unwrap(),
            (&p_witness_split[1].0[..]).try_into().unwrap(),
        ];
        self.witness_high = [
            (&p_witness_split[0].1[..]).try_into().unwrap(),
            (&p_witness_split[1].1[..]).try_into().unwrap(),
        ];

        result
    }
}

impl<V: Copy, U: LimbWidth> QuadFieldOpCols<V, U> {
    pub fn eval<
        AB: SP1AirBuilder<Var = V>,
        P: FieldParameters<NB_LIMBS = U>,
        A: Into<Polynomial<AB::Expr>> + Clone,
        B: Into<Polynomial<AB::Expr>> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &[A; 2],
        b: &[B; 2],
        op: QuadFieldOperation,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a: [Polynomial<AB::Expr>; 2] = a.clone().map(|a| a.into());
        let p_b: [Polynomial<AB::Expr>; 2] = b.clone().map(|b| b.into());
        let p_result: [Polynomial<AB::Expr>; 2] = self.result.clone().map(|r| r.into());
        // Flip p_a and p_result for Sub/Div
        let (p_a, p_result) = match op {
            QuadFieldOperation::Add | QuadFieldOperation::Mul => (p_a, p_result),
            QuadFieldOperation::Sub | QuadFieldOperation::Div => (p_result, p_a),
        };
        let p_carry: [Polynomial<<AB as AirBuilder>::Expr>; 2] =
            self.carry.clone().map(|c| c.into());
        let p_modulus = P::modulus_field_iter::<AB::F>()
            .map(AB::Expr::from)
            .collect();
        let p_modulus_minus_one = P::modulus_field_iter::<AB::F>()
            .enumerate()
            .map(|(i, m)| {
                if i == 0 {
                    AB::Expr::from(m - AB::F::one())
                } else {
                    AB::Expr::from(m)
                }
            })
            .collect();
        let p_op = match op {
            QuadFieldOperation::Add | QuadFieldOperation::Sub => {
                [&p_a[0] + &p_b[0], &p_a[1] + &p_b[1]]
            }
            QuadFieldOperation::Mul | QuadFieldOperation::Div => [
                &p_modulus * &p_modulus_minus_one + &p_a[0] * &p_b[0] - &p_a[1] * &p_b[1],
                &p_a[0] * &p_b[1] + &p_a[1] * &p_b[0],
            ],
        };
        let p_op_minus_result: [Polynomial<AB::Expr>; 2] = [
            p_op[0].clone() - p_result[0].clone(),
            p_op[1].clone() - p_result[1].clone(),
        ];
        let p_vanishing = [
            p_op_minus_result[0].clone() - &(&p_carry[0] * &p_modulus),
            p_op_minus_result[1].clone() - &(&p_carry[1] * &p_modulus),
        ];
        let p_witness_low = self.witness_low.each_ref().map(|w| w.iter().into());
        let p_witness_high = self.witness_high.each_ref().map(|w| w.iter().into());
        eval_field_operation::<AB, P>(
            builder,
            &p_vanishing[0],
            &p_witness_low[0],
            &p_witness_high[0],
        );
        eval_field_operation::<AB, P>(
            builder,
            &p_vanishing[1],
            &p_witness_low[1],
            &p_witness_high[1],
        );
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use p3_air::BaseAir;
    use p3_field::{Field, PrimeField32};

    use super::{QuadFieldOpCols, QuadFieldOperation};
    use crate::operations::field::params::Limbs;

    use crate::air::MachineAir;
    use crate::operations::field::params::LimbWidth;
    use crate::runtime::Program;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::field::FieldParameters;
    use crate::utils::ec::weierstrass::bls12381::Bls12381BaseField;
    use crate::utils::{pad_to_power_of_two_nongeneric, BabyBearPoseidon2};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::{air::SP1AirBuilder, runtime::ExecutionRecord};
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::size_of;
    use hybrid_array::typenum::Unsigned;
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use rand::thread_rng;
    use wp1_derive::AlignedBorrow;

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T, U: LimbWidth> {
        pub a: [Limbs<T, U>; 2],
        pub b: [Limbs<T, U>; 2],
        pub a_op_b: QuadFieldOpCols<T, U>,
    }

    struct QuadFieldOpChip<P: FieldParameters> {
        pub(crate) operation: QuadFieldOperation,
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> QuadFieldOpChip<P> {
        pub(crate) fn new(operation: QuadFieldOperation) -> Self {
            Self {
                operation,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for QuadFieldOpChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            format!("QuadFieldOp{:?}", self.operation)
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            // Hardcoded edge cases. We purposely include 0 / 0. While mathematically, that is not
            // allowed, we allow it in our implementation so padded rows can be all 0.
            let hardcoded_edge_cases = vec![
                (
                    [BigUint::zero(), BigUint::zero()],
                    [BigUint::zero(), BigUint::zero()],
                ),
                (
                    [BigUint::zero(), BigUint::zero()],
                    [BigUint::one(), BigUint::zero()],
                ),
                (
                    [BigUint::one(), BigUint::zero()],
                    [BigUint::one(), BigUint::zero()],
                ),
                (
                    [BigUint::one(), BigUint::one()],
                    [BigUint::one(), BigUint::one()],
                ),
                (
                    [BigUint::from(4u32), BigUint::from(6u32)],
                    [BigUint::from(5u32), BigUint::from(7u32)],
                ),
                (
                    [BigUint::from(10u32), BigUint::from(19u32)],
                    [BigUint::from(20u32), BigUint::from(57u32)],
                ),
                (
                    [P::modulus() - BigUint::one(), BigUint::zero()],
                    [P::modulus() - BigUint::one(), BigUint::zero()],
                ),
                (
                    [BigUint::zero(), P::modulus() - BigUint::one()],
                    [BigUint::zero(), P::modulus() - BigUint::one()],
                ),
                (
                    [P::modulus() - BigUint::one(), BigUint::zero()],
                    [BigUint::zero(), P::modulus() - BigUint::one()],
                ),
                (
                    [BigUint::zero(), P::modulus() - BigUint::one()],
                    [P::modulus() - BigUint::one(), BigUint::zero()],
                ),
            ];
            let num_rand_rows = (1 << 8) - hardcoded_edge_cases.len();
            let mut operands: Vec<([BigUint; 2], [BigUint; 2])> = (0..num_rand_rows)
                .map(|_| {
                    let a = [
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                    ];
                    let b = [
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                    ];
                    (a, b)
                })
                .collect();
            operands.extend(hardcoded_edge_cases);

            let num_test_cols = <QuadFieldOpChip<P> as BaseAir<F>>::width(self);

            let rows = operands
                .into_iter()
                .map(|(a, b)| {
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P::NB_LIMBS> = row.as_mut_slice().borrow_mut();
                    cols.a = [P::to_limbs_field::<F>(&a[0]), P::to_limbs_field::<F>(&a[1])];
                    cols.b = [P::to_limbs_field::<F>(&b[0]), P::to_limbs_field::<F>(&b[1])];
                    cols.a_op_b.populate::<P>(&a, &b, self.operation);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.
            let mut trace = RowMajorMatrix::new(
                rows.into_iter().flatten().collect::<Vec<_>>(),
                num_test_cols,
            );

            // Pad the trace to a power of two.
            pad_to_power_of_two_nongeneric::<F>(num_test_cols, &mut trace.values);

            trace
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for QuadFieldOpChip<P> {
        fn width(&self) -> usize {
            size_of::<TestCols<u8, P::NB_LIMBS>>()
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for QuadFieldOpChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P::NB_LIMBS> = (*local).borrow();
            local
                .a_op_b
                .eval::<AB, P, _, _>(builder, &local.a, &local.b, self.operation);

            // A dummy constraint to keep the degree 3.
            #[allow(clippy::eq_op)]
            builder.assert_zero(
                local.a[0][0] * local.b[0][0] * local.a[0][0]
                    - local.a[0][0] * local.b[0][0] * local.a[0][0],
            )
        }
    }

    fn generate_trace_for<F: FieldParameters>() {
        for op in [
            QuadFieldOperation::Add,
            QuadFieldOperation::Sub,
            QuadFieldOperation::Mul,
            QuadFieldOperation::Div,
        ]
        .iter()
        {
            let chip: QuadFieldOpChip<F> = QuadFieldOpChip::new(*op);
            let shard = ExecutionRecord::default();
            let _trace: RowMajorMatrix<BabyBear> =
                chip.generate_trace(&shard, &mut ExecutionRecord::default());
            // println!("{:?}", _trace.values)
        }
    }

    fn prove_babybear_for<F: FieldParameters>() {
        let config = BabyBearPoseidon2::new();

        for op in [
            QuadFieldOperation::Add,
            QuadFieldOperation::Sub,
            QuadFieldOperation::Mul,
            QuadFieldOperation::Div,
        ]
        .iter()
        {
            let mut challenger = config.challenger();

            let chip: QuadFieldOpChip<F> = QuadFieldOpChip::new(*op);
            let shard = ExecutionRecord::default();
            let trace: RowMajorMatrix<BabyBear> =
                chip.generate_trace(&shard, &mut ExecutionRecord::default());
            let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

            let mut challenger = config.challenger();
            verify(&config, &chip, &mut challenger, &proof).unwrap();
        }
    }

    #[test]
    fn generate_trace() {
        generate_trace_for::<Bls12381BaseField>();
    }

    #[test]
    fn prove_babybear() {
        prove_babybear_for::<Bls12381BaseField>();
    }

    /// Function used to check whether `-1` is a quadratic non-residue in `P` and whether
    /// the limbed representation can fit the max carry value. If the field does not pass
    /// this test, it is not currently safe to use with `QuadFieldOpCols`
    fn check_quad_extension_preconditions<P: FieldParameters>() {
        // Check that -1 is a quadratic non-residue, i.e. `((-1)^((P::modulus()-1)/2) == -1`
        let a = P::modulus() - BigUint::one();
        let modulus = P::modulus();
        let exp = (&modulus - BigUint::one()) / BigUint::from(2u32);
        assert_eq!(
            (a.modpow(&exp, &modulus) + BigUint::one()) % &modulus,
            BigUint::zero()
        );

        // Check that `2*P::modulus() - 1` fits in one `Limbs<_, P::NB_LIMBS>` element
        let max_carry = (&modulus * BigUint::from(2u32)) - BigUint::one();
        let max_carry_bytes = max_carry.to_bytes_le().len();
        assert!(max_carry_bytes <= P::NB_LIMBS::USIZE);
    }

    #[test]
    fn test_check_fields() {
        check_quad_extension_preconditions::<Bls12381BaseField>();
    }
}
