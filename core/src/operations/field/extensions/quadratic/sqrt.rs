use crate::air::SP1AirBuilder;
use crate::operations::field::extensions::quadratic::QuadFieldOperation;
use crate::operations::field::params::Limbs;
use crate::utils::ec::field::FieldParameters;
use num::BigUint;
use p3_field::PrimeField32;
use std::fmt::Debug;
use wp1_derive::AlignedBorrow;

use super::QuadFieldOpCols;

/// A set of columns to compute the square root in some quadratic extension field. `T` is the field in which each
/// limb lives, while `U` is how many limbs are necessary to represent a quadratic extension field element.
/// See additional comments on `QuadFieldOpCols` to determine which specific field extensions are supported.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct QuadFieldSqrtCols<T, P: FieldParameters> {
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: QuadFieldOpCols<T, P>,
}

impl<F: PrimeField32, P: FieldParameters> QuadFieldSqrtCols<F, P> {
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate(
        &mut self,
        a: &[BigUint; 2],
        sqrt_fn: impl Fn(&[BigUint; 2]) -> [BigUint; 2],
    ) -> [BigUint; 2] {
        let sqrt = sqrt_fn(a);

        // Use QuadFieldOpCols to compute result * result.
        let sqrt_squared = self
            .multiplication
            .populate(&sqrt, &sqrt, QuadFieldOperation::Mul);

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, *a);

        // This is a hack to save a column in QuadFieldSqrtCols. We will receive the value a again in the
        // eval function, so we'll overwrite it with the sqrt.
        self.multiplication.result = [
            P::to_limbs_field::<F>(&sqrt[0]),
            P::to_limbs_field::<F>(&sqrt[1]),
        ];

        sqrt
    }
}

impl<V: Copy, P: FieldParameters> QuadFieldSqrtCols<V, P> {
    /// Calculates the square root of `a`.
    pub fn eval<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &[Limbs<AB::Var, P::NB_LIMBS>; 2],
    ) where
        V: Into<AB::Expr>,
    {
        // As a space-saving hack, we store the sqrt of the input in `self.multiplication.result`
        // even though it's technically not the result of the multiplication. Now, we should
        // retrieve that value and overwrite that member variable with a.
        let sqrt = self.multiplication.result.clone();
        let mut multiplication = self.multiplication.clone();
        multiplication.result = a.clone();

        // Compute sqrt * sqrt. We pass in P since we want its BaseField to be the mod.
        multiplication.eval(builder, &sqrt, &sqrt, QuadFieldOperation::Mul);
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use p3_air::BaseAir;
    use p3_field::{Field, PrimeField32};

    use super::QuadFieldSqrtCols;

    use crate::air::MachineAir;

    use crate::operations::field::params::Limbs;
    use crate::runtime::Program;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::field::FieldParameters;
    use crate::utils::ec::weierstrass::bls12_381::{bls12381_fp2_sqrt, Bls12381BaseField};
    use crate::utils::{pad_to_power_of_two_nongeneric, BabyBearPoseidon2};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::{air::SP1AirBuilder, runtime::ExecutionRecord};
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::size_of;
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use rand::thread_rng;
    use wp1_derive::AlignedBorrow;

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: [Limbs<T, P::NB_LIMBS>; 2],
        pub sqrt: QuadFieldSqrtCols<T, P>,
    }

    struct QuadSqrtChip<P: FieldParameters> {
        pub(crate) sqrt_fn: fn(&[BigUint; 2]) -> [BigUint; 2],
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> QuadSqrtChip<P> {
        pub(crate) fn new(sqrt_fn: fn(&[BigUint; 2]) -> [BigUint; 2]) -> Self {
            Self {
                sqrt_fn,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for QuadSqrtChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "QuadSqrtChip".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let num_test_cols = size_of::<TestCols<u8, P>>();
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let hardcoded_cases = vec![
                [BigUint::zero(), BigUint::zero()],
                [BigUint::one(), BigUint::zero()],
                [BigUint::zero(), BigUint::one()],
            ];
            let mut operands: Vec<[BigUint; 2]> = (0..num_rows - hardcoded_cases.len())
                .map(|_| {
                    // Take the square of a random number to make sure that the square root exists.
                    let a = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    let b = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    let (r0, r1) = {
                        // Following the textbook Karatsuba expansion:
                        let v0 = &a * &a;
                        let v1 = &b * &b;
                        let t0 = &a + &b;
                        // t1 is equal to t0 in this case
                        // Worst case scenario, v0 is 0 and v1 is (modulus-1)*(modulus-1)
                        // to ensure this is all positive, we add modulus*(modulus-1)
                        let c0 = &P::modulus() * &(P::modulus() - BigUint::one()) + &v0 - &v1;
                        let c1 = (&t0 * &t0) - (v0 + v1);
                        (c0, c1)
                    };
                    // We want to mod by the modulus.
                    [r0 % &P::modulus(), r1 % &P::modulus()]
                })
                .collect();

            // hardcoded edge cases.
            operands.extend(hardcoded_cases);

            let rows = operands
                .iter()
                .map(|a| {
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a = [P::to_limbs_field::<F>(&a[0]), P::to_limbs_field::<F>(&a[1])];
                    cols.sqrt.populate(a, self.sqrt_fn);
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

    impl<F: Field, P: FieldParameters> BaseAir<F> for QuadSqrtChip<P> {
        fn width(&self) -> usize {
            size_of::<TestCols<u8, P>>()
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for QuadSqrtChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();

            // eval verifies that local.sqrt.result is indeed the square root of local.a.
            local.sqrt.eval(builder, &local.a);

            // A dummy constraint to keep the degree 3.
            #[allow(clippy::eq_op)]
            builder.assert_zero(
                local.a[0][0] * local.a[0][0] * local.a[0][0]
                    - local.a[0][0] * local.a[0][0] * local.a[0][0],
            )
        }
    }

    fn generate_trace_for<F: FieldParameters>(sqrt_fn: fn(&[BigUint; 2]) -> [BigUint; 2]) {
        let chip: QuadSqrtChip<F> = QuadSqrtChip::new(sqrt_fn);
        let shard = ExecutionRecord::default();
        let _: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
    }

    fn prove_babybear_for<F: FieldParameters>(sqrt_fn: fn(&[BigUint; 2]) -> [BigUint; 2]) {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip: QuadSqrtChip<F> = QuadSqrtChip::new(sqrt_fn);
        let shard = ExecutionRecord::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn generate_trace() {
        generate_trace_for::<Bls12381BaseField>(bls12381_fp2_sqrt);
    }

    #[test]
    fn prove_babybear() {
        prove_babybear_for::<Bls12381BaseField>(bls12381_fp2_sqrt);
    }
}
