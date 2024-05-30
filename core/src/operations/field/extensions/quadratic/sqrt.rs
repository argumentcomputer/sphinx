use crate::air::WordAirBuilder;
use crate::bytes::event::ByteRecord;
use crate::operations::field::extensions::quadratic::QuadFieldOperation;
use crate::operations::field::params::{FieldParameters, Limbs};
use crate::operations::field::range::FieldRangeCols;
use num::BigUint;
use p3_field::PrimeField32;
use sphinx_derive::AlignedBorrow;
use std::fmt::Debug;

use super::QuadFieldOpCols;

/// A set of columns to compute the square root in some quadratic extension field. `T` is the field in which each
/// limb lives, while `U` is how many limbs are necessary to represent a quadratic extension field element.
/// See additional comments on `QuadFieldOpCols` to determine which specific field extensions are supported.
///
/// *Safety*: The `FieldSqrtCols` asserts that `multiplication.result` is a square root of the given
/// input lying within the range `[0, modulus)`
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct QuadFieldSqrtCols<T, P: FieldParameters> {
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: QuadFieldOpCols<T, P>,

    pub range: [FieldRangeCols<T, P>; 2],
}

impl<F: PrimeField32, P: FieldParameters> QuadFieldSqrtCols<F, P> {
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a: &[BigUint; 2],
        sqrt_fn: impl Fn(&[BigUint; 2]) -> [BigUint; 2],
    ) -> [BigUint; 2] {
        let modulus = P::modulus();
        assert!(a[0] < modulus && a[1] < modulus);
        let sqrt = sqrt_fn(a);

        // Use QuadFieldOpCols to compute result * result.
        let sqrt_squared =
            self.multiplication
                .populate(record, shard, &sqrt, &sqrt, QuadFieldOperation::Mul);

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, *a);

        // This is a hack to save a column in QuadFieldSqrtCols. We will receive the value a again in the
        // eval function, so we'll overwrite it with the sqrt.
        self.multiplication.result = [
            P::to_limbs_field::<F>(&sqrt[0]),
            P::to_limbs_field::<F>(&sqrt[1]),
        ];

        self.range[0].populate(record, shard, &sqrt[0]);
        self.range[1].populate(record, shard, &sqrt[1]);

        sqrt
    }
}

impl<V: Copy, P: FieldParameters> QuadFieldSqrtCols<V, P> {
    /// Calculates the square root of `a`.
    pub fn eval<
        AB: WordAirBuilder<Var = V>,
        ER: Into<AB::Expr> + Clone,
        EShard: Into<AB::Expr> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &[Limbs<AB::Var, P::NB_LIMBS>; 2],
        shard: &EShard,
        is_real: &ER,
    ) where
        V: Into<AB::Expr>,
    {
        // As a space-saving hack, we store the sqrt of the input in `self.multiplication.result`
        // even though it's technically not the result of the multiplication. Now, we should
        // retrieve that value and overwrite that member variable with a.
        let sqrt = self.multiplication.result.clone();
        let mut multiplication = self.multiplication.clone();
        multiplication.result.clone_from(a);

        // Compute sqrt * sqrt. We pass in P since we want its BaseField to be the mod.
        multiplication.eval(
            builder,
            &sqrt,
            &sqrt,
            QuadFieldOperation::Mul,
            shard.clone(),
            is_real.clone(),
        );

        self.range[0].eval(builder, &sqrt[0], shard.clone(), is_real.clone());
        self.range[1].eval(builder, &sqrt[1], shard.clone(), is_real.clone());
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use p3_air::BaseAir;
    use p3_field::{AbstractField, Field, PrimeField32};

    use super::QuadFieldSqrtCols;

    use crate::air::MachineAir;
    use crate::air::{EventLens, WordAirBuilder};
    use crate::bytes::event::ByteRecord;
    use crate::operations::field::params::{FieldParameters, Limbs};
    use crate::runtime::ExecutionRecord;
    use crate::runtime::Program;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::weierstrass::bls12_381::{bls12381_fp2_sqrt, Bls12381BaseField};
    use crate::utils::{pad_to_power_of_two_nongeneric, BabyBearPoseidon2};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::size_of;
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use rand::thread_rng;
    use sphinx_derive::AlignedBorrow;

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

    impl<'a, P: FieldParameters> crate::air::WithEvents<'a> for QuadSqrtChip<P> {
        type Events = &'a ();
    }

    impl<P: FieldParameters> EventLens<QuadSqrtChip<P>> for ExecutionRecord {
        fn events(&self) -> <QuadSqrtChip<P> as crate::air::WithEvents>::Events {
            &()
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for QuadSqrtChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "QuadSqrtChip".to_string()
        }

        fn generate_trace<EL: EventLens<Self>>(
            &self,
            _: &EL,
            output: &mut ExecutionRecord,
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
                    let mut blu_events = Vec::new();
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a = [P::to_limbs_field::<F>(&a[0]), P::to_limbs_field::<F>(&a[1])];
                    cols.sqrt.populate(&mut blu_events, 1, a, self.sqrt_fn);
                    output.add_byte_lookup_events(blu_events);
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
        AB: WordAirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();

            // eval verifies that local.sqrt.result is indeed the square root of local.a.
            local
                .sqrt
                .eval(builder, &local.a, &AB::F::one(), &AB::F::one());
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
