use std::fmt::Debug;

use num::BigUint;
use p3_field::PrimeField32;
use sphinx_derive::AlignedBorrow;

use super::field_op::FieldOpCols;
use super::params::Limbs;
use super::range::FieldRangeCols;
use crate::air::BaseAirBuilder;
use crate::bytes::event::ByteRecord;
use crate::operations::field::params::FieldParameters;

/// A set of columns to compute the square root in emulated arithmetic.
///
/// *Safety*: The `FieldSqrtCols` asserts that `multiplication.result` is a square root of the given
/// input lying within the range `[0, modulus)`
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldSqrtCols<T, P: FieldParameters> {
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: FieldOpCols<T, P>,

    pub range: FieldRangeCols<T, P>,
}

impl<F: PrimeField32, P: FieldParameters> FieldSqrtCols<F, P> {
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u32,
        a: &BigUint,
        sqrt_fn: impl Fn(&BigUint) -> BigUint,
    ) -> BigUint {
        let modulus = P::modulus();
        assert!(a < &modulus);
        let sqrt = sqrt_fn(a);

        // Use FieldOpCols to compute result * result.
        let sqrt_squared = self.multiplication.populate(
            record,
            shard,
            channel,
            &sqrt,
            &sqrt,
            super::field_op::FieldOperation::Mul,
        );

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, a.clone());

        // This is a hack to save a column in FieldSqrtCols. We will receive the value a again in the
        // eval function, so we'll overwrite it with the sqrt.
        self.multiplication.result = P::to_limbs_field::<F>(&sqrt);

        // Populate the range columns.
        self.range.populate(record, shard, channel, &sqrt);

        sqrt
    }
}

impl<V: Copy, P: FieldParameters> FieldSqrtCols<V, P> {
    /// Calculates the square root of `a`.
    pub fn eval<AB: BaseAirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &Limbs<AB::Var, P::NB_LIMBS>,
        shard: impl Into<AB::Expr> + Clone,
        channel: impl Into<AB::Expr> + Clone,
        is_real: impl Into<AB::Expr> + Clone,
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
        multiplication.eval(
            builder,
            &sqrt,
            &sqrt,
            super::field_op::FieldOperation::Mul,
            shard.clone(),
            channel.clone(),
            is_real.clone(),
        );

        self.range.eval(builder, &sqrt, shard, channel, is_real);
    }
}

#[cfg(test)]
mod tests {
    use core::{
        borrow::{Borrow, BorrowMut},
        mem::size_of,
    };

    use num::{bigint::RandBigInt, BigUint, One, Zero};
    use p3_air::{Air, BaseAir};
    use p3_baby_bear::BabyBear;
    use p3_field::{Field, PrimeField32};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use rand::thread_rng;
    use sphinx_derive::AlignedBorrow;

    use super::{FieldSqrtCols, Limbs};

    use crate::air::WordAirBuilder;
    use crate::air::{EventLens, MachineAir};
    use crate::bytes::event::ByteRecord;
    use crate::operations::field::params::{FieldParameters, DEFAULT_NUM_LIMBS_T};
    use crate::runtime::ExecutionRecord;
    use crate::runtime::Program;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::edwards::ed25519::{ed25519_sqrt, Ed25519BaseField};
    use crate::utils::{pad_to_power_of_two, BabyBearPoseidon2};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_field::AbstractField;

    #[derive(AlignedBorrow, Debug)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: Limbs<T, P::NB_LIMBS>,
        pub sqrt: FieldSqrtCols<T, P>,
    }

    pub(crate) const NUM_TEST_COLS: usize = size_of::<TestCols<u8, Ed25519BaseField>>();

    struct EdSqrtChip<P: FieldParameters> {
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> EdSqrtChip<P> {
        pub(crate) const fn new() -> Self {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<'a, P: FieldParameters> crate::air::WithEvents<'a> for EdSqrtChip<P> {
        type Events = &'a ();
    }

    impl<P: FieldParameters> EventLens<EdSqrtChip<P>> for ExecutionRecord {
        fn events(&self) -> <EdSqrtChip<P> as crate::air::WithEvents<'_>>::Events {
            &()
        }
    }

    impl<F: PrimeField32, P: FieldParameters<NB_LIMBS = DEFAULT_NUM_LIMBS_T>> MachineAir<F>
        for EdSqrtChip<P>
    {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "EdSqrtChip".to_string()
        }

        fn generate_trace<EL: EventLens<Self>>(
            &self,
            _: &EL,
            output: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<BigUint> = (0..num_rows - 2)
                .map(|_| {
                    // Take the square of a random number to make sure that the square root exists.
                    let a = rng.gen_biguint(Ed25519BaseField::nb_bits() as u64);
                    let sq = a.clone() * a.clone();
                    // We want to mod by the ed25519 modulus.
                    sq % &Ed25519BaseField::modulus()
                })
                .collect();

            // hardcoded edge cases.
            operands.extend(vec![BigUint::zero(), BigUint::one()]);

            let rows = operands
                .iter()
                .map(|a| {
                    let mut blu_events = Vec::new();
                    let mut row = [F::zero(); NUM_TEST_COLS];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a = P::to_limbs_field::<F>(a);
                    cols.sqrt.populate(&mut blu_events, 1, 0, a, ed25519_sqrt);
                    output.add_byte_lookup_events(blu_events);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.
            let mut trace = RowMajorMatrix::new(
                rows.into_iter().flatten().collect::<Vec<_>>(),
                NUM_TEST_COLS,
            );

            // Pad the trace to a power of two.
            pad_to_power_of_two::<NUM_TEST_COLS, F>(&mut trace.values);

            trace
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for EdSqrtChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters<NB_LIMBS = DEFAULT_NUM_LIMBS_T>> Air<AB> for EdSqrtChip<P>
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
                .eval(builder, &local.a, AB::F::one(), AB::F::zero(), AB::F::one());
        }
    }

    #[test]
    fn generate_trace() {
        let chip: EdSqrtChip<Ed25519BaseField> = EdSqrtChip::new();
        let shard = ExecutionRecord::default();
        let _: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        // println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip: EdSqrtChip<Ed25519BaseField> = EdSqrtChip::new();
        let shard = ExecutionRecord::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
