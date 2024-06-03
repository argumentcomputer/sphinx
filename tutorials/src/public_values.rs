use std::{borrow::Borrow, mem::size_of};

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sphinx_core::air::BaseAirBuilder;
use sphinx_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default)]
struct Cols<T> {
    /// The current value of `n`, decreasing in each row until it reaches zero
    n: T,
    /// The sum of the all previous values of `n`
    s: T,
    /// A boolean flag to tell whether we've already **f**inished the sum
    f: T,
}

struct Chip;

const NUM_COLS: usize = size_of::<Cols<u8>>();

impl Chip {
    #[allow(dead_code)]
    fn generate_trace<F: Field>(mut n: usize) -> RowMajorMatrix<F> {
        let trace_height = (n + 1).next_power_of_two();
        let mut rows = Vec::with_capacity(trace_height);
        let f = F::from_canonical_usize;
        let mut s = 0;
        loop {
            let finished = n == 0;
            rows.push([f(n), f(s), F::from_bool(finished)]);
            if finished {
                break;
            }
            s += n;
            n -= 1;
        }
        loop {
            if rows.len() == trace_height {
                break;
            }
            rows.push([F::zero(), f(s), F::one()]);
        }
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_COLS)
    }
}

impl<F: Send + Sync> BaseAir<F> for Chip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> Air<AB> for Chip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let local: &Cols<AB::Var> = (*local).borrow();

        let next = main.row_slice(1);
        let next: &Cols<AB::Var> = (*next).borrow();

        let public_values = builder.public_values();
        assert_eq!(public_values.len(), 2);
        let (n, s) = (public_values[0], public_values[1]);

        // f is a boolean
        builder.assert_bool(local.f);

        // Boundary constraints
        {
            // Constrain according to the public values
            builder.when_first_row().assert_eq(local.n, n);
            builder.when_last_row().assert_eq(local.s, s);

            // Constrain the initial sum
            builder.when_first_row().assert_eq(local.s, AB::F::zero());

            // Constrain the stop condition
            builder.when_last_row().assert_eq(local.f, AB::F::one());
        }

        // Integrity constraints
        {
            // Constrain the next s
            // * When finished, repeat the local s
            // * When not finished, sum local s and n
            let next_s_expected = builder.if_else(local.f, local.s, local.s + local.n);
            builder.when_transition().assert_eq(next.s, next_s_expected);

            // When finished, n must be zero
            builder.when(local.f).assert_zero(local.n);
            // ... and the next row must also indicate a "finished" state
            builder.when_transition().when(local.f).assert_one(next.f);

            // Constrain the next n
            // * When finished, the next n should be zero
            // * When not finished, the next n should be the local n minus one
            let next_n_expected = builder.if_else(local.f, AB::F::zero(), local.n - AB::F::one());
            builder.when_transition().assert_eq(next.n, next_n_expected);

            // What if a prover does not set f = 1 when n reaches zero and keeps subtracting n by
            // one, roundtripping over the field until reaching zero again to, then, finally set
            // f = 1? Would that be a breach for accepting wrong values of s?
            // It turns out the prover can roundtrip as many times as he wants as long as the field
            // of choice has an odd size. In this case, s will always have the value it should when
            // f = 1. We leave that as an exercise for the reader.
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};
    use sphinx_core::{
        stark::{StarkGenericConfig, UniConfig},
        utils::BabyBearPoseidon2,
    };

    use super::*;

    #[test]
    fn prove_trace() {
        let f = BabyBear::from_canonical_usize;

        let trace: RowMajorMatrix<BabyBear> = Chip::generate_trace(5);
        let public_values = vec![f(5), f(15)];

        let trace_expected = RowMajorMatrix::new(
            [
                // n     s     f
                [f(5), f(0), f(0)],
                [f(4), f(5), f(0)],
                [f(3), f(9), f(0)],
                [f(2), f(12), f(0)],
                [f(1), f(14), f(0)],
                [f(0), f(15), f(1)],
                // fill rows until we reach the next power of two
                [f(0), f(15), f(1)],
                [f(0), f(15), f(1)],
            ]
            .into_iter()
            .flatten()
            .collect(),
            NUM_COLS,
        );
        assert_eq!(trace, trace_expected);

        let chip = Chip;

        let config = BabyBearPoseidon2::new();
        let chllngr_p = &mut config.challenger();
        let chllngr_v = &mut config.challenger();
        let uni_config = UniConfig(config);

        let proof = prove(&uni_config, &chip, chllngr_p, trace, &public_values);
        verify(&uni_config, &chip, chllngr_v, &proof, &public_values).unwrap();
    }
}
