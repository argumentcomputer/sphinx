//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.
use crate::air::BaseAirBuilder;
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sphinx_derive::AlignedBorrow;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

impl<F: Field> IsZeroOperation<F> {
    pub fn populate(&mut self, a: u32) -> u32 {
        self.populate_from_field_element(F::from_canonical_u32(a))
    }

    pub fn populate_from_field_element(&mut self, a: F) -> u32 {
        if a == F::zero() {
            self.inverse = F::zero();
            self.result = F::one();
        } else {
            self.inverse = a.inverse();
            self.result = F::zero();
        }
        let prod = self.inverse * a;
        debug_assert!(prod == F::one() || prod == F::zero());
        u32::from(a == F::zero())
    }

    pub fn eval<AB: BaseAirBuilder<F = F>, Ea, Ereal>(
        builder: &mut AB,
        a: Ea,
        cols: IsZeroOperation<AB::Var>,
        is_real: Ereal,
    ) where
        Ea: Into<AB::Expr>,
        Ereal: Into<AB::Expr>,
    {
        let mut builder_is_real = builder.when(is_real.into());
        let a = a.into();

        // 1. Input == 0 => is_zero = 1 regardless of the inverse.
        // 2. Input != 0
        //   2.1. inverse is correctly set => is_zero = 0.
        //   2.2. inverse is incorrect
        //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
        //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
        //                           assert fails.

        // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
        // is correctly set, then the product is 1.
        let is_zero = AB::Expr::one() - cols.inverse * a.clone();
        builder_is_real.assert_eq(is_zero, cols.result);
        builder_is_real.assert_bool(cols.result);

        // If the result is 1, then the input is 0.
        builder_is_real.when(cols.result).assert_zero(a);
    }
}
