use core::fmt::Debug;
use std::{
    array::IntoIter,
    ops::{Index, IndexMut},
};

use p3_field::{AbstractField, Field};
use serde::{Deserialize, Serialize};
use sphinx_derive::AlignedBorrow;

use super::BaseAirBuilder;
use crate::air::Word;

/// The size of a word64 in bytes.
pub const WORD64_SIZE: usize = 8;

/// A double word is a 64-bit value represented in an AIR.
#[derive(
    AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[repr(C)]
pub struct Word64<T>(pub [T; WORD64_SIZE]);

impl<T> Word64<T> {
    /// Applies `f` to each element of the word64.
    pub fn map<F, S>(self, f: F) -> Word64<S>
    where
        F: FnMut(T) -> S,
    {
        Word64(self.0.map(f))
    }

    /// Extends a variable to a word64.
    pub fn extend_var<AB: BaseAirBuilder<Var = T>>(var: T) -> Word64<AB::Expr> {
        Word64([
            AB::Expr::zero() + var,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ])
    }
}

impl<T: Clone> Word64<T> {
    /// Splits into two words.
    pub fn to_le_words(self) -> [Word<T>; 2] {
        let limbs: Vec<T> = self.into_iter().collect();
        [
            limbs[..4].iter().cloned().collect(),
            limbs[4..].iter().cloned().collect(),
        ]
    }
}

impl<T: AbstractField> Word64<T> {
    /// Extends a variable to a word64.
    pub fn extend_expr<AB: BaseAirBuilder<Expr = T>>(expr: T) -> Word64<AB::Expr> {
        Word64([
            AB::Expr::zero() + expr,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ])
    }

    /// Returns a word64 with all zero expressions.
    pub fn zero<AB: BaseAirBuilder<Expr = T>>() -> Word64<T> {
        Word64([
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ])
    }
}

impl<F: Field> Word64<F> {
    /// Converts a word64 to a u64.
    pub fn to_u64(&self) -> u64 {
        // TODO: avoid string conversion
        u64::from_le_bytes(self.0.map(|x| x.to_string().parse::<u8>().unwrap()))
    }
}

impl<T> Index<usize> for Word64<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Word64<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: AbstractField> From<u64> for Word64<F> {
    fn from(value: u64) -> Self {
        Word64(value.to_le_bytes().map(F::from_canonical_u8))
    }
}

impl<T> IntoIterator for Word64<T> {
    type Item = T;
    type IntoIter = IntoIter<T, WORD64_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Clone> FromIterator<T> for Word64<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut iter = iter.into_iter();
        let elements = std::array::from_fn(|_| iter.next().unwrap());
        Word64(elements)
    }
}
