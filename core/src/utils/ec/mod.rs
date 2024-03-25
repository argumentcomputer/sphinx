pub mod edwards;
pub mod field;
pub mod scalar_mul;
pub mod utils;
pub mod weierstrass;

use field::FieldParameters;
use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use num::BigUint;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::ops::{Add, Neg};

use crate::air::WORD_SIZE;
use crate::operations::field::params::WORDS_CURVEPOINT;

pub const DEFAULT_NUM_WORDS_FIELD_ELEMENT: usize = 8;
pub const DEFAULT_NUM_BYTES_FIELD_ELEMENT: usize = DEFAULT_NUM_WORDS_FIELD_ELEMENT * WORD_SIZE;

pub const DEFAULT_COMPRESSED_POINT_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinePoint<E> {
    pub x: BigUint,
    pub y: BigUint,
    _marker: std::marker::PhantomData<E>,
}

impl<E> AffinePoint<E> {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn from_words_le(words: &[u32]) -> Self {
        let x_bytes = words[0..words.len() / 2]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>();
        let y_bytes = &words[words.len() / 2..]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>();
        let x = BigUint::from_bytes_le(x_bytes.as_slice());
        let y = BigUint::from_bytes_le(y_bytes.as_slice());
        Self {
            x,
            y,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<E: EllipticCurveParameters> AffinePoint<E> {
    const fn field_u32_digits() -> usize {
        BaseLimbWidth::<E>::USIZE * E::BaseField::NB_BITS_PER_LIMB / 32
    }

    pub fn to_words_le(&self) -> Array<u32, WORDS_CURVEPOINT<BaseLimbWidth<E>>> {
        let x_digits = self.x.to_u32_digits();
        assert_eq!(x_digits.len(), Self::field_u32_digits());
        let y_digits = self.y.to_u32_digits();
        assert_eq!(y_digits.len(), Self::field_u32_digits());

        x_digits.into_iter().chain(y_digits).collect()
    }
}

/// A convenience type projection to retrieve the limb width of the curve's base field.
pub type BaseLimbWidth<E> =
    <<E as EllipticCurveParameters>::BaseField as FieldParameters>::NB_LIMBS;

pub trait EllipticCurveParameters:
    Debug + Send + Sync + Copy + Serialize + DeserializeOwned + 'static
{
    type BaseField: FieldParameters;
}

/// An interface for elliptic curve groups.
pub trait EllipticCurve: EllipticCurveParameters {
    /// Adds two different points on the curve.
    ///
    /// Warning: This method assumes that the two points are different.
    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self>;

    /// Doubles a point on the curve.
    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self>;

    /// Returns the generator of the curve group for a curve/subgroup of prime order.
    fn ec_generator() -> AffinePoint<Self>;

    /// Returns the neutral element of the curve group, if this element is affine (such as in the
    /// case of the Edwards curve group). Otherwise, returns `None`.
    fn ec_neutral() -> Option<AffinePoint<Self>>;

    /// Returns the negative of a point on the curve.
    fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self>;

    /// Returns the number of bits needed to represent a scalar in the group.
    fn nb_scalar_bits() -> usize {
        <Self::BaseField as FieldParameters>::NB_LIMBS::USIZE * Self::BaseField::NB_BITS_PER_LIMB
    }
}

impl<E: EllipticCurve> Add<&AffinePoint<E>> for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn add(self, other: &AffinePoint<E>) -> AffinePoint<E> {
        E::ec_add(self, other)
    }
}

impl<E: EllipticCurve> Add<AffinePoint<E>> for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn add(self, other: AffinePoint<E>) -> AffinePoint<E> {
        &self + &other
    }
}

impl<E: EllipticCurve> Add<&AffinePoint<E>> for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn add(self, other: &AffinePoint<E>) -> AffinePoint<E> {
        &self + other
    }
}

impl<E: EllipticCurve> Neg for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn neg(self) -> AffinePoint<E> {
        E::ec_neg(self)
    }
}

impl<E: EllipticCurve> Neg for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn neg(self) -> AffinePoint<E> {
        -&self
    }
}
