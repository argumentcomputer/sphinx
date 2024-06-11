pub mod edwards;
pub mod scalar_mul;
pub mod utils;
pub mod weierstrass;

use std::fmt::{Debug, Display, Formatter, Result};
use std::ops::{Add, Neg};

use hybrid_array::{typenum::Unsigned, Array};
use num::BigUint;
use serde::{de::DeserializeOwned, Serialize};

use crate::air::WORD_SIZE;
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::WORDS_CURVEPOINT;
use crate::operations::field::params::WORDS_FIELD_ELEMENT;
use crate::runtime::ExecutionRecord;
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};

pub const DEFAULT_NUM_WORDS_FIELD_ELEMENT: usize = 8;
pub const DEFAULT_NUM_BYTES_FIELD_ELEMENT: usize = DEFAULT_NUM_WORDS_FIELD_ELEMENT * WORD_SIZE;
pub const DEFAULT_COMPRESSED_POINT_BYTES: usize = 32;

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CurveType {
    Secp256k1,
    Bn254,
    Ed25519,
    Bls12381,
}

impl Display for CurveType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            CurveType::Secp256k1 => write!(f, "Secp256k1"),
            CurveType::Bn254 => write!(f, "Bn254"),
            CurveType::Ed25519 => write!(f, "Ed25519"),
            CurveType::Bls12381 => write!(f, "Bls12381"),
        }
    }
}

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
        WORDS_FIELD_ELEMENT::<BaseLimbWidth<E>>::USIZE
    }

    pub fn to_words_le(&self) -> Array<u32, WORDS_CURVEPOINT<BaseLimbWidth<E>>> {
        let mut x_digits = self.x.to_u32_digits();
        let field_u32_digits = Self::field_u32_digits();

        match x_digits.len().cmp(&field_u32_digits) {
            std::cmp::Ordering::Less => {
                x_digits.resize(field_u32_digits, 0u32);
            }
            std::cmp::Ordering::Greater => {
                panic!("Input point coordinates too large for the chosen representation");
            }
            std::cmp::Ordering::Equal => {}
        }

        let mut y_digits = self.y.to_u32_digits();
        match y_digits.len().cmp(&field_u32_digits) {
            std::cmp::Ordering::Less => {
                y_digits.resize(field_u32_digits, 0u32);
            }
            std::cmp::Ordering::Greater => {
                panic!("Input point coordinates too large for the chosen representation");
            }
            std::cmp::Ordering::Equal => {}
        }

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

    const CURVE_TYPE: CurveType;
}

pub trait WithAddition: EllipticCurveParameters {
    fn add_events(
        record: &ExecutionRecord,
    ) -> (
        &[ECAddEvent<<Self::BaseField as FieldParameters>::NB_LIMBS>],
        &[ECDoubleEvent<<Self::BaseField as FieldParameters>::NB_LIMBS>],
    );
}

pub trait WithDoubling: EllipticCurveParameters {
    fn double_events(
        record: &ExecutionRecord,
    ) -> &[ECDoubleEvent<<Self::BaseField as FieldParameters>::NB_LIMBS>];
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
