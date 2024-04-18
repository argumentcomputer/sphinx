use std::array::TryFromSliceError;
use std::fmt::Debug;
use std::ops::{Div, Mul, Shl, Shr, Sub};
use std::slice::Iter;

use hybrid_array::{
    sizes::{U32, U4},
    typenum::{Double, Shright, Sub1, B1},
    Array, ArraySize, AssocArraySize,
};

use crate::air::Polynomial;

pub const NB_BITS_PER_LIMB: usize = 8;

/// The size of a word in bytes, reflected as a type
#[allow(non_camel_case_types)]
pub type WORD_SIZE = <[u8; crate::air::WORD_SIZE] as AssocArraySize>::Size;

/// The default number of limbs reflected at the type level
// This is also <[T; DEFAULT_NUM_LIMBS] as AssocArraySize>::Size
#[allow(non_camel_case_types)]
pub type DEFAULT_NUM_LIMBS_T = U32;

// here N is NB_LIMBS in the field representation, so the following is a
// type-level function N -> 2 * N - 2
#[allow(non_camel_case_types)]
pub type WITNESS_LIMBS<N> = Double<Sub1<N>>;

/// Number of words needed to represent a point on an elliptic curve. This is twice the number of
/// words needed to represent a field element as a point consists of the x and y coordinates.
// Can also be seen as a type-level function N -> N / 2
#[allow(non_camel_case_types)]
pub type WORDS_CURVEPOINT<N> = Shright<N, B1>;

/// Number of words needed to represent a field element.
// Can also be seen as a type-level function N -> N / 4
#[allow(non_camel_case_types)]
pub type WORDS_FIELD_ELEMENT<N> = <N as Div<U4>>::Output;

/// Number of words needed to represent a quadratic extension field element. This is twice the number of
/// words needed to represent a field element.
// Can also be seen as a type-level function N -> N / 2
#[allow(non_camel_case_types)]
pub type WORDS_QUAD_EXT_FIELD_ELEMENT<N> = Shright<N, B1>;

/// Number of bytes needed to represent a field element.
/// Can also be seen as a type-level function N -> WORDS_FIELD_ELEMENT(N) * WORD_SIZE
#[allow(non_camel_case_types)]
pub type BYTES_FIELD_ELEMENT<N> = <WORDS_FIELD_ELEMENT<N> as Mul<WORD_SIZE>>::Output;

/// Number of bytes needed to represent a curve point in compressed form.
/// This is the number of bytes needed to represent a single field element (since we only represent the x-coordinate).
/// Can also be seen as a type-level function N -> WORDS_FIELD_ELEMENT(N) * WORD_SIZE
#[allow(non_camel_case_types)]
pub type BYTES_COMPRESSED_CURVEPOINT<N> = <WORDS_FIELD_ELEMENT<N> as Mul<WORD_SIZE>>::Output;

// technical bounds indicating an N s.t. :
// - 2 (N - 1) is well-defined
// - N / 2 is well-defined
// - N / 4 is well-defined
// - N / 4 * 4 is well-defined
pub trait LimbWidth:
    ArraySize + Sub<B1, Output = Self::S1> + Shr<B1, Output = Self::S3> + Div<U4, Output = Self::S4>
{
    type S1: Shl<B1, Output = Self::S2>;
    type S2: ArraySize;
    type S3: ArraySize;
    type S4: ArraySize + Mul<WORD_SIZE, Output = Self::S5>;
    type S5: ArraySize;
}

impl<U: ArraySize> LimbWidth for U
where
    U: Sub<B1> + Shr<B1> + Div<U4>,
    Sub1<U>: Shl<B1>,
    <U as Div<U4>>::Output: Mul<U4>,
    WITNESS_LIMBS<U>: ArraySize,
    WORDS_CURVEPOINT<U>: ArraySize,
    WORDS_FIELD_ELEMENT<U>: ArraySize,
    BYTES_FIELD_ELEMENT<U>: ArraySize,
{
    type S1 = Sub1<U>;
    type S2 = WITNESS_LIMBS<U>;
    type S3 = WORDS_CURVEPOINT<U>;
    type S4 = WORDS_FIELD_ELEMENT<U>;
    type S5 = BYTES_FIELD_ELEMENT<U>;
}

pub type Limbs<T, U = DEFAULT_NUM_LIMBS_T> = Array<T, U>;

impl<Var: Into<Expr> + Clone, Expr: Clone, U: ArraySize> From<Limbs<Var, U>> for Polynomial<Expr> {
    fn from(value: Limbs<Var, U>) -> Self {
        Polynomial::from_coefficients(&value.into_iter().map(|x| x.into()).collect::<Vec<_>>())
    }
}

impl<'a, Var: Into<Expr> + Clone, Expr: Clone> From<Iter<'a, Var>> for Polynomial<Expr> {
    fn from(value: Iter<'a, Var>) -> Self {
        Polynomial::from_coefficients(&value.map(|x| (*x).clone().into()).collect::<Vec<_>>())
    }
}

impl<T, U> TryFrom<Polynomial<T>> for Limbs<T, U>
where
    T: Debug + Default + Clone,
    U: ArraySize,
{
    type Error = TryFromSliceError;

    fn try_from(value: Polynomial<T>) -> Result<Self, Self::Error> {
        let coefficients = value.as_coefficients();
        Array::try_from(&coefficients[..])
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;

    use crate::utils::ec::{edwards::ed25519::Ed25519BaseField, field::FieldParameters};

    #[test]
    fn test_modulus() {
        // Convert the MODULUS array to BigUint
        let array_modulus = BigUint::from_bytes_le(&Ed25519BaseField::MODULUS);

        // Get the modulus from the function
        let func_modulus = Ed25519BaseField::modulus();

        // println!("array_modulus: {:?}", func_modulus.to_bytes_le());

        // Assert equality
        assert_eq!(
            array_modulus, func_modulus,
            "MODULUS array does not match the modulus() function output."
        );
    }
}
