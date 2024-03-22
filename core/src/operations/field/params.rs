use hybrid_array::sizes::U32;
use hybrid_array::typenum::{Double, Shright, Sub1, Unsigned, B1};
use hybrid_array::{Array, ArraySize};

use crate::air::Polynomial;
use std::fmt::Debug;
use std::ops::{Shl, Shr, Sub};
use std::slice::Iter;

pub const NB_BITS_PER_LIMB: usize = 8;
pub const NUM_WITNESS_LIMBS: usize = 2 * DEFAULT_NUM_LIMBS_T::USIZE - 2;

/// The default number of limbs reflected at the type level
// This is also <[T; DEFAULT_NUM_LIMBS] as AssocArraySize>::Size
#[allow(non_camel_case_types)]
pub type DEFAULT_NUM_LIMBS_T = U32;

// here N is NB_LIMBS in the field representation, so the following is a
// type-level function N -> 2 * N - 2
#[allow(non_camel_case_types)]
pub type NUM_WITNESS_LIMBS<N> = Double<Sub1<N>>;

// a type-level function N -> N / 2
#[allow(non_camel_case_types)]
pub type DIV2<N> = Shright<N, B1>;

// technical bounds indicating an N s.t. 2 (N - 1) is well-defined
pub trait LimbWidth: ArraySize + Sub<B1, Output = Self::S1> + Shr<B1, Output = Self::S3> {
    type S1: Shl<B1, Output = Self::S2>;
    type S2: ArraySize;
    type S3: ArraySize;
}

impl<U: ArraySize> LimbWidth for U
where
    U: Sub<B1> + Shr<B1>,
    Sub1<U>: Shl<B1>,
    DIV2<U>: ArraySize,
    NUM_WITNESS_LIMBS<U>: ArraySize,
{
    type S1 = Sub1<U>;
    type S2 = NUM_WITNESS_LIMBS<U>;
    type S3 = DIV2<U>;
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

impl<T: Debug + Default + Clone, U: ArraySize> From<Polynomial<T>> for Limbs<T, U> {
    fn from(value: Polynomial<T>) -> Self {
        Array::try_from(&value.as_coefficients()[..]).unwrap()
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
