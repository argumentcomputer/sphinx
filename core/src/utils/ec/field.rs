use super::utils::biguint_from_limbs;
use crate::operations::field::params::LimbWidth;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::NB_BITS_PER_LIMB;
use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use num::BigUint;
use p3_field::Field;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Debug + Serialize + DeserializeOwned
{
    #[allow(non_camel_case_types)]
    type NB_LIMBS: LimbWidth;
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;

    const WITNESS_OFFSET: usize = 1usize << 13;
    const MODULUS: Array<u8, Self::NB_LIMBS>;

    fn modulus() -> BigUint {
        biguint_from_limbs(&Self::MODULUS)
    }

    fn nb_bits() -> usize {
        Self::NB_BITS_PER_LIMB * Self::NB_LIMBS::USIZE
    }

    fn modulus_field_iter<F: Field>() -> impl Iterator<Item = F> {
        Self::MODULUS
            .into_iter()
            .map(|x| F::from_canonical_u8(x))
            .take(Self::NB_LIMBS::USIZE)
    }

    // TODO(fg): there's a faster implementation of this
    fn to_limbs(x: &BigUint) -> Array<u8, Self::NB_LIMBS> {
        let mut bytes = x.to_bytes_le();
        if Self::NB_LIMBS::USIZE > bytes.len() {
            bytes.resize(Self::NB_LIMBS::USIZE, 0u8);
        }
        Array::try_from(&bytes[..]).unwrap()
    }

    fn to_limbs_field<F: Field>(x: &BigUint) -> Limbs<F, Self::NB_LIMBS> {
        Self::to_limbs(x).map(|x| F::from_canonical_u8(x))
    }
}
