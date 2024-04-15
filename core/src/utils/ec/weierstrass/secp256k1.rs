//! Modulo defining the Secp256k1 curve and its base field. The constants are all taken from
//! https://en.bitcoin.it/wiki/Secp256k1.

use std::str::FromStr;

use hybrid_array::Array;
use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};

use super::{SwCurve, WeierstrassParameters};
use crate::operations::field::params::DEFAULT_NUM_LIMBS_T;
use crate::runtime::Syscall;
use crate::stark::WeierstrassAddAssignChip;
use crate::stark::WeierstrassDoubleAssignChip;
use crate::syscall::precompiles::create_ec_add_event;
use crate::syscall::precompiles::create_ec_double_event;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::field::FieldType;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurveParameters;
use crate::utils::ec::WithAddition;
use crate::utils::ec::WithDoubling;
use k256::FieldElement;
use num::traits::FromBytes;
use num::traits::ToBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Secp256k1 curve parameter
pub struct Secp256k1Parameters;

pub type Secp256k1 = SwCurve<Secp256k1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    const FIELD_TYPE: FieldType = FieldType::Secp256k1;

    type NB_LIMBS = DEFAULT_NUM_LIMBS_T;

    const MODULUS: Array<u8, Self::NB_LIMBS> = Array([
        0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ]);

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(&Self::MODULUS)
    }
}

impl EllipticCurveParameters for Secp256k1Parameters {
    type BaseField = Secp256k1BaseField;
    const CURVE_TYPE: CurveType = CurveType::Secp256k1;
}

impl WithAddition for Secp256k1Parameters {
    fn add_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::ECAddEvent<<Self::BaseField as FieldParameters>::NB_LIMBS>]
    {
        &record.secp256k1_add_events
    }
}

impl WithDoubling for Secp256k1Parameters {
    fn double_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::ECDoubleEvent<
        <Self::BaseField as FieldParameters>::NB_LIMBS,
    >] {
        &record.secp256k1_double_events
    }
}

impl WeierstrassParameters for Secp256k1Parameters {
    const A: Array<u16, <Self::BaseField as FieldParameters>::NB_LIMBS> = Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    const B: Array<u16, <Self::BaseField as FieldParameters>::NB_LIMBS> = Array([
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        )
        .unwrap();
        let y = BigUint::from_str(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> BigUint {
        BigUint::from_slice(&[
            0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(7u32)
    }
}

impl Syscall for WeierstrassAddAssignChip<Secp256k1> {
    fn execute(
        &self,
        rt: &mut crate::runtime::SyscallContext<'_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<Secp256k1>(rt, arg1, arg2);
        rt.record_mut().secp256k1_add_events.push(event);
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

impl Syscall for WeierstrassDoubleAssignChip<Secp256k1> {
    fn execute(
        &self,
        rt: &mut crate::runtime::SyscallContext<'_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_double_event::<Secp256k1>(rt, arg1, arg2);
        rt.record_mut().secp256k1_double_events.push(event);
        None
    }
}

pub fn secp256k1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().unwrap().to_bytes();
    BigUint::from_be_bytes(&result_bytes)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Secp256k1BaseField::MODULUS),
            Secp256k1BaseField::modulus()
        );
    }

    #[test]
    fn test_secp256k_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(Secp256k1BaseField::nb_bits() as u64)
                % Secp256k1BaseField::modulus();
            let x_2 = (&x * &x) % Secp256k1BaseField::modulus();
            let sqrt = secp256k1_sqrt(&x_2);
            if sqrt > x_2 {
                println!("wtf");
            }

            let sqrt_2 = (&sqrt * &sqrt) % Secp256k1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
