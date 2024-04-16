use hybrid_array::typenum::U48;
use hybrid_array::Array;
use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};

use amcl::bls381::big::Big;
use amcl::bls381::bls381::utils::deserialize_g1;
use amcl::bls381::fp::FP;

use super::{SwCurve, WeierstrassParameters};
use crate::runtime::Syscall;
use crate::stark::{WeierstrassAddAssignChip, WeierstrassDoubleAssignChip};
use crate::syscall::precompiles::{create_ec_add_event, create_ec_double_event};
use crate::utils::ec::field::{
    FieldParameters, FieldType, WithFieldAddition, WithFieldMultiplication, WithFieldSubtraction,
    WithQuadFieldAddition, WithQuadFieldMultiplication, WithQuadFieldSubtraction, //NumLimbs
};
use crate::utils::ec::{AffinePoint, EllipticCurve, CurveType, EllipticCurveParameters, WithAddition, WithDoubling};

// Serialization flags
const COMPRESION_FLAG: u8 = 0b_1000_0000;
const Y_IS_ODD_FLAG: u8 = 0b_0010_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Bls12381 curve parameter
pub struct Bls12381Parameters;

pub type Bls12381 = SwCurve<Bls12381Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Bls12381 base field (Fp) parameter
pub struct Bls12381BaseField;

impl FieldParameters for Bls12381BaseField {
    const FIELD_TYPE: FieldType = FieldType::Bls12381;

    type NB_LIMBS = U48;

    const MODULUS: Array<u8, Self::NB_LIMBS> = Array([
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ]);

    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_str_radix(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
            10,
        )
            .unwrap()
    }

    // For now, we use the default WITNESS_OFFSET value of 1 << 13

    fn nb_bits() -> usize {
        381
    }
}

/*
impl NumLimbs for Bls12381BaseField {
    type Limbs = U48;
    type Witness = U94;
}
*/

impl WithFieldAddition for Bls12381BaseField {
    fn add_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::field::add::FieldAddEvent<Bls12381BaseField>] {
        &record.bls12381_fp_add_events
    }
}

impl WithFieldSubtraction for Bls12381BaseField {
    fn sub_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::field::sub::FieldSubEvent<Bls12381BaseField>] {
        &record.bls12381_fp_sub_events
    }
}

impl WithFieldMultiplication for Bls12381BaseField {
    fn mul_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::field::mul::FieldMulEvent<Bls12381BaseField>] {
        &record.bls12381_fp_mul_events
    }
}

impl WithQuadFieldAddition for Bls12381BaseField {
    fn add_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::quad_field::add::QuadFieldAddEvent<Bls12381BaseField>] {
        &record.bls12381_fp2_add_events
    }
}

impl WithQuadFieldSubtraction for Bls12381BaseField {
    fn sub_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::quad_field::sub::QuadFieldSubEvent<Bls12381BaseField>] {
        &record.bls12381_fp2_sub_events
    }
}

impl WithQuadFieldMultiplication for Bls12381BaseField {
    fn mul_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::quad_field::mul::QuadFieldMulEvent<Bls12381BaseField>] {
        &record.bls12381_fp2_mul_events
    }
}

impl EllipticCurveParameters for Bls12381Parameters {
    type BaseField = Bls12381BaseField;
    const CURVE_TYPE: CurveType = CurveType::Bls12381;
}

impl WithAddition for Bls12381Parameters {
    fn add_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::ECAddEvent<<Self::BaseField as FieldParameters>::NB_LIMBS>]
    {
        &record.bls12381_add_events
    }
}

impl WithDoubling for Bls12381Parameters {
    fn double_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::ECDoubleEvent<
        <Self::BaseField as FieldParameters>::NB_LIMBS,
    >] {
        &record.bls12381_double_events
    }
}

/// The WeierstrassParameters for BLS12-381 G1
impl WeierstrassParameters for Bls12381Parameters {
    const A: Array<u16, <Self::BaseField as FieldParameters>::NB_LIMBS> = Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    const B: Array<u16, <Self::BaseField as FieldParameters>::NB_LIMBS> = Array([
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    fn generator() -> (BigUint, BigUint) {
        // Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-10.html#name-bls-curves-for-the-128-bit-
        let x = BigUint::from_str_radix(
            "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            16
        ).unwrap();
        let y = BigUint::from_str_radix(
            "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
            16
        ).unwrap();
        (x, y)
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(4u32)
    }

    fn prime_group_order() -> BigUint {
        BigUint::from_str_radix(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            16,
        )
        .unwrap()
    }
}

impl Syscall for WeierstrassAddAssignChip<Bls12381> {
    fn execute(
        &self,
        rt: &mut crate::runtime::SyscallContext<'_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<Bls12381>(rt, arg1, arg2);
        rt.record_mut().bls12381_add_events.push(event);
        None
    }
    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

pub fn bls12381_decompress<E: EllipticCurve>(bytes_be: &[u8], is_odd: u32) -> AffinePoint<E> {
    let mut g1_bytes_be: [u8; 48] = bytes_be.try_into().unwrap();
    let mut flags = COMPRESION_FLAG;
    if is_odd == 0 {
        flags |= Y_IS_ODD_FLAG;
    };

    // set sign and compression flag
    g1_bytes_be[0] |= flags;
    let point = deserialize_g1(&g1_bytes_be).unwrap();

    let x_str = point.getx().to_string();
    let x = BigUint::from_str_radix(x_str.as_str(), 16).unwrap();
    let y_str = point.gety().to_string();
    let y = BigUint::from_str_radix(y_str.as_str(), 16).unwrap();

    AffinePoint::new(x, y)
}

pub fn bls12381_sqrt(a: &BigUint) -> BigUint {
    let a_big = Big::from_bytes(a.to_bytes_be().as_slice());

    let a_sqrt = FP::new_big(a_big).sqrt();

    BigUint::from_str_radix(a_sqrt.to_string().as_str(), 16).unwrap()
}

impl Syscall for WeierstrassDoubleAssignChip<Bls12381> {
    fn execute(
        &self,
        rt: &mut crate::runtime::SyscallContext<'_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_double_event::<Bls12381>(rt, arg1, arg2);
        rt.record_mut().bls12381_double_events.push(event);
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::ec::utils::biguint_from_limbs;

    use super::*;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Bls12381BaseField::MODULUS),
            Bls12381BaseField::modulus()
        );
    }

    use amcl::bls381::bls381::proof_of_possession::G1_BYTES;

    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    const NUM_TEST_CASES: usize = 10;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Bls12381BaseField::MODULUS),
            Bls12381BaseField::modulus()
        );
    }

    #[test]
    fn test_bls12381_decompress() {
        // This test checks that decompression of generator, 2x generator, 4x generator, etc. works.

        // Get the generator point.
        let mut point = {
            let (x, y) = Bls12381Parameters::generator();
            AffinePoint::<SwCurve<Bls12381Parameters>>::new(x, y)
        };
        for _ in 0..NUM_TEST_CASES {
            let (compressed_point, is_odd) = {
                let mut result = [0u8; G1_BYTES];
                let x = point.x.to_bytes_le();
                result[..x.len()].copy_from_slice(&x);
                result.reverse();

                // Evaluate if y > -y
                let y = point.y.clone();
                let y_neg = Bls12381BaseField::modulus() - y.clone();

                // Set flags
                let mut is_odd = 0;
                if y > y_neg {
                    result[0] += Y_IS_ODD_FLAG;
                    is_odd = 1;
                }
                result[0] += COMPRESION_FLAG;

                (result, is_odd)
            };
            assert_eq!(point, bls12381_decompress(&compressed_point, is_odd));

            // Double the point to create a "random" point for the next iteration.
            point = point.clone().sw_double();
        }
    }

    #[test]
    fn test_bls12381_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..NUM_TEST_CASES {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Bls12381BaseField::modulus();
            let x_2 = (&x * &x) % Bls12381BaseField::modulus();
            let sqrt = bls12381_sqrt(&x_2);
            if sqrt > x_2 {
                println!("wtf");
            }

            let sqrt_2 = (&sqrt * &sqrt) % Bls12381BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
