use bls12_381::fp::Fp;
use bls12_381::G1Affine;
use hybrid_array::typenum::U48;
use hybrid_array::Array;
use num::{BigUint, Num, One as _, Zero};
use serde::{Deserialize, Serialize};

use super::{SwCurve, WeierstrassParameters};
use crate::runtime::Syscall;
use crate::stark::{
    WeierstrassAddAssignChip, WeierstrassDecompressChip, WeierstrassDoubleAssignChip,
};
use crate::syscall::precompiles::{
    create_ec_add_event, create_ec_decompress_event, create_ec_double_event,
};
use crate::utils::ec::field::{
    FieldParameters,
    FieldType,
    WithFieldAddition,
    WithFieldMultiplication,
    WithFieldSubtraction,
    WithQuadFieldAddition,
    WithQuadFieldMultiplication,
    WithQuadFieldSubtraction, //NumLimbs
};
use crate::utils::ec::{
    AffinePoint, CurveType, EllipticCurve, EllipticCurveParameters, WithAddition,
    WithDecompression, WithDoubling,
};

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

impl WithDecompression for Bls12381Parameters {
    fn decompression_events(
        record: &crate::runtime::ExecutionRecord,
    ) -> &[crate::syscall::precompiles::ECDecompressEvent<
        <Self::BaseField as FieldParameters>::NB_LIMBS,
    >] {
        &record.bls12381_decompress_events
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

impl Syscall for WeierstrassDecompressChip<Bls12381> {
    fn execute(
        &self,
        rt: &mut crate::runtime::SyscallContext<'_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_decompress_event::<Bls12381>(rt, arg1, arg2);
        rt.record_mut().bls12381_decompress_events.push(event);
        None
    }
}

pub fn bls12381_decompress<E: EllipticCurve>(bytes_be: &[u8], is_odd: u32) -> AffinePoint<E> {
    let mut arr_be: [u8; 48] = bytes_be.try_into().expect("Invalid input length");
    // assume we're receiving an unmasked point in compressed form, re-do the masking for bls12_381
    if arr_be == [0u8; 48] {
        arr_be[0] |= 1 << 6; // infinity case
    }
    arr_be[0] |= 1 << 7; // activate the compression flag
    arr_be[0] |= (is_odd as u8 ^ 1) << 5; // sign bit

    let Some(point): Option<G1Affine> = G1Affine::from_compressed(&arr_be).into() else {
        panic!("Invalid coordinate for G1 point: {:?}", arr_be);
    };

    if point.is_identity().into() {
        // the conventional representation of the infinity point
        return AffinePoint::new(BigUint::zero(), BigUint::one());
    }
    // For BLS12-381, the y-coordinate sign id deduced from a byte flag, so we ignore
    // the explicit is_odd argument
    let x = BigUint::from_bytes_be(&point.x.to_bytes()[..]);
    let y = BigUint::from_bytes_be(&point.y.to_bytes()[..]);
    AffinePoint::new(x, y)
}

pub fn bls12381_sqrt(a: &BigUint) -> BigUint {
    let mut a_bytes = a.to_bytes_le();
    // resize truncates larger inputs, so check the length
    assert!(a_bytes.len() <= 48);
    a_bytes.resize(48, 0);
    // Fp takes BE input
    a_bytes.reverse();
    let sqrt = Fp::from_bytes(&a_bytes.try_into().unwrap())
        .unwrap()
        .sqrt()
        .unwrap();
    BigUint::from_bytes_be(&sqrt.to_bytes()[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;
    use hybrid_array::typenum::Unsigned;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    const NUM_TEST_CASES: usize = 10;
    // Serialization flags
    const COMPRESSION_FLAG: u8 = 0b_1000_0000;
    const Y_IS_ODD_FLAG: u8 = 0b_0010_0000;

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
                let mut result = [0u8; <Bls12381BaseField as FieldParameters>::NB_LIMBS::USIZE];
                let x = point.x.to_bytes_le();
                result[..x.len()].copy_from_slice(&x);
                result.reverse();

                // Evaluate if y > -y
                let y = point.y.clone();
                let y_neg = Bls12381BaseField::modulus() - y.clone();

                // Set flags
                let mut is_odd = 1;
                if y > y_neg {
                    result[0] += Y_IS_ODD_FLAG;
                    is_odd = 0;
                }
                result[0] += COMPRESSION_FLAG;

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

            let sqrt_2 = (&sqrt * &sqrt) % Bls12381BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
