use bls12_381::{fp::Fp, fp2::Fp2, G2Affine};
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::group::Curve;
use elliptic_curve::subtle::Choice;
use hybrid_array::{typenum::U48, Array};
use num::{BigUint, Num, One, Zero};
use serde::{Deserialize, Serialize};
use std::ops::Neg;

use super::{SwCurve, WeierstrassParameters};
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::FieldType;
use crate::runtime::Syscall;
use crate::stark::WeierstrassAddAssignChip;
use crate::stark::WeierstrassDoubleAssignChip;
use crate::syscall::precompiles::create_ec_add_event;
use crate::syscall::precompiles::create_ec_double_event;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurveParameters;

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

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 15;

    fn modulus() -> BigUint {
        BigUint::from_str_radix(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
            10,
        )
            .unwrap()
    }

    fn nb_bits() -> usize {
        381
    }
}

pub fn fp_to_biguint(val: &Fp) -> BigUint {
    let bytes: [u8; 48] = val.to_bytes();
    BigUint::from_bytes_be(&bytes)
}

pub fn biguint_to_fp(val: &BigUint) -> Fp {
    assert!(val < &Bls12381BaseField::modulus());
    let be_bytes = BigUint::to_bytes_le(val);
    let mut bytes: Vec<u8> = be_bytes;
    assert!(bytes.len() <= 48);
    bytes.resize(48, 0);
    bytes.reverse();
    let bytes: [u8; 48] = bytes.try_into().unwrap();
    Fp::from_bytes(&bytes).unwrap()
}

pub fn bls12381_fp2_sqrt(a: &[BigUint; 2]) -> [BigUint; 2] {
    let a = Fp2 {
        c0: biguint_to_fp(&a[0]),
        c1: biguint_to_fp(&a[1]),
    };
    let a_sqrt = a.sqrt().unwrap();
    [fp_to_biguint(&a_sqrt.c0), fp_to_biguint(&a_sqrt.c1)]
}

pub fn bls12381_g2_add(a: &[BigUint; 4], b: &[BigUint; 4]) -> [BigUint; 4] {
    fn is_identity(input: &[BigUint; 4]) -> Choice {
        if input[0] == BigUint::zero()
            && input[1] == BigUint::zero()
            && input[2] == BigUint::one()
            && input[3] == BigUint::zero()
        {
            return Choice::from(1u8);
        }
        Choice::from(0u8)
    }

    let a_identity = is_identity(a);
    let b_identity = is_identity(b);

    assert!(
        !bool::from(a_identity),
        "[bls12381_g2_add] point A is identity"
    );
    assert!(
        !bool::from(b_identity),
        "[bls12381_g2_add] point B is identity"
    );
    let a_equals_b = a.iter().zip(b.iter()).all(|(a, b)| a == b);
    assert!(!a_equals_b, "[bls12381_g2_add] A and B points are equal");

    let a = G2Affine {
        x: Fp2 {
            c0: biguint_to_fp(&a[0]),
            c1: biguint_to_fp(&a[1]),
        },
        y: Fp2 {
            c0: biguint_to_fp(&a[2]),
            c1: biguint_to_fp(&a[3]),
        },
        infinity: a_identity,
    };

    let b = G2Affine {
        x: Fp2 {
            c0: biguint_to_fp(&b[0]),
            c1: biguint_to_fp(&b[1]),
        },
        y: Fp2 {
            c0: biguint_to_fp(&b[2]),
            c1: biguint_to_fp(&b[3]),
        },
        infinity: b_identity,
    };

    let neg_b = b.neg();
    assert_ne!(a, neg_b, "[bls12381_g2_add] A equals -B | B equals -A");

    let expected = (a.to_curve() + b.to_curve()).to_affine();
    let out_x_c0 = fp_to_biguint(&expected.x.c0);
    let out_x_c1 = fp_to_biguint(&expected.x.c1);
    let out_y_c0 = fp_to_biguint(&expected.y.c0);
    let out_y_c1 = fp_to_biguint(&expected.y.c1);
    [out_x_c0, out_x_c1, out_y_c0, out_y_c1]
}

pub fn bls12381_double(p: &[BigUint; 4]) -> [BigUint; 4] {
    fn is_identity(p: &[BigUint; 4]) -> Choice {
        if p[0] == BigUint::zero()
            && p[1] == BigUint::zero()
            && p[2] == BigUint::one()
            && p[3] == BigUint::zero()
        {
            return Choice::from(1u8);
        }
        Choice::from(0u8)
    }
    let p_identity = is_identity(p);
    assert!(
        !bool::from(p_identity),
        "[bls12381_double] P is infinity point"
    );

    let p = G2Affine {
        x: Fp2 {
            c0: biguint_to_fp(&p[0]),
            c1: biguint_to_fp(&p[1]),
        },
        y: Fp2 {
            c0: biguint_to_fp(&p[2]),
            c1: biguint_to_fp(&p[3]),
        },
        infinity: p_identity,
    };

    let double: G2Affine = p.to_curve().double().to_affine();

    [
        fp_to_biguint(&double.x.c0),
        fp_to_biguint(&double.x.c1),
        fp_to_biguint(&double.y.c0),
        fp_to_biguint(&double.y.c1),
    ]
}

impl EllipticCurveParameters for Bls12381Parameters {
    type BaseField = Bls12381BaseField;
    const CURVE_TYPE: CurveType = CurveType::Bls12381;
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
        rt: &mut crate::runtime::SyscallContext<'_, '_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<Bls12381>(rt, arg1, arg2);
        rt.record_mut().bls12381_g1_add_events.push(event);
        None
    }
    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

impl Syscall for WeierstrassDoubleAssignChip<Bls12381> {
    fn execute(
        &self,
        rt: &mut crate::runtime::SyscallContext<'_, '_>,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_double_event::<Bls12381>(rt, arg1, arg2);
        rt.record_mut().bls12381_g1_double_events.push(event);
        None
    }
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
