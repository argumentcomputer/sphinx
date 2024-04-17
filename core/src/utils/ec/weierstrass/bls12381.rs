use hybrid_array::{typenum::U48, Array};
use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};

use super::{SwCurve, WeierstrassParameters};
use crate::{
    runtime::Syscall,
    stark::{WeierstrassAddAssignChip, WeierstrassDoubleAssignChip},
    syscall::precompiles::{create_ec_add_event, create_ec_double_event},
    utils::ec::{
        field::{
            FieldParameters, FieldType, WithFieldAddition, WithFieldMultiplication,
            WithFieldSubtraction, WithQuadFieldAddition, WithQuadFieldMultiplication,
            WithQuadFieldSubtraction,
        },
        CurveType, EllipticCurveParameters, WithAddition, WithDoubling,
    },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Bls12381BaseField::MODULUS),
            Bls12381BaseField::modulus()
        );
    }
}
