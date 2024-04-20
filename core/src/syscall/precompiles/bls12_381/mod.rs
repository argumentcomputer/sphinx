pub mod g1_decompress;

use super::{
    field::{
        add::{create_fp_add_event, FieldAddChip},
        mul::{create_fp_mul_event, FieldMulChip},
        sub::{create_fp_sub_event, FieldSubChip},
    },
    quad_field::{
        add::{create_fp2_add_event, QuadFieldAddChip},
        mul::{create_fp2_mul_event, QuadFieldMulChip},
        sub::{create_fp2_sub_event, QuadFieldSubChip},
    },
};
use crate::{
    operations::field::params::{FieldParameters, WORDS_FIELD_ELEMENT},
    runtime::{Syscall, SyscallContext},
    utils::ec::weierstrass::bls12_381::Bls12381BaseField,
};

// Convenience short-hand types for usage in chips and syscalls.
#[allow(non_camel_case_types)]
pub type BLS12_381_NUM_LIMBS = <Bls12381BaseField as FieldParameters>::NB_LIMBS;
#[allow(non_camel_case_types)]
pub type BLS12_381_NUM_WORDS_FOR_FIELD = WORDS_FIELD_ELEMENT<BLS12_381_NUM_LIMBS>;

impl Syscall for FieldAddChip<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp_add_event::<Bls12381BaseField>(rt, arg1, arg2);
        rt.record_mut().bls12381_fp_add_events.push(event);
        None
    }
}

impl Syscall for FieldSubChip<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp_sub_event::<Bls12381BaseField>(rt, arg1, arg2);
        rt.record_mut().bls12381_fp_sub_events.push(event);
        None
    }
}

impl Syscall for FieldMulChip<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp_mul_event::<Bls12381BaseField>(rt, arg1, arg2);
        rt.record_mut().bls12381_fp_mul_events.push(event);
        None
    }
}

impl Syscall for QuadFieldAddChip<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp2_add_event::<Bls12381BaseField>(rt, arg1, arg2);
        rt.record_mut().bls12381_fp2_add_events.push(event);
        None
    }
}

impl Syscall for QuadFieldSubChip<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp2_sub_event::<Bls12381BaseField>(rt, arg1, arg2);
        rt.record_mut().bls12381_fp2_sub_events.push(event);
        None
    }
}

impl Syscall for QuadFieldMulChip<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp2_mul_event::<Bls12381BaseField>(rt, arg1, arg2);
        rt.record_mut().bls12381_fp2_mul_events.push(event);
        None
    }
}
