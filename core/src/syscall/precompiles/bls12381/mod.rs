use crate::{
    runtime::{Syscall, SyscallContext},
    utils::ec::weierstrass::bls12381::Bls12381BaseField,
};

use super::field::add::{create_fp_add_event, FieldAddChip};
use super::field::mul::{create_fp_mul_event, FieldMulChip};
use super::field::sub::{create_fp_sub_event, FieldSubChip};
use super::quad_field::add::{create_fp2_add_event, QuadFieldAddChip};
use super::quad_field::mul::{create_fp2_mul_event, QuadFieldMulChip};
use super::quad_field::sub::{create_fp2_sub_event, QuadFieldSubChip};

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
