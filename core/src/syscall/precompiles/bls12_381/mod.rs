pub mod g1_decompress;
pub mod g2_add;
pub mod g2_double;

use super::{
    field::{create_fp_event, FieldAddSyscall, FieldMulSyscall, FieldSubSyscall},
    quad_field::{create_fp2_event, QuadFieldAddSyscall, QuadFieldMulSyscall, QuadFieldSubSyscall},
};
use crate::{
    operations::field::extensions::quadratic::QuadFieldOperation,
    operations::field::field_op::FieldOperation,
    operations::field::params::{FieldParameters, WORDS_FIELD_ELEMENT},
    runtime::{Syscall, SyscallContext},
    utils::ec::weierstrass::bls12_381::Bls12381BaseField,
};

// Convenience short-hand types for usage in chips and syscalls.
#[allow(non_camel_case_types)]
pub type BLS12_381_NUM_LIMBS = <Bls12381BaseField as FieldParameters>::NB_LIMBS;
#[allow(non_camel_case_types)]
pub type BLS12_381_NUM_WORDS_FOR_FIELD = WORDS_FIELD_ELEMENT<BLS12_381_NUM_LIMBS>;

impl Syscall for FieldAddSyscall<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp_event::<Bls12381BaseField>(rt, FieldOperation::Add, arg1, arg2);
        rt.record_mut().bls12381_fp_events.push(event);
        None
    }
}

impl Syscall for FieldSubSyscall<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp_event::<Bls12381BaseField>(rt, FieldOperation::Sub, arg1, arg2);
        rt.record_mut().bls12381_fp_events.push(event);
        None
    }
}

impl Syscall for FieldMulSyscall<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp_event::<Bls12381BaseField>(rt, FieldOperation::Mul, arg1, arg2);
        rt.record_mut().bls12381_fp_events.push(event);
        None
    }
}

impl Syscall for QuadFieldAddSyscall<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp2_event::<Bls12381BaseField>(rt, QuadFieldOperation::Add, arg1, arg2);
        rt.record_mut().bls12381_fp2_events.push(event);
        None
    }
}

impl Syscall for QuadFieldSubSyscall<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp2_event::<Bls12381BaseField>(rt, QuadFieldOperation::Sub, arg1, arg2);
        rt.record_mut().bls12381_fp2_events.push(event);
        None
    }
}

impl Syscall for QuadFieldMulSyscall<Bls12381BaseField> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_fp2_event::<Bls12381BaseField>(rt, QuadFieldOperation::Mul, arg1, arg2);
        rt.record_mut().bls12381_fp2_events.push(event);
        None
    }
}
