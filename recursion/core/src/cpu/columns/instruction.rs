use std::{iter::once, vec::IntoIter};

use p3_field::PrimeField;
use wp1_derive::AlignedBorrow;

use crate::{air::Block, cpu::Instruction};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct InstructionCols<T> {
    pub opcode: T,
    pub op_a: T,
    pub op_b: Block<T>,
    pub op_c: Block<T>,
    pub imm_b: T,
    pub imm_c: T,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: &Instruction<F>) {
        self.opcode = instruction.opcode.as_field::<F>();
        self.op_a = instruction.op_a;
        self.op_b = instruction.op_b;
        self.op_c = instruction.op_c;
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c)
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(once(self.op_a))
            .chain(self.op_b)
            .chain(self.op_c)
            .collect::<Vec<_>>()
            .into_iter()
    }
}
