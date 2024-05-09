use wp1_derive::AlignedBorrow;

use crate::{air::IsExtZeroOperation, memory::MemoryReadWriteCols};

mod branch;
mod instruction;
mod jump;
mod opcode;
mod opcode_specific;

pub use instruction::*;
pub use opcode::*;

use self::opcode_specific::OpcodeSpecificCols;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Debug)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    pub clk: T,
    pub pc: T,
    pub fp: T,

    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,

    pub a: MemoryReadWriteCols<T>,
    pub b: MemoryReadWriteCols<T>,
    pub c: MemoryReadWriteCols<T>,

    pub opcode_specific: OpcodeSpecificCols<T>,

    // result = operand_1 == operand_2;
    pub eq_1_2: IsExtZeroOperation<T>,

    pub is_real: T,
}
