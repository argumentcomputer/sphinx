mod air;
mod columns;
mod execute;
mod trace;

pub use columns::*;
use serde::{Deserialize, Serialize};

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sha512ExtendEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub w_ptr: u32,
    pub i: u32,
    pub w_i_minus_15_reads: Vec<MemoryReadRecord>,
    pub w_i_minus_2_reads: Vec<MemoryReadRecord>,
    pub w_i_minus_16_reads: Vec<MemoryReadRecord>,
    pub w_i_minus_7_reads: Vec<MemoryReadRecord>,
    pub w_i_writes: Vec<MemoryWriteRecord>,
}

/// Implements the SHA extension operation which loops over i = [16, 63] and modifies w[i] in each
/// iteration. The only input to the syscall is the 4byte-aligned pointer to the w array.
///
/// In the AIR, each SHA extend syscall takes up 48 rows, where each row corresponds to a single
/// iteration of the loop.
#[derive(Default)]
pub struct Sha512ExtendChip;

impl Sha512ExtendChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod extend_tests {

    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::Sha512ExtendChip;
    use crate::{
        air::MachineAir,
        runtime::{ExecutionRecord, Instruction, Opcode, Program, SyscallCode},
        utils::{
            self, run_test,
            tests::{SHA512_ELF, SHA512_EXTEND_ELF},
        },
    };

    pub fn sha512_extend_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 0, false, true),
        ];
        for i in 0..80 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 8, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 8 + 4, false, true),
                Instruction::new(Opcode::SW, 28, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::SHA512_EXTEND as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, 16, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn generate_trace() {
        let shard = ExecutionRecord::default();
        let chip = Sha512ExtendChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn test_sha512_prove() {
        utils::setup_logger();
        let program = sha512_extend_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_sha512_program() {
        utils::setup_logger();
        let program = Program::from(SHA512_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_sha512_extend_program() {
        utils::setup_logger();
        let program = Program::from(SHA512_EXTEND_ELF);
        run_test(program).unwrap();
    }
}
