mod air;
mod columns;
mod execute;
mod flags;
mod trace;

pub use columns::*;
use serde::{Deserialize, Serialize};

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake2sXorRotate16Event {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub w_ptr: u32,

    pub w_0_reads: Vec<MemoryReadRecord>,
    pub w_1_reads: Vec<MemoryReadRecord>,
    pub w_2_reads: Vec<MemoryReadRecord>,
    pub w_3_reads: Vec<MemoryReadRecord>,
    pub w_4_reads: Vec<MemoryReadRecord>,
    pub w_5_reads: Vec<MemoryReadRecord>,
    pub w_6_reads: Vec<MemoryReadRecord>,
    pub w_7_reads: Vec<MemoryReadRecord>,

    pub w_16_writes: Vec<MemoryWriteRecord>,
    pub w_17_writes: Vec<MemoryWriteRecord>,
    pub w_18_writes: Vec<MemoryWriteRecord>,
    pub w_19_writes: Vec<MemoryWriteRecord>,
}

#[derive(Default)]
pub struct Blake2sXorRotate16Chip;

impl Blake2sXorRotate16Chip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod blake2s_xor_rotate_tests {
    use crate::utils::run_test;
    use crate::utils::tests::BLAKE2S_XOR_RIGHT_16_ELF;
    use crate::{
        runtime::{Instruction, Opcode, Program, SyscallCode},
        utils::{self, run_test_with_memory_inspection},
    };

    pub fn blake2s_xor_rotate_16_program() -> Program {
        let w_ptr = 100u32;
        let mut words = [0u32; 64];
        words[0] = 0x6b08e647;
        words[1] = 0xbb67ae85;
        words[2] = 0x3c6ef372;
        words[3] = 0xa54ff53a;

        words[4] = 0x510e527f;
        words[5] = 0x9b05688c;
        words[6] = 0x1f83d9ab;
        words[7] = 0x5be0cd19;

        let mut instructions = vec![];
        for (i, word) in words.into_iter().enumerate() {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, word, false, true),
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + (i * 4) as u32, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::BLAKE_2S_XOR_ROTATE_16 as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_blake2s_xor_rotate_16_prove() {
        utils::setup_logger();
        let program = blake2s_xor_rotate_16_program();
        let (_, memory) = run_test_with_memory_inspection(program);
        let mut result = vec![];
        for i in 0..64 {
            result.push(memory.get(&(100 + i * 4)).unwrap().value);
        }
        assert_eq!(
            result,
            vec![
                0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19, 0, 0, 0, 0, 0, 0, 0, 0, 0xb4383a06, 0xc6092062, 0x2ad923ed, 0x3823feaf,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_blake2s_xor_rotate_16_program() {
        utils::setup_logger();
        let program = Program::from(BLAKE2S_XOR_RIGHT_16_ELF);
        run_test(program).unwrap();
    }
}
