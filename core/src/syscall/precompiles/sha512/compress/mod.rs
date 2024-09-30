mod air;
mod columns;
mod execute;
mod trace;

use serde::{Deserialize, Serialize};

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

pub const SHA512_COMPRESS_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sha512CompressEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub w_ptr: u32,
    pub h_ptr: u32,
    pub i: u32,
    pub w_i: u64,
    pub k_i: u64,
    pub h: [u64; 8],
    pub w_i_read_records: [MemoryReadRecord; 2],
    pub k_i_read_records: [MemoryReadRecord; 2],
    pub h_write_records: [MemoryWriteRecord; 16],
    pub i_write_record: MemoryWriteRecord,
}

/// Implements the SHA-512 compress operation by running one iteration of the inner loop and modifying
/// the A-H state for each iteration.
/// The inputs to the syscall are a pointer to the 80-long double word array W and a pointer to the
/// 89-long double word state array, composed of H (hash state), i (loop iteration) and K (SHA constants).
///
/// It is the responsibility of the caller to ensure that the correct state is passed. In particular, if
/// the `i` or `K` values are incorrect, the result is likely to be garbage.
///
/// In the AIR, each SHA-512 compress syscall takes up a single row. For a full SHA-512 hash, it is
/// necessary to call this syscall multiple times.
#[derive(Default)]
pub struct Sha512CompressChip;

impl Sha512CompressChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, SyscallCode},
        stark::DefaultProver,
        utils::{run_test, setup_logger, tests::SHA512_COMPRESS_ELF, u64_to_le_u32s},
    };

    use super::SHA512_COMPRESS_K;

    pub fn sha512_compress_program() -> Program {
        let w_ptr = 100;
        let h_ptr = 100000;
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
        // Fill out state and the `i` value after it
        for i in 0..9 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, h_ptr + i * 8, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                Instruction::new(Opcode::ADD, 30, 0, h_ptr + i * 8 + 4, false, true),
                Instruction::new(Opcode::SW, 28, 30, 0, false, true),
            ]);
        }
        // Fill out the constants `k`
        for i in 0..80 {
            let k_i = u64_to_le_u32s(SHA512_COMPRESS_K[i]);
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, k_i[0], false, true),
                Instruction::new(Opcode::ADD, 28, 0, k_i[1], false, true),
                Instruction::new(Opcode::ADD, 30, 0, h_ptr + 72 + i as u32 * 8, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                Instruction::new(
                    Opcode::ADD,
                    30,
                    0,
                    h_ptr + 72 + i as u32 * 8 + 4,
                    false,
                    true,
                ),
                Instruction::new(Opcode::SW, 28, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::SHA512_COMPRESS as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, h_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = sha512_compress_program();
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sha512_compress_program() {
        setup_logger();
        let program = Program::from(SHA512_COMPRESS_ELF);
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
