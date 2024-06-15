use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use strum_macros::EnumIter;

use crate::runtime::{Register, Runtime};
use crate::stark::{
    Ed25519Parameters, FieldAddChip, FieldMulChip, FieldSubChip, QuadFieldAddChip,
    QuadFieldMulChip, QuadFieldSubChip,
};
use crate::syscall::precompiles::bls12_381::g1_decompress::Bls12381G1DecompressChip;
use crate::syscall::precompiles::bls12_381::g2_add::Bls12381G2AffineAddChip;
use crate::syscall::precompiles::bls12_381::g2_double::Bls12381G2AffineDoubleChip;
use crate::syscall::precompiles::edwards::EdAddAssignChip;
use crate::syscall::precompiles::edwards::EdDecompressChip;
use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
use crate::syscall::precompiles::secp256k1::decompress::Secp256k1DecompressChip;
use crate::syscall::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::syscall::precompiles::weierstrass::{
    WeierstrassAddAssignChip, WeierstrassDoubleAssignChip,
};
use crate::syscall::{
    SyscallCommit, SyscallCommitDeferred, SyscallEnterUnconstrained, SyscallExitUnconstrained,
    SyscallHalt, SyscallHintLen, SyscallHintRead, SyscallVerifySphinxProof, SyscallWrite,
};
use crate::utils::ec::edwards::ed25519::Ed25519;
use crate::utils::ec::weierstrass::bls12_381::{Bls12381, Bls12381BaseField};
use crate::utils::ec::weierstrass::bn254::Bn254;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1;

use super::{ExecutionRecord, MemoryReadRecord, MemoryWriteRecord};

/// A system call is invoked by the the `ecall` instruction with a specific value in register t0.
/// The syscall number is a 32-bit integer, with the following layout (in little-endian format)
/// - The first byte is the syscall id.
/// - The second byte is 0/1 depending on whether the syscall has a separate table. This is used
/// in the CPU table to determine whether to lookup the syscall using the syscall interaction.
/// - The third byte is the number of additional cycles the syscall uses.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
pub enum SyscallCode {
    /// Halts the program.
    HALT = 0x00_00_00_00,

    /// Write to the output buffer.
    WRITE = 0x00_00_00_02,

    /// Enter unconstrained block.
    ENTER_UNCONSTRAINED = 0x00_00_00_03,

    /// Exit unconstrained block.
    EXIT_UNCONSTRAINED = 0x00_00_00_04,

    /// Executes the `SHA_EXTEND` precompile.
    SHA_EXTEND = 0x00_30_01_05,

    /// Executes the `SHA_COMPRESS` precompile.
    SHA_COMPRESS = 0x00_01_01_06,

    /// Executes the `ED_ADD` precompile.
    ED_ADD = 0x00_01_01_07,

    /// Executes the `ED_DECOMPRESS` precompile.
    ED_DECOMPRESS = 0x00_00_01_08,

    /// Executes the `KECCAK_PERMUTE` precompile.
    KECCAK_PERMUTE = 0x00_01_01_09,

    /// Executes the `SECP256K1_ADD` precompile.
    SECP256K1_ADD = 0x00_01_01_0A,

    /// Executes the `SECP256K1_DOUBLE` precompile.
    SECP256K1_DOUBLE = 0x00_00_01_0B,

    /// Executes the `SECP256K1_DECOMPRESS` precompile.
    SECP256K1_DECOMPRESS = 0x00_00_01_0C,

    /// Executes the `BLAKE3_COMPRESS_INNER` precompile.
    BLAKE3_COMPRESS_INNER = 0x00_38_01_0D,

    /// Executes the `BN254_ADD` precompile.
    BN254_ADD = 0x00_01_01_0E,

    /// Executes the `BN254_DOUBLE` precompile.
    BN254_DOUBLE = 0x00_00_01_0F,

    /// Executes the `BLS12381_ADD` precompile.
    BLS12381_G1_ADD = 0x00_01_01_71,

    /// Executes the `BLS12381_DOUBLE` precompile.
    BLS12381_G1_DOUBLE = 0x00_00_01_72,

    /// Executes the `BLS12381_G1_DECOMPRESS` precompile.
    BLS12381_G1_DECOMPRESS = 0x00_01_01_F2,

    /// Executes the `BLS12381_FP_ADD` precompile.
    BLS12381_FP_ADD = 0x00_01_01_73,
    BLS12381_FP_SUB = 0x00_01_01_74,
    BLS12381_FP_MUL = 0x00_01_01_75,
    BLS12381_FP2_ADD = 0x00_01_01_77,
    BLS12381_FP2_SUB = 0x00_01_01_78,
    BLS12381_FP2_MUL = 0x00_01_01_79,
    BLS12381_G2_ADD = 0x00_01_01_80,
    BLS12381_G2_DOUBLE = 0x00_00_01_81,

    /// Executes the `COMMIT` precompile.
    COMMIT = 0x00_00_00_10,

    /// Executes the `COMMIT_DEFERRED_PROOFS` precompile.
    COMMIT_DEFERRED_PROOFS = 0x00_00_00_1A,

    /// Executes the `VERIFY_SP1_PROOF` precompile.
    VERIFY_SPHINX_PROOF = 0x00_00_00_1B,

    /// Executes the `HINT_LEN` precompile.
    HINT_LEN = 0x00_00_00_F0,

    /// Executes the `HINT_READ` precompile.
    HINT_READ = 0x00_00_00_F1,
}

impl SyscallCode {
    /// Create a syscall from a u32.
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x00_00_00_00 => SyscallCode::HALT,
            0x00_00_00_02 => SyscallCode::WRITE,
            0x00_00_00_03 => SyscallCode::ENTER_UNCONSTRAINED,
            0x00_00_00_04 => SyscallCode::EXIT_UNCONSTRAINED,
            0x00_30_01_05 => SyscallCode::SHA_EXTEND,
            0x00_01_01_06 => SyscallCode::SHA_COMPRESS,
            0x00_01_01_07 => SyscallCode::ED_ADD,
            0x00_00_01_08 => SyscallCode::ED_DECOMPRESS,
            0x00_01_01_09 => SyscallCode::KECCAK_PERMUTE,
            0x00_01_01_0A => SyscallCode::SECP256K1_ADD,
            0x00_00_01_0B => SyscallCode::SECP256K1_DOUBLE,
            0x00_00_01_0C => SyscallCode::SECP256K1_DECOMPRESS,
            0x00_38_01_0D => SyscallCode::BLAKE3_COMPRESS_INNER,
            0x00_01_01_0E => SyscallCode::BN254_ADD,
            0x00_00_01_0F => SyscallCode::BN254_DOUBLE,
            0x00_01_01_73 => SyscallCode::BLS12381_FP_ADD,
            0x00_01_01_74 => SyscallCode::BLS12381_FP_SUB,
            0x00_01_01_75 => SyscallCode::BLS12381_FP_MUL,
            0x00_01_01_77 => SyscallCode::BLS12381_FP2_ADD,
            0x00_01_01_78 => SyscallCode::BLS12381_FP2_SUB,
            0x00_01_01_79 => SyscallCode::BLS12381_FP2_MUL,
            0x00_00_00_10 => SyscallCode::COMMIT,
            0x00_00_00_1A => SyscallCode::COMMIT_DEFERRED_PROOFS,
            0x00_00_00_1B => SyscallCode::VERIFY_SPHINX_PROOF,
            0x00_00_00_F0 => SyscallCode::HINT_LEN,
            0x00_00_00_F1 => SyscallCode::HINT_READ,
            0x00_01_01_71 => SyscallCode::BLS12381_G1_ADD,
            0x00_00_01_72 => SyscallCode::BLS12381_G1_DOUBLE,
            0x00_01_01_F2 => SyscallCode::BLS12381_G1_DECOMPRESS,
            0x00_01_01_80 => SyscallCode::BLS12381_G2_ADD,
            0x00_00_01_81 => SyscallCode::BLS12381_G2_DOUBLE,
            _ => panic!("invalid syscall number: {}", value),
        }
    }

    pub fn syscall_id(&self) -> u32 {
        (*self as u32).to_le_bytes()[0].into()
    }

    pub fn should_send(&self) -> u32 {
        (*self as u32).to_le_bytes()[1].into()
    }

    pub fn num_cycles(&self) -> u32 {
        (*self as u32).to_le_bytes()[2].into()
    }
}

impl fmt::Display for SyscallCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait Syscall: Send + Sync {
    /// Execute the syscall and return the resulting value of register a0. `arg1` and `arg2` are the
    /// values in registers X10 and X11, respectively. While not a hard requirement, the convention
    /// is that the return value is only for system calls such as `HALT`. Most precompiles use `arg1`
    /// and `arg2` to denote the addresses of the input data, and write the result to the memory at
    /// `arg1`.
    fn execute(&self, ctx: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32>;

    /// The number of extra cycles that the syscall takes to execute. Unless this syscall is complex
    /// and requires many cycles, this should be zero.
    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

/// A runtime for syscalls that is protected so that developers cannot arbitrarily modify the runtime.
pub struct SyscallContext<'a> {
    current_shard: u32,
    pub clk: u32,

    pub(crate) next_pc: u32,
    /// This is the exit_code used for the HALT syscall
    pub(crate) exit_code: u32,
    pub(crate) rt: &'a mut Runtime,
}

impl<'a> SyscallContext<'a> {
    pub fn new(runtime: &'a mut Runtime) -> Self {
        let current_shard = runtime.shard();
        let clk = runtime.state.clk;
        Self {
            current_shard,
            clk,
            next_pc: runtime.state.pc.wrapping_add(4),
            exit_code: 0,
            rt: runtime,
        }
    }

    pub fn record_mut(&mut self) -> &mut ExecutionRecord {
        &mut self.rt.record
    }

    pub fn current_shard(&self) -> u32 {
        self.rt.state.current_shard
    }

    pub fn current_channel(&self) -> u32 {
        self.rt.state.channel
    }

    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let record = self.rt.mr(addr, self.current_shard, self.clk);
        (record, record.value)
    }

    pub fn mr_slice(&mut self, addr: u32, len: usize) -> (Vec<MemoryReadRecord>, Vec<u32>) {
        let mut records = Vec::new();
        let mut values = Vec::new();
        for i in 0..len {
            let (record, value) = self.mr(addr + i as u32 * 4);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        self.rt.mw(addr, value, self.current_shard, self.clk)
    }

    pub fn mw_slice(&mut self, addr: u32, values: &[u32]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::new();
        for i in 0..values.len() {
            let record = self.mw(addr + i as u32 * 4, values[i]);
            records.push(record);
        }
        records
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// This is generally unconstrained, so you must be careful using it.
    pub fn register_unsafe(&self, register: Register) -> u32 {
        self.rt.register(register)
    }

    pub fn byte_unsafe(&self, addr: u32) -> u8 {
        self.rt.byte(addr)
    }

    pub fn word_unsafe(&self, addr: u32) -> u32 {
        self.rt.word(addr)
    }

    pub fn slice_unsafe(&self, addr: u32, len: usize) -> Vec<u32> {
        let mut values = Vec::new();
        for i in 0..len {
            values.push(self.rt.word(addr + i as u32 * 4));
        }
        values
    }

    pub fn set_next_pc(&mut self, next_pc: u32) {
        self.next_pc = next_pc;
    }

    pub fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }
}

pub fn default_syscall_map() -> HashMap<SyscallCode, Arc<dyn Syscall>> {
    let mut syscall_map = HashMap::<SyscallCode, Arc<dyn Syscall>>::default();
    syscall_map.insert(SyscallCode::HALT, Arc::new(SyscallHalt {}));
    syscall_map.insert(SyscallCode::SHA_EXTEND, Arc::new(ShaExtendChip::new()));
    syscall_map.insert(SyscallCode::SHA_COMPRESS, Arc::new(ShaCompressChip::new()));
    syscall_map.insert(
        SyscallCode::ED_ADD,
        Arc::new(EdAddAssignChip::<Ed25519>::new()),
    );
    syscall_map.insert(
        SyscallCode::ED_DECOMPRESS,
        Arc::new(EdDecompressChip::<Ed25519Parameters>::new()),
    );
    syscall_map.insert(
        SyscallCode::KECCAK_PERMUTE,
        Arc::new(KeccakPermuteChip::new()),
    );
    syscall_map.insert(
        SyscallCode::SECP256K1_ADD,
        Arc::new(WeierstrassAddAssignChip::<Secp256k1>::new()),
    );
    syscall_map.insert(
        SyscallCode::SECP256K1_DOUBLE,
        Arc::new(WeierstrassDoubleAssignChip::<Secp256k1>::new()),
    );
    syscall_map.insert(
        SyscallCode::SECP256K1_DECOMPRESS,
        Arc::new(Secp256k1DecompressChip::new()),
    );
    syscall_map.insert(
        SyscallCode::BN254_ADD,
        Arc::new(WeierstrassAddAssignChip::<Bn254>::new()),
    );
    syscall_map.insert(
        SyscallCode::BN254_DOUBLE,
        Arc::new(WeierstrassDoubleAssignChip::<Bn254>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_G1_ADD,
        Arc::new(WeierstrassAddAssignChip::<Bls12381>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_G1_DOUBLE,
        Arc::new(WeierstrassDoubleAssignChip::<Bls12381>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP_ADD,
        Arc::new(FieldAddChip::<Bls12381BaseField>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP_SUB,
        Arc::new(FieldSubChip::<Bls12381BaseField>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP_MUL,
        Arc::new(FieldMulChip::<Bls12381BaseField>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP2_ADD,
        Arc::new(QuadFieldAddChip::<Bls12381BaseField>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP2_SUB,
        Arc::new(QuadFieldSubChip::<Bls12381BaseField>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP2_MUL,
        Arc::new(QuadFieldMulChip::<Bls12381BaseField>::new()),
    );
    syscall_map.insert(
        SyscallCode::ENTER_UNCONSTRAINED,
        Arc::new(SyscallEnterUnconstrained::new()),
    );
    syscall_map.insert(
        SyscallCode::EXIT_UNCONSTRAINED,
        Arc::new(SyscallExitUnconstrained::new()),
    );
    syscall_map.insert(SyscallCode::WRITE, Arc::new(SyscallWrite::new()));
    syscall_map.insert(SyscallCode::COMMIT, Arc::new(SyscallCommit::new()));
    syscall_map.insert(
        SyscallCode::COMMIT_DEFERRED_PROOFS,
        Arc::new(SyscallCommitDeferred::new()),
    );
    syscall_map.insert(
        SyscallCode::VERIFY_SPHINX_PROOF,
        Arc::new(SyscallVerifySphinxProof::new()),
    );
    syscall_map.insert(SyscallCode::HINT_LEN, Arc::new(SyscallHintLen::new()));
    syscall_map.insert(SyscallCode::HINT_READ, Arc::new(SyscallHintRead::new()));
    syscall_map.insert(
        SyscallCode::BLS12381_G1_DECOMPRESS,
        Arc::new(Bls12381G1DecompressChip::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_G2_ADD,
        Arc::new(Bls12381G2AffineAddChip::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_G2_DOUBLE,
        Arc::new(Bls12381G2AffineDoubleChip::new()),
    );

    syscall_map
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::{default_syscall_map, SyscallCode};

    #[test]
    fn test_syscalls_in_default_map() {
        let default_syscall_map = default_syscall_map();
        for code in SyscallCode::iter() {
            if code == SyscallCode::BLAKE3_COMPRESS_INNER {
                // Blake3 is currently disabled.
                continue;
            }
            default_syscall_map.get(&code).unwrap();
        }
    }

    #[test]
    fn test_syscall_num_cycles_encoding() {
        for (syscall_code, syscall_impl) in default_syscall_map().iter() {
            let encoded_num_cycles = syscall_code.num_cycles();
            assert_eq!(syscall_impl.num_extra_cycles(), encoded_num_cycles);
        }
    }

    #[test]
    fn test_encoding_roundtrip() {
        for (syscall_code, _) in default_syscall_map().iter() {
            assert_eq!(SyscallCode::from_u32(*syscall_code as u32), *syscall_code);
        }
    }

    #[test]
    /// Check that the Syscall number match the zkVM crate's.
    fn test_syscall_consistency_zkvm() {
        for code in SyscallCode::iter() {
            match code {
                SyscallCode::HALT => assert_eq!(code as u32, sphinx_zkvm::syscalls::HALT),
                SyscallCode::WRITE => assert_eq!(code as u32, sphinx_zkvm::syscalls::WRITE),
                SyscallCode::ENTER_UNCONSTRAINED => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::ENTER_UNCONSTRAINED)
                }
                SyscallCode::EXIT_UNCONSTRAINED => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::EXIT_UNCONSTRAINED)
                }
                SyscallCode::SHA_EXTEND => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::SHA_EXTEND)
                }
                SyscallCode::SHA_COMPRESS => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::SHA_COMPRESS)
                }
                SyscallCode::ED_ADD => assert_eq!(code as u32, sphinx_zkvm::syscalls::ED_ADD),
                SyscallCode::ED_DECOMPRESS => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::ED_DECOMPRESS)
                }
                SyscallCode::KECCAK_PERMUTE => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::KECCAK_PERMUTE)
                }
                SyscallCode::SECP256K1_ADD => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::SECP256K1_ADD)
                }
                SyscallCode::SECP256K1_DOUBLE => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::SECP256K1_DOUBLE)
                }
                SyscallCode::BLAKE3_COMPRESS_INNER => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLAKE3_COMPRESS_INNER)
                }
                SyscallCode::SECP256K1_DECOMPRESS => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::SECP256K1_DECOMPRESS)
                }
                SyscallCode::BN254_ADD => assert_eq!(code as u32, sphinx_zkvm::syscalls::BN254_ADD),
                SyscallCode::BN254_DOUBLE => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BN254_DOUBLE)
                }
                SyscallCode::BLS12381_FP_ADD => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_FP_ADD)
                }
                SyscallCode::BLS12381_FP_SUB => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_FP_SUB)
                }
                SyscallCode::BLS12381_FP_MUL => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_FP_MUL)
                }
                SyscallCode::BLS12381_FP2_ADD => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_FP2_ADD)
                }
                SyscallCode::BLS12381_FP2_SUB => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_FP2_SUB)
                }
                SyscallCode::BLS12381_FP2_MUL => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_FP2_MUL)
                }
                SyscallCode::BLS12381_G1_ADD => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_G1_ADD)
                }
                SyscallCode::BLS12381_G1_DOUBLE => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_G1_DOUBLE)
                }
                SyscallCode::COMMIT => assert_eq!(code as u32, sphinx_zkvm::syscalls::COMMIT),
                SyscallCode::BLS12381_G1_DECOMPRESS => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_G1_DECOMPRESS)
                }
                SyscallCode::COMMIT_DEFERRED_PROOFS => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::COMMIT_DEFERRED_PROOFS)
                }
                SyscallCode::VERIFY_SPHINX_PROOF => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::VERIFY_SPHINX_PROOF)
                }
                SyscallCode::HINT_LEN => assert_eq!(code as u32, sphinx_zkvm::syscalls::HINT_LEN),
                SyscallCode::HINT_READ => assert_eq!(code as u32, sphinx_zkvm::syscalls::HINT_READ),
                SyscallCode::BLS12381_G2_ADD => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_G2_ADD)
                }
                SyscallCode::BLS12381_G2_DOUBLE => {
                    assert_eq!(code as u32, sphinx_zkvm::syscalls::BLS12381_G2_DOUBLE)
                }
            }
        }
    }
}
