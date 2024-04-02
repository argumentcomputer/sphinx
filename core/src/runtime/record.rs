use std::collections::BTreeMap;
use std::collections::HashMap;
use std::mem::take;
use std::sync::Arc;

use super::program::Program;
use super::Opcode;
use crate::alu::AluEvent;
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::cpu::CpuEvent;
use crate::runtime::MemoryInitializeFinalizeEvent;
use crate::runtime::MemoryRecordEnum;
use crate::stark::MachineRecord;
use crate::syscall::precompiles::blake3::Blake3CompressInnerEvent;
use crate::syscall::precompiles::edwards::EdDecompressEvent;
use crate::syscall::precompiles::k256::K256DecompressEvent;
use crate::syscall::precompiles::keccak256::KeccakPermuteEvent;
use crate::syscall::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::weierstrass::bls12381::Bls12381BaseField;
use crate::utils::env;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// A record of the execution of a program. Contains event data for everything that happened during
/// the execution of the shard.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// The index of the shard.
    pub index: u32,

    /// The program.
    pub program: Arc<Program>,

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,

    /// A trace of the MUL events.
    pub mul_events: Vec<AluEvent>,

    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,

    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,

    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,

    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,

    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,

    /// A trace of the byte lookups needed.
    pub byte_lookups: BTreeMap<ByteLookupEvent, usize>,

    pub sha_extend_events: Vec<ShaExtendEvent>,

    pub sha_compress_events: Vec<ShaCompressEvent>,

    pub keccak_permute_events: Vec<KeccakPermuteEvent>,

    pub ed_add_events: Vec<ECAddEvent>,

    pub ed_decompress_events: Vec<EdDecompressEvent>,

    pub secp256k1_add_events: Vec<ECAddEvent>,

    pub secp256k1_double_events: Vec<ECDoubleEvent>,

    pub bn254_add_events: Vec<ECAddEvent>,

    pub bn254_double_events: Vec<ECDoubleEvent>,

    pub bls12381_add_events: Vec<ECAddEvent<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,

    pub bls12381_double_events:
        Vec<ECDoubleEvent<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,

    pub k256_decompress_events: Vec<K256DecompressEvent>,

    pub blake3_compress_inner_events: Vec<Blake3CompressInnerEvent>,

    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,

    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,

    pub program_memory_events: Vec<MemoryInitializeFinalizeEvent>,
}

pub struct ShardingConfig {
    pub shard_size: usize,
    pub add_len: usize,
    pub mul_len: usize,
    pub sub_len: usize,
    pub bitwise_len: usize,
    pub shift_left_len: usize,
    pub shift_right_len: usize,
    pub divrem_len: usize,
    pub lt_len: usize,
    pub field_len: usize,
    pub keccak_len: usize,
    pub secp256k1_add_len: usize,
    pub secp256k1_double_len: usize,
    pub bn254_add_len: usize,
    pub bn254_double_len: usize,
    pub bls12381_add_len: usize,
    pub bls12381_double_len: usize,
}

impl ShardingConfig {
    pub const fn shard_size(&self) -> usize {
        self.shard_size
    }
}

impl Default for ShardingConfig {
    fn default() -> Self {
        let shard_size = env::shard_size();
        Self {
            shard_size,
            add_len: shard_size,
            sub_len: shard_size,
            bitwise_len: shard_size,
            shift_left_len: shard_size,
            divrem_len: shard_size,
            lt_len: shard_size,
            mul_len: shard_size,
            shift_right_len: shard_size,
            field_len: shard_size * 4,
            keccak_len: shard_size,
            secp256k1_add_len: shard_size,
            secp256k1_double_len: shard_size,
            bn254_add_len: shard_size,
            bn254_double_len: shard_size,
            bls12381_add_len: shard_size,
            bls12381_double_len: shard_size,
        }
    }
}

impl MachineRecord for ExecutionRecord {
    type Config = ShardingConfig;

    fn index(&self) -> u32 {
        self.index
    }

    fn set_index(&mut self, index: u32) {
        self.index = index;
    }

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert("add_events".to_string(), self.add_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("sub_events".to_string(), self.sub_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert(
            "shift_left_events".to_string(),
            self.shift_left_events.len(),
        );
        stats.insert(
            "shift_right_events".to_string(),
            self.shift_right_events.len(),
        );
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert(
            "sha_extend_events".to_string(),
            self.sha_extend_events.len(),
        );
        stats.insert(
            "sha_compress_events".to_string(),
            self.sha_compress_events.len(),
        );
        stats.insert(
            "keccak_permute_events".to_string(),
            self.keccak_permute_events.len(),
        );
        stats.insert("ed_add_events".to_string(), self.ed_add_events.len());
        stats.insert(
            "ed_decompress_events".to_string(),
            self.ed_decompress_events.len(),
        );
        stats.insert(
            "secp256k1_add_events".to_string(),
            self.secp256k1_add_events.len(),
        );
        stats.insert(
            "secp256k1_double_events".to_string(),
            self.secp256k1_double_events.len(),
        );
        stats.insert("bn254_add_events".to_string(), self.bn254_add_events.len());
        stats.insert(
            "bn254_double_events".to_string(),
            self.bn254_double_events.len(),
        );
        stats.insert(
            "bls12381_add_events".to_string(),
            self.bls12381_add_events.len(),
        );
        stats.insert(
            "bls12381_double_events".to_string(),
            self.bls12381_double_events.len(),
        );
        stats.insert(
            "k256_decompress_events".to_string(),
            self.k256_decompress_events.len(),
        );
        stats.insert(
            "blake3_compress_inner_events".to_string(),
            self.blake3_compress_inner_events.len(),
        );
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_events.append(&mut other.cpu_events);
        self.add_events.append(&mut other.add_events);
        self.sub_events.append(&mut other.sub_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_right_events
            .append(&mut other.shift_right_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.sha_extend_events.append(&mut other.sha_extend_events);
        self.sha_compress_events
            .append(&mut other.sha_compress_events);
        self.keccak_permute_events
            .append(&mut other.keccak_permute_events);
        self.ed_add_events.append(&mut other.ed_add_events);
        self.ed_decompress_events
            .append(&mut other.ed_decompress_events);
        self.secp256k1_add_events
            .append(&mut other.secp256k1_add_events);
        self.secp256k1_double_events
            .append(&mut other.secp256k1_double_events);
        self.bn254_add_events.append(&mut other.bn254_add_events);
        self.bn254_double_events
            .append(&mut other.bn254_double_events);
        self.bls12381_add_events
            .append(&mut other.bls12381_add_events);
        self.bls12381_double_events
            .append(&mut other.bls12381_double_events);
        self.k256_decompress_events
            .append(&mut other.k256_decompress_events);
        self.blake3_compress_inner_events
            .append(&mut other.blake3_compress_inner_events);

        for (event, mult) in other.byte_lookups.iter_mut() {
            self.byte_lookups
                .entry(*event)
                .and_modify(|i| *i += *mult)
                .or_insert(*mult);
        }

        self.memory_initialize_events
            .append(&mut other.memory_initialize_events);
        self.memory_finalize_events
            .append(&mut other.memory_finalize_events);
        self.program_memory_events
            .append(&mut other.program_memory_events);
    }

    fn shard(mut self, config: &ShardingConfig) -> Vec<Self> {
        // Make the shard vector by splitting CPU and program events.
        let num_cpu_events = self.cpu_events.len();
        let mut num_shards = 0;
        if num_cpu_events > 0 {
            // The first shard is at 1.  See [ExecutionState::new].
            num_shards = self.cpu_events[num_cpu_events - 1].shard;
        }

        let mut shards = (0..num_shards)
            .map(|_| ExecutionRecord::default())
            .collect::<Vec<_>>();
        let mut start_idx = 0;
        let mut current_shard_num = 1;
        for (i, cpu_event) in self.cpu_events.iter().enumerate() {
            let at_last_event = i == num_cpu_events - 1;
            if cpu_event.shard != current_shard_num || at_last_event {
                let last_idx = if at_last_event { i + 1 } else { i };

                let shard = &mut shards[current_shard_num as usize - 1];
                shard.index = current_shard_num;
                shard.cpu_events = self.cpu_events[start_idx..last_idx].to_vec();
                shard.program = self.program.clone();

                if !(at_last_event) {
                    start_idx = i;
                    current_shard_num = cpu_event.shard;
                }
            }
        }

        // Shard all the other events according to the configuration.

        // Shard the ADD events.
        for (add_chunk, shard) in take(&mut self.add_events)
            .chunks_mut(config.add_len)
            .zip(shards.iter_mut())
        {
            shard.add_events.extend_from_slice(add_chunk);
        }

        // Shard the MUL events.
        for (mul_chunk, shard) in take(&mut self.mul_events)
            .chunks_mut(config.mul_len)
            .zip(shards.iter_mut())
        {
            shard.mul_events.extend_from_slice(mul_chunk);
        }

        // Shard the SUB events.
        for (sub_chunk, shard) in take(&mut self.sub_events)
            .chunks_mut(config.sub_len)
            .zip(shards.iter_mut())
        {
            shard.sub_events.extend_from_slice(sub_chunk);
        }

        // Shard the bitwise events.
        for (bitwise_chunk, shard) in take(&mut self.bitwise_events)
            .chunks_mut(config.bitwise_len)
            .zip(shards.iter_mut())
        {
            shard.bitwise_events.extend_from_slice(bitwise_chunk);
        }

        // Shard the shift left events.
        for (shift_left_chunk, shard) in take(&mut self.shift_left_events)
            .chunks_mut(config.shift_left_len)
            .zip(shards.iter_mut())
        {
            shard.shift_left_events.extend_from_slice(shift_left_chunk);
        }

        // Shard the shift right events.
        for (shift_right_chunk, shard) in take(&mut self.shift_right_events)
            .chunks_mut(config.shift_right_len)
            .zip(shards.iter_mut())
        {
            shard
                .shift_right_events
                .extend_from_slice(shift_right_chunk);
        }

        // Shard the divrem events.
        for (divrem_chunk, shard) in take(&mut self.divrem_events)
            .chunks_mut(config.divrem_len)
            .zip(shards.iter_mut())
        {
            shard.divrem_events.extend_from_slice(divrem_chunk);
        }

        // Shard the LT events.
        for (lt_chunk, shard) in take(&mut self.lt_events)
            .chunks_mut(config.lt_len)
            .zip(shards.iter_mut())
        {
            shard.lt_events.extend_from_slice(lt_chunk);
        }

        // Keccak-256 permute events.
        for (keccak_chunk, shard) in take(&mut self.keccak_permute_events)
            .chunks_mut(config.keccak_len)
            .zip(shards.iter_mut())
        {
            shard.keccak_permute_events.extend_from_slice(keccak_chunk);
        }

        // secp256k1 curve add events.
        for (secp256k1_add_chunk, shard) in take(&mut self.secp256k1_add_events)
            .chunks_mut(config.secp256k1_add_len)
            .zip(shards.iter_mut())
        {
            shard
                .secp256k1_add_events
                .extend_from_slice(secp256k1_add_chunk);
        }

        // secp256k1 curve double events.
        for (secp256k1_double_chunk, shard) in take(&mut self.secp256k1_double_events)
            .chunks_mut(config.secp256k1_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .secp256k1_double_events
                .extend_from_slice(secp256k1_double_chunk);
        }

        // bn254 curve add events.
        for (bn254_add_chunk, shard) in take(&mut self.bn254_add_events)
            .chunks_mut(config.bn254_add_len)
            .zip(shards.iter_mut())
        {
            shard.bn254_add_events.extend_from_slice(bn254_add_chunk);
        }

        // bn254 curve double events.
        for (bn254_double_chunk, shard) in take(&mut self.bn254_double_events)
            .chunks_mut(config.bn254_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .bn254_double_events
                .extend_from_slice(bn254_double_chunk);
        }

        // BLS12-381 curve add events.
        for (bls12381_add_chunk, shard) in take(&mut self.bls12381_add_events)
            .chunks_mut(config.bls12381_add_len)
            .zip(shards.iter_mut())
        {
            shard
                .bls12381_add_events
                .extend_from_slice(bls12381_add_chunk);
        }

        // BLS12-381 curve double events.
        for (bls12381_double_chunk, shard) in take(&mut self.bls12381_double_events)
            .chunks_mut(config.bls12381_double_len)
            .zip(shards.iter_mut())
        {
            shard
                .bls12381_double_events
                .extend_from_slice(bls12381_double_chunk);
        }

        // Put the precompile events in the first shard.
        let first = shards.first_mut().unwrap();

        // SHA-256 extend events.
        first.sha_extend_events = take(&mut self.sha_extend_events);

        // SHA-256 compress events.
        first.sha_compress_events = take(&mut self.sha_compress_events);

        // Edwards curve add events.
        first.ed_add_events = take(&mut self.ed_add_events);

        // Edwards curve decompress events.
        first.ed_decompress_events = take(&mut self.ed_decompress_events);

        // K256 curve decompress events.
        first.k256_decompress_events = take(&mut self.k256_decompress_events);

        // Blake3 compress events .
        first.blake3_compress_inner_events = take(&mut self.blake3_compress_inner_events);

        // Put all byte lookups in the first shard (as the table size is fixed)
        first.byte_lookups = take(&mut self.byte_lookups);

        // Put the memory records in the last shard.
        let last_shard = shards.last_mut().unwrap();

        last_shard
            .memory_initialize_events
            .extend_from_slice(&self.memory_initialize_events);
        last_shard
            .memory_finalize_events
            .extend_from_slice(&self.memory_finalize_events);
        last_shard
            .program_memory_events
            .extend_from_slice(&self.program_memory_events);

        shards
    }
}

impl ExecutionRecord {
    pub fn new(index: u32, program: Arc<Program>) -> Self {
        Self {
            index,
            program,
            ..Default::default()
        }
    }

    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    pub fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.byte_lookups
            .entry(blu_event)
            .and_modify(|i| *i += 1)
            .or_insert(1);
    }

    pub fn add_alu_events(&mut self, alu_events: &HashMap<Opcode, Vec<AluEvent>>) {
        let keys = alu_events.keys().sorted();
        for opcode in keys {
            match opcode {
                Opcode::ADD => {
                    self.add_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SUB => {
                    self.sub_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SLL => {
                    self.shift_left_events
                        .extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events
                        .extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.extend_from_slice(&alu_events[opcode]);
                }
                _ => {
                    panic!("Invalid opcode: {:?}", opcode);
                }
            }
        }
    }

    pub fn add_byte_lookup_events<I: IntoIterator<Item = ByteLookupEvent>>(
        &mut self,
        blu_events: I,
    ) {
        for blu_event in blu_events {
            self.add_byte_lookup_event(blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b are indeed bytes to the shard.
    pub fn add_u8_range_check(&mut self, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: u32::from(a),
            c: u32::from(b),
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    pub fn add_u16_range_check(&mut self, a: u32) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    pub fn add_u8_range_checks(&mut self, ls: &[u8]) {
        let mut index = 0;
        while index + 1 < ls.len() {
            self.add_u8_range_check(ls[index], ls[index + 1]);
            index += 2;
        }
        if index < ls.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(ls[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    pub fn add_u16_range_checks(&mut self, ls: &[u32]) {
        ls.iter().for_each(|x| self.add_u16_range_check(*x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    pub fn lookup_or(&mut self, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::OR,
            a1: u32::from(b | c),
            a2: 0,
            b: u32::from(b),
            c: u32::from(c),
        });
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    pub a: Option<MemoryRecordEnum>,
    pub b: Option<MemoryRecordEnum>,
    pub c: Option<MemoryRecordEnum>,
    pub memory: Option<MemoryRecordEnum>,
}
