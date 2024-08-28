use hashbrown::HashMap;
use itertools::EitherOrBoth;
use itertools::Itertools;
use p3_field::Field;
use std::mem::take;
use std::sync::Arc;

use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

use super::program::Program;
use super::Opcode;
use crate::air::PublicValues;
use crate::air::Word;
use crate::alu::AluEvent;
use crate::bytes::event::add_sharded_byte_lookup_events;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::runtime::MemoryInitializeFinalizeEvent;
use crate::runtime::MemoryRecordEnum;
use crate::stark::MachineRecord;
use crate::stark::{
    AddSubChip, BitwiseChip, ByteChip, CpuChip, DivRemChip, Ed25519Parameters, EdAddAssignChip,
    EdDecompressChip, KeccakPermuteChip, LtChip, MemoryChip, MulChip, ProgramChip, ShaCompressChip,
    ShaExtendChip, ShiftLeft, ShiftRightChip, WeierstrassAddAssignChip,
    WeierstrassDoubleAssignChip,
};
use crate::syscall::precompiles::edwards::EdDecompressEvent;
use crate::syscall::precompiles::keccak256::KeccakPermuteEvent;
use crate::syscall::precompiles::sha256::{ShaCompressEvent, ShaExtendEvent};
use crate::syscall::precompiles::{ECAddEvent, ECDoubleEvent};
use crate::utils::SphinxCoreOpts;
use crate::{
    air::EventLens,
    memory::MemoryProgramChip,
    operations::field::params::FieldParameters,
    stark::PublicValued,
    syscall::precompiles::{
        bls12_381::{
            g1_decompress::{Bls12381G1DecompressChip, Bls12381G1DecompressEvent},
            g2_add::{Bls12381G2AffineAddChip, Bls12381G2AffineAddEvent},
            g2_double::{Bls12381G2AffineDoubleChip, Bls12381G2AffineDoubleEvent},
        },
        field::{FieldChip, FieldEvent},
        quad_field::{QuadFieldChip, QuadFieldEvent},
        secp256k1::decompress::{Secp256k1DecompressChip, Secp256k1DecompressEvent},
    },
    utils::ec::{
        edwards::ed25519::Ed25519,
        weierstrass::{
            bls12_381::{Bls12381, Bls12381BaseField},
            bn254::Bn254,
            secp256k1::Secp256k1,
        },
    },
};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord {
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

    /// All byte lookups that are needed.
    ///
    /// The layout is shard -> (event -> count). Byte lookups are sharded to prevent the
    /// multiplicities from overflowing.
    pub byte_lookups: HashMap<u32, HashMap<ByteLookupEvent, usize>>,

    pub sha_extend_events: Vec<ShaExtendEvent>,

    pub sha_compress_events: Vec<ShaCompressEvent>,

    pub keccak_permute_events: Vec<KeccakPermuteEvent>,

    pub ed_add_events: Vec<ECAddEvent>,

    pub ed_decompress_events: Vec<EdDecompressEvent>,

    pub secp256k1_add_events: Vec<ECAddEvent>,

    pub secp256k1_double_events: Vec<ECDoubleEvent>,

    pub bn254_add_events: Vec<ECAddEvent>,

    pub bn254_double_events: Vec<ECDoubleEvent>,

    pub bls12381_g1_add_events: Vec<ECAddEvent<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,

    pub bls12381_g1_double_events:
        Vec<ECDoubleEvent<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,

    pub secp256k1_decompress_events: Vec<Secp256k1DecompressEvent>,

    pub bls12381_fp_events: Vec<FieldEvent<Bls12381BaseField>>,
    pub bls12381_fp2_events: Vec<QuadFieldEvent<Bls12381BaseField>>,
    pub bls12381_g1_decompress_events: Vec<Bls12381G1DecompressEvent>,
    pub bls12381_g2_add_events: Vec<Bls12381G2AffineAddEvent>,
    pub bls12381_g2_double_events: Vec<Bls12381G2AffineDoubleEvent>,

    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,

    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,

    /// The public values.
    pub public_values: PublicValues<u32, u32>,

    pub nonce_lookup: HashMap<usize, u32>,
}

// Event lenses connect the record to the events relative to a particular chip
impl EventLens<AddSubChip> for ExecutionRecord {
    fn events(&self) -> <AddSubChip as crate::air::WithEvents<'_>>::Events {
        (&self.add_events, &self.sub_events)
    }
}

impl EventLens<BitwiseChip> for ExecutionRecord {
    fn events(&self) -> <BitwiseChip as crate::air::WithEvents<'_>>::Events {
        &self.bitwise_events
    }
}

impl EventLens<DivRemChip> for ExecutionRecord {
    fn events(&self) -> <DivRemChip as crate::air::WithEvents<'_>>::Events {
        (&self.divrem_events, &self.nonce_lookup)
    }
}

impl EventLens<LtChip> for ExecutionRecord {
    fn events(&self) -> <LtChip as crate::air::WithEvents<'_>>::Events {
        &self.lt_events
    }
}

impl EventLens<MulChip> for ExecutionRecord {
    fn events(&self) -> <MulChip as crate::air::WithEvents<'_>>::Events {
        &self.mul_events
    }
}

impl EventLens<ShiftLeft> for ExecutionRecord {
    fn events(&self) -> <ShiftLeft as crate::air::WithEvents<'_>>::Events {
        &self.shift_left_events
    }
}

impl EventLens<ShiftRightChip> for ExecutionRecord {
    fn events(&self) -> <ShiftRightChip as crate::air::WithEvents<'_>>::Events {
        &self.shift_right_events
    }
}

impl<F: Field> EventLens<ByteChip<F>> for ExecutionRecord {
    fn events(&self) -> <ByteChip<F> as crate::air::WithEvents<'_>>::Events {
        &self.byte_lookups
    }
}

impl EventLens<CpuChip> for ExecutionRecord {
    fn events(&self) -> <CpuChip as crate::air::WithEvents<'_>>::Events {
        (&self.cpu_events, &self.nonce_lookup)
    }
}

impl EventLens<MemoryChip> for ExecutionRecord {
    fn events(&self) -> <MemoryChip as crate::air::WithEvents<'_>>::Events {
        (&self.memory_initialize_events, &self.memory_finalize_events)
    }
}

impl EventLens<MemoryProgramChip> for ExecutionRecord {
    fn events(&self) -> <MemoryProgramChip as crate::air::WithEvents<'_>>::Events {
        &self.program.memory_image
    }
}

impl EventLens<ProgramChip> for ExecutionRecord {
    fn events(&self) -> <ProgramChip as crate::air::WithEvents<'_>>::Events {
        (&self.cpu_events, &self.program)
    }
}

impl EventLens<ShaExtendChip> for ExecutionRecord {
    fn events(&self) -> <ShaExtendChip as crate::air::WithEvents<'_>>::Events {
        &self.sha_extend_events
    }
}

impl EventLens<ShaCompressChip> for ExecutionRecord {
    fn events(&self) -> <ShaCompressChip as crate::air::WithEvents<'_>>::Events {
        &self.sha_compress_events
    }
}

impl EventLens<KeccakPermuteChip> for ExecutionRecord {
    fn events(&self) -> <KeccakPermuteChip as crate::air::WithEvents<'_>>::Events {
        &self.keccak_permute_events
    }
}

impl EventLens<Bls12381G1DecompressChip> for ExecutionRecord {
    fn events(&self) -> <Bls12381G1DecompressChip as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_g1_decompress_events
    }
}

impl EventLens<Secp256k1DecompressChip> for ExecutionRecord {
    fn events(&self) -> <Secp256k1DecompressChip as crate::air::WithEvents<'_>>::Events {
        &self.secp256k1_decompress_events
    }
}

impl EventLens<Bls12381G2AffineAddChip> for ExecutionRecord {
    fn events(&self) -> <Bls12381G2AffineAddChip as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_g2_add_events
    }
}

impl EventLens<Bls12381G2AffineDoubleChip> for ExecutionRecord {
    fn events(&self) -> <Bls12381G2AffineDoubleChip as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_g2_double_events
    }
}

impl EventLens<FieldChip<Bls12381BaseField>> for ExecutionRecord {
    fn events(&self) -> <FieldChip<Bls12381BaseField> as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_fp_events
    }
}

impl EventLens<QuadFieldChip<Bls12381BaseField>> for ExecutionRecord {
    fn events(&self) -> <QuadFieldChip<Bls12381BaseField> as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_fp2_events
    }
}

impl EventLens<WeierstrassAddAssignChip<Secp256k1>> for ExecutionRecord {
    fn events(
        &self,
    ) -> <WeierstrassAddAssignChip<Secp256k1> as crate::air::WithEvents<'_>>::Events {
        &self.secp256k1_add_events
    }
}

impl EventLens<WeierstrassAddAssignChip<Bls12381>> for ExecutionRecord {
    fn events(&self) -> <WeierstrassAddAssignChip<Bls12381> as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_g1_add_events
    }
}

impl EventLens<WeierstrassAddAssignChip<Bn254>> for ExecutionRecord {
    fn events(&self) -> <WeierstrassAddAssignChip<Bn254> as crate::air::WithEvents<'_>>::Events {
        &self.bn254_add_events
    }
}

impl EventLens<WeierstrassDoubleAssignChip<Secp256k1>> for ExecutionRecord {
    fn events(
        &self,
    ) -> <WeierstrassDoubleAssignChip<Secp256k1> as crate::air::WithEvents<'_>>::Events {
        &self.secp256k1_double_events
    }
}

impl EventLens<WeierstrassDoubleAssignChip<Bls12381>> for ExecutionRecord {
    fn events(
        &self,
    ) -> <WeierstrassDoubleAssignChip<Bls12381> as crate::air::WithEvents<'_>>::Events {
        &self.bls12381_g1_double_events
    }
}

impl EventLens<WeierstrassDoubleAssignChip<Bn254>> for ExecutionRecord {
    fn events(&self) -> <WeierstrassDoubleAssignChip<Bn254> as crate::air::WithEvents<'_>>::Events {
        &self.bn254_double_events
    }
}

impl EventLens<EdAddAssignChip<Ed25519>> for ExecutionRecord {
    fn events(&self) -> <EdAddAssignChip<Ed25519> as crate::air::WithEvents<'_>>::Events {
        &self.ed_add_events
    }
}

impl EventLens<EdDecompressChip<Ed25519Parameters>> for ExecutionRecord {
    fn events(
        &self,
    ) -> <EdDecompressChip<Ed25519Parameters> as crate::air::WithEvents<'_>>::Events {
        &self.ed_decompress_events
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitOpts {
    pub deferred_shift_threshold: usize,
    pub keccak_split_threshold: usize,
    pub sha_extend_split_threshold: usize,
    pub sha_compress_split_threshold: usize,
    pub memory_split_threshold: usize,
}

impl SplitOpts {
    pub fn new(deferred_shift_threshold: usize) -> Self {
        Self {
            deferred_shift_threshold,
            keccak_split_threshold: deferred_shift_threshold / 24,
            sha_extend_split_threshold: deferred_shift_threshold / 48,
            sha_compress_split_threshold: deferred_shift_threshold / 80,
            memory_split_threshold: deferred_shift_threshold,
        }
    }
}

impl PublicValued for ExecutionRecord {
    fn public_values<F: AbstractField>(&self) -> PublicValues<Word<F>, F> {
        PublicValues::from(self.public_values)
    }
}

impl MachineRecord for ExecutionRecord {
    type Config = SphinxCoreOpts;

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
            "bls12381_g1_add_events".to_string(),
            self.bls12381_g1_add_events.len(),
        );
        stats.insert(
            "bls12381_g1_double_events".to_string(),
            self.bls12381_g1_double_events.len(),
        );
        stats.insert(
            "k256_decompress_events".to_string(),
            self.secp256k1_decompress_events.len(),
        );
        stats.insert(
            "bls12381_g1_decompress_events".to_string(),
            self.bls12381_g1_decompress_events.len(),
        );
        stats.insert(
            "bls12381_fp_events".to_string(),
            self.bls12381_fp_events.len(),
        );
        stats.insert(
            "bls12381_fp2_events".to_string(),
            self.bls12381_fp2_events.len(),
        );
        stats.insert(
            "bls12381_g2_add_events".to_string(),
            self.bls12381_g2_add_events.len(),
        );
        stats.insert(
            "bls12381_g2_double_events".to_string(),
            self.bls12381_g2_double_events.len(),
        );
        stats.insert(
            "memory_initialize_events".to_string(),
            self.memory_initialize_events.len(),
        );
        stats.insert(
            "memory_finalize_events".to_string(),
            self.memory_finalize_events.len(),
        );
        if !self.cpu_events.is_empty() {
            let shard = self.cpu_events[0].shard;
            stats.insert(
                "byte_lookups".to_string(),
                self.byte_lookups.get(&shard).map_or(0, |v| v.len()),
            );
        }
        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
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
        self.bls12381_g1_add_events
            .append(&mut other.bls12381_g1_add_events);
        self.bls12381_g1_double_events
            .append(&mut other.bls12381_g1_double_events);
        self.secp256k1_decompress_events
            .append(&mut other.secp256k1_decompress_events);
        self.bls12381_fp_events
            .append(&mut other.bls12381_fp_events);
        self.bls12381_fp2_events
            .append(&mut other.bls12381_fp2_events);
        self.bls12381_g1_decompress_events
            .append(&mut other.bls12381_g1_decompress_events);
        self.bls12381_g2_add_events
            .append(&mut other.bls12381_g2_add_events);
        self.bls12381_g2_double_events
            .append(&mut other.bls12381_g2_double_events);

        if self.byte_lookups.is_empty() {
            self.byte_lookups = take(&mut other.byte_lookups);
        } else {
            self.add_sharded_byte_lookup_events(vec![&other.byte_lookups]);
        }

        self.memory_initialize_events
            .append(&mut other.memory_initialize_events);
        self.memory_finalize_events
            .append(&mut other.memory_finalize_events);
    }

    fn register_nonces(&mut self, _opts: &Self::Config) {
        self.add_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        self.sub_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup
                .insert(event.lookup_id, (self.add_events.len() + i) as u32);
        });

        self.mul_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });

        self.bitwise_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.shift_left_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.shift_right_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.divrem_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                self.nonce_lookup.insert(event.lookup_id, i as u32);
            });

        self.lt_events.iter().enumerate().for_each(|(i, event)| {
            self.nonce_lookup.insert(event.lookup_id, i as u32);
        });
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }
}

impl ExecutionRecord {
    pub fn new(program: Arc<Program>) -> Self {
        Self {
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

    pub fn add_alu_events(&mut self, mut alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for (opcode, value) in alu_events.iter_mut() {
            match opcode {
                Opcode::ADD => {
                    self.add_events.append(value);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.append(value);
                }
                Opcode::SUB => {
                    self.sub_events.append(value);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.append(value);
                }
                Opcode::SLL => {
                    self.shift_left_events.append(value);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events.append(value);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.append(value);
                }
                _ => {
                    panic!("Invalid opcode: {:?}", opcode);
                }
            }
        }
    }

    /// Take out events from the [ExecutionRecord] that should be deferred to a separate shard.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every shard.
    pub fn defer(&mut self) -> ExecutionRecord {
        ExecutionRecord {
            keccak_permute_events: take(&mut self.keccak_permute_events),
            secp256k1_add_events: take(&mut self.secp256k1_add_events),
            secp256k1_double_events: take(&mut self.secp256k1_double_events),
            bn254_add_events: take(&mut self.bn254_add_events),
            bn254_double_events: take(&mut self.bn254_double_events),
            bls12381_g1_add_events: take(&mut self.bls12381_g1_add_events),
            bls12381_g1_double_events: take(&mut self.bls12381_g1_double_events),
            sha_extend_events: take(&mut self.sha_extend_events),
            sha_compress_events: take(&mut self.sha_compress_events),
            ed_add_events: take(&mut self.ed_add_events),
            ed_decompress_events: take(&mut self.ed_decompress_events),
            secp256k1_decompress_events: take(&mut self.secp256k1_decompress_events),
            bls12381_g1_decompress_events: take(&mut self.bls12381_g1_decompress_events),
            memory_initialize_events: take(&mut self.memory_initialize_events),
            memory_finalize_events: take(&mut self.memory_finalize_events),
            ..Default::default()
        }
    }

    /// Splits the deferred [ExecutionRecord] into multiple [ExecutionRecord]s, each which contain
    /// a "reasonable" number of deferred events.
    pub fn split(&mut self, last: bool, opts: SplitOpts) -> Vec<ExecutionRecord> {
        let mut shards = Vec::new();

        println!("keccak split {}", opts.keccak_split_threshold);

        macro_rules! split_events {
            ($self:ident, $events:ident, $shards:ident, $threshold:expr, $exact:expr) => {
                let events = std::mem::take(&mut $self.$events);
                let chunks = events.chunks_exact($threshold);
                if !$exact {
                    $self.$events = chunks.remainder().to_vec();
                } else {
                    let remainder = chunks.remainder().to_vec();
                    if !remainder.is_empty() {
                        $shards.push(ExecutionRecord {
                            $events: chunks.remainder().to_vec(),
                            program: self.program.clone(),
                            ..Default::default()
                        });
                    }
                }
                let mut event_shards = chunks
                    .map(|chunk| ExecutionRecord {
                        $events: chunk.to_vec(),
                        program: self.program.clone(),
                        ..Default::default()
                    })
                    .collect::<Vec<_>>();
                $shards.append(&mut event_shards);
            };
        }

        split_events!(
            self,
            keccak_permute_events,
            shards,
            opts.keccak_split_threshold,
            last
        );
        split_events!(
            self,
            secp256k1_add_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            secp256k1_double_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            bn254_add_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            bn254_double_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            bls12381_g1_add_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            bls12381_g1_double_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            sha_extend_events,
            shards,
            opts.sha_extend_split_threshold,
            last
        );
        split_events!(
            self,
            sha_compress_events,
            shards,
            opts.sha_compress_split_threshold,
            last
        );
        split_events!(
            self,
            ed_add_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            ed_decompress_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            secp256k1_decompress_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );
        split_events!(
            self,
            bls12381_g1_decompress_events,
            shards,
            opts.deferred_shift_threshold,
            last
        );

        if last {
            self.memory_initialize_events
                .sort_by_key(|event| event.addr);
            self.memory_finalize_events.sort_by_key(|event| event.addr);

            let mut init_addr_bits = [0; 32];
            let mut finalize_addr_bits = [0; 32];
            for mem_chunks in self
                .memory_initialize_events
                .chunks(opts.memory_split_threshold)
                .zip_longest(
                    self.memory_finalize_events
                        .chunks(opts.memory_split_threshold),
                )
            {
                let (mem_init_chunk, mem_finalize_chunk) = match mem_chunks {
                    EitherOrBoth::Both(mem_init_chunk, mem_finalize_chunk) => {
                        (mem_init_chunk, mem_finalize_chunk)
                    }
                    EitherOrBoth::Left(mem_init_chunk) => (mem_init_chunk, [].as_slice()),
                    EitherOrBoth::Right(mem_finalize_chunk) => ([].as_slice(), mem_finalize_chunk),
                };
                let mut shard = ExecutionRecord::default();
                shard.program = self.program.clone();
                shard
                    .memory_initialize_events
                    .extend_from_slice(mem_init_chunk);
                shard.public_values.previous_init_addr_bits = init_addr_bits;
                if let Some(last_event) = mem_init_chunk.last() {
                    let last_init_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    init_addr_bits = last_init_addr_bits;
                }
                shard.public_values.last_init_addr_bits = init_addr_bits;

                shard
                    .memory_finalize_events
                    .extend_from_slice(mem_finalize_chunk);
                shard.public_values.previous_finalize_addr_bits = finalize_addr_bits;
                if let Some(last_event) = mem_finalize_chunk.last() {
                    let last_finalize_addr_bits =
                        core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    finalize_addr_bits = last_finalize_addr_bits;
                }
                shard.public_values.last_finalize_addr_bits = finalize_addr_bits;

                shards.push(shard);
            }
        }

        shards
    }
}

impl ByteRecord for ExecutionRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self
            .byte_lookups
            .entry(blu_event.shard)
            .or_default()
            .entry(blu_event)
            .or_insert(0) += 1
    }

    #[inline]
    fn add_sharded_byte_lookup_events(
        &mut self,
        new_events: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    ) {
        add_sharded_byte_lookup_events(&mut self.byte_lookups, new_events);
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    pub a: Option<MemoryRecordEnum>,
    pub b: Option<MemoryRecordEnum>,
    pub c: Option<MemoryRecordEnum>,
    pub memory: Option<MemoryRecordEnum>,
}

/// The threshold for splitting deferred events.
pub const DEFERRED_SPLIT_THRESHOLD: usize = 1 << 19;
