use std::cmp::Reverse;
use std::collections::HashMap;
use std::fmt::Debug;

use itertools::Itertools;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::Pcs;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Dimensions;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use serde::Deserialize;
use serde::Serialize;
use tracing::instrument;

use super::debug_constraints;
use super::Dom;
use crate::air::MachineAir;
use crate::air::MachineProgram;
use crate::air::PublicValues;
use crate::lookup::debug_interactions_with_all_chips;
use crate::lookup::InteractionBuilder;
use crate::lookup::InteractionKind;
use crate::stark::record::MachineRecord;
use crate::stark::DebugConstraintBuilder;
use crate::stark::ProverConstraintFolder;
use crate::stark::ShardProof;
use crate::stark::VerifierConstraintFolder;

use super::Chip;
use super::Com;
use super::MachineProof;
use super::PcsProverData;
use super::Prover;
use super::StarkGenericConfig;
use super::Val;
use super::VerificationError;
use super::Verifier;

pub type MachineChip<SC, A> = Chip<Val<SC>, A>;

/// A STARK for proving RISC-V execution.
pub struct StarkMachine<SC: StarkGenericConfig, A> {
    /// The STARK settings for the RISC-V STARK.
    config: SC,
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<Val<SC>, A>>,

    /// The number of public values elements that the machine uses
    num_pv_elts: usize,
}

impl<SC: StarkGenericConfig, A> StarkMachine<SC, A> {
    pub fn new(config: SC, chips: Vec<Chip<Val<SC>, A>>, num_pv_elts: usize) -> Self {
        Self {
            config,
            chips,
            num_pv_elts,
        }
    }
}

pub struct StarkProvingKey<SC: StarkGenericConfig> {
    pub commit: Com<SC>,
    pub pc_start: Val<SC>,
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    pub data: PcsProverData<SC>,
    pub chip_ordering: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> StarkProvingKey<SC> {
    pub fn observe_into(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "SC: StarkGenericConfig")]
pub struct StarkVerifyingKey<SC>
where
    SC: StarkGenericConfig,
{
    pub commit: Com<SC>,
    pub pc_start: Val<SC>,
    #[serde(skip)]
    pub chip_information: Vec<(String, Dom<SC>, Dimensions)>,
    pub chip_ordering: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> StarkVerifyingKey<SC> {
    pub fn observe_into(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
    }
}

impl<SC: StarkGenericConfig> Debug for StarkVerifyingKey<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey").finish()
    }
}

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> StarkMachine<SC, A> {
    /// Get an array containing a `ChipRef` for all the chips of this RISC-V STARK machine.
    pub fn chips(&self) -> &[MachineChip<SC, A>] {
        &self.chips
    }

    pub fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns the id of all chips in the machine that have preprocessed columns.
    pub fn preprocessed_chip_ids(&self) -> Vec<usize> {
        self.chips
            .iter()
            .enumerate()
            .filter(|(_, chip)| chip.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn shard_chips<'a, 'b>(
        &'a self,
        shard: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips.iter().filter(|chip| chip.included(shard))
    }

    pub fn shard_chips_ordered<'a, 'b>(
        &'a self,
        chip_ordering: &'b HashMap<String, usize>,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips
            .iter()
            .filter(|chip| chip_ordering.contains_key(&chip.name()))
            .sorted_by_key(|chip| chip_ordering.get(&chip.name()))
    }

    pub fn chips_sorted_indices(&self, proof: &ShardProof<SC>) -> Vec<Option<usize>> {
        self.chips()
            .iter()
            .map(|chip| proof.chip_ordering.get(&chip.name()).cloned())
            .collect()
    }

    /// The setup preprocessing phase.
    ///
    /// Given a program, this function generates the proving and verifying keys. The keys correspond
    /// to the program code and other preprocessed colunms such as lookup tables.
    #[instrument("setup machine", level = "info", skip_all)]
    pub fn setup(&self, program: &A::Program) -> (StarkProvingKey<SC>, StarkVerifyingKey<SC>) {
        let mut named_preprocessed_traces = tracing::debug_span!("generate preprocessed traces")
            .in_scope(|| {
                self.chips()
                    .iter()
                    .map(|chip| {
                        let prep_trace = chip.generate_preprocessed_trace(program);
                        // Assert that the chip width data is correct.
                        let expected_width = prep_trace.as_ref().map_or(0, |t| t.width());
                        assert_eq!(
                            expected_width,
                            chip.preprocessed_width(),
                            "Incorrect number of preprocessed columns for chip {}",
                            chip.name()
                        );

                        (chip.name(), prep_trace)
                    })
                    .filter(|(_, prep_trace)| prep_trace.is_some())
                    .map(|(name, prep_trace)| {
                        let prep_trace = prep_trace.unwrap();
                        (name, prep_trace)
                    })
                    .collect::<Vec<_>>()
            });

        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_preprocessed_traces.sort_by_key(|(_, trace)| Reverse(trace.height()));

        let pcs = self.config.pcs();

        let (chip_information, domains_and_traces): (Vec<_>, Vec<_>) = named_preprocessed_traces
            .iter()
            .map(|(name, trace)| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                (
                    (name.to_owned(), domain, trace.dimensions()),
                    (domain, trace.to_owned()),
                )
            })
            .unzip();

        // Commit to the batch of traces.
        let (commit, data) = tracing::debug_span!("commit to preprocessed traces")
            .in_scope(|| pcs.commit(domains_and_traces));

        // Get the chip ordering.
        let chip_ordering = named_preprocessed_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();

        // Get the preprocessed traces
        let traces = named_preprocessed_traces
            .into_iter()
            .map(|(_, trace)| trace)
            .collect::<Vec<_>>();

        let pc_start = program.pc_start();

        (
            StarkProvingKey {
                commit: commit.clone(),
                pc_start,
                traces,
                data,
                chip_ordering: chip_ordering.clone(),
            },
            StarkVerifyingKey {
                commit,
                pc_start,
                chip_information,
                chip_ordering,
            },
        )
    }

    pub fn shard(
        &self,
        mut record: A::Record,
        config: &<A::Record as MachineRecord>::Config,
    ) -> Vec<A::Record> {
        // Get the local and global chips.
        let chips = self.chips();

        // Generate the trace for each chip to collect events emitted from chips with dependencies.
        tracing::debug_span!("collect record events from chips").in_scope(|| {
            chips.iter().for_each(|chip| {
                let mut output = A::Record::default();
                output.set_index(record.index());
                chip.generate_dependencies(&record, &mut output);
                record.append(&mut output);
            })
        });

        // Display some statistics about the workload.
        let stats = record.stats();
        for (k, v) in stats {
            log::info!("{} = {}", k, v);
        }

        // For each chip, shard the events into segments.
        record.shard(config)
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    #[instrument("prove", level = "info", skip_all)]
    pub fn prove<P: Prover<SC, A>>(
        &self,
        pk: &StarkProvingKey<SC>,
        record: A::Record,
        challenger: &mut SC::Challenger,
    ) -> MachineProof<SC>
    where
        A: for<'a> Air<ProverConstraintFolder<'a, SC>>
            + Air<InteractionBuilder<Val<SC>>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        let shards = tracing::info_span!("shard execution record")
            .in_scope(|| self.shard(record, &<A::Record as MachineRecord>::Config::default()));

        tracing::info_span!("generate shard proofs")
            .in_scope(|| P::prove_shards(self, pk, shards, challenger))
    }

    pub const fn config(&self) -> &SC {
        &self.config
    }

    /// Verify that a proof is complete and valid given a verifying key and a claimed digest.
    #[instrument("verify", level = "info", skip_all)]
    pub fn verify(
        &self,
        vk: &StarkVerifyingKey<SC>,
        proof: &MachineProof<SC>,
        challenger: &mut SC::Challenger,
    ) -> Result<(), ProgramVerificationError<SC>>
    where
        SC::Challenger: Clone,
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // Observe the preprocessed commitment.
        vk.observe_into(challenger);
        tracing::debug_span!("observe challenges for all shards").in_scope(|| {
            proof.shard_proofs.iter().for_each(|proof| {
                challenger.observe(proof.commitment.main_commit.clone());
                challenger.observe_slice(&proof.public_values[0..self.num_pv_elts()]);
            });
        });

        // Verify the shard proofs.
        if proof.shard_proofs.is_empty() {
            return Err(ProgramVerificationError::InvalidShardTransition(
                "no shards",
            ));
        }

        tracing::debug_span!("verify shard proofs").in_scope(|| {
            for (i, shard_proof) in proof.shard_proofs.iter().enumerate() {
                tracing::debug_span!("verifying shard", segment = i).in_scope(|| {
                    let public_values = PublicValues::from_vec(&shard_proof.public_values);
                    // Verify shard transitions
                    if i == 0 {
                        // If it's the first shard, index should be 1.
                        if public_values.shard != SC::Val::one() {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "first shard not 1",
                            ));
                        }
                        if public_values.start_pc != vk.pc_start {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "wrong pc_start",
                            ));
                        }
                        // let pv_digest: [u32; 8] = public_values
                        //     .committed_value_digest
                        //     .iter()
                        //     .map(|w| w.to_u32())
                        //     .collect::<Vec<_>>()
                        //     .try_into()
                        //     .unwrap();
                        // let deferred_proofs_digest: [u32; 8] = public_values
                        //     .deferred_proofs_digest
                        //     .iter()
                        //     .map(|w| w.to_string().parse::<u32>().unwrap())
                        //     .collect::<Vec<_>>()
                        //     .try_into()
                        //     .unwrap();
                    } else {
                        let prev_shard_proof = &proof.shard_proofs[i - 1];
                        let prev_public_values =
                            PublicValues::from_vec(&prev_shard_proof.public_values);
                        // For non-first shards, the index should be the previous index + 1.
                        if public_values.shard != prev_public_values.shard + SC::Val::one() {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "non incremental shard index",
                            ));
                        }
                        // Start pc should be what the next pc declared in the previous shard was.
                        if public_values.start_pc != prev_public_values.next_pc {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "pc mismatch",
                            ));
                        }
                        // Digests and exit code should be the same in all shards.
                        if public_values.committed_value_digest
                            != prev_public_values.committed_value_digest
                            || public_values.deferred_proofs_digest
                                != prev_public_values.deferred_proofs_digest
                            || public_values.exit_code != prev_public_values.exit_code
                        {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "digest or exit code mismatch",
                            ));
                        }
                        // The last shard should be halted. Halt is signaled with next_pc == 0.
                        if i == proof.shard_proofs.len() - 1
                            && public_values.next_pc != SC::Val::zero()
                        {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "last shard isn't halted",
                            ));
                        }
                        // All non-last shards should not be halted.
                        if i != proof.shard_proofs.len() - 1
                            && public_values.next_pc == SC::Val::zero()
                        {
                            return Err(ProgramVerificationError::InvalidShardTransition(
                                "non-last shard is halted",
                            ));
                        }
                    }

                    let chips = self
                        .shard_chips_ordered(&shard_proof.chip_ordering)
                        .collect::<Vec<_>>();
                    Verifier::verify_shard(
                        &self.config,
                        vk,
                        &chips,
                        &mut challenger.clone(),
                        shard_proof,
                    )
                    .map_err(ProgramVerificationError::InvalidSegmentProof)
                })?;
            }

            Ok(())
        })?;

        // Verify the cumulative sum is 0.
        tracing::debug_span!("verify cumulative sum is 0").in_scope(|| {
            let mut sum = SC::Challenge::zero();
            for proof in proof.shard_proofs.iter() {
                sum += proof.cumulative_sum();
            }
            match sum.is_zero() {
                true => Ok(()),
                false => Err(ProgramVerificationError::NonZeroCumulativeSum),
            }
        })
    }

    #[instrument("debug constraints", level = "debug", skip_all)]
    pub fn debug_constraints(
        &self,
        pk: &StarkProvingKey<SC>,
        record: A::Record,
        challenger: &mut SC::Challenger,
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        tracing::debug!("sharding the execution record");
        let shards = self.shard(record, &<A::Record as MachineRecord>::Config::default());

        tracing::debug!("checking constraints for each shard");

        let mut cumulative_sum = SC::Challenge::zero();
        for shard in shards.iter() {
            // Filter the chips based on what is used.
            let chips = self.shard_chips(shard).collect::<Vec<_>>();

            // Generate the main trace for each chip.
            let pre_traces = chips
                .iter()
                .map(|chip| {
                    pk.chip_ordering
                        .get(&chip.name())
                        .map(|index| &pk.traces[*index])
                })
                .collect::<Vec<_>>();
            let mut traces = chips
                .par_iter()
                .map(|chip| chip.generate_trace(shard, &mut A::Record::default()))
                .zip(pre_traces)
                .collect::<Vec<_>>();

            // Get a permutation challenge.
            // Obtain the challenges used for the permutation argument.
            let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
            for _ in 0..2 {
                permutation_challenges.push(challenger.sample_ext_element());
            }

            // Generate the permutation traces.
            let mut permutation_traces = Vec::with_capacity(chips.len());
            let mut cumulative_sums = Vec::with_capacity(chips.len());
            tracing::debug_span!("generate permutation traces").in_scope(|| {
                chips
                    .par_iter()
                    .zip(traces.par_iter_mut())
                    .map(|(chip, (main_trace, pre_trace))| {
                        let perm_trace = chip.generate_permutation_trace(
                            *pre_trace,
                            main_trace,
                            &permutation_challenges,
                        );
                        let cumulative_sum = perm_trace
                            .row_slice(main_trace.height() - 1)
                            .last()
                            .copied()
                            .unwrap();
                        (perm_trace, cumulative_sum)
                    })
                    .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
            });

            cumulative_sum += cumulative_sums.iter().copied().sum::<SC::Challenge>();

            // Compute some statistics.
            for i in 0..chips.len() {
                let trace_width = traces[i].0.width();
                let permutation_width = permutation_traces[i].width();
                let total_width = trace_width + permutation_width;
                tracing::debug!(
                "{:<11} | Main Cols = {:<5} | Perm Cols = {:<5} | Rows = {:<10} | Cells = {:<10}",
                chips[i].name(),
                trace_width,
                permutation_width,
                traces[i].0.height(),
                total_width * traces[i].0.height(),
                );
            }

            tracing::info_span!("debug constraints").in_scope(|| {
                for i in 0..chips.len() {
                    let permutation_trace = pk
                        .chip_ordering
                        .get(&chips[i].name())
                        .map(|index| &pk.traces[*index]);
                    debug_constraints::<SC, A>(
                        chips[i],
                        permutation_trace,
                        &traces[i].0,
                        &permutation_traces[i],
                        &permutation_challenges,
                        &shard.public_values(),
                    );
                }
            });
        }

        // If the cumulative sum is not zero, debug the interactions.
        if !cumulative_sum.is_zero() {
            debug_interactions_with_all_chips::<SC, A>(
                self,
                pk,
                &shards,
                &InteractionKind::all_kinds(),
            );
        }
    }
}

pub enum ProgramVerificationError<SC: StarkGenericConfig> {
    InvalidSegmentProof(VerificationError<SC>),
    InvalidGlobalProof(VerificationError<SC>),
    NonZeroCumulativeSum,
    InvalidShardTransition(&'static str),
    InvalidPublicValuesDigest,
    DebugInteractionsFailed,
}

impl<SC: StarkGenericConfig> Debug for ProgramVerificationError<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramVerificationError::InvalidSegmentProof(e) => {
                write!(f, "Invalid segment proof: {:?}", e)
            }
            ProgramVerificationError::InvalidGlobalProof(e) => {
                write!(f, "Invalid global proof: {:?}", e)
            }
            ProgramVerificationError::NonZeroCumulativeSum => {
                write!(f, "Non-zero cumulative sum")
            }
            ProgramVerificationError::InvalidShardTransition(s) => {
                write!(f, "Invalid shard transition: {}", s)
            }
            ProgramVerificationError::InvalidPublicValuesDigest => {
                write!(f, "Invalid public values digest")
            }
            ProgramVerificationError::DebugInteractionsFailed => {
                write!(f, "Debug interactions failed")
            }
        }
    }
}

impl<SC: StarkGenericConfig> std::fmt::Display for ProgramVerificationError<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl<SC: StarkGenericConfig> std::error::Error for ProgramVerificationError<SC> {}

#[cfg(test)]
pub mod tests {

    use crate::{
        runtime::{
            tests::{
                fibonacci_program, simple_memory_program, simple_program, ssz_withdrawals_program,
            },
            Instruction, Opcode, Program,
        },
        utils::{run_test, setup_logger},
    };

    #[test]
    fn test_simple_prove() {
        setup_logger();
        let program = simple_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_shift_prove() {
        setup_logger();
        let shift_ops = [Opcode::SRL, Opcode::SRA, Opcode::SLL];
        let operands = [
            (1, 1),
            (1234, 5678),
            (0xffff, 0xffff - 1),
            (u32::MAX - 1, u32::MAX),
            (u32::MAX, 0),
        ];
        for shift_op in shift_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*shift_op, 31, 29, 3, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test(program).unwrap();
            }
        }
    }

    #[test]
    fn test_sub_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test(program).unwrap();
    }

    #[test]
    fn test_add_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test(program).unwrap();
    }

    #[test]
    fn test_mul_prove() {
        let mul_ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU];
        setup_logger();
        let operands = [
            (1, 1),
            (1234, 5678),
            (8765, 4321),
            (0xffff, 0xffff - 1),
            (u32::MAX - 1, u32::MAX),
        ];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, operand.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, operand.1, false, true),
                    Instruction::new(*mul_op, 31, 30, 29, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test(program).unwrap();
            }
        }
    }

    #[test]
    fn test_lt_prove() {
        setup_logger();
        let less_than = [Opcode::SLT, Opcode::SLTU];
        for lt_op in less_than.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*lt_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_bitwise_prove() {
        setup_logger();
        let bitwise_opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];

        for bitwise_op in bitwise_opcodes.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*bitwise_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_divrem_prove() {
        setup_logger();
        let div_rem_ops = [Opcode::DIV, Opcode::DIVU, Opcode::REM, Opcode::REMU];
        let operands = [
            (1, 1),
            (123, 456 * 789),
            (123 * 456, 789),
            (0xffff * (0xffff - 1), 0xffff),
            (u32::MAX - 5, u32::MAX - 7),
        ];
        for div_rem_op in div_rem_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*div_rem_op, 31, 29, 30, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test(program).unwrap();
            }
        }
    }

    #[test]
    fn test_fibonacci_prove() {
        setup_logger();
        let program = fibonacci_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        run_test(program).unwrap();
    }

    #[test]
    fn test_ssz_withdrawal() {
        let program = ssz_withdrawals_program();
        run_test(program).unwrap();
    }
}
