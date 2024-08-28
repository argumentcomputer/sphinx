//! An end-to-end-prover implementation for the SP1 RISC-V zkVM.
//!
//! Seperates the proof generation process into multiple stages:
//!
//! 1. Generate shard proofs which split up and prove the valid execution of a RISC-V program.
//! 2. Compress shard proofs into a single shard proof.
//! 3. Wrap the shard proof into a SNARK-friendly field.
//! 4. Wrap the last shard proof, proven over the SNARK-friendly field, into a PLONK proof.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::new_without_default)]
#![allow(clippy::collapsible_else_if)]

pub mod build;
pub mod components;
pub mod types;
pub mod utils;
pub mod verify;

use std::borrow::Borrow;
use std::path::Path;
use std::sync::Arc;

use components::{DefaultProverComponents, SphinxProverComponents};
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::{AbstractField, PrimeField};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::prelude::*;
use sphinx_core::air::{PublicValues, Word};
pub use sphinx_core::io::{SphinxPublicValues, SphinxStdin};
use sphinx_core::runtime::{ExecutionError, ExecutionReport, Runtime, SphinxContext};
use sphinx_core::stark::MachineProver;
use sphinx_core::stark::{Challenge, StarkProvingKey};
use sphinx_core::stark::{Challenger, MachineVerificationError};
use sphinx_core::utils::{SphinxCoreOpts, SphinxProverOpts, DIGEST_SIZE};
use sphinx_core::{
    runtime::Program,
    stark::{RiscvAir, ShardProof, StarkGenericConfig, StarkVerifyingKey, Val},
    utils::{BabyBearPoseidon2, SphinxCoreProverError},
};
use sphinx_primitives::hash_deferred_proof;
use sphinx_primitives::types::RecursionProgramType;
use sphinx_recursion_circuit::witness::Witnessable;
use sphinx_recursion_compiler::config::InnerConfig;
use sphinx_recursion_compiler::ir::Witness;
use sphinx_recursion_core::{
    air::RecursionPublicValues,
    runtime::{RecursionProgram, Runtime as RecursionRuntime},
    stark::{config::BabyBearPoseidon2Outer, RecursionAir},
};
pub use sphinx_recursion_gnark_ffi::plonk_bn254::PlonkBn254Proof;
use sphinx_recursion_gnark_ffi::plonk_bn254::PlonkBn254Prover;
use sphinx_recursion_program::hints::Hintable;
pub use sphinx_recursion_program::machine::ReduceProgramType;
use sphinx_recursion_program::machine::{
    SphinxCompressVerifier, SphinxDeferredVerifier, SphinxRecursiveVerifier, SphinxRootVerifier,
};
pub use sphinx_recursion_program::machine::{
    SphinxDeferredMemoryLayout, SphinxRecursionMemoryLayout, SphinxReduceMemoryLayout,
    SphinxRootMemoryLayout,
};
use tracing::instrument;
pub use types::{
    SphinxCoreProof, SphinxCoreProofData, SphinxProvingKey, SphinxRecursionProverError,
    SphinxReduceProof, SphinxVerifyingKey,
};
use utils::words_to_bytes;

pub use sphinx_core::SPHINX_CIRCUIT_VERSION;

/// The configuration for the core prover.
pub type CoreSC = BabyBearPoseidon2;

/// The configuration for the inner prover.
pub type InnerSC = BabyBearPoseidon2;

/// The configuration for the outer prover.
pub type OuterSC = BabyBearPoseidon2Outer;

const REDUCE_DEGREE: usize = 3;
const COMPRESS_DEGREE: usize = 9;
const WRAP_DEGREE: usize = 17;

pub type ReduceAir<F> = RecursionAir<F, REDUCE_DEGREE>;
pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE>;

/// A end-to-end prover implementation for the SP1 RISC-V zkVM.
pub struct SphinxProver<C: SphinxProverComponents = DefaultProverComponents> {
    /// The program that can recursively verify a set of proofs into a single proof.
    pub recursion_program: RecursionProgram<BabyBear>,

    /// The proving key for the recursion step.
    pub rec_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the recursion step.
    pub rec_vk: StarkVerifyingKey<InnerSC>,

    /// The program that recursively verifies deferred proofs and accumulates the digests.
    pub deferred_program: RecursionProgram<BabyBear>,

    /// The proving key for the reduce step.
    pub deferred_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the reduce step.
    pub deferred_vk: StarkVerifyingKey<InnerSC>,

    /// The program that reduces a set of recursive proofs into a single proof.
    pub compress_program: RecursionProgram<BabyBear>,

    /// The proving key for the reduce step.
    pub compress_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the reduce step.
    pub compress_vk: StarkVerifyingKey<InnerSC>,

    /// The shrink program that compresses a proof into a succinct proof.
    pub shrink_program: RecursionProgram<BabyBear>,

    /// The proving key for the compress step.
    pub shrink_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the compress step.
    pub shrink_vk: StarkVerifyingKey<InnerSC>,

    /// The wrap program that wraps a proof into a SNARK-friendly field.
    pub wrap_program: RecursionProgram<BabyBear>,

    /// The proving key for the wrap step.
    pub wrap_pk: StarkProvingKey<OuterSC>,

    /// The verification key for the wrapping step.
    pub wrap_vk: StarkVerifyingKey<OuterSC>,

    /// The machine used for proving the core step.
    pub core_prover: C::CoreProver,

    /// The machine used for proving the recursive and reduction steps.
    pub compress_prover: C::CompressProver,

    /// The machine used for proving the shrink step.
    pub shrink_prover: C::ShrinkProver,

    /// The machine used for proving the wrapping step.
    pub wrap_prover: C::WrapProver,
}

impl<C: SphinxProverComponents> SphinxProver<C> {
    /// Initializes a new [SP1Prover].
    #[instrument(name = "initialize prover", level = "debug", skip_all)]
    pub fn new() -> Self {
        let core_machine = RiscvAir::machine(CoreSC::default());
        let core_prover = C::CoreProver::new(core_machine);

        // Get the recursive verifier and setup the proving and verifying keys.
        let recursion_program =
            SphinxRecursiveVerifier::<InnerConfig, _>::build(core_prover.machine());
        let compress_machine = ReduceAir::machine(InnerSC::default());
        let compress_prover = C::CompressProver::new(compress_machine);
        let (rec_pk, rec_vk) = compress_prover.setup(&recursion_program);

        // Get the deferred program and keys.
        let deferred_program =
            SphinxDeferredVerifier::<InnerConfig, _, _>::build(compress_prover.machine());
        let (deferred_pk, deferred_vk) = compress_prover.setup(&deferred_program);

        // Make the reduce program and keys.
        let compress_program = SphinxCompressVerifier::<InnerConfig, _, _>::build(
            compress_prover.machine(),
            &rec_vk,
            &deferred_vk,
        );
        let (compress_pk, compress_vk) = compress_prover.setup(&compress_program);

        // Get the compress program, machine, and keys.
        let shrink_program = SphinxRootVerifier::<InnerConfig, _, _>::build(
            compress_prover.machine(),
            &compress_vk,
            RecursionProgramType::Shrink,
        );
        let shrink_machine = CompressAir::wrap_machine_dyn(InnerSC::compressed());
        let shrink_prover = C::ShrinkProver::new(shrink_machine);
        let (shrink_pk, shrink_vk) = shrink_prover.setup(&shrink_program);

        // Get the wrap program, machine, and keys.
        let wrap_program = SphinxRootVerifier::<InnerConfig, _, _>::build(
            shrink_prover.machine(),
            &shrink_vk,
            RecursionProgramType::Wrap,
        );
        let wrap_machine = WrapAir::wrap_machine(OuterSC::default());
        let wrap_prover = C::WrapProver::new(wrap_machine);
        let (wrap_pk, wrap_vk) = wrap_prover.setup(&wrap_program);

        Self {
            recursion_program,
            rec_pk,
            rec_vk,
            deferred_program,
            deferred_pk,
            deferred_vk,
            compress_program,
            compress_pk,
            compress_vk,
            shrink_program,
            shrink_pk,
            shrink_vk,
            wrap_program,
            wrap_pk,
            wrap_vk,
            core_prover,
            compress_prover,
            shrink_prover,
            wrap_prover,
        }
    }

    /// Creates a proving key and a verifying key for a given RISC-V ELF.
    #[instrument(name = "setup", level = "debug", skip_all)]
    pub fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        let program = Program::from(elf);
        let (pk, vk) = self.core_prover.setup(&program);
        let vk = SphinxVerifyingKey { vk };
        let pk = SphinxProvingKey {
            pk,
            elf: elf.to_vec(),
            vk: vk.clone(),
        };
        (pk, vk)
    }

    /// Generate a proof of an SP1 program with the specified inputs.
    #[instrument(name = "execute", level = "info", skip_all)]
    pub fn execute(
        elf: &[u8],
        stdin: &SphinxStdin,
        context: SphinxContext<'_>,
    ) -> Result<(SphinxPublicValues, ExecutionReport), ExecutionError> {
        let program = Program::from(elf);
        let opts = SphinxCoreOpts::default();
        let mut runtime = Runtime::with_context(program, opts, context);
        runtime.write_vecs(&stdin.buffer);
        for (proof, vkey) in stdin.proofs.iter() {
            runtime.write_proof(proof.clone(), vkey.clone());
        }
        runtime.run_untraced()?;
        Ok((
            SphinxPublicValues::from(&runtime.state.public_values_stream),
            runtime.report,
        ))
    }

    /// Generate shard proofs which split up and prove the valid execution of a RISC-V program with
    /// the core prover. Uses the provided context.
    #[instrument(name = "prove_core", level = "info", skip_all)]
    pub fn prove_core<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: &SphinxStdin,
        opts: SphinxProverOpts,
        mut context: SphinxContext<'a>,
    ) -> Result<SphinxCoreProof, SphinxCoreProverError> {
        context
            .subproof_verifier
            .get_or_insert_with(|| Arc::new(self));
        let config = CoreSC::default();
        let program = Program::from(&pk.elf);
        let (proof, public_values_stream) = sphinx_core::utils::prove_with_context::<
            _,
            C::CoreProver,
        >(
            &program, stdin, config, opts.core_opts, context
        )?;
        let public_values = SphinxPublicValues::from(&public_values_stream);
        Ok(SphinxCoreProof {
            proof: SphinxCoreProofData(proof.shard_proofs),
            stdin: stdin.clone(),
            public_values,
        })
    }

    pub fn get_recursion_core_inputs<'a>(
        &'a self,
        vk: &'a StarkVerifyingKey<CoreSC>,
        leaf_challenger: &'a Challenger<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
        batch_size: usize,
        is_complete: bool,
    ) -> Vec<SphinxRecursionMemoryLayout<'a, CoreSC, RiscvAir<BabyBear>>> {
        let mut core_inputs = Vec::new();
        let mut reconstruct_challenger = self.core_prover.config().challenger();
        vk.observe_into(&mut reconstruct_challenger);

        // Prepare the inputs for the recursion programs.
        for batch in shard_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            let public_values: &PublicValues<Word<BabyBear>, BabyBear> =
                proofs.last().unwrap().public_values.as_slice().borrow();
            println!("core execution shard: {}", public_values.execution_shard);

            core_inputs.push(SphinxRecursionMemoryLayout {
                vk,
                machine: self.core_prover.machine(),
                shard_proofs: proofs.clone(),
                leaf_challenger,
                initial_reconstruct_challenger: reconstruct_challenger.clone(),
                is_complete,
            });

            for proof in batch.iter() {
                reconstruct_challenger.observe(proof.commitment.main_commit);
                reconstruct_challenger
                    .observe_slice(&proof.public_values[0..self.core_prover.num_pv_elts()]);
            }
        }

        // Check that the leaf challenger is the same as the reconstruct challenger.
        assert_eq!(
            reconstruct_challenger.sponge_state,
            leaf_challenger.sponge_state
        );
        assert_eq!(
            reconstruct_challenger.input_buffer,
            leaf_challenger.input_buffer
        );
        assert_eq!(
            reconstruct_challenger.output_buffer,
            leaf_challenger.output_buffer
        );
        core_inputs
    }

    pub fn get_recursion_deferred_inputs<'a>(
        &'a self,
        vk: &'a StarkVerifyingKey<CoreSC>,
        leaf_challenger: &'a Challenger<InnerSC>,
        last_proof_pv: &PublicValues<Word<BabyBear>, BabyBear>,
        deferred_proofs: &[ShardProof<InnerSC>],
        batch_size: usize,
    ) -> Vec<SphinxDeferredMemoryLayout<'a, InnerSC, RecursionAir<BabyBear, 3>>> {
        // Prepare the inputs for the deferred proofs recursive verification.
        let mut deferred_digest = [Val::<InnerSC>::zero(); DIGEST_SIZE];
        let mut deferred_inputs = Vec::new();

        for batch in deferred_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            deferred_inputs.push(SphinxDeferredMemoryLayout {
                compress_vk: &self.compress_vk,
                machine: self.compress_prover.machine(),
                proofs,
                start_reconstruct_deferred_digest: deferred_digest.to_vec(),
                is_complete: false,
                sphinx_vk: vk,
                sphinx_machine: self.core_prover.machine(),
                end_pc: Val::<InnerSC>::zero(),
                end_shard: last_proof_pv.shard + BabyBear::one(),
                end_execution_shard: last_proof_pv.execution_shard,
                init_addr_bits: last_proof_pv.last_init_addr_bits,
                finalize_addr_bits: last_proof_pv.last_finalize_addr_bits,
                leaf_challenger: leaf_challenger.clone(),
                committed_value_digest: last_proof_pv.committed_value_digest.to_vec(),
                deferred_proofs_digest: last_proof_pv.deferred_proofs_digest.to_vec(),
            });

            deferred_digest = Self::hash_deferred_proofs(deferred_digest, batch);
        }
        deferred_inputs
    }

    /// Generate the inputs for the first layer of recursive proofs.
    #[allow(clippy::type_complexity)]
    pub fn get_first_layer_inputs<'a>(
        &'a self,
        vk: &'a SphinxVerifyingKey,
        leaf_challenger: &'a Challenger<InnerSC>,
        shard_proofs: &[ShardProof<InnerSC>],
        deferred_proofs: &[ShardProof<InnerSC>],
        batch_size: usize,
    ) -> (
        Vec<SphinxRecursionMemoryLayout<'a, InnerSC, RiscvAir<BabyBear>>>,
        Vec<SphinxDeferredMemoryLayout<'a, InnerSC, RecursionAir<BabyBear, 3>>>,
    ) {
        let is_complete = shard_proofs.len() == 1 && deferred_proofs.is_empty();
        let core_inputs = self.get_recursion_core_inputs(
            &vk.vk,
            leaf_challenger,
            shard_proofs,
            batch_size,
            is_complete,
        );
        let last_proof_pv = shard_proofs
            .last()
            .unwrap()
            .public_values
            .as_slice()
            .borrow();
        let deferred_inputs = self.get_recursion_deferred_inputs(
            &vk.vk,
            leaf_challenger,
            last_proof_pv,
            deferred_proofs,
            batch_size,
        );
        (core_inputs, deferred_inputs)
    }

    /// Reduce shards proofs to a single shard proof using the recursion prover.
    #[instrument(name = "compress", level = "info", skip_all)]
    pub fn compress(
        &self,
        vk: &SphinxVerifyingKey,
        proof: SphinxCoreProof,
        deferred_proofs: Vec<ShardProof<InnerSC>>,
        opts: SphinxProverOpts,
    ) -> Result<SphinxReduceProof<InnerSC>, SphinxRecursionProverError> {
        // Set the batch size for the reduction tree.
        let batch_size = 2;

        let shard_proofs = &proof.proof.0;

        // Get the leaf challenger.
        let mut leaf_challenger = self.core_prover.config().challenger();
        vk.vk.observe_into(&mut leaf_challenger);
        for proof in shard_proofs.iter() {
            leaf_challenger.observe(proof.commitment.main_commit);
            leaf_challenger.observe_slice(&proof.public_values[0..self.core_prover.num_pv_elts()]);
        }

        // Run the recursion and reduce programs.
        let (core_inputs, deferred_inputs) = self.get_first_layer_inputs(
            vk,
            &leaf_challenger,
            shard_proofs,
            &deferred_proofs,
            batch_size,
        );

        let mut reduce_proofs = Vec::new();
        // We want the ability to set SHARD_BATCH_SIZE to 0 to run everything in one chunk
        let shard_batch_size = if opts.recursion_opts.shard_batch_size > 0 {
            opts.recursion_opts.shard_batch_size
        } else {
            usize::MAX
        };
        for inputs in core_inputs.chunks(shard_batch_size) {
            let proofs = inputs
                .into_par_iter()
                .map(|input| {
                    self.compress_machine_proof(input, &self.recursion_program, &self.rec_pk, opts)
                        .map(|p| (p, ReduceProgramType::Core))
                })
                .collect::<Result<Vec<_>, _>>()?;
            reduce_proofs.extend(proofs);
        }

        // Run the deferred proofs programs.
        for inputs in deferred_inputs.chunks(shard_batch_size) {
            let proofs = inputs
                .into_par_iter()
                .map(|input| {
                    self.compress_machine_proof(
                        input,
                        &self.deferred_program,
                        &self.deferred_pk,
                        opts,
                    )
                    .map(|p| (p, ReduceProgramType::Deferred))
                })
                .collect::<Result<Vec<_>, _>>()?;
            reduce_proofs.extend(proofs);
        }

        // Iterate over the recursive proof batches until there is one proof remaining.
        let mut is_complete;
        loop {
            tracing::debug!("Recursive proof layer size: {}", reduce_proofs.len());
            is_complete = reduce_proofs.len() <= batch_size;

            let compress_inputs = reduce_proofs.chunks(batch_size).collect::<Vec<_>>();
            let batched_compress_inputs =
                compress_inputs.chunks(shard_batch_size).collect::<Vec<_>>();
            reduce_proofs = batched_compress_inputs
                .into_par_iter()
                .flat_map(|batches| {
                    batches
                        .par_iter()
                        .map(|batch| {
                            let (shard_proofs, kinds) =
                                batch.iter().cloned().unzip::<_, _, Vec<_>, Vec<_>>();

                            let input = SphinxReduceMemoryLayout {
                                compress_vk: &self.compress_vk,
                                recursive_machine: self.compress_prover.machine(),
                                shard_proofs,
                                kinds,
                                is_complete,
                            };

                            self.compress_machine_proof(
                                input,
                                &self.compress_program,
                                &self.compress_pk,
                                opts,
                            )
                            .map(|p| (p, ReduceProgramType::Reduce))
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Result<Vec<_>, _>>()?;

            if reduce_proofs.len() == 1 {
                break;
            }
        }
        debug_assert_eq!(reduce_proofs.len(), 1);
        let reduce_proof = reduce_proofs.pop().unwrap();

        Ok(SphinxReduceProof {
            proof: reduce_proof.0,
        })
    }

    pub fn compress_machine_proof(
        &self,
        input: impl Hintable<InnerConfig>,
        program: &RecursionProgram<BabyBear>,
        pk: &StarkProvingKey<InnerSC>,
        opts: SphinxProverOpts,
    ) -> Result<ShardProof<InnerSC>, SphinxRecursionProverError> {
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program,
            self.compress_prover.config().perm.clone(),
        );

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();

        runtime
            .run()
            .map_err(|e| SphinxRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();

        let mut recursive_challenger = self.compress_prover.config().challenger();
        let proof = self
            .compress_prover
            .prove(
                pk,
                vec![runtime.record],
                &mut recursive_challenger,
                opts.recursion_opts,
            )
            .unwrap()
            .shard_proofs
            .pop()
            .unwrap();

        Ok(proof)
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "shrink", level = "info", skip_all)]
    pub fn shrink(
        &self,
        reduced_proof: SphinxReduceProof<InnerSC>,
        opts: SphinxProverOpts,
    ) -> Result<SphinxReduceProof<InnerSC>, SphinxRecursionProverError> {
        // Make the compress proof.
        let input = SphinxRootMemoryLayout {
            machine: self.compress_prover.machine(),
            proof: reduced_proof.proof,
            is_reduce: true,
        };

        // Run the compress program.
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.shrink_program,
            self.shrink_prover.config().perm.clone(),
        );

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();

        runtime
            .run()
            .map_err(|e| SphinxRecursionProverError::RuntimeError(e.to_string()))?;

        runtime.print_stats();
        tracing::debug!("Compress program executed successfully");

        // Prove the compress program.
        let mut compress_challenger = self.shrink_prover.config().challenger();
        let mut compress_proof = self
            .shrink_prover
            .prove(
                &self.shrink_pk,
                vec![runtime.record],
                &mut compress_challenger,
                opts.recursion_opts,
            )
            .unwrap();

        Ok(SphinxReduceProof {
            proof: compress_proof.shard_proofs.pop().unwrap(),
        })
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        compressed_proof: SphinxReduceProof<InnerSC>,
        opts: SphinxProverOpts,
    ) -> Result<SphinxReduceProof<OuterSC>, SphinxRecursionProverError> {
        let input = SphinxRootMemoryLayout {
            machine: self.shrink_prover.machine(),
            proof: compressed_proof.proof,
            is_reduce: false,
        };

        // Run the compress program.
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.wrap_program,
            self.shrink_prover.config().perm.clone(),
        );

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();

        runtime
            .run()
            .map_err(|e| SphinxRecursionProverError::RuntimeError(e.to_string()))?;

        runtime.print_stats();
        tracing::debug!("Wrap program executed successfully");

        // Prove the wrap program.
        let mut wrap_challenger = self.wrap_prover.config().challenger();
        let time = std::time::Instant::now();
        let mut wrap_proof = self
            .wrap_prover
            .prove(
                &self.wrap_pk,
                vec![runtime.record],
                &mut wrap_challenger,
                opts.recursion_opts,
            )
            .unwrap();
        let elapsed = time.elapsed();
        tracing::debug!("Wrap proving time: {:?}", elapsed);
        let mut wrap_challenger = self.wrap_prover.config().challenger();
        let result =
            self.wrap_prover
                .machine()
                .verify(&self.wrap_vk, &wrap_proof, &mut wrap_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(MachineVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }
        tracing::info!("Wrapping successful");

        Ok(SphinxReduceProof {
            proof: wrap_proof.shard_proofs.pop().unwrap(),
        })
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a PLONK proof.
    #[instrument(name = "wrap_plonk_bn254", level = "info", skip_all)]
    pub fn wrap_plonk_bn254(
        &self,
        proof: SphinxReduceProof<OuterSC>,
        build_dir: &Path,
    ) -> PlonkBn254Proof {
        let vkey_digest = proof.sphinx_vkey_digest_bn254();
        let commited_values_digest = proof.sphinx_commited_values_digest_bn254();

        let mut witness = Witness::default();
        proof.proof.write(&mut witness);
        witness.write_commited_values_digest(commited_values_digest);
        witness.write_vkey_hash(vkey_digest);

        let prover = PlonkBn254Prover::new();
        let proof = prover.prove(witness, build_dir);

        // Verify the proof.
        prover.verify(
            &proof,
            &vkey_digest.as_canonical_biguint(),
            &commited_values_digest.as_canonical_biguint(),
            build_dir,
        );

        proof
    }

    /// Accumulate deferred proofs into a single digest.
    pub fn hash_deferred_proofs(
        prev_digest: [Val<CoreSC>; DIGEST_SIZE],
        deferred_proofs: &[ShardProof<InnerSC>],
    ) -> [Val<CoreSC>; 8] {
        let mut digest = prev_digest;
        for proof in deferred_proofs.iter() {
            let pv: &RecursionPublicValues<Val<CoreSC>> = proof.public_values.as_slice().borrow();
            let committed_values_digest = words_to_bytes(&pv.committed_value_digest);
            digest = hash_deferred_proof(
                &digest,
                &pv.sphinx_vk_digest,
                &committed_values_digest.try_into().unwrap(),
            );
        }
        digest
    }
}

#[cfg(test)]
pub mod tests {

    use std::fs::File;
    use std::io::{Read, Write};

    use super::*;

    use anyhow::Result;
    use build::try_build_plonk_bn254_artifacts_dev;
    use p3_field::PrimeField32;
    use sphinx_core::io::SphinxStdin;

    #[cfg(test)]
    use serial_test::serial;
    #[cfg(test)]
    use sphinx_core::utils::setup_logger;
    use types::HashableKey as _;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Test {
        Core,
        Compress,
        Shrink,
        Wrap,
        Plonk,
    }

    pub fn test_e2e_prover<C: SphinxProverComponents>(
        elf: &[u8],
        opts: SphinxProverOpts,
        test_kind: Test,
    ) -> Result<()> {
        tracing::info!("initializing prover");
        let prover: SphinxProver<C> = SphinxProver::<C>::new();
        let context = SphinxContext::default();

        tracing::info!("setup elf");
        let (pk, vk) = prover.setup(elf);

        tracing::info!("prove core");
        let stdin = SphinxStdin::new();
        let core_proof = prover.prove_core(&pk, &stdin, opts, context)?;
        let public_values = core_proof.public_values.clone();

        tracing::info!("verify core");
        prover.verify(&core_proof.proof, &vk)?;

        if test_kind == Test::Core {
            return Ok(());
        }

        tracing::info!("compress");
        let compressed_proof = prover.compress(&vk, core_proof, vec![], opts)?;

        tracing::info!("verify compressed");
        prover.verify_compressed(&compressed_proof, &vk)?;

        if test_kind == Test::Compress {
            return Ok(());
        }

        tracing::info!("shrink");
        let shrink_proof = prover.shrink(compressed_proof, opts)?;

        tracing::info!("verify shrink");
        prover.verify_shrink(&shrink_proof, &vk)?;

        if test_kind == Test::Shrink {
            return Ok(());
        }

        tracing::info!("wrap bn254");
        let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof, opts)?;
        let bytes = bincode::serialize(&wrapped_bn254_proof).unwrap();

        // Save the proof.
        let mut file = File::create("proof-with-pis.bin").unwrap();
        file.write_all(bytes.as_slice()).unwrap();

        // Load the proof.
        let mut file = File::open("proof-with-pis.bin").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();

        let wrapped_bn254_proof = bincode::deserialize(&bytes).unwrap();

        tracing::info!("verify wrap bn254");
        prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk).unwrap();

        if test_kind == Test::Wrap {
            return Ok(());
        }

        tracing::info!("checking vkey hash babybear");
        let vk_digest_babybear = wrapped_bn254_proof.sphinx_vkey_digest_babybear();
        assert_eq!(vk_digest_babybear, vk.hash_babybear());

        tracing::info!("checking vkey hash bn254");
        let vk_digest_bn254 = wrapped_bn254_proof.sphinx_vkey_digest_bn254();
        assert_eq!(vk_digest_bn254, vk.hash_bn254());

        tracing::info!("generate plonk bn254 proof");
        let artifacts_dir =
            try_build_plonk_bn254_artifacts_dev(&prover.wrap_vk, &wrapped_bn254_proof.proof);

        let plonk_bn254_proof = prover.wrap_plonk_bn254(wrapped_bn254_proof, &artifacts_dir);
        println!("{:?}", plonk_bn254_proof);

        prover.verify_plonk_bn254(&plonk_bn254_proof, &vk, &public_values, &artifacts_dir)?;

        Ok(())
    }

    pub fn test_e2e_with_deferred_proofs_prover<C: SphinxProverComponents>() -> Result<()> {
        // Test program which proves the Keccak-256 hash of various inputs.
        let keccak_elf = include_bytes!("../../tests/keccak256/elf/riscv32im-succinct-zkvm-elf");

        // Test program which verifies proofs of a vkey and a list of committed inputs.
        let verify_elf = include_bytes!("../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");

        tracing::info!("initializing prover");
        let prover: SphinxProver = SphinxProver::new();
        let opts = SphinxProverOpts::default();

        tracing::info!("setup keccak elf");
        let (keccak_pk, keccak_vk) = prover.setup(keccak_elf);

        tracing::info!("setup verify elf");
        let (verify_pk, verify_vk) = prover.setup(verify_elf);

        tracing::info!("prove subproof 1");
        let mut stdin = SphinxStdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        let deferred_proof_1 = prover.prove_core(&keccak_pk, &stdin, opts, Default::default())?;
        let pv_1 = deferred_proof_1.public_values.as_slice().to_vec().clone();

        // Generate a second proof of keccak of various inputs.
        tracing::info!("prove subproof 2");
        let mut stdin = SphinxStdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        let deferred_proof_2 = prover.prove_core(&keccak_pk, &stdin, opts, Default::default())?;
        let pv_2 = deferred_proof_2.public_values.as_slice().to_vec().clone();

        // Generate recursive proof of first subproof.
        tracing::info!("compress subproof 1");
        let deferred_reduce_1 = prover.compress(&keccak_vk, deferred_proof_1, vec![], opts)?;

        // Generate recursive proof of second subproof.
        tracing::info!("compress subproof 2");
        let deferred_reduce_2 = prover.compress(&keccak_vk, deferred_proof_2, vec![], opts)?;

        // Run verify program with keccak vkey, subproofs, and their committed values.
        let mut stdin = SphinxStdin::new();
        let vkey_digest = keccak_vk.hash_babybear();
        let vkey_digest: [u32; 8] = vkey_digest
            .iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        stdin.write(&vkey_digest);
        stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        stdin.write_proof(deferred_reduce_1.proof.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.proof.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.proof.clone(), keccak_vk.vk.clone());

        tracing::info!("proving verify program (core)");
        let verify_proof = prover.prove_core(&verify_pk, &stdin, opts, Default::default())?;

        // Generate recursive proof of verify program
        tracing::info!("compress verify program");
        let verify_reduce = prover.compress(
            &verify_vk,
            verify_proof,
            vec![
                deferred_reduce_1.proof,
                deferred_reduce_2.proof.clone(),
                deferred_reduce_2.proof,
            ],
            opts,
        )?;
        let reduce_pv: &RecursionPublicValues<_> =
            verify_reduce.proof.public_values.as_slice().borrow();
        println!("deferred_hash: {:?}", reduce_pv.deferred_proofs_digest);
        println!("complete: {:?}", reduce_pv.is_complete);

        tracing::info!("verify verify program");
        prover.verify_compressed(&verify_reduce, &verify_vk)?;

        Ok(())
    }

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline.
    ///
    /// Add `FRI_QUERIES`=1 to your environment for faster execution. Should only take a few minutes
    /// on a Mac M2. Note: This test always re-builds the plonk bn254 artifacts, so setting SP1_DEV is
    /// not needed.
    #[test]
    #[serial]
    fn test_e2e() -> Result<()> {
        let elf = include_bytes!("../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
        setup_logger();
        let opts = SphinxProverOpts::default();
        test_e2e_prover::<DefaultProverComponents>(elf, opts, Test::Plonk)
    }

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline in addition to verifying deferred proofs.
    #[test]
    #[serial]
    fn test_e2e_with_deferred_proofs() -> Result<()> {
        setup_logger();
        test_e2e_with_deferred_proofs_prover::<DefaultProverComponents>()
    }
}
