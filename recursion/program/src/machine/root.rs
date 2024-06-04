use std::borrow::Borrow;

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use sphinx_core::air::MachineAir;
use sphinx_core::stark::StarkMachine;
use sphinx_core::stark::{Com, ShardProof, StarkGenericConfig, StarkVerifyingKey};
use sphinx_core::utils::BabyBearPoseidon2;
use sphinx_recursion_compiler::config::InnerConfig;
use sphinx_recursion_compiler::ir::{Builder, Config, Felt, Var};
use sphinx_recursion_compiler::prelude::DslVariable;
use sphinx_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sphinx_recursion_core::runtime::{RecursionProgram, DIGEST_SIZE};

use sphinx_recursion_compiler::prelude::*;

use crate::challenger::{CanObserveVariable, DuplexChallengerVariable};
use crate::fri::TwoAdicFriPcsVariable;
use crate::hints::Hintable;
use crate::machine::utils::proof_data_from_vk;
use crate::stark::{RecursiveVerifierConstraintFolder, ShardProofHint, StarkVerifier};
use crate::types::ShardProofVariable;
use crate::utils::{const_fri_config, hash_vkey};

use super::utils::{commit_public_values, verify_public_values_hash};

/// The program that gets a final verifier at the root of the tree.
#[derive(Debug, Clone, Copy)]
pub struct SphinxRootVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

pub struct SphinxRootMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub machine: &'a StarkMachine<SC, A>,
    pub proof: ShardProof<SC>,
    pub is_reduce: bool,
}

#[derive(DslVariable, Clone)]
pub struct SphinxRootMemoryLayoutVariable<C: Config> {
    pub proof: ShardProofVariable<C>,
    pub is_reduce: Var<C::N>,
}

impl<A> SphinxRootVerifier<InnerConfig, BabyBearPoseidon2, A>
where
    A: MachineAir<BabyBear> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, InnerConfig>>,
{
    /// Create a new instance of the program for the [BabyBearPoseidon2] config.
    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, A>,
        vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        is_compress: bool,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();
        let proof: ShardProofVariable<_> = builder.uninit();
        ShardProofHint::<BabyBearPoseidon2, A>::witness(&proof, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };

        SphinxRootVerifier::verify(&mut builder, &pcs, machine, vk, &proof, is_compress);

        builder.compile_program()
    }
}

impl<C: Config, SC, A> SphinxRootVerifier<C, SC, A>
where
    C::F: PrimeField32 + TwoAdicField,
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
    A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
{
    /// Verify a proof with given vk and aggregate their public values.
    ///
    /// is_reduce : if the proof is a reduce proof, we will assert that the given vk indentifies
    /// with the reduce vk digest of public inputs.
    pub fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        vk: &StarkVerifyingKey<SC>,
        proof: &ShardProofVariable<C>,
        is_compress: bool,
    ) {
        // Get the verifying key info from the vk.
        let vk = proof_data_from_vk(builder, vk, machine);

        // Verify the proof.

        let mut challenger = DuplexChallengerVariable::new(builder);
        // Observe the vk and start pc.
        challenger.observe(builder, vk.commitment.clone());
        challenger.observe(builder, vk.pc_start);
        // Observe the main commitment and public values.
        challenger.observe(builder, proof.commitment.main_commit.clone());
        for j in 0..machine.num_pv_elts() {
            let element = builder.get(&proof.public_values, j);
            challenger.observe(builder, element);
        }
        // verify proof.
        StarkVerifier::<C, SC>::verify_shard(builder, &vk, pcs, machine, &mut challenger, proof);

        // Get the public inputs from the proof.
        let public_values_elements = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|i| builder.get(&proof.public_values, i))
            .collect::<Vec<Felt<_>>>();
        let public_values: &RecursionPublicValues<Felt<C::F>> =
            public_values_elements.as_slice().borrow();

        // Check that the public values digest is correct.
        verify_public_values_hash(builder, public_values);

        // Assert that the proof is complete.
        //
        // *Remark*: here we are assuming on that the program we are verifying indludes the check
        // of completeness conditions are satisfied if the flag is set to one, so we are only
        // checking the `is_complete` flag in this program.
        builder.assert_felt_eq(public_values.is_complete, C::F::one());

        // If the proof is a compress proof, assert that the vk is the same as the compress vk from
        // the public values.
        if is_compress {
            let vk_digest = hash_vkey(builder, &vk);
            for (i, reduce_digest_elem) in public_values.compress_vk_digest.iter().enumerate() {
                let vk_digest_elem = builder.get(&vk_digest, i);
                builder.assert_felt_eq(vk_digest_elem, *reduce_digest_elem);
            }
        }

        commit_public_values(builder, public_values);

        builder.halt();
    }
}
