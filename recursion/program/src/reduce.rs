use std::time::Instant;

use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, TwoAdicMultiplicativeCoset};
use p3_field::{extension::BinomialExtensionField, AbstractField, Field, TwoAdicField};
use p3_fri::FriConfig;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use wp1_core::stark::{RiscvAir, ShardProof, StarkGenericConfig, VerifyingKey};
use wp1_recursion_compiler::{
    asm::{AsmBuilder, AsmConfig},
    ir::{Array, Builder, Felt, MemVariable, Var},
};
use wp1_recursion_core::{
    runtime::{RecursionProgram, DIGEST_SIZE},
    stark::{
        config::{inner_fri_config, wp1_fri_config, BabyBearPoseidon2Inner},
        RecursionAir,
    },
};
use wp1_sdk::utils::BabyBearPoseidon2;

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    fri::{types::FriConfigVariable, TwoAdicFriPcsVariable, TwoAdicMultiplicativeCosetVariable},
    hints::Hintable,
    stark::StarkVerifier,
    types::{ShardProofVariable, VerifyingKeyVariable},
};

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type RecursionConfig = AsmConfig<Val, Challenge>;
type RecursionBuilder = Builder<RecursionConfig>;

pub fn const_fri_config(
    builder: &mut RecursionBuilder,
    config: &FriConfig<ChallengeMmcs>,
) -> FriConfigVariable<RecursionConfig> {
    let two_addicity = Val::TWO_ADICITY;
    let mut generators = builder.dyn_array(two_addicity);
    let mut subgroups = builder.dyn_array(two_addicity);
    for i in 0..two_addicity {
        let constant_generator = Val::two_adic_generator(i);
        builder.set(&mut generators, i, constant_generator);

        let constant_domain = TwoAdicMultiplicativeCoset {
            log_n: i,
            shift: Val::one(),
        };
        let domain_value: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(constant_domain);
        builder.set(&mut subgroups, i, domain_value);
    }
    FriConfigVariable {
        log_blowup: config.log_blowup,
        num_queries: config.num_queries,
        proof_of_work_bits: config.proof_of_work_bits,
        subgroups,
        generators,
    }
}

fn clone<T: MemVariable<C>>(builder: &mut RecursionBuilder, var: &T) -> T {
    let mut arr = builder.dyn_array(1);
    builder.set(&mut arr, 0, var.clone());
    builder.get(&arr, 0)
}

fn felt_to_var(builder: &mut RecursionBuilder, felt: Felt<BabyBear>) -> Var<BabyBear> {
    let bits = builder.num2bits_f(felt);
    builder.bits2num_v(&bits)
}

pub fn build_reduce_program(setup: bool) -> RecursionProgram<Val> {
    let wp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
    let recursion_machine = RecursionAir::machine(BabyBearPoseidon2Inner::default());

    let time = Instant::now();
    let mut builder = AsmBuilder::<F, EF>::default();
    let wp1_config = const_fri_config(&mut builder, &wp1_fri_config());
    // TODO: this config may change
    let recursion_config = const_fri_config(&mut builder, &inner_fri_config());
    let wp1_pcs = TwoAdicFriPcsVariable { config: wp1_config };
    let recursion_pcs = TwoAdicFriPcsVariable {
        config: recursion_config,
    };

    // 1) Allocate inputs to the stack.
    let is_recursive_flags: Array<_, Var<_>> = builder.uninit();
    let sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
    let wp1_challenger: DuplexChallengerVariable<_> = builder.uninit();
    let mut reconstruct_challenger: DuplexChallengerVariable<_> = builder.uninit();
    let prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
    let prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
    let recursion_prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
    let recursion_prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
    let wp1_vk: VerifyingKeyVariable<_> = builder.uninit();
    let recursion_vk: VerifyingKeyVariable<_> = builder.uninit();
    let proofs: Array<_, ShardProofVariable<_>> = builder.uninit();

    // 2) Witness the inputs.
    if setup {
        Vec::<usize>::witness(&is_recursive_flags, &mut builder);
        Vec::<Vec<usize>>::witness(&sorted_indices, &mut builder);
        DuplexChallenger::witness(&wp1_challenger, &mut builder);
        DuplexChallenger::witness(&reconstruct_challenger, &mut builder);
        Vec::<usize>::witness(&prep_sorted_indices, &mut builder);
        Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(&prep_domains, &mut builder);
        Vec::<usize>::witness(&recursion_prep_sorted_indices, &mut builder);
        Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(&recursion_prep_domains, &mut builder);
        VerifyingKey::<SC>::witness(&wp1_vk, &mut builder);
        VerifyingKey::<SC>::witness(&recursion_vk, &mut builder);
        let num_proofs = is_recursive_flags.len();
        let mut proofs_target = builder.dyn_array(num_proofs);
        builder.range(0, num_proofs).for_each(|i, builder| {
            let proof = ShardProof::<SC>::read(builder);
            builder.set(&mut proofs_target, i, proof);
        });
        builder.assign(&proofs, proofs_target);

        // Compile the program up to this point.
        return builder.compile_program();
    }

    builder.print_debug(99999);
    let num_proofs = is_recursive_flags.len();
    let _pre_reconstruct_challenger = clone(&mut builder, &reconstruct_challenger);
    let zero: Var<_> = builder.constant(F::zero());
    let one: Var<_> = builder.constant(F::one());
    let _one_felt: Felt<_> = builder.constant(F::one());

    // Setup recursion challenger
    let mut recursion_challenger = DuplexChallengerVariable::new(&mut builder);
    for j in 0..DIGEST_SIZE {
        let element = builder.get(&recursion_vk.commitment, j);
        recursion_challenger.observe(&mut builder, element);
    }

    builder.range(0, num_proofs).for_each(|i, builder| {
        let proof = builder.get(&proofs, i);
        let sorted_indices = builder.get(&sorted_indices, i);
        let is_recursive = builder.get(&is_recursive_flags, i);
        builder.if_eq(is_recursive, zero).then_or_else(
            // Non-recursive proof
            |builder| {
                let shard_f = builder.get(&proof.public_values, 32);
                let shard = felt_to_var(builder, shard_f);
                // First shard logic
                builder.if_eq(shard, one).then(|builder| {
                    // Initialize the current challenger
                    let empty_challenger = DuplexChallengerVariable::new(builder);
                    builder.assign(&reconstruct_challenger, empty_challenger);
                    reconstruct_challenger.observe(builder, wp1_vk.commitment.clone());
                });

                // TODO: more shard transition constraints here

                // Observe current proof commit and public values into reconstruct challenger
                for j in 0..DIGEST_SIZE {
                    let element = builder.get(&proof.commitment.main_commit, j);
                    reconstruct_challenger.observe(builder, element);
                }
                // TODO: fix public values observe
                // let public_values = proof.public_values.to_vec(builder);
                // reconstruct_challenger.observe_slice(builder, &public_values);

                // Verify proof with copy of witnessed challenger
                let mut current_challenger = wp1_challenger.as_clone(builder);
                StarkVerifier::<C, BabyBearPoseidon2>::verify_shard(
                    builder,
                    &wp1_vk.clone(),
                    &wp1_pcs,
                    &wp1_machine,
                    &mut current_challenger,
                    &proof,
                    &sorted_indices,
                    &prep_sorted_indices,
                    &prep_domains,
                );
            },
            // Recursive proof
            |builder| {
                // TODO: Verify proof public values

                // Build recursion challenger
                let mut current_challenger = recursion_challenger.as_clone(builder);
                for j in 0..DIGEST_SIZE {
                    let element = builder.get(&proof.commitment.main_commit, j);
                    current_challenger.observe(builder, element);
                }
                builder
                    .range(0, proof.public_values.len())
                    .for_each(|j, builder| {
                        let element = builder.get(&proof.public_values, j);
                        current_challenger.observe(builder, element);
                    });
                // Verify the proof
                StarkVerifier::<C, BabyBearPoseidon2Inner>::verify_shard(
                    builder,
                    &recursion_vk.clone(),
                    &recursion_pcs,
                    &recursion_machine,
                    &mut current_challenger,
                    &proof,
                    &sorted_indices,
                    &recursion_prep_sorted_indices,
                    &recursion_prep_domains,
                );
            },
        );
    });

    // Public values:
    // (
    //     committed_values_digest,
    //     start_pc,
    //     next_pc,
    //     exit_code,
    //     reconstruct_challenger,
    //     pre_reconstruct_challenger,
    //     verify_start_challenger,
    //     recursion_vk,
    // )
    // Note we still need to check that verify_start_challenger matches final reconstruct_challenger
    // after observing pv_digest at the end.

    let program = builder.compile_program();
    let elapsed = time.elapsed();
    println!("Building took: {:?}", elapsed);
    program
}
