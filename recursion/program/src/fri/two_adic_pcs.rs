use p3_field::TwoAdicField;
use wp1_recursion_compiler::prelude::*;
use wp1_recursion_core::runtime::DIGEST_SIZE;

use crate::challenger::DuplexChallengerVariable;
use crate::types::{Commitment, Dimensions, FriConfigVariable, FriProofVariable};

use crate::commit::PcsVariable;

use super::{
    new_coset, verify_batch, verify_challenges, verify_shape_and_sample_challenges,
    TwoAdicMultiplicativeCosetVariable,
};

use p3_field::AbstractField;
use p3_symmetric::Hash;

use p3_commit::TwoAdicMultiplicativeCoset;

#[derive(DslVariable, Clone)]
#[allow(clippy::type_complexity)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub opening_proof: Array<C, Array<C, Felt<C::F>>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Array<C, Array<C, BatchOpeningVariable<C>>>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: Commitment<C>,
    pub mats: Array<C, TwoAdicPcsMatsVariable<C>>,
}

#[allow(clippy::type_complexity)]
#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCosetVariable<C>,
    pub points: Array<C, Ext<C::F, C::EF>>,
    pub values: Array<C, Array<C, Ext<C::F, C::EF>>>,
}

#[allow(clippy::type_complexity)]
pub fn verify_two_adic_pcs<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfigVariable<C>,
    rounds: &Array<C, TwoAdicPcsRoundVariable<C>>,
    proof: &TwoAdicPcsProofVariable<C>,
    challenger: &mut DuplexChallengerVariable<C>,
) where
    C::EF: TwoAdicField,
{
    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);

    let commit_phase_commits_len = proof
        .fri_proof
        .commit_phase_commits
        .len()
        .materialize(builder);
    let log_global_max_height: Var<_> = builder.eval(commit_phase_commits_len + config.log_blowup);

    let mut reduced_openings: Array<C, Array<C, Ext<C::F, C::EF>>> =
        builder.array(proof.query_openings.len());
    builder
        .range(0, proof.query_openings.len())
        .for_each(|i, builder| {
            let query_opening = builder.get(&proof.query_openings, i);
            let index = builder.get(&fri_challenges.query_indices, i);
            let mut ro: Array<C, Ext<C::F, C::EF>> = builder.array(32);
            let zero: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::zero()));
            for j in 0..32 {
                builder.set(&mut ro, j, zero);
            }
            let mut alpha_pow: Array<C, Ext<C::F, C::EF>> = builder.array(32);
            let one: Ext<C::F, C::EF> = builder.eval(SymbolicExt::Const(C::EF::one()));
            for j in 0..32 {
                builder.set(&mut alpha_pow, j, one);
            }

            builder.range(0, rounds.len()).for_each(|j, builder| {
                let batch_opening = builder.get(&query_opening, j);
                let round = builder.get(rounds, j);
                let batch_commit = round.batch_commit;
                let mats = round.mats;

                let mut batch_heights_log2: Array<C, Var<C::N>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let height_log2: Var<_> = builder.eval(mat.domain.log_n + config.log_blowup);
                    builder.set(&mut batch_heights_log2, k, height_log2);
                });
                let mut batch_dims: Array<C, Dimensions<C>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let dim = Dimensions::<C> {
                        height: builder.eval(mat.domain.size() * C::N::two()), // TODO: fix this to use blowup
                    };
                    builder.set(&mut batch_dims, k, dim);
                });

                let log_batch_max_height = builder.get(&batch_heights_log2, 0);
                let bits_reduced: Var<_> =
                    builder.eval(log_global_max_height - log_batch_max_height);
                let index_bits = builder.num2bits_v(index);
                let index_bits_shifted_v1 = index_bits.shift(builder, bits_reduced);
                verify_batch::<C, 1>(
                    builder,
                    &batch_commit,
                    &batch_dims,
                    &index_bits_shifted_v1,
                    &batch_opening.opened_values,
                    &batch_opening.opening_proof,
                );

                builder
                    .range(0, batch_opening.opened_values.len())
                    .for_each(|k, builder| {
                        let mat_opening = builder.get(&batch_opening.opened_values, k);
                        let mat = builder.get(&mats, k);
                        let mat_points = mat.points;
                        let mat_values = mat.values;

                        let log2_domain_size = mat.domain.log_n;
                        let log_height: Var<C::N> =
                            builder.eval(log2_domain_size + config.log_blowup);

                        let bits_reduced: Var<C::N> =
                            builder.eval(log_global_max_height - log_height);
                        let index_bits_shifted_v2 = index_bits.shift(builder, bits_reduced);
                        let index_shifted_v2 = builder.bits_to_num_var(&index_bits_shifted_v2);
                        // TODO: perf
                        let rev_reduced_index =
                            builder.reverse_bits_len(index_shifted_v2, Usize::Var(log_height));
                        let rev_reduced_index = rev_reduced_index.materialize(builder);

                        let g = builder.generator();
                        let two_adic_generator = builder.two_adic_generator(Usize::Var(log_height));
                        let two_adic_generator_exp =
                        // TODO: don't duplicate this bit decomposition
                        // TODO: add break to early terminate
                            builder.exp_usize_f(two_adic_generator, Usize::Var(rev_reduced_index));
                        let x: Felt<C::F> = builder.eval(two_adic_generator_exp * g);

                        builder.range(0, mat_points.len()).for_each(|l, builder| {
                            let z: Ext<C::F, C::EF> = builder.get(&mat_points, l);
                            let ps_at_z = builder.get(&mat_values, l);
                            builder.range(0, ps_at_z.len()).for_each(|m, builder| {
                                let p_at_x: SymbolicExt<C::F, C::EF> =
                                    builder.get(&mat_opening, m).into();
                                let p_at_z: SymbolicExt<C::F, C::EF> =
                                    builder.get(&ps_at_z, m).into();
                                let quotient: SymbolicExt<C::F, C::EF> =
                                    (-p_at_z + p_at_x) / (-z + x);

                                let ro_at_log_height = builder.get(&ro, log_height);
                                let alpha_pow_at_log_height = builder.get(&alpha_pow, log_height);
                                let new_ro_at_log_height: Ext<C::F, C::EF> = builder
                                    .eval(ro_at_log_height + alpha_pow_at_log_height * quotient);

                                builder.set(&mut ro, log_height, new_ro_at_log_height);
                                builder.set(
                                    &mut alpha_pow,
                                    log_height,
                                    alpha_pow_at_log_height * alpha,
                                );
                            });
                        });
                    });
            });
            builder.set(&mut reduced_openings, i, ro);
        });

    verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        &reduced_openings,
    );
}

impl<C: Config> FromConstant<C> for TwoAdicPcsRoundVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = (
        Hash<C::F, C::F, DIGEST_SIZE>,
        Vec<(TwoAdicMultiplicativeCoset<C::F>, Vec<(C::EF, Vec<C::EF>)>)>,
    );

    fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        let (commit_val, domains_and_openings_val) = value;

        // Allocate the commitment.
        let mut commit = builder.dyn_array::<Felt<_>>(DIGEST_SIZE);
        let commit_val: [C::F; DIGEST_SIZE] = commit_val.into();
        for (i, f) in commit_val.into_iter().enumerate() {
            builder.set(&mut commit, i, f);
        }

        let mut mats =
            builder.dyn_array::<TwoAdicPcsMatsVariable<C>>(domains_and_openings_val.len());

        for (i, (domain, opening)) in domains_and_openings_val.into_iter().enumerate() {
            let domain = builder.eval_const::<TwoAdicMultiplicativeCosetVariable<_>>(domain);

            let points_val = opening.iter().map(|(p, _)| *p).collect::<Vec<_>>();
            let values_val = opening.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
            let mut points: Array<_, Ext<_, _>> = builder.dyn_array(points_val.len());
            for (j, point) in points_val.into_iter().enumerate() {
                let el: Ext<_, _> = builder.eval(point.cons());
                builder.set(&mut points, j, el);
            }
            let mut values: Array<_, Array<_, Ext<_, _>>> = builder.dyn_array(values_val.len());
            for (j, val) in values_val.into_iter().enumerate() {
                let mut tmp = builder.dyn_array(val.len());
                for (k, v) in val.into_iter().enumerate() {
                    let el: Ext<_, _> = builder.eval(v.cons());
                    builder.set(&mut tmp, k, el);
                }
                builder.set(&mut values, j, tmp);
            }

            let mat = TwoAdicPcsMatsVariable {
                domain,
                points,
                values,
            };
            builder.set(&mut mats, i, mat);
        }

        Self {
            batch_commit: commit,
            mats,
        }
    }
}

pub struct TwoAdicFriPcsVariable<C: Config> {
    pub config: FriConfigVariable<C>,
}

impl<C: Config> PcsVariable<C, DuplexChallengerVariable<C>> for TwoAdicFriPcsVariable<C>
where
    C::F: TwoAdicField,
    C::EF: TwoAdicField,
{
    type Domain = TwoAdicMultiplicativeCosetVariable<C>;

    type Commitment = Commitment<C>;

    type Proof = TwoAdicPcsProofVariable<C>;

    fn natural_domain_for_log_degree(
        &self,
        builder: &mut Builder<C>,
        log_degree: Usize<C::N>,
    ) -> Self::Domain {
        new_coset(builder, log_degree)
    }

    // Todo: change TwoAdicPcsRoundVariable to RoundVariable
    fn verify(
        &self,
        builder: &mut Builder<C>,
        rounds: &Array<C, TwoAdicPcsRoundVariable<C>>,
        proof: &Self::Proof,
        challenger: &mut DuplexChallengerVariable<C>,
    ) {
        verify_two_adic_pcs(builder, &self.config, rounds, proof, challenger)
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::cmp::Reverse;

    use crate::challenger::DuplexChallengerVariable;
    use crate::commit::PolynomialSpaceVariable;
    use crate::fri::TwoAdicMultiplicativeCosetVariable;
    use crate::fri::TwoAdicPcsRoundVariable;
    use crate::types::Commitment;
    use crate::types::FriCommitPhaseProofStepVariable;
    use crate::types::FriConfigVariable;
    use crate::types::FriProofVariable;
    use crate::types::FriQueryProofVariable;
    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
    use p3_challenger::CanObserve;
    use p3_challenger::DuplexChallenger;
    use p3_challenger::FieldChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_commit::Pcs;
    use p3_commit::TwoAdicMultiplicativeCoset;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::AbstractField;
    use p3_field::Field;
    use p3_field::PrimeField32;
    use p3_fri::FriConfig;
    use p3_fri::FriProof;
    use p3_fri::TwoAdicFriPcs;
    use p3_fri::TwoAdicFriPcsProof;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::Poseidon2;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::rngs::OsRng;
    use wp1_core::utils::poseidon2_instance::RC_16_30;
    use wp1_recursion_compiler::asm::AsmConfig;
    use wp1_recursion_compiler::ir::Array;
    use wp1_recursion_compiler::ir::Builder;
    use wp1_recursion_compiler::ir::Config;
    use wp1_recursion_compiler::ir::Ext;
    use wp1_recursion_compiler::ir::Felt;
    use wp1_recursion_compiler::ir::SymbolicExt;
    use wp1_recursion_compiler::ir::SymbolicFelt;
    use wp1_recursion_compiler::ir::Usize;
    use wp1_recursion_compiler::ir::Var;
    use wp1_recursion_core::runtime::Runtime;
    use wp1_recursion_core::runtime::DIGEST_SIZE;

    use crate::commit::PcsVariable;
    use crate::fri::TwoAdicFriPcsVariable;

    use super::BatchOpeningVariable;
    use super::TwoAdicPcsProofVariable;

    pub(crate) type Val = BabyBear;
    pub(crate) type Challenge = BinomialExtensionField<Val, 4>;
    pub(crate) type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
    pub(crate) type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
    pub(crate) type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub(crate) type ValMmcs =
        FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 8>;
    pub(crate) type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    pub(crate) type Challenger = DuplexChallenger<Val, Perm, 16>;
    pub(crate) type Dft = Radix2DitParallel;
    pub(crate) type CustomPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    pub(crate) type CustomFriProof = FriProof<Challenge, ChallengeMmcs, Val>;
    pub(crate) type RecursionConfig = AsmConfig<Val, Challenge>;
    pub(crate) type RecursionBuilder = Builder<RecursionConfig>;

    pub(crate) fn const_fri_config(
        builder: &mut RecursionBuilder,
        config: &FriConfig<ChallengeMmcs>,
    ) -> FriConfigVariable<RecursionConfig> {
        FriConfigVariable {
            log_blowup: builder.eval(Val::from_canonical_usize(config.log_blowup)),
            num_queries: builder.eval(Val::from_canonical_usize(config.num_queries)),
            proof_of_work_bits: builder.eval(Val::from_canonical_usize(config.proof_of_work_bits)),
        }
    }

    #[allow(clippy::needless_range_loop)]
    pub(crate) fn const_fri_proof<C>(
        builder: &mut Builder<C>,
        fri_proof: &CustomFriProof,
    ) -> FriProofVariable<C>
    where
        C: Config<F = Val, EF = Challenge>,
    {
        // Initialize the FRI proof variable.
        let mut fri_proof_var = FriProofVariable {
            commit_phase_commits: builder.dyn_array(fri_proof.commit_phase_commits.len()),
            query_proofs: builder.dyn_array(fri_proof.query_proofs.len()),
            final_poly: builder.eval(SymbolicExt::Const(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        };

        // Set the commit phase commits.
        for i in 0..fri_proof.commit_phase_commits.len() {
            let mut commitment: Commitment<_> = builder.dyn_array(DIGEST_SIZE);
            let h: [Val; DIGEST_SIZE] = fri_proof.commit_phase_commits[i].into();
            for j in 0..DIGEST_SIZE {
                builder.set(&mut commitment, j, h[j]);
            }
            builder.set(&mut fri_proof_var.commit_phase_commits, i, commitment);
        }

        // Set the query proofs.
        for (i, query_proof) in fri_proof.query_proofs.iter().enumerate() {
            let mut commit_phase_openings_var: Array<_, FriCommitPhaseProofStepVariable<_>> =
                builder.dyn_array(query_proof.commit_phase_openings.len());

            for (j, commit_phase_opening) in query_proof.commit_phase_openings.iter().enumerate() {
                let mut commit_phase_opening_var = FriCommitPhaseProofStepVariable {
                    sibling_value: builder
                        .eval(SymbolicExt::Const(commit_phase_opening.sibling_value)),
                    opening_proof: builder.dyn_array(commit_phase_opening.opening_proof.len()),
                };
                for (k, proof) in commit_phase_opening.opening_proof.iter().enumerate() {
                    let mut proof_var = builder.dyn_array(DIGEST_SIZE);
                    for l in 0..DIGEST_SIZE {
                        builder.set(&mut proof_var, l, proof[l]);
                    }
                    builder.set(&mut commit_phase_opening_var.opening_proof, k, proof_var);
                }
                builder.set(&mut commit_phase_openings_var, j, commit_phase_opening_var);
            }
            let query_proof = FriQueryProofVariable {
                commit_phase_openings: commit_phase_openings_var,
            };
            builder.set(&mut fri_proof_var.query_proofs, i, query_proof);
        }

        fri_proof_var
    }

    #[allow(clippy::needless_range_loop)]
    pub(crate) fn const_two_adic_pcs_proof<C>(
        builder: &mut Builder<C>,
        proof: &TwoAdicFriPcsProof<Val, Challenge, ValMmcs, ChallengeMmcs>,
    ) -> TwoAdicPcsProofVariable<C>
    where
        C: Config<F = Val, EF = Challenge>,
    {
        let fri_proof_var = const_fri_proof(builder, &proof.fri_proof);
        let mut proof_var = TwoAdicPcsProofVariable {
            fri_proof: fri_proof_var,
            query_openings: builder.dyn_array(proof.query_openings.len()),
        };

        for (i, openings) in proof.query_openings.iter().enumerate() {
            let mut openings_var: Array<_, BatchOpeningVariable<_>> =
                builder.dyn_array(openings.len());
            for (j, opening) in openings.iter().enumerate() {
                let mut opened_values_var = builder.dyn_array(opening.opened_values.len());
                for (k, opened_value) in opening.opened_values.iter().enumerate() {
                    let mut opened_value_var: Array<_, Ext<_, _>> =
                        builder.dyn_array(opened_value.len());
                    for (l, ext) in opened_value.iter().enumerate() {
                        let el: Ext<_, _> =
                            builder.eval(SymbolicExt::Base(SymbolicFelt::Const(*ext).into()));
                        builder.set(&mut opened_value_var, l, el);
                    }
                    builder.set(&mut opened_values_var, k, opened_value_var);
                }

                let mut opening_proof_var = builder.dyn_array(opening.opening_proof.len());
                for (k, sibling) in opening.opening_proof.iter().enumerate() {
                    let mut sibling_var = builder.dyn_array(DIGEST_SIZE);
                    for l in 0..DIGEST_SIZE {
                        let el: Felt<_> = builder.eval(sibling[l]);
                        builder.set(&mut sibling_var, l, el);
                    }
                    builder.set(&mut opening_proof_var, k, sibling_var);
                }
                let batch_opening_var = BatchOpeningVariable {
                    opened_values: opened_values_var,
                    opening_proof: opening_proof_var,
                };
                builder.set(&mut openings_var, j, batch_opening_var);
            }

            builder.set(&mut proof_var.query_openings, i, openings_var);
        }

        proof_var
    }

    pub(crate) fn default_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        FriConfig {
            log_blowup: 1,
            num_queries: 100,
            proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        }
    }

    #[allow(clippy::type_complexity)]
    #[test]
    fn test_two_adic_fri_pcs_single_batch() {
        let mut rng = &mut OsRng;
        let log_degrees = &[10, 16];
        let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
        let fri_config = default_fri_config();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress);
        let dft = Dft {};
        let pcs_val: CustomPcs = CustomPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <CustomPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                        &pcs_val,
                        1 << d,
                    ),
                    RowMajorMatrix::<Val>::rand(&mut rng, 1 << d, 10 + d),
                )
            })
            .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
            .collect::<Vec<_>>();
        let (commit, data) =
            <CustomPcs as Pcs<Challenge, Challenger>>::commit(&pcs_val, domains_and_polys.clone());
        let mut challenger = Challenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<Challenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (opening, proof) = pcs_val.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = Challenger::new(perm.clone());
        challenger.observe(commit);
        challenger.sample_ext_element::<Challenge>();
        let os: Vec<(
            TwoAdicMultiplicativeCoset<Val>,
            Vec<(Challenge, Vec<Challenge>)>,
        )> = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect();
        pcs_val
            .verify(vec![(commit, os.clone())], &proof, &mut challenger)
            .unwrap();

        // Test the recursive Pcs.
        let mut builder = RecursionBuilder::default();
        let config = const_fri_config(&mut builder, &default_fri_config());
        let pcs = TwoAdicFriPcsVariable { config };
        let rounds =
            builder.eval_const::<Array<_, TwoAdicPcsRoundVariable<_>>>(vec![(commit, os.clone())]);

        // Test natural domain for degree.
        for log_d_val in log_degrees.iter() {
            let log_d: Var<_> = builder.eval(Val::from_canonical_usize(*log_d_val));
            let domain = pcs.natural_domain_for_log_degree(&mut builder, Usize::Var(log_d));

            let domain_val = <CustomPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &pcs_val,
                1 << log_d_val,
            );

            let expected_domain =
                TwoAdicMultiplicativeCosetVariable::from_constant(&mut builder, domain_val);

            builder
                .assert_eq::<TwoAdicMultiplicativeCosetVariable<_>, _, _>(domain, expected_domain);
        }

        // Test proof verification.
        let proof = const_two_adic_pcs_proof(&mut builder, &proof);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let commit = <[Val; DIGEST_SIZE]>::from(commit).to_vec();
        let commit = builder.eval_const::<Array<_, _>>(commit);
        challenger.observe_commitment(&mut builder, &commit);
        challenger.sample_ext(&mut builder);
        pcs.verify(&mut builder, &rounds, &proof, &mut challenger);

        let program = builder.compile();
        let mut runtime = Runtime::<Val, Challenge, _>::new(&program, perm.clone());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }

    #[allow(clippy::type_complexity)]
    #[test]
    fn test_two_adic_fri_pcs_multi_batches() {
        let mut rng = &mut OsRng;
        let log_degrees = &[10, 16];
        let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
        let fri_config = default_fri_config();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress);
        let dft = Dft {};
        let pcs_val: CustomPcs = CustomPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let num_of_batches = 3;

        let mut batch_domains_and_polys = vec![];
        let mut batches_commits = vec![];
        let mut batches_prover_data = vec![];

        for _ in 0..num_of_batches {
            let domains_and_polys = log_degrees
                .iter()
                .map(|&d| {
                    (
                        <CustomPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                            &pcs_val,
                            1 << d,
                        ),
                        RowMajorMatrix::<Val>::rand(&mut rng, 1 << d, 10 + d),
                    )
                })
                .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
                .collect::<Vec<_>>();
            let (commit, data) = <CustomPcs as Pcs<Challenge, Challenger>>::commit(
                &pcs_val,
                domains_and_polys.clone(),
            );

            batch_domains_and_polys.push(domains_and_polys);
            batches_commits.push(commit);
            batches_prover_data.push(data);
        }

        let mut challenger = Challenger::new(perm.clone());
        for commit in batches_commits.iter() {
            challenger.observe(*commit);
        }

        let zeta = challenger.sample_ext_element::<Challenge>();
        let points = log_degrees.iter().map(|_| vec![zeta]).collect::<Vec<_>>();

        let data_and_points = batches_prover_data
            .iter()
            .map(|data| (data, points.clone()))
            .collect::<Vec<_>>();
        let (opening, proof) = pcs_val.open(data_and_points, &mut challenger);

        // Verify proof.
        let mut challenger = Challenger::new(perm.clone());
        for commit in batches_commits.iter() {
            challenger.observe(*commit);
        }
        challenger.sample_ext_element::<Challenge>();

        let rounds_val = batches_commits
            .clone()
            .into_iter()
            .zip(batch_domains_and_polys)
            .zip(opening)
            .map(|((commit, domains_and_polys), open_vals)| {
                let os = domains_and_polys
                    .iter()
                    .zip(open_vals)
                    .map(|((domain, _), mat_openings)| {
                        (*domain, vec![(zeta, mat_openings[0].clone())])
                    })
                    .collect();
                (commit, os)
            })
            .collect::<Vec<_>>();

        pcs_val
            .verify(rounds_val.clone(), &proof, &mut challenger)
            .unwrap();

        // Test the recursive Pcs.
        let mut builder = RecursionBuilder::default();
        let config = const_fri_config(&mut builder, &default_fri_config());
        let pcs = TwoAdicFriPcsVariable { config };
        let rounds = builder.eval_const::<Array<_, TwoAdicPcsRoundVariable<_>>>(rounds_val);

        // // Test proof verification.
        let proof = const_two_adic_pcs_proof(&mut builder, &proof);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        for commit in batches_commits {
            let commit: [Val; DIGEST_SIZE] = commit.into();
            let commit = builder.eval_const::<Array<_, _>>(commit.to_vec());
            challenger.observe_commitment(&mut builder, &commit);
        }
        challenger.sample_ext(&mut builder);
        pcs.verify(&mut builder, &rounds, &proof, &mut challenger);

        let program = builder.compile();
        let mut runtime = Runtime::<Val, Challenge, _>::new(&program, perm.clone());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }
}
