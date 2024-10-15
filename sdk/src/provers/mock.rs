#![allow(unused_variables)]
use hashbrown::HashMap;

use crate::{
    Prover, SphinxProof, SphinxProofKind, SphinxProofWithPublicValues, SphinxProvingKey,
    SphinxVerificationError, SphinxVerifyingKey,
};
use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField};
use p3_fri::{FriProof, TwoAdicFriPcsProof};
use sphinx_core::{
    runtime::SphinxContext,
    stark::{ShardCommitment, ShardOpenedValues, ShardProof},
    utils::SphinxProverOpts,
};
use sphinx_prover::{
    components::DefaultProverComponents, types::HashableKey as _,
    verify::verify_plonk_bn254_public_inputs, PlonkBn254Proof, SphinxProver, SphinxStdin,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate mock proofs.
pub struct MockProver {
    pub(crate) prover: SphinxProver,
}

impl MockProver {
    /// Creates a new [MockProver].
    pub fn new() -> Self {
        let prover = SphinxProver::new();
        Self { prover }
    }
}

impl Prover<DefaultProverComponents> for MockProver {
    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver {
        &self.prover
    }

    fn prove<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
        _opts: SphinxProverOpts,
        context: SphinxContext<'a>,
        kind: SphinxProofKind,
    ) -> Result<SphinxProofWithPublicValues> {
        match kind {
            SphinxProofKind::Core => {
                let (public_values, _) =
                    SphinxProver::<DefaultProverComponents>::execute(&pk.elf, &stdin, context)?;
                Ok(SphinxProofWithPublicValues {
                    proof: SphinxProof::Core(vec![]),
                    stdin,
                    public_values,
                    sphinx_version: self.version().to_string(),
                })
            }
            SphinxProofKind::Compressed => {
                let (public_values, _) =
                    SphinxProver::<DefaultProverComponents>::execute(&pk.elf, &stdin, context)?;
                Ok(SphinxProofWithPublicValues {
                    proof: SphinxProof::Compressed(ShardProof {
                        commitment: ShardCommitment {
                            main_commit: [BabyBear::zero(); 8].into(),
                            permutation_commit: [BabyBear::zero(); 8].into(),
                            quotient_commit: [BabyBear::zero(); 8].into(),
                        },
                        opened_values: ShardOpenedValues { chips: vec![] },
                        opening_proof: TwoAdicFriPcsProof {
                            fri_proof: FriProof {
                                commit_phase_commits: vec![],
                                query_proofs: vec![],
                                final_poly: Default::default(),
                                pow_witness: BabyBear::zero(),
                            },
                            query_openings: vec![],
                        },
                        chip_ordering: HashMap::new(),
                        public_values: vec![],
                    }),
                    stdin,
                    public_values,
                    sphinx_version: self.version().to_string(),
                })
            }
            SphinxProofKind::Plonk => {
                let (public_values, _) =
                    SphinxProver::<DefaultProverComponents>::execute(&pk.elf, &stdin, context)?;
                Ok(SphinxProofWithPublicValues {
                    proof: SphinxProof::Plonk(PlonkBn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash().to_string(),
                        ],
                        encoded_proof: "".to_string(),
                        raw_proof: "".to_string(),
                        plonk_vkey_hash: [0; 32],
                    }),
                    stdin,
                    public_values,
                    sphinx_version: self.version().to_string(),
                })
            }
        }
    }

    fn verify(
        &self,
        bundle: &SphinxProofWithPublicValues,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        match &bundle.proof {
            SphinxProof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(SphinxVerificationError::Plonk)
            }
            _ => Ok(()),
        }
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
