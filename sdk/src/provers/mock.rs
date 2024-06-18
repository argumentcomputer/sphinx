#![allow(unused_variables)]
use crate::{
    Prover, SphinxProof, SphinxProofKind, SphinxProofWithPublicValues, SphinxProvingKey,
    SphinxVerificationError, SphinxVerifyingKey,
};
use anyhow::Result;
use p3_field::PrimeField;
use sphinx_core::{runtime::SphinxContext, utils::SphinxProverOpts};
use sphinx_prover::{
    types::HashableKey, verify::verify_plonk_bn254_public_inputs, PlonkBn254Proof, SphinxProver,
    SphinxStdin,
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

impl Prover for MockProver {
    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver {
        unimplemented!("MockProver does not support SP1Prover")
    }

    fn prove<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
        opts: SphinxProverOpts,
        context: SphinxContext<'a>,
        kind: SphinxProofKind,
    ) -> Result<SphinxProofWithPublicValues> {
        match kind {
            SphinxProofKind::Core => {
                let (public_values, _) = SphinxProver::execute(&pk.elf, &stdin, context)?;
                Ok(SphinxProofWithPublicValues {
                    proof: SphinxProof::Core(vec![]),
                    stdin,
                    public_values,
                    sphinx_version: self.version().to_string(),
                })
            }
            SphinxProofKind::Compressed => unimplemented!(),
            SphinxProofKind::Plonk => {
                let (public_values, _) = SphinxProver::execute(&pk.elf, &stdin, context)?;
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
