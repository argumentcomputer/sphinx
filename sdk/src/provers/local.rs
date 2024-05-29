use anyhow::Result;
use cfg_if::cfg_if;
use sphinx_prover::{SphinxProver, SphinxStdin};

use crate::{
    Prover, SphinxCompressedProof, SphinxPlonkBn254Proof, SphinxProof, SphinxProofWithPublicValues,
    SphinxProvingKey, SphinxVerifyingKey,
};

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct LocalProver {
    prover: SphinxProver,
}

impl LocalProver {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = SphinxProver::new();
        Self { prover }
    }
}

impl Prover for LocalProver {
    fn id(&self) -> String {
        "local".to_string()
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver {
        &self.prover
    }

    fn prove(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxProof> {
        let proof = self.prover.prove_core(pk, &stdin)?;
        Ok(SphinxProofWithPublicValues {
            proof: proof.proof.0,
            stdin: proof.stdin,
            public_values: proof.public_values,
        })
    }

    fn prove_compressed(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxCompressedProof> {
        let proof = self.prover.prove_core(pk, &stdin)?;
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs)?;
        Ok(SphinxCompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
        })
    }

    #[allow(unused_variables)] // only unused w/o feature
    fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof> {
        cfg_if! {
            if #[cfg(feature = "plonk")] {

                let proof = self.prover.prove_core(pk, &stdin)?;
                let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
                let public_values = proof.public_values.clone();
                let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs)?;
                let compress_proof = self.prover.shrink(reduce_proof)?;
                let outer_proof = self.prover.wrap_bn254(compress_proof)?;

                let plonk_bn254_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
                    sphinx_prover::build::try_build_plonk_bn254_artifacts_dev(
                        &self.prover.wrap_vk,
                        &outer_proof.proof,
                    )
                } else {
                    sphinx_prover::build::try_install_plonk_bn254_artifacts()
                };
                let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_aritfacts);
                Ok(SphinxProofWithPublicValues {
                    proof,
                    stdin,
                    public_values,
                })
            } else {
                panic!("plonk feature not enabled")
            }
        }
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
