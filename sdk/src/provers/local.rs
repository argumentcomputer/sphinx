use std::{env, path::Path};

use anyhow::Result;
use sphinx_prover::{types::SphinxReduceProof, SphinxProver, SphinxStdin};
use sphinx_recursion_core::stark::config::BabyBearPoseidon2Outer;

use crate::{
    Prover, SphinxCompressedProof, SphinxPlonkBn254Proof, SphinxProof, SphinxProofWithPublicValues,
    SphinxProvingKey, SphinxVerifyingKey,
};

use super::ProverType;

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
    fn id(&self) -> ProverType {
        ProverType::Local
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

    #[cfg(not(feature = "plonk"))]
    #[allow(unused)]
    fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof> {
        panic!("plonk feature not enabled")
    }

    #[cfg(feature = "plonk")]
    #[allow(unused)]
    fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof> {
        let checkpoint = env::var("CHECKPOINT").is_ok();
        let checkpoint_path = env::var("CHECKPOINT").unwrap_or_else(|_| "checkpoint.pi".into());

        let proof = self.prover.prove_core(pk, &stdin)?;
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();

        let outer_proof = if checkpoint && Path::new(&checkpoint_path).exists() {
            tracing::info!("loading checkpointed proof from {}", &checkpoint_path);
            SphinxReduceProof::<BabyBearPoseidon2Outer>::load(&checkpoint_path)
                .expect("failed to load checkpointed proof")
        } else {
            let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs)?;
            let compress_proof = self.prover.shrink(reduce_proof)?;
            let outer_proof = self.prover.wrap_bn254(compress_proof)?;
            tracing::info!("saving checkpointed proof to {}", &checkpoint_path);
            outer_proof
                .save(&checkpoint_path)
                .expect("failed to save checkpointed proof");
            outer_proof
        };

        let plonk_bn254_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
            sphinx_prover::build::try_build_plonk_bn254_artifacts_dev(
                &self.prover.wrap_vk,
                &outer_proof.proof,
            )
        } else {
            sphinx_prover::build::try_install_plonk_bn254_artifacts(false)
        };

        let proof = self
            .prover
            .wrap_plonk_bn254(outer_proof, &plonk_bn254_aritfacts);
        Ok(SphinxProofWithPublicValues {
            proof,
            stdin,
            public_values,
        })
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
