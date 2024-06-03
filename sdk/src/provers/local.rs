use anyhow::Result;
use sphinx_prover::{SphinxProver, SphinxStdin};

use crate::{
    Prover, SphinxCompressedProof, SphinxGroth16Proof, SphinxPlonkProof, SphinxProof, SphinxProofWithPublicValues,
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

    fn prove_compressed(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxCompressedProof> {
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

    fn prove_groth16(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxGroth16Proof> {
        let proof = self.prover.prove_core(pk, &stdin)?;
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs)?;
        let compress_proof = self.prover.shrink(reduce_proof)?;
        let outer_proof = self.prover.wrap_bn254(compress_proof)?;

        let groth16_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
            sphinx_prover::build::try_build_groth16_artifacts_dev(
                &self.prover.wrap_vk,
                &outer_proof.proof,
            )
        } else {
            sphinx_prover::build::try_install_groth16_artifacts()
        };
        let proof = self.prover.wrap_groth16(outer_proof, &groth16_aritfacts);
        Ok(SphinxProofWithPublicValues {
            proof,
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, _pk: &SphinxProvingKey, _stdin: SphinxStdin) -> Result<SphinxPlonkProof> {
        // let proof = self.prover.prove_core(pk, &stdin);
        // let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        // let public_values = proof.public_values.clone();
        // let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        // let compress_proof = self.prover.shrink(&pk.vk, reduce_proof);
        // let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        // let proof = self.prover.wrap_plonk(outer_proof, artifacts_dir);
        // Ok(SP1ProofWithPublicValues {
        //     proof,
        //     stdin,
        //     public_values,
        // })
        todo!()
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
