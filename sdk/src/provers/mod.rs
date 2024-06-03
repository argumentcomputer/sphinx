mod local;
mod mock;
mod network;

use crate::{SphinxCompressedProof, SphinxGroth16Proof, SphinxPlonkProof, SphinxProof};
use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
pub use network::NetworkProver;
use sphinx_core::stark::MachineVerificationError;
use sphinx_prover::types::SphinxCoreProofData;
use sphinx_prover::types::SphinxProvingKey;
use sphinx_prover::types::SphinxReduceProof;
use sphinx_prover::types::SphinxVerifyingKey;
use sphinx_prover::CoreSC;
use sphinx_prover::SphinxProver;
use sphinx_prover::SphinxStdin;

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> String;

    fn sphinx_prover(&self) -> &SphinxProver;

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxProof>;

    /// Generate a compressed proof of the execution of a RISCV ELF with the given inputs.
    fn prove_compressed(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxCompressedProof>;

    /// Given an SP1 program and input, generate a Groth16 proof that can be verified on-chain.
    fn prove_groth16(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxGroth16Proof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxPlonkProof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(
        &self,
        proof: &SphinxProof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), MachineVerificationError<CoreSC>> {
        self.sphinx_prover()
            .verify(&SphinxCoreProofData(proof.proof.clone()), vkey)
    }

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(
        &self,
        proof: &SphinxCompressedProof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<()> {
        self.sphinx_prover()
            .verify_compressed(
                &SphinxReduceProof {
                    proof: proof.proof.clone(),
                },
                vkey,
            )
            .map_err(|e| e.into())
    }

    /// Verify that a SP1 Groth16 proof is valid. Verify that the public inputs of the Groth16Proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify_groth16(&self, proof: &SphinxGroth16Proof, vkey: &SphinxVerifyingKey) -> Result<()> {
        let sphinx_prover = self.sphinx_prover();

        let groth16_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
            sphinx_prover::build::groth16_artifacts_dev_dir()
        } else {
            sphinx_prover::build::groth16_artifacts_dir()
        };
        sphinx_prover.verify_groth16(
            &proof.proof,
            vkey,
            &proof.public_values,
            &groth16_aritfacts,
        )?;

        Ok(())
    }

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, _proof: &SphinxPlonkProof, _vkey: &SphinxVerifyingKey) -> Result<()> {
        Ok(())
    }
}
