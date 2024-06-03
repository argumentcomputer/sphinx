mod local;
mod mock;
mod network;

use crate::{SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof};
use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
pub use network::NetworkProver;
use sphinx_core::stark::MachineVerificationError;
use sphinx_prover::types::SP1CoreProofData;
use sphinx_prover::types::SP1ProvingKey;
use sphinx_prover::types::SP1ReduceProof;
use sphinx_prover::types::SP1VerifyingKey;
use sphinx_prover::CoreSC;
use sphinx_prover::SP1Prover;
use sphinx_prover::SP1Stdin;

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> String;

    fn sphinx_prover(&self) -> &SP1Prover;

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof>;

    /// Generate a compressed proof of the execution of a RISCV ELF with the given inputs.
    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof>;

    /// Given an SP1 program and input, generate a Groth16 proof that can be verified on-chain.
    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(
        &self,
        proof: &SP1Proof,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), MachineVerificationError<CoreSC>> {
        self.sphinx_prover()
            .verify(&SP1CoreProofData(proof.proof.clone()), vkey)
    }

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.sphinx_prover()
            .verify_compressed(
                &SP1ReduceProof {
                    proof: proof.proof.clone(),
                },
                vkey,
            )
            .map_err(|e| e.into())
    }

    /// Verify that a SP1 Groth16 proof is valid. Verify that the public inputs of the Groth16Proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        let sphinx_prover = self.sphinx_prover();

        let groth16_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
            sphinx_prover::build::groth16_artifacts_dev_dir()
        } else {
            sphinx_prover::build::groth16_artifacts_dir()
        };
        sphinx_prover.verify_groth16(&proof.proof, vkey, &proof.public_values, &groth16_aritfacts)?;

        Ok(())
    }

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, _proof: &SP1PlonkProof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }
}
