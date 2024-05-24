mod local;
mod mock;
mod network;

use std::str::FromStr;

use crate::{SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof};
use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
pub use network::NetworkProver;
use num_bigint::BigUint;
use wp1_core::stark::MachineVerificationError;
use wp1_prover::CoreSC;
use wp1_prover::SP1CoreProofData;
use wp1_prover::SP1Prover;
use wp1_prover::SP1ReduceProof;
use wp1_prover::{SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> String;

    fn wp1_prover(&self) -> &SP1Prover;

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
        self.wp1_prover()
            .verify(&SP1CoreProofData(proof.proof.clone()), vkey)
    }

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.wp1_prover()
            .verify_compressed(
                &SP1ReduceProof {
                    proof: proof.proof.clone(),
                },
                vkey,
            )
            .map_err(|e| e.into())
    }

    /// Verify that a SP1 Groth16 proof is valid. Additionally, verify the public inputs of the Groth16Proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        let wp1_prover = self.wp1_prover();

        let groth16_aritfacts = if wp1_prover::build::wp1_dev_mode() {
            wp1_prover::build::groth16_artifacts_dev_dir()
        } else {
            wp1_prover::build::groth16_artifacts_dir()
        };
        wp1_prover.verify_groth16(&proof.proof, vkey, &groth16_aritfacts)?;

        // Verify that the public values of the SP1ProofWithPublicValues match the committed public
        // values of the Groth16 proof.
        let pv_biguint = proof.public_values.hash();
        let committed_values_digest = BigUint::from_str(&proof.proof.public_inputs[1])?;

        if pv_biguint != committed_values_digest {
            return Err(anyhow::Error::msg("public values hash mismatch"));
        }

        Ok(())
    }

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, _proof: &SP1PlonkProof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }
}
