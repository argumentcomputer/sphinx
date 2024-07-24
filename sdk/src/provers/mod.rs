mod local;
mod mock;

use crate::{SphinxCompressedProof, SphinxPlonkBn254Proof, SphinxProof};
use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
use sphinx_core::stark::MachineVerificationError;
use sphinx_core::SP1_CIRCUIT_VERSION;
use sphinx_prover::CoreSC;
use sphinx_prover::InnerSC;
use sphinx_prover::SphinxCoreProofData;
use sphinx_prover::SphinxProver;
use sphinx_prover::SphinxReduceProof;
use sphinx_prover::{SphinxProvingKey, SphinxStdin, SphinxVerifyingKey};
use strum_macros::EnumString;
use thiserror::Error;

/// The type of prover.
#[derive(Debug, PartialEq, Eq, EnumString)]
pub enum ProverType {
    Local,
    Mock,
    Network,
}

#[derive(Error, Debug)]
pub enum SphinxVerificationError {
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
}

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> ProverType;

    fn sphinx_prover(&self) -> &SphinxProver;

    fn version(&self) -> &str {
        SP1_CIRCUIT_VERSION
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxProof>;

    /// Generate a compressed proof of the execution of a RISCV ELF with the given inputs.
    fn prove_compressed(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxCompressedProof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(
        &self,
        proof: &SphinxProof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        if proof.sphinx_version != self.version() {
            return Err(SphinxVerificationError::VersionMismatch(
                proof.sphinx_version.clone(),
            ));
        }
        self.sphinx_prover()
            .verify(&SphinxCoreProofData(proof.proof.clone()), vkey)
            .map_err(SphinxVerificationError::Core)
    }

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(
        &self,
        proof: &SphinxCompressedProof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        if proof.sphinx_version != self.version() {
            return Err(SphinxVerificationError::VersionMismatch(
                proof.sphinx_version.clone(),
            ));
        }
        self.sphinx_prover()
            .verify_compressed(
                &SphinxReduceProof {
                    proof: proof.proof.clone(),
                },
                vkey,
            )
            .map_err(SphinxVerificationError::Recursion)
    }

    /// Verify that a SP1 PLONK proof is valid. Verify that the public inputs of the PlonkBn254 proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify_plonk(
        &self,
        proof: &SphinxPlonkBn254Proof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        if proof.sphinx_version != self.version() {
            return Err(SphinxVerificationError::VersionMismatch(
                proof.sphinx_version.clone(),
            ));
        }
        let sphinx_prover = self.sphinx_prover();

        let plonk_bn254_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
            sphinx_prover::build::plonk_bn254_artifacts_dev_dir()
        } else {
            sphinx_prover::build::try_install_plonk_bn254_artifacts(false)
        };
        sphinx_prover
            .verify_plonk_bn254(
                &proof.proof,
                vkey,
                &proof.public_values,
                &plonk_bn254_aritfacts,
            )
            .map_err(SphinxVerificationError::Plonk)?;

        Ok(())
    }
}
