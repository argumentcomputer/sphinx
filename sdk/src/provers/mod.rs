mod local;
mod mock;

use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
use sphinx_core::runtime::SphinxContext;
use sphinx_core::stark::MachineVerificationError;
use sphinx_core::utils::SphinxProverOpts;
use sphinx_core::SPHINX_CIRCUIT_VERSION;
use sphinx_prover::components::SphinxProverComponents;
use sphinx_prover::CoreSC;
use sphinx_prover::InnerSC;
use sphinx_prover::SphinxCoreProofData;
use sphinx_prover::SphinxProver;
use sphinx_prover::SphinxReduceProof;
use sphinx_prover::{SphinxProvingKey, SphinxStdin, SphinxVerifyingKey};
use strum_macros::EnumString;
use thiserror::Error;

use crate::SphinxProof;
use crate::SphinxProofKind;
use crate::SphinxProofWithPublicValues;

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
pub trait Prover<C: SphinxProverComponents>: Send + Sync {
    fn id(&self) -> ProverType;

    fn sphinx_prover(&self) -> &SphinxProver<C>;

    fn version(&self) -> &str {
        SPHINX_CIRCUIT_VERSION
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs, according to the given proof mode.
    fn prove<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
        opts: SphinxProverOpts,
        context: SphinxContext<'a>,
        kind: SphinxProofKind,
    ) -> Result<SphinxProofWithPublicValues>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    /// For Plonk proofs, verifies that the public inputs of the PlonkBn254 proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify(
        &self,
        bundle: &SphinxProofWithPublicValues,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        if bundle.sphinx_version != self.version() {
            return Err(SphinxVerificationError::VersionMismatch(
                bundle.sphinx_version.clone(),
            ));
        }
        match bundle.proof.clone() {
            SphinxProof::Core(proof) => self
                .sphinx_prover()
                .verify(&SphinxCoreProofData(proof), vkey)
                .map_err(SphinxVerificationError::Core),
            SphinxProof::Compressed(proof) => self
                .sphinx_prover()
                .verify_compressed(&SphinxReduceProof { proof }, vkey)
                .map_err(SphinxVerificationError::Recursion),
            SphinxProof::Plonk(proof) => self
                .sphinx_prover()
                .verify_plonk_bn254(
                    &proof,
                    vkey,
                    &bundle.public_values,
                    &if sphinx_prover::build::sphinx_dev_mode() {
                        sphinx_prover::build::plonk_bn254_artifacts_dev_dir()
                    } else {
                        sphinx_prover::build::try_install_plonk_bn254_artifacts(false)
                    },
                )
                .map_err(SphinxVerificationError::Plonk),
        }
    }
}
