mod local;
mod mock;

use crate::{SphinxCompressedProof, SphinxPlonkBn254Proof, SphinxProof};
use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
use sphinx_core::stark::MachineVerificationError;
use sphinx_prover::types::SphinxCoreProofData;
use sphinx_prover::types::SphinxReduceProof;
use sphinx_prover::CoreSC;
use sphinx_prover::SphinxProver;
use sphinx_prover::{types::SphinxProvingKey, types::SphinxVerifyingKey, SphinxStdin};
use strum_macros::EnumString;

/// The type of prover.
#[derive(Debug, PartialEq, Eq, EnumString)]
pub enum ProverType {
    Local,
    Mock,
    Network,
}

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> ProverType;

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

    /// Verify that a SP1 PLONK proof is valid. Verify that the public inputs of the PlonkBn254 proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify_plonk(&self, proof: &SphinxPlonkBn254Proof, vkey: &SphinxVerifyingKey) -> Result<()> {
        let sphinx_prover = self.sphinx_prover();

        let plonk_bn254_aritfacts = if sphinx_prover::build::sphinx_dev_mode() {
            sphinx_prover::build::plonk_bn254_artifacts_dev_dir()
        } else {
            sphinx_prover::build::try_install_plonk_bn254_artifacts(true)
        };
        sphinx_prover.verify_plonk_bn254(
            &proof.proof,
            vkey,
            &proof.public_values,
            &plonk_bn254_aritfacts,
        )?;

        Ok(())
    }
}
