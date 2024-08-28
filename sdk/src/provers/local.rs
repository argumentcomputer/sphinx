use anyhow::Result;
use sphinx_core::{runtime::SphinxContext, utils::SphinxProverOpts};
use sphinx_prover::{components::SphinxProverComponents, SphinxProver, SphinxStdin};
use sysinfo::System;

use crate::{
    Prover, SphinxProof, SphinxProofKind, SphinxProofWithPublicValues, SphinxProvingKey,
    SphinxVerifyingKey,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct LocalProver<C: SphinxProverComponents> {
    prover: SphinxProver<C>,
}

impl<C: SphinxProverComponents> LocalProver<C> {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = SphinxProver::new();
        Self { prover }
    }

    /// Creates a new [LocalProver] from an existing [SP1Prover].
    pub fn from_prover(prover: SphinxProver<C>) -> Self {
        Self { prover }
    }
}

impl<C: SphinxProverComponents> Prover<C> for LocalProver<C> {
    fn id(&self) -> ProverType {
        ProverType::Local
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver<C> {
        &self.prover
    }

    fn prove<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
        opts: SphinxProverOpts,
        context: SphinxContext<'a>,
        kind: SphinxProofKind,
    ) -> Result<SphinxProofWithPublicValues> {
        let total_ram_gb = System::new_all().total_memory() / 1_000_000_000;
        if kind == SphinxProofKind::Plonk && total_ram_gb <= 120 {
            return Err(anyhow::anyhow!(
                "not enough memory to generate plonk proof. at least 128GB is required."
            ));
        }

        let proof = self.prover.prove_core(pk, &stdin, opts, context)?;
        if kind == SphinxProofKind::Core {
            return Ok(SphinxProofWithPublicValues {
                proof: SphinxProof::Core(proof.proof.0),
                stdin: proof.stdin,
                public_values: proof.public_values,
                sphinx_version: self.version().to_string(),
            });
        }
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs, opts)?;
        if kind == SphinxProofKind::Compressed {
            return Ok(SphinxProofWithPublicValues {
                proof: SphinxProof::Compressed(reduce_proof.proof),
                stdin,
                public_values,
                sphinx_version: self.version().to_string(),
            });
        }
        let compress_proof = self.prover.shrink(reduce_proof, opts)?;
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;

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
        if kind == SphinxProofKind::Plonk {
            return Ok(SphinxProofWithPublicValues {
                proof: SphinxProof::Plonk(proof),
                stdin,
                public_values,
                sphinx_version: self.version().to_string(),
            });
        }
        unreachable!()
    }
}

impl<C: SphinxProverComponents> Default for LocalProver<C> {
    fn default() -> Self {
        Self::new()
    }
}
