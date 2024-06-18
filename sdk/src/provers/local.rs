use anyhow::Result;
use sphinx_core::{runtime::SphinxContext, utils::SphinxProverOpts};
use sphinx_prover::{SphinxProver, SphinxStdin};

use crate::{
    Prover, SphinxProof, SphinxProofKind, SphinxProofWithPublicValues, SphinxProvingKey,
    SphinxVerifyingKey,
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

    fn prove<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
        opts: SphinxProverOpts,
        context: SphinxContext<'a>,
        kind: SphinxProofKind,
    ) -> Result<SphinxProofWithPublicValues> {
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

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
