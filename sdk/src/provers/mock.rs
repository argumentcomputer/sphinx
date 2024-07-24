#![allow(unused_variables)]
use crate::{
    Prover, SphinxCompressedProof, SphinxPlonkBn254Proof, SphinxProof, SphinxProofWithPublicValues,
    SphinxProvingKey, SphinxVerificationError, SphinxVerifyingKey,
};
use anyhow::Result;
use p3_field::PrimeField;
use sphinx_prover::{
    types::HashableKey, verify::verify_plonk_bn254_public_inputs, PlonkBn254Proof, SphinxProver,
    SphinxStdin,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate mock proofs.
pub struct MockProver {
    pub(crate) prover: SphinxProver,
}

impl MockProver {
    /// Creates a new [MockProver].
    pub fn new() -> Self {
        let prover = SphinxProver::new();
        Self { prover }
    }
}

impl Prover for MockProver {
    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver {
        unimplemented!("MockProver does not support SP1Prover")
    }

    fn prove(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxProof> {
        let (public_values, _) = SphinxProver::execute(&pk.elf, &stdin)?;
        Ok(SphinxProofWithPublicValues {
            proof: vec![],
            stdin,
            public_values,
            sphinx_version: self.version().to_string(),
        })
    }

    fn prove_compressed(
        &self,
        _pk: &SphinxProvingKey,
        _stdin: SphinxStdin,
    ) -> Result<SphinxCompressedProof> {
        unimplemented!()
    }

    fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof> {
        let (public_values, _) = SphinxProver::execute(&pk.elf, &stdin)?;
        Ok(SphinxPlonkBn254Proof {
            proof: PlonkBn254Proof {
                public_inputs: [
                    pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                    public_values.hash().to_string(),
                ],
                encoded_proof: "".to_string(),
                raw_proof: "".to_string(),
                plonk_vkey_hash: [0; 32],
            },
            stdin,
            public_values,
            sphinx_version: self.version().to_string(),
        })
    }

    fn verify(
        &self,
        _proof: &SphinxProof,
        _vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        Ok(())
    }

    fn verify_compressed(
        &self,
        _proof: &SphinxCompressedProof,
        _vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        Ok(())
    }

    fn verify_plonk(
        &self,
        proof: &SphinxPlonkBn254Proof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        verify_plonk_bn254_public_inputs(vkey, &proof.public_values, &proof.proof.public_inputs)
            .map_err(SphinxVerificationError::Plonk)?;
        Ok(())
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
