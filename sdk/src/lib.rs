pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::all)]
    pub mod network;
}
pub mod auth;
pub mod client;
pub mod prove;
pub mod utils;

use anyhow::{Ok, Result};
use prove::{
    LocalProver, NetworkProver, Prover, SP1CompressedProof, SP1DefaultProof, SP1Groth16Proof,
    SP1PlonkProof,
};
use std::env;
pub use wp1_prover::{
    CoreSC, SP1CoreProof, SP1Prover, SP1ProvingKey, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};

/// A client that can prove RISCV ELFs and verify those proofs.
pub struct ProverClient {
    pub prover: Box<dyn Prover>,
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ProverClient {
    /// Creates a new ProverClient with the prover set to either local or remote based on the
    /// SP1_PROVER environment variable.
    pub fn new() -> Self {
        dotenv::dotenv().ok();
        match env::var("SP1_PROVER")
            .unwrap_or("local".to_string())
            .to_lowercase()
            .as_str()
        {
            "local" => Self {
                prover: Box::new(LocalProver::new()),
            },
            "remote" => Self {
                prover: Box::new(NetworkProver::new()),
            },
            _ => panic!("Invalid SP1_PROVER value"),
        }
    }

    /// Executes the elf with the given inputs and returns the output.
    pub fn execute(elf: &[u8], stdin: &SP1Stdin) -> Result<SP1PublicValues> {
        Ok(SP1Prover::execute(elf, stdin))
    }

    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    /// Proves the execution of the given elf with the given inputs.
    pub fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        self.prover.prove(pk, stdin)
    }

    /// Generates a compressed proof for the given elf and stdin.
    pub fn prove_compressed(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Result<SP1CompressedProof> {
        self.prover.prove_compressed(pk, stdin)
    }

    /// Generates a groth16 proof, verifiable onchain, of the given elf and stdin.
    pub fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        self.prover.prove_groth16(pk, stdin)
    }

    /// Generates a PLONK proof, verifiable onchain, of the given elf and stdin.
    pub fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        self.prover.prove_plonk(pk, stdin)
    }

    /// Verifies the given proof is valid and matches the given vkey.
    pub fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify(proof, vkey)
    }

    /// Verifies the given compressed proof is valid and matches the given vkey.
    pub fn verify_compressed(
        &self,
        proof: &SP1CompressedProof,
        vkey: &SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify_compressed(proof, vkey)
    }

    /// Verifies the given groth16 proof is valid and matches the given vkey.
    pub fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_plonk(proof, vkey)
    }

    /// Verifies the given groth16 proof is valid and matches the given vkey.
    pub fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_groth16(proof, vkey)
    }
}
