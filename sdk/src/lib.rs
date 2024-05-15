pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::all)]
    pub mod network;
}
pub mod artifacts;
pub mod auth;
pub mod client;
pub mod local;
pub mod mock;
pub mod network;
pub mod utils;

use anyhow::{Ok, Result};
use artifacts::WrapCircuitType;
use local::LocalProver;
use mock::MockProver;
use network::NetworkProver;
use std::env;
pub use wp1_prover::{
    CoreSC, SP1CoreProofData, SP1Prover, SP1ProvingKey, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};
use wp1_prover::{
    SP1CoreProof, SP1Groth16Proof, SP1Groth16ProofData, SP1PlonkProof, SP1PlonkProofData,
    SP1ProofWithMetadata, SP1ReducedProof,
};

use serde::{Deserialize, Serialize};

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
    /// Creates a new ProverClient with the prover set to either prove locally or prove via the
    /// prover network based on the SP1_PROVER environment variable.
    pub fn new() -> Self {
        dotenv::dotenv().ok();
        match env::var("SP1_PROVER")
            .unwrap_or("local".to_string())
            .to_lowercase()
            .as_str()
        {
            "mock" => Self {
                prover: Box::new(MockProver::new()),
            },
            "local" => Self {
                prover: Box::new(LocalProver::new()),
            },
            "network" => Self {
                prover: Box::new(NetworkProver::new()),
            },
            _ => panic!("Invalid SP1_PROVER value"),
        }
    }

    pub fn new_groth16() -> Self {
        dotenv::dotenv().ok();
        match env::var("SP1_PROVER")
            .unwrap_or("local".to_string())
            .to_lowercase()
            .as_str()
        {
            "mock" => Self {
                prover: Box::new(MockProver::new()),
            },
            "local" => {
                let prover = LocalProver::new();
                prover.initialize_circuit(WrapCircuitType::Groth16);
                Self {
                    prover: Box::new(prover),
                }
            }
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
    pub fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CoreProof> {
        self.prover.prove(pk, stdin)
    }

    /// Generates a compressed proof for the given elf and stdin.
    pub fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ReducedProof> {
        self.prover.prove_reduced(pk, stdin)
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
    pub fn verify(&self, proof: &SP1CoreProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify(proof, vkey)
    }

    /// Verifies the given compressed proof is valid and matches the given vkey.
    pub fn verify_compressed(&self, proof: &SP1ReducedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_reduced(proof, vkey)
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

#[derive(Serialize, Deserialize)]
pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}
pub trait Prover: Send + Sync {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CoreProof>;

    /// Given an SP1 program and input, generate a reduced proof of its execution. Reduced proofs
    /// are constant size and can be verified inside of SP1.
    fn prove_reduced(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ReducedProof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof>;

    /// Given an SP1 program and input, generate a Groth16 proof that can be verified on-chain.
    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(&self, proof: &SP1CoreProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_reduced(&self, proof: &SP1ReducedProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 Groth16 proof is valid given its vkey and metadata.
    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()>;
}
