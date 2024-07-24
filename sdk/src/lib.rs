//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

#[rustfmt::skip]
pub mod proto {
    pub mod network;
}
pub mod artifacts;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver;

pub mod provers;
pub mod utils {
    pub use sphinx_core::utils::setup_logger;
}

use cfg_if::cfg_if;
pub use provers::SphinxVerificationError;
use std::{env, fmt::Debug, fs::File, path::Path};

use anyhow::{Ok, Result};

pub use provers::{LocalProver, MockProver, Prover};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sphinx_core::{
    runtime::ExecutionReport,
    stark::{MachineVerificationError, ShardProof},
    SPHINX_CIRCUIT_VERSION,
};
pub use sphinx_prover::{
    types::HashableKey, types::SphinxProvingKey, types::SphinxVerifyingKey, CoreSC, InnerSC,
    OuterSC, PlonkBn254Proof, SphinxProver, SphinxPublicValues, SphinxStdin,
};

/// A client for interacting with SP1.
pub struct ProverClient {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover>,
}

/// A proof generated with SP1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize + Debug + Clone"))]
#[serde(bound(deserialize = "P: DeserializeOwned + Debug + Clone"))]
pub struct SphinxProofWithPublicValues<P> {
    pub proof: P,
    pub stdin: SphinxStdin,
    pub public_values: SphinxPublicValues,
    pub sphinx_version: String,
}

/// A [SP1ProofWithPublicValues] generated with [ProverClient::prove].
pub type SphinxProof = SphinxProofWithPublicValues<Vec<ShardProof<CoreSC>>>;
pub type SphinxProofVerificationError = MachineVerificationError<CoreSC>;

/// A [SP1ProofWithPublicValues] generated with [ProverClient::prove_compressed].
pub type SphinxCompressedProof = SphinxProofWithPublicValues<ShardProof<InnerSC>>;
pub type SphinxCompressedProofVerificationError = MachineVerificationError<InnerSC>;

/// A [SP1ProofWithPublicValues] generated with [ProverClient::prove_plonk].
pub type SphinxPlonkBn254Proof = SphinxProofWithPublicValues<PlonkBn254Proof>;

impl ProverClient {
    /// Creates a new [ProverClient].
    ///
    /// Setting the `SP1_PROVER` enviroment variable can change the prover used under the hood.
    /// - `local` (default): Uses [LocalProver]. Recommended for proving end-to-end locally.
    /// - `mock`: Uses [MockProver]. Recommended for testing and development.
    /// - `network`: Uses [NetworkProver]. Recommended for outsourcing proof generation to an RPC.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sphinx_sdk::ProverClient;
    ///
    /// std::env::set_var("SP1_PROVER", "local");
    /// let client = ProverClient::new();
    /// ```
    pub fn new() -> Self {
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
            "network" => {
                cfg_if! {
                    if #[cfg(feature = "network")] {
                        Self {
                            prover: Box::new(NetworkProver::new()),
                        }
                    } else {
                        panic!("network feature is not enabled")
                    }
                }
            }
            _ => panic!(
                "invalid value for SP1_PROVER enviroment variable: expected 'local', 'mock', or 'network'"
            ),
        }
    }

    /// Creates a new [ProverClient] with the mock prover.
    ///
    /// Recommended for testing and development. You can also use [ProverClient::new] to set the
    /// prover to `mock` with the `SP1_PROVER` enviroment variable.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sphinx_sdk::ProverClient;
    ///
    /// let client = ProverClient::mock();
    /// ```
    pub fn mock() -> Self {
        Self {
            prover: Box::new(MockProver::new()),
        }
    }

    /// Creates a new [ProverClient] with the local prover.
    ///
    /// Recommended for proving end-to-end locally. You can also use [ProverClient::new] to set the
    /// prover to `local` with the `SP1_PROVER` enviroment variable.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sphinx_sdk::ProverClient;
    ///
    /// let client = ProverClient::local();
    /// ```
    pub fn local() -> Self {
        Self {
            prover: Box::new(LocalProver::new()),
        }
    }

    /// Creates a new [ProverClient] with the network prover.
    ///
    /// Recommended for outsourcing proof generation to an RPC. You can also use [ProverClient::new]
    /// to set the prover to `network` with the `SP1_PROVER` enviroment variable.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sphinx_sdk::ProverClient;
    ///
    /// let client = ProverClient::network();
    /// ```
    pub fn network() -> Self {
        cfg_if! {
            if #[cfg(feature = "network")] {
                Self {
                    prover: Box::new(NetworkProver::new()),
                }
            } else {
                panic!("network feature is not enabled")
            }
        }
    }

    /// Gets the current version of the SP1 zkVM.
    ///
    /// Note: This is not the same as the version of the SP1 SDK.
    pub fn version(&self) -> String {
        SPHINX_CIRCUIT_VERSION.to_string()
    }

    /// Executes the given program on the given input (without generating a proof).
    ///
    /// Returns the public values and execution report of the program after it has been executed.
    ///
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Execute the program on the inputs.
    /// let (public_values, report) = client.execute(elf, &stdin).unwrap();
    /// ```
    pub fn execute(
        &self,
        elf: &[u8],
        stdin: &SphinxStdin,
    ) -> Result<(SphinxPublicValues, ExecutionReport)> {
        Ok(SphinxProver::execute(elf, stdin)?)
    }

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    ///
    /// The proving key and verifying key essentially embed the program, as well as other auxiliary
    /// data (such as lookup tables) that are used to prove the program's correctness.
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    /// let client = ProverClient::new();
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    /// let (pk, vk) = client.setup(elf);
    /// ```
    pub fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.prover.setup(elf)
    }

    /// Proves the execution of the given program with the given input in the default mode.
    ///
    /// Returns a proof of the program's execution. By default the proof generated will not be
    /// compressed to constant size. To create a more succinct proof, use the [Self::prove_compressed],
    /// [Self::prove_plonk], or [Self::prove_plonk] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove(&pk, stdin).unwrap();
    /// ```
    pub fn prove(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxProof> {
        self.prover.prove(pk, stdin)
    }

    /// Proves the execution of the given program with the given input in the compressed mode.
    ///
    /// Returns a compressed proof of the program's execution. The compressed proof is a succinct
    /// proof that is of constant size and friendly for recursion and off-chain verification.
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_compressed(&pk, stdin).unwrap();
    /// ```
    pub fn prove_compressed(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxCompressedProof> {
        self.prover.prove_compressed(pk, stdin)
    }

    /// Proves the execution of the given program with the given input in the plonk bn254 mode.
    ///
    /// Returns a proof of the program's execution in the plonk bn254format. The proof is a succinct
    /// proof that is of constant size and friendly for on-chain verification.
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_plonk(&pk, stdin).unwrap();
    /// ```
    /// Generates a plonk bn254 proof, verifiable onchain, of the given elf and stdin.
    pub fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof> {
        self.prover.prove_plonk(pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    /// let client = ProverClient::new();
    /// let (pk, vk) = client.setup(elf);
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    /// let proof = client.prove(&pk, stdin).unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &SphinxProof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        self.prover.verify(proof, vkey)
    }

    /// Verifies that the given compressed proof is valid and matches the given verification key
    /// produced by [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_compressed(&pk, stdin).unwrap();
    /// client.verify_compressed(&proof, &vk).unwrap();
    /// ```
    pub fn verify_compressed(
        &self,
        proof: &SphinxCompressedProof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        self.prover.verify_compressed(proof, vkey)
    }

    /// Verifies that the given plonk bn254 proof is valid and matches the given verification key
    /// produced by [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin};
    ///
    /// // Load the program.
    /// let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SphinxStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove_plonk(&pk, stdin).unwrap();
    ///
    /// // Verify the proof.
    /// client.verify_plonk(&proof, &vk).unwrap();
    /// ```
    pub fn verify_plonk(
        &self,
        proof: &SphinxPlonkBn254Proof,
        vkey: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        self.prover.verify_plonk(proof, vkey)
    }
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Debug + Clone + Serialize + DeserializeOwned> SphinxProofWithPublicValues<P> {
    /// Saves the proof to a path.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    /// Loads a proof from a path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl SphinxPlonkBn254Proof {
    /// Returns the encoded proof bytes with a prefix of the VK hash.
    pub fn bytes(&self) -> String {
        format!(
            "0x{}{}",
            hex::encode(&self.proof.plonk_vkey_hash[..4]),
            &self.proof.encoded_proof
        )
    }
}

#[cfg(test)]
mod tests {

    use crate::{utils, ProverClient, SphinxStdin};

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).unwrap();
    }

    #[test]
    fn test_e2e_prove_plonk() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let (pk, vk) = client.setup(elf);
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        let proof = client.prove_plonk(&pk, stdin).unwrap();
        client.verify_plonk(&proof, &vk).unwrap();
    }

    #[test]
    fn test_e2e_prove_plonk_mock() {
        utils::setup_logger();
        let client = ProverClient::mock();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let (pk, vk) = client.setup(elf);
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        let proof = client.prove_plonk(&pk, stdin).unwrap();
        client.verify_plonk(&proof, &vk).unwrap();
    }
}
