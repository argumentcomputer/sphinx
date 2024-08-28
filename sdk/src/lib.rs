//! # Sphinx SDK
//!
//! A library for interacting with the Sphinx RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/Sphinx/getting-started.html) section
//! in the official Sphinx documentation for a quick start guide.

#[rustfmt::skip]
pub mod proto {
    pub mod network;
}
pub mod action;
pub mod artifacts;
#[cfg(feature = "network")]
pub mod network;
#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver;

pub mod proof;
pub mod provers;
pub mod utils {
    pub use sphinx_core::utils::setup_logger;
}

use cfg_if::cfg_if;
pub use proof::*;
pub use provers::SphinxVerificationError;
use std::env;

pub use provers::{LocalProver, MockProver, Prover};

pub use sphinx_core::runtime::{Hook, HookEnv, SphinxContext, SphinxContextBuilder};
use sphinx_core::SPHINX_CIRCUIT_VERSION;
pub use sphinx_prover::{
    types::HashableKey, CoreSC, InnerSC, OuterSC, PlonkBn254Proof, SphinxProver, SphinxProvingKey,
    SphinxPublicValues, SphinxStdin, SphinxVerifyingKey,
};

/// A client for interacting with Sphinx.
pub struct ProverClient {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover>,
}

impl ProverClient {
    /// Creates a new [ProverClient].
    ///
    /// Setting the `SPHINX_PROVER` enviroment variable can change the prover used under the hood.
    /// - `local` (default): Uses [LocalProver]. Recommended for proving end-to-end locally.
    /// - `mock`: Uses [MockProver]. Recommended for testing and development.
    /// - `network`: Uses [NetworkProver]. Recommended for outsourcing proof generation to an RPC.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use sphinx_sdk::ProverClient;
    ///
    /// std::env::set_var("SPHINX_PROVER", "local");
    /// let client = ProverClient::new();
    /// ```
    pub fn new() -> Self {
        match env::var("SPHINX_PROVER")
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
                "invalid value for SPHINX_PROVER enviroment variable: expected 'local', 'mock', or 'network'"
            ),
        }
    }

    /// Creates a new [ProverClient] with the mock prover.
    ///
    /// Recommended for testing and development. You can also use [ProverClient::new] to set the
    /// prover to `mock` with the `SPHINX_PROVER` enviroment variable.
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
    /// prover to `local` with the `SPHINX_PROVER` enviroment variable.
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
    /// to set the prover to `network` with the `SPHINX_PROVER` enviroment variable.
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

    /// Prepare to execute the given program on the given input (without generating a proof).
    /// The returned [action::Execute] may be configured via its methods before running.
    /// For example, calling [action::Execute::with_hook] registers hooks for execution.
    ///
    /// To execute, call [action::Execute::run], which returns
    /// the public values and execution report of the program after it has been executed.
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin, SphinxContext};
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
    /// let (public_values, report) = client.execute(elf, stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&self, elf: &'a [u8], stdin: SphinxStdin) -> action::Execute<'a> {
        action::Execute::new(elf, stdin)
    }

    /// Prepare to prove the execution of the given program with the given input in the default mode.
    /// The returned [action::Prove] may be configured via its methods before running.
    /// For example, calling [action::Prove::compress] sets the mode to compressed mode.
    ///
    /// To prove, call [action::Prove::run], which returns a proof of the program's execution.
    /// By default the proof generated will not be compressed to constant size.
    /// To create a more succinct proof, use the [Self::prove_compressed],
    /// [Self::prove_plonk], or [Self::prove_plonk] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use sphinx_sdk::{ProverClient, SphinxStdin, SphinxContext};
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
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a SphinxProvingKey, stdin: SphinxStdin) -> action::Prove<'a> {
        action::Prove::new(self.prover.as_ref(), pk, stdin)
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
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &SphinxProofWithPublicValues,
        vk: &SphinxVerifyingKey,
    ) -> Result<(), SphinxVerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Gets the current version of the Sphinx zkVM.
    ///
    /// Note: This is not the same as the version of the Sphinx SDK.
    pub fn version(&self) -> String {
        SPHINX_CIRCUIT_VERSION.to_string()
    }

    /// Setup a program to be proven and verified by the Sphinx RISC-V zkVM by computing the proving
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
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use std::sync::atomic::{AtomicU32, Ordering};

    use sphinx_core::runtime::{hook_ecrecover, FD_ECRECOVER_HOOK};

    use crate::{utils, ProverClient, SphinxStdin};

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
    }

    #[test]
    fn test_execute_new() {
        // Wrap the hook and check that it was called.
        let call_ct = AtomicU32::new(0);
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/ecrecover/elf/riscv32im-succinct-zkvm-elf");
        let stdin = SphinxStdin::new();
        client
            .execute(elf, stdin)
            .with_hook(FD_ECRECOVER_HOOK, |env, buf| {
                call_ct.fetch_add(1, Ordering::Relaxed);
                hook_ecrecover(env, buf)
            })
            .run()
            .unwrap();
        assert_ne!(call_ct.into_inner(), 0);
    }

    #[test]
    fn test_prove_new() {
        // Wrap the hook and check that it was called.
        let call_ct = AtomicU32::new(0);
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/ecrecover/elf/riscv32im-succinct-zkvm-elf");
        let stdin = SphinxStdin::new();
        let (pk, _) = client.setup(elf);
        client
            .prove(&pk, stdin)
            .with_hook(FD_ECRECOVER_HOOK, |env, buf| {
                call_ct.fetch_add(1, Ordering::Relaxed);
                hook_ecrecover(env, buf)
            })
            .run()
            .unwrap();
        assert_ne!(call_ct.into_inner(), 0);
    }

    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
    }

    #[should_panic]
    #[test]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = include_bytes!("../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
        let mut stdin = SphinxStdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).max_cycles(1).run().unwrap();
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
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
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
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}
