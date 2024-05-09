pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::all)]
    pub mod network;
}
pub mod auth;
pub mod client;
pub mod utils;

use anyhow::{Context, Ok, Result};
use proto::network::{ProofStatus, TransactionStatus};
use std::env;
use std::time::Duration;
use tokio::runtime;
use tokio::time::sleep;
use wp1_core::runtime::Program;
use wp1_core::utils::run_and_prove;
pub use wp1_prover::{CoreSC, SP1CoreProof, SP1Prover, SP1PublicValues, SP1Stdin};

use crate::client::NetworkClient;

/// A client that can prove RISCV ELFs and verify those proofs.
pub struct ProverClient {
    /// An optional Succinct prover network client used for remote operations.
    pub client: Option<NetworkClient>,
}

impl ProverClient {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        dotenv::dotenv().ok();
        let remote_proving = env::var("REMOTE_PROVE")
            .unwrap_or_else(|_| String::from("false"))
            .parse::<bool>()
            .unwrap_or(false);

        if remote_proving {
            let private_key = env::var("PRIVATE_KEY")
                .unwrap_or_else(|_| panic!("PRIVATE_KEY must be set for remote proving"));
            Self {
                client: Some(NetworkClient::new(&private_key)),
            }
        } else {
            Self { client: None }
        }
    }

    pub fn with_network(mut self, private_key: &str) -> Self {
        self.client = Some(NetworkClient::new(private_key));
        self
    }

    /// Executes the elf with the given inputs and returns the output.
    pub fn execute(elf: &[u8], stdin: &SP1Stdin) -> Result<SP1PublicValues> {
        Ok(SP1Prover::execute(elf, stdin))
    }

    /// Generate a proof for the execution of the ELF with the given public inputs. If a
    /// NetworkClient is configured, it uses remote proving, otherwise, it proves locally.
    pub fn prove(&self, elf: &[u8], stdin: &SP1Stdin) -> Result<SP1CoreProof> {
        if self.client.is_some() {
            println!("Proving remotely");
            self.prove_remote(elf, stdin)
        } else {
            println!("Proving locally");
            self.prove_local(elf, stdin)
        }
    }

    // Generate a proof remotely using the Succinct Network in an async context.
    // Note: If the simulation of the runtime is expensive for user programs, we can add an optional
    // flag to skip it. This shouldn't be the case for the vast majority of user programs.
    pub async fn prove_remote_async(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<SP1CoreProof, anyhow::Error> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Network client not initialized"))?;

        // Execute the runtime before creating the proof request.
        let _ = ProverClient::execute(elf, stdin);
        println!("Simulation complete");

        let proof_id = client.create_proof(elf, stdin).await?;
        println!("Proof request ID: {:?}", proof_id);

        let mut is_claimed = false;
        loop {
            let (status, maybe_proof) = client.get_proof_status(&proof_id).await?;

            match status.status() {
                ProofStatus::ProofFulfilled => {
                    return Ok(maybe_proof.unwrap());
                }
                ProofStatus::ProofClaimed => {
                    if !is_claimed {
                        println!("Proof request claimed");
                        is_claimed = true;
                    }
                }
                ProofStatus::ProofFailed => {
                    return Err(anyhow::anyhow!("Proof generation failed"));
                }
                _ => {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    // Generate a proof remotely using the Succinct Network in a sync context.
    pub fn prove_remote(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<SP1CoreProof, anyhow::Error> {
        let rt = runtime::Runtime::new()?;
        rt.block_on(async { self.prove_remote_async(elf, stdin).await })
    }

    // Generate a proof locally for the execution of the ELF with the given public inputs.
    pub fn prove_local(&self, elf: &[u8], stdin: &SP1Stdin) -> Result<SP1CoreProof> {
        let config = CoreSC::default();
        let program = Program::from(elf);
        let (proof, public_values_stream) = run_and_prove(&program, &stdin.buffer, config);
        let public_values = SP1PublicValues::from(&public_values_stream);
        Ok(SP1CoreProof {
            shard_proofs: proof.shard_proofs,
            stdin: stdin.clone(),
            public_values,
        })
    }

    /// Remotely relay a proof to a set of chains with their callback contracts.
    pub fn remote_relay(
        &self,
        proof_id: &str,
        chain_ids: &[u32],
        callbacks: &[[u8; 20]],
        callback_data: &[Vec<u8>],
    ) -> Result<Vec<String>> {
        let rt = runtime::Runtime::new()?;
        rt.block_on(async {
            let client = self
                .client
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Network client not initialized"))?;

            let verifier = NetworkClient::get_wp1_verifier_address();

            let mut tx_details = Vec::new();
            for ((i, callback), callback_data) in
                callbacks.iter().enumerate().zip(callback_data.iter())
            {
                if let Some(&chain_id) = chain_ids.get(i) {
                    let tx_id = client
                        .relay_proof(proof_id, chain_id, verifier, *callback, callback_data)
                        .await
                        .with_context(|| format!("Failed to relay proof to chain {}", chain_id))?;
                    tx_details.push((tx_id.clone(), chain_id));
                }
            }

            let mut tx_ids = Vec::new();
            for (tx_id, chain_id) in tx_details.iter() {
                loop {
                    let (status_res, maybe_tx_hash, maybe_simulation_url) =
                        client.get_relay_status(tx_id).await?;

                    match status_res.status() {
                        TransactionStatus::TransactionFinalized => {
                            println!(
                                "Relaying to chain {} succeeded with tx hash: {:?}",
                                chain_id,
                                maybe_tx_hash.as_deref().unwrap_or("None")
                            );
                            tx_ids.push(tx_id.clone());
                            break;
                        }
                        TransactionStatus::TransactionFailed
                        | TransactionStatus::TransactionTimedout => {
                            return Err(anyhow::anyhow!(
                                "Relaying to chain {} failed with tx hash: {:?}, simulation url: {:?}",
                                chain_id,
                                maybe_tx_hash.as_deref().unwrap_or("None"),
                                maybe_simulation_url.as_deref().unwrap_or("None")
                            ));
                        }
                        _ => {
                            sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }

            Ok(tx_ids)
        })
    }

    pub fn verify(&self, _elf: &[u8], _proof: &SP1CoreProof) -> Result<()> {
        // TODO:
        Ok(())
    }
}
