use std::{env, time::Duration};

use crate::proto::network::ProofMode;
use crate::{
    network::client::{NetworkClient, DEFAULT_PROVER_NETWORK_RPC},
    proto::network::ProofStatus,
    Prover,
};
use crate::{
    SphinxCompressedProof, SphinxPlonkBn254Proof, SphinxProof, SphinxProvingKey, SphinxVerifyingKey,
};
use anyhow::Result;
use serde::de::DeserializeOwned;
use sphinx_prover::utils::block_on;
use sphinx_prover::{SphinxProver, SphinxStdin, SPHINX_CIRCUIT_VERSION};
use tokio::time::sleep;

use crate::provers::{LocalProver, ProverType};

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: LocalProver,
}

impl NetworkProver {
    /// Creates a new [NetworkProver] with the private key set in `SP1_PRIVATE_KEY`.
    pub fn new() -> Self {
        let private_key = env::var("SP1_PRIVATE_KEY")
            .unwrap_or_else(|_| panic!("SP1_PRIVATE_KEY must be set for remote proving"));
        Self::new_from_key(&private_key)
    }

    /// Creates a new [NetworkProver] with the given private key.
    pub fn new_from_key(private_key: &str) -> Self {
        let version = SPHINX_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);

        let local_prover = LocalProver::new();
        Self {
            client: NetworkClient::new(private_key),
            local_prover,
        }
    }

    /// Requests a proof from the prover network, returning the proof ID.
    pub async fn request_proof(
        &self,
        elf: &[u8],
        stdin: SphinxStdin,
        mode: ProofMode,
    ) -> Result<String> {
        let client = &self.client;

        let skip_simulation = env::var("SKIP_SIMULATION")
            .map(|val| val == "true")
            .unwrap_or(false);

        if !skip_simulation {
            let (_, report) = SphinxProver::execute(elf, &stdin)?;
            log::info!(
                "Simulation complete, cycles: {}",
                report.total_instruction_count()
            );
        } else {
            log::info!("Skipping simulation");
        }

        let version = SPHINX_CIRCUIT_VERSION;
        let proof_id = client.create_proof(elf, &stdin, mode, version).await?;
        log::info!("Created {}", proof_id);

        if NetworkClient::rpc_url() == DEFAULT_PROVER_NETWORK_RPC {
            log::info!(
                "View in explorer: https://explorer.succinct.xyz/{}",
                proof_id
            );
        }
        Ok(proof_id)
    }

    /// Waits for a proof to be generated and returns the proof.
    pub async fn wait_proof<P: DeserializeOwned>(&self, proof_id: &str) -> Result<P> {
        let client = &self.client;
        let mut is_claimed = false;
        loop {
            let (status, maybe_proof) = client.get_proof_status::<P>(proof_id).await?;

            match status.status() {
                ProofStatus::ProofFulfilled => {
                    return Ok(maybe_proof.unwrap());
                }
                ProofStatus::ProofClaimed => {
                    if !is_claimed {
                        log::info!("Proof request claimed, proving...");
                        is_claimed = true;
                    }
                }
                ProofStatus::ProofUnclaimed => {
                    return Err(anyhow::anyhow!(
                        "Proof generation failed: {}",
                        status.unclaim_description()
                    ));
                }
                _ => {}
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Requests a proof from the prover network and waits for it to be generated.
    pub async fn prove<P: ProofType>(&self, elf: &[u8], stdin: SphinxStdin) -> Result<P> {
        let proof_id = self.request_proof(elf, stdin, P::PROOF_MODE).await?;
        self.wait_proof(&proof_id).await
    }
}

impl Prover for NetworkProver {
    fn id(&self) -> ProverType {
        ProverType::Network
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver {
        self.local_prover.sphinx_prover()
    }

    fn prove(&self, pk: &SphinxProvingKey, stdin: SphinxStdin) -> Result<SphinxProof> {
        block_on(self.prove(&pk.elf, stdin))
    }

    fn prove_compressed(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxCompressedProof> {
        block_on(self.prove(&pk.elf, stdin))
    }

    fn prove_plonk(
        &self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
    ) -> Result<SphinxPlonkBn254Proof> {
        block_on(self.prove(&pk.elf, stdin))
    }
}

impl Default for NetworkProver {
    fn default() -> Self {
        Self::new()
    }
}

/// A deserializable proof struct that has an associated ProofMode.
pub trait ProofType: DeserializeOwned {
    const PROOF_MODE: ProofMode;
}

impl ProofType for SphinxProof {
    const PROOF_MODE: ProofMode = ProofMode::Core;
}

impl ProofType for SphinxCompressedProof {
    const PROOF_MODE: ProofMode = ProofMode::Compressed;
}

impl ProofType for SphinxPlonkBn254Proof {
    const PROOF_MODE: ProofMode = ProofMode::Plonk;
}
