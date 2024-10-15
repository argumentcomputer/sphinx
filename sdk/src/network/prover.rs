use std::{env, time::Duration};

use crate::proto::network::ProofMode;
use crate::{
    network::client::{NetworkClient, DEFAULT_PROVER_NETWORK_RPC},
    proto::network::ProofStatus,
    Prover,
};
use crate::{
    SphinxContext, SphinxProofKind, SphinxProofWithPublicValues, SphinxProvingKey,
    SphinxVerifyingKey,
};
use anyhow::Result;
use serde::de::DeserializeOwned;
use sphinx_core::utils::SphinxProverOpts;
use sphinx_prover::components::DefaultProverComponents;
use sphinx_prover::utils::block_on;
use sphinx_prover::{SphinxProver, SphinxStdin, SPHINX_CIRCUIT_VERSION};
use tokio::time::sleep;

use crate::provers::{LocalProver, ProverType};

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: LocalProver<DefaultProverComponents>,
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
            let (_, report) =
                SphinxProver::<DefaultProverComponents>::execute(elf, &stdin, Default::default())?;
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
    pub async fn prove(
        &self,
        elf: &[u8],
        stdin: SphinxStdin,
        mode: ProofMode,
    ) -> Result<SphinxProofWithPublicValues> {
        let proof_id = self.request_proof(elf, stdin, mode).await?;
        self.wait_proof(&proof_id).await
    }
}

impl Prover<DefaultProverComponents> for NetworkProver {
    fn id(&self) -> ProverType {
        ProverType::Network
    }

    fn setup(&self, elf: &[u8]) -> (SphinxProvingKey, SphinxVerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn sphinx_prover(&self) -> &SphinxProver {
        self.local_prover.sphinx_prover()
    }

    fn prove<'a>(
        &'a self,
        pk: &SphinxProvingKey,
        stdin: SphinxStdin,
        opts: SphinxProverOpts,
        context: SphinxContext<'a>,
        kind: SphinxProofKind,
    ) -> Result<SphinxProofWithPublicValues> {
        warn_if_not_default(&opts, &context);
        block_on(self.prove(&pk.elf, stdin, kind.into()))
    }
}

impl Default for NetworkProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Warns if `opts` or `context` are not default values, since they are currently unsupported.
fn warn_if_not_default(opts: &SphinxProverOpts, context: &SphinxContext<'_>) {
    let _guard = tracing::warn_span!("network_prover").entered();
    if opts != &SphinxProverOpts::default() {
        tracing::warn!("non-default opts will be ignored: {:?}", opts.core_opts);
        tracing::warn!("custom SP1ProverOpts are currently unsupported by the network prover");
    }
    // Exhaustive match is done to ensure we update the warnings if the types change.
    let SphinxContext {
        hook_registry,
        subproof_verifier,
        ..
    } = context;
    if hook_registry.is_some() {
        tracing::warn!(
            "non-default context.hook_registry will be ignored: {:?}",
            hook_registry
        );
        tracing::warn!("custom runtime hooks are currently unsupported by the network prover");
        tracing::warn!("proving may fail due to missing hooks");
    }
    if subproof_verifier.is_some() {
        tracing::warn!("non-default context.subproof_verifier will be ignored");
        tracing::warn!("custom subproof verifiers are currently unsupported by the network prover");
    }
}

impl From<SphinxProofKind> for ProofMode {
    fn from(value: SphinxProofKind) -> Self {
        match value {
            SphinxProofKind::Core => Self::Core,
            SphinxProofKind::Compressed => Self::Compressed,
            SphinxProofKind::Plonk => Self::Plonk,
        }
    }
}
