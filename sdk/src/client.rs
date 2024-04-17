use std::{env, time::Duration};

use crate::{auth::NetworkAuth, SP1Stdin};
use anyhow::{Ok, Result};
use futures::future::join_all;
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::{de::DeserializeOwned, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use twirp::reqwest::{Client as HttpClient, Url};
use twirp::Client as TwirpClient;
use wp1_core::stark::StarkGenericConfig;

use crate::{
    proto::network::{
        CreateProofRequest, GetNonceRequest, GetProofStatusRequest, GetProofStatusResponse,
        GetRelayStatusRequest, GetRelayStatusResponse, NetworkServiceClient, ProofStatus,
        RelayProofRequest, SubmitProofRequest, TransactionStatus,
    },
    SP1ProofWithIO,
};

/// The default RPC endpoint for the Succinct prover network.
const DEFAULT_PROVER_NETWORK_RPC: &str = "https://rpc.succinct.xyz/";
/// The default SP1 Verifier address on all chains.
const DEFAULT_SP1_VERIFIER_ADDRESS: &str = "0xed2107448519345059eab9cddab42ddc78fbebe9";

pub struct NetworkClient {
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
    pub auth: NetworkAuth,
}

impl NetworkClient {
    pub fn new(private_key: &str) -> Self {
        let auth = NetworkAuth::new(private_key);

        let rpc_url = env::var("PROVER_NETWORK_RPC")
            .unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string());

        let twirp_http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();

        let rpc =
            TwirpClient::new(Url::parse(&rpc_url).unwrap(), twirp_http_client, vec![]).unwrap();

        let http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();

        Self {
            auth,
            rpc,
            http: http_client.into(),
        }
    }

    pub fn get_wp1_verifier_address() -> [u8; 20] {
        let verifier_hex = env::var("SP1_VERIFIER_ADDRESS")
            .unwrap_or_else(|_| DEFAULT_SP1_VERIFIER_ADDRESS.to_string());
        let verifier_bytes = hex::decode(verifier_hex.trim_start_matches("0x"))
            .expect("Invalid SP1_VERIFIER_ADDRESS format");

        verifier_bytes
            .try_into()
            .expect("SP1_VERIFIER_ADDRESS must be 20 bytes")
    }

    /// Gets the latest nonce for this auth's account.
    pub async fn get_nonce(&self) -> u64 {
        let res = self
            .rpc
            .get_nonce(GetNonceRequest {
                address: self.auth.get_address().to_vec(),
            })
            .await
            .unwrap();
        res.nonce
    }

    async fn upload_file(&self, url: &str, data: Vec<u8>) -> Result<()> {
        self.http.put(url).body(data).send().await?;
        Ok(())
    }

    /// Makes a request to create a proof for the given ELF and stdin.
    pub async fn create_proof(&self, elf: &[u8], stdin: &SP1Stdin) -> Result<String> {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Invalid start time");
        let deadline = since_the_epoch.as_secs() + 1000;

        let nonce = self.get_nonce().await;
        let create_proof_signature = self.auth.sign_create_proof_message(nonce, deadline).await?;
        let res = self
            .rpc
            .create_proof(CreateProofRequest {
                nonce,
                deadline,
                signature: create_proof_signature.clone(),
            })
            .await?;

        let program_bytes = bincode::serialize(elf)?;
        let stdin_bytes = bincode::serialize(&stdin)?;
        let program_promise = self.upload_file(&res.program_put_url, program_bytes);
        let stdin_promise = self.upload_file(&res.stdin_put_url, stdin_bytes);
        let v = vec![program_promise, stdin_promise];
        let mut results = join_all(v).await;
        results.pop().expect("Failed to upload stdin")?;
        results.pop().expect("Failed to upload program")?;

        let nonce = self.get_nonce().await;
        let submit_proof_signature = self
            .auth
            .sign_submit_proof_message(nonce, &res.proof_id)
            .await?;
        self.rpc
            .submit_proof(SubmitProofRequest {
                nonce,
                proof_id: res.proof_id.clone(),
                signature: submit_proof_signature.clone(),
            })
            .await?;

        Ok(res.proof_id)
    }

    pub async fn get_proof_status<SC: StarkGenericConfig + Serialize + DeserializeOwned>(
        &self,
        proof_id: &str,
    ) -> Result<(GetProofStatusResponse, Option<SP1ProofWithIO<SC>>)> {
        let res = self
            .rpc
            .get_proof_status(GetProofStatusRequest {
                proof_id: proof_id.to_string(),
            })
            .await?;

        let proof = if res.status() == ProofStatus::ProofSucceeded {
            let proof = self
                .http
                .get(res.result_get_url.clone())
                .send()
                .await?
                .bytes()
                .await?;
            Some(bincode::deserialize(&proof).expect("Failed to deserialize proof"))
        } else {
            None
        };

        Ok((res, proof))
    }

    pub async fn relay_proof(
        &self,
        proof_id: &str,
        chain_id: u32,
        verifier: [u8; 20],
        callback: [u8; 20],
        callback_data: &[u8],
    ) -> Result<String> {
        let nonce = self.get_nonce().await;
        let relay_proof_signature = self
            .auth
            .sign_relay_proof_message(nonce, proof_id, chain_id, verifier, callback, callback_data)
            .await?;
        let req = RelayProofRequest {
            nonce,
            proof_id: proof_id.to_string(),
            chain_id,
            verifier: verifier.to_vec(),
            callback: callback.to_vec(),
            callback_data: callback_data.to_vec(),
            signature: relay_proof_signature.clone(),
        };
        let result = self.rpc.relay_proof(req).await?;
        Ok(result.tx_id)
    }

    pub async fn get_relay_status(
        &self,
        tx_id: &str,
    ) -> Result<(GetRelayStatusResponse, Option<String>, Option<String>)> {
        let res = self
            .rpc
            .get_relay_status(GetRelayStatusRequest {
                tx_id: tx_id.to_string(),
            })
            .await?;

        let tx_hash = match res.status() {
            TransactionStatus::TransactionScheduled => None,
            _ => Some(format!("0x{}", hex::encode(res.tx_hash.clone()))),
        };

        let simulation_url = match res.status() {
            TransactionStatus::TransactionFailed => Some(res.simulation_url.clone()),
            _ => None,
        };

        Ok((res, tx_hash, simulation_url))
    }
}
