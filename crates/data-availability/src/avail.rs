// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use anyhow::ensure;
use avail_rust_client::{
    avail, ext::codec::Decode, Client, HasHeader, Keypair, Options, SecretUri,
};
use std::str::FromStr;

fn validate_rpc_endpoint(endpoint: &str) -> Result<()> {
    let url = reqwest::Url::parse(endpoint).context("invalid Avail RPC URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "Avail RPC URL must use HTTP or HTTPS; avail-rust-client does not accept WebSocket URLs"
    );
    Ok(())
}

/// Avail reader that finds a `submit_data` call in the Ethereum-verified block by content hash.
#[derive(Clone)]
pub struct AvailReader {
    endpoint: String,
}

impl AvailReader {
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into().trim().to_owned();
        validate_rpc_endpoint(&endpoint)?;
        Ok(Self { endpoint })
    }
}

#[async_trait]
impl DataAvailabilityReader for AvailReader {
    async fn retrieve(&self, reference: DataReference) -> Result<Vec<u8>> {
        let client = tokio::time::timeout(Duration::from_secs(20), Client::new(&self.endpoint))
            .await
            .context("timed out while connecting to Avail")??;
        let calls = tokio::time::timeout(
            Duration::from_secs(30),
            client
                .block(reference.block_number)
                .extrinsics()
                .all::<avail::data_availability::tx::SubmitData>(Default::default()),
        )
        .await
        .context("timed out while reading the Avail block")??;

        for call in calls {
            if keccak256(&call.call.data).0 == reference.content_hash {
                return verify_retrieved_bytes(reference, call.call.data);
            }
        }
        bail!(
            "Avail block {} does not contain object 0x{}",
            reference.block_number,
            hex::encode(reference.content_hash)
        )
    }
}

/// Avail `submit_data` publisher paired with the official VectorX bridge API.
pub struct AvailPublisher {
    endpoint: String,
    app_id: u32,
    signer: Keypair,
    bridge: VectorXBridgeApi,
    // Avail account nonces are sequential. The client resolves the next nonce from chain state,
    // so concurrent submissions from one signer can otherwise select the same nonce.
    submission_lock: tokio::sync::Mutex<()>,
}

impl AvailPublisher {
    pub fn new(
        endpoint: impl Into<String>,
        app_id: u32,
        secret_uri: &str,
        bridge_api: impl Into<String>,
        destination_chain_id: u64,
    ) -> Result<Self> {
        let endpoint = endpoint.into().trim().to_owned();
        validate_rpc_endpoint(&endpoint)?;
        let secret = SecretUri::from_str(secret_uri).context("invalid Avail secret URI")?;
        let signer = Keypair::from_uri(&secret).context("invalid Avail signing key")?;
        Ok(Self {
            endpoint,
            app_id,
            signer,
            bridge: VectorXBridgeApi::new(bridge_api, destination_chain_id)?,
            submission_lock: tokio::sync::Mutex::new(()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_requires_the_http_transport_used_by_avail_rust_client() {
        assert!(AvailReader::new("https://avail.example/rpc").is_ok());
        let error = AvailReader::new("wss://avail.example/ws")
            .err()
            .expect("WebSocket transport must be rejected");
        assert!(error.to_string().contains("HTTP or HTTPS"));
    }
}

#[async_trait]
impl DataAvailabilityPublisher for AvailPublisher {
    async fn publish(&self, bytes: &[u8]) -> Result<PendingPublication> {
        validate_object_bytes(bytes)?;
        // Keep the lock through finality. A second nonce lookup before the first transaction is
        // finalized can return the same nonce on RPCs that ignore their pending pool.
        let _submission = self.submission_lock.lock().await;
        let client = tokio::time::timeout(Duration::from_secs(20), Client::new(&self.endpoint))
            .await
            .context("timed out while connecting to Avail")??;
        let tx = client.tx().data_availability().submit_data(bytes);
        let submitted = tokio::time::timeout(
            Duration::from_secs(30),
            tx.sign_and_submit(&self.signer, Options::new(self.app_id)),
        )
        .await
        .context("timed out while submitting data to Avail")??;
        let receipt = tokio::time::timeout(Duration::from_secs(300), submitted.receipt(false))
            .await
            .context("timed out while waiting for Avail finality")??
            .context("Avail transaction expired before finalization")?;
        let events = tokio::time::timeout(Duration::from_secs(30), receipt.events())
            .await
            .context("timed out while checking the finalized Avail transaction")??;
        if !events.is_extrinsic_success_present() {
            bail!("Avail submit_data transaction failed in finalized block");
        }

        Ok(PendingPublication {
            content_hash: keccak256(bytes).0,
            block_hash: format!("{:#x}", receipt.block_hash),
            block_number: receipt.block_height,
            extrinsic_index: receipt.ext_index,
        })
    }

    async fn proof(&self, publication: &PendingPublication) -> Result<ProofStatus> {
        self.bridge.proof(publication).await
    }
}

// Keep these imports checked against the SDK's typed-call API at compile time.
fn _typed_submit_data<T: HasHeader + Decode>() {}
