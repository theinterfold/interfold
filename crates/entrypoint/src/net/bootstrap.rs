// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{ensure, Result};
use e3_ciphernode_builder::ProviderCache;
use e3_config::AppConfig;
use e3_crypto::Cipher;
use e3_net::{setup_libp2p_keypair, Libp2pNetInterface, NetRepositoryFactory, NetworkPolicy};
use std::sync::Arc;
use tracing::info;

use crate::helpers::datastore::get_repositories;

/// Load the existing network identity without hydrating protocol state or loading an EVM signer.
pub async fn create(config: &AppConfig) -> Result<Libp2pNetInterface> {
    let mut providers = ProviderCache::new();
    let mut deployments = Vec::new();
    for chain in config
        .chains()
        .iter()
        .filter(|chain| chain.enabled.unwrap_or(true))
    {
        let provider = providers.ensure_read_provider(chain).await?;
        ensure!(
            chain
                .chain_id
                .is_none_or(|expected| expected == provider.chain_id()),
            "configured chain ID does not match the RPC chain for {}",
            chain.name
        );
        deployments.push((
            provider.chain_id(),
            chain.contracts.interfold.address()?.into_array(),
        ));
    }
    let network = NetworkPolicy::new(config.network().clone(), deployments)?;
    let cipher = Arc::new(Cipher::from_file(config.key_file()).await?);
    let repositories = get_repositories(config)?;
    let keypair = setup_libp2p_keypair(repositories.libp2p_keypair(), &cipher).await;
    repositories.store.shutdown().await?;
    let keypair = keypair?;
    info!(peer_id = %keypair.peer_id(), "Starting bootstrap-only networking; committee participation is disabled");
    Libp2pNetInterface::new_bootstrap(keypair, config.peers(), Some(config.quic_port()), network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{web, App, HttpServer};
    use e3_config::UnscopedAppConfig;
    use e3_evm::EthPrivateKeyRepositoryFactory;
    use serde_json::{json, Value};
    use std::{net::TcpListener, sync::Mutex};
    use zeroize::Zeroizing;

    async fn chain_identity(
        body: web::Json<Value>,
        calls: web::Data<Mutex<Vec<String>>>,
    ) -> web::Json<Value> {
        calls
            .lock()
            .unwrap()
            .push(body["method"].as_str().unwrap_or_default().to_string());
        web::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": "0x7a69"}))
    }

    #[actix::test]
    async fn bootstrap_reads_only_chain_identity_and_preserves_stored_state() -> Result<()> {
        let calls = web::Data::new(Mutex::new(Vec::<String>::new()));
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let recorded = calls.clone();
        let server = HttpServer::new(move || {
            App::new()
                .app_data(recorded.clone())
                .route("/", web::post().to(chain_identity))
        })
        .listen(listener)?
        .run();
        let server_handle = server.handle();
        actix::spawn(server);
        let directory = tempfile::tempdir()?;
        let path = directory.path().to_path_buf();
        let unscoped: UnscopedAppConfig = serde_yaml::from_str(&format!(
            r#"
node:
  network: local
  quic_port: 0
chains:
  - name: local
    chain_id: 31337
    rpc_url: http://{address}
    contracts:
      interfold: "0x0000000000000000000000000000000000000001"
      bonding_registry: "0x0000000000000000000000000000000000000002"
      ciphernode_registry: "0x0000000000000000000000000000000000000003"
"#
        ))?;
        let config = unscoped.into_scoped_with_defaults("_default", &path, &path, &path)?;
        crate::password::set::execute(&config, Zeroizing::new("test-password".into())).await?;
        crate::wallet::set::execute(
            &config,
            Zeroizing::new(
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
            ),
        )
        .await?;
        let before = get_repositories(&config)?;
        let operator = before.eth_private_key().read().await?;
        let peer = before.libp2p_keypair().read().await?;
        before
            .store
            .scope("opaque-protocol-state")
            .write_sync(vec![1u8, 2, 3])
            .await?;
        before.store.shutdown().await?;

        let interface = create(&config).await?;
        drop(interface);
        let after = get_repositories(&config)?;
        assert_eq!(after.eth_private_key().read().await?, operator);
        assert_eq!(after.libp2p_keypair().read().await?, peer);
        assert_eq!(
            after
                .store
                .scope("opaque-protocol-state")
                .read::<Vec<u8>>()
                .await?,
            Some(vec![1, 2, 3])
        );
        assert!(!config.log_file().exists());
        after.store.shutdown().await?;
        assert_eq!(*calls.lock().unwrap(), ["eth_chainId"]);
        server_handle.stop(true).await;
        Ok(())
    }
}
