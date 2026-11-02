// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{hex::FromHex, primitives::FixedBytes, signers::local::PrivateKeySigner};
use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use e3_ciphernode_config::NodeConfig;
use e3_crypto::Cipher;
use e3_data::Repositories;
use e3_events::StoreKeys;
use e3_evm::EthPrivateKeyRepositoryFactory;
use e3_net::NetRepositoryFactory;
use libp2p::{identity::Keypair, PeerId};
use zeroize::{Zeroize, Zeroizing};

use crate::helpers::{datastore::get_repositories, rand::generate_random_bytes};

pub fn validate_private_key(input: &String) -> Result<()> {
    let bytes =
        FixedBytes::<32>::from_hex(input).map_err(|e| anyhow!("Invalid private key: {}", e))?;
    let _ =
        PrivateKeySigner::from_bytes(&bytes).map_err(|e| anyhow!("Invalid private key: {}", e))?;
    Ok(())
}

pub async fn execute(config: &NodeConfig, input: Zeroizing<String>) -> Result<(Address, PeerId)> {
    let cipher = Cipher::from_file(config.key_file()).await?;

    let (encrypted_private_key, encrypted_keypair, address, peer_id) = process_key(&cipher, input)?;

    let repositories = get_repositories(config)?;
    write_key_pair(&repositories, encrypted_private_key, encrypted_keypair).await?;
    Ok((address, peer_id))
}

async fn write_key_pair(
    repositories: &Repositories,
    encrypted_private_key: Vec<u8>,
    encrypted_keypair: Vec<u8>,
) -> Result<()> {
    repositories
        .store
        .write_batch_sync([
            (StoreKeys::eth_private_key(), encrypted_private_key),
            (StoreKeys::libp2p_keypair(), encrypted_keypair),
        ])
        .await
}

fn process_key(
    cipher: &Cipher,
    private_key: Zeroizing<String>,
) -> Result<(Vec<u8>, Vec<u8>, Address, PeerId)> {
    let private_key_bytes = FixedBytes::<32>::from_hex(private_key)?;
    let keypair = Keypair::ed25519_from_bytes(&mut private_key_bytes.clone())?;
    let peer_id = PeerId::from(&keypair.public());
    let mut keypair = keypair.try_into_ed25519()?.to_bytes().to_vec();
    let address = PrivateKeySigner::from_bytes(&private_key_bytes)?.address();
    let encrypted_private_key = cipher.encrypt_data(&mut private_key_bytes.to_vec())?;
    let encrypted_keypair = cipher.encrypt_data(&mut keypair)?;

    Ok((encrypted_private_key, encrypted_keypair, address, peer_id))
}

pub async fn autowallet(config: &NodeConfig) -> Result<()> {
    let cipher = Cipher::from_file(config.key_file()).await?;
    let repositories = get_repositories(config)?;
    ensure_autowallet(&repositories, &cipher).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AutowalletOutcome {
    Existing,
    Generated,
}

async fn read_key_pair(repositories: &Repositories) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let private_key = repositories.eth_private_key().read().await?;
    let network_key = repositories.libp2p_keypair().read().await?;
    Ok((private_key, network_key))
}

async fn ensure_autowallet(
    repositories: &Repositories,
    cipher: &Cipher,
) -> Result<AutowalletOutcome> {
    match read_key_pair(repositories).await? {
        (Some(_), Some(_)) => return Ok(AutowalletOutcome::Existing),
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "wallet storage is inconsistent: operator and libp2p keys must either both exist or both be absent"
            );
        }
        (None, None) => {}
    }

    let mut bytes = generate_random_bytes(32);
    let input = Zeroizing::new(hex::encode(&bytes));
    bytes.zeroize();
    let (encrypted_private_key, encrypted_keypair, _, _) = process_key(cipher, input)?;
    let inserted = repositories
        .store
        .write_batch_if_absent_sync([
            (StoreKeys::eth_private_key(), encrypted_private_key),
            (StoreKeys::libp2p_keypair(), encrypted_keypair),
        ])
        .await?;
    if inserted {
        return Ok(AutowalletOutcome::Generated);
    }

    // Another process may have initialized the pair between our read and conditional insert.
    // Accept only a complete pair; never repair a half-written identity by rotating one side.
    match read_key_pair(repositories).await? {
        (Some(_), Some(_)) => Ok(AutowalletOutcome::Existing),
        _ => anyhow::bail!(
            "wallet storage became inconsistent during initialization; refusing to rotate keys"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_data::Repositories;

    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[tokio::test]
    async fn test_process_key() -> Result<()> {
        let cipher = Cipher::from_password("test_password").await?;
        // Hardhat default private key
        let input = Zeroizing::new(TEST_PRIVATE_KEY.to_string());

        let (encrypted_private_key, encrypted_keypair, address, peer_id) =
            process_key(&cipher, input)?;

        assert!(!encrypted_private_key.is_empty());
        assert!(!encrypted_keypair.is_empty());
        assert_eq!(
            address,
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".parse::<Address>()?
        );
        assert_eq!(
            &peer_id.to_string(),
            "12D3KooWEZiPVmEZkwCFEWYxPL6xts6LnPHRFqsSEDGmt1vQ17By"
        );

        Ok(())
    }

    #[actix::test]
    async fn autowallet_preserves_an_existing_operator_and_peer_identity() -> Result<()> {
        let repositories = Repositories::in_mem();
        let cipher = Cipher::from_password("test_password").await?;
        let (private_key, network_key, expected_address, expected_peer_id) =
            process_key(&cipher, Zeroizing::new(TEST_PRIVATE_KEY.to_owned()))?;
        write_key_pair(&repositories, private_key.clone(), network_key.clone()).await?;

        let outcome = ensure_autowallet(&repositories, &cipher).await?;

        assert_eq!(outcome, AutowalletOutcome::Existing);
        assert_eq!(
            read_key_pair(&repositories).await?,
            (Some(private_key.clone()), Some(network_key.clone()))
        );
        let decrypted_private_key = cipher.decrypt_data(&private_key)?;
        let address =
            PrivateKeySigner::from_bytes(&FixedBytes::<32>::from_slice(&decrypted_private_key))?
                .address();
        let mut decrypted_network_key = cipher.decrypt_data(&network_key)?;
        let keypair: Keypair =
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut decrypted_network_key)?.into();
        assert_eq!(address, expected_address);
        assert_eq!(PeerId::from(keypair.public()), expected_peer_id);
        Ok(())
    }

    #[actix::test]
    async fn autowallet_creates_both_keys_when_storage_is_empty() -> Result<()> {
        let repositories = Repositories::in_mem();
        let cipher = Cipher::from_password("test_password").await?;

        let outcome = ensure_autowallet(&repositories, &cipher).await?;
        let (private_key, network_key) = read_key_pair(&repositories).await?;

        assert_eq!(outcome, AutowalletOutcome::Generated);
        assert!(private_key.is_some());
        assert!(network_key.is_some());
        Ok(())
    }

    #[actix::test]
    async fn autowallet_rejects_half_initialized_storage_without_mutation() -> Result<()> {
        let repositories = Repositories::in_mem();
        let cipher = Cipher::from_password("test_password").await?;
        let sentinel = vec![1, 2, 3, 4];
        repositories.eth_private_key().write_sync(&sentinel).await?;

        let error = ensure_autowallet(&repositories, &cipher).await.unwrap_err();

        assert!(error.to_string().contains("wallet storage is inconsistent"));
        assert_eq!(read_key_pair(&repositories).await?, (Some(sentinel), None));
        Ok(())
    }

    #[actix::test]
    async fn concurrent_autowallet_initialization_creates_only_one_pair() -> Result<()> {
        let repositories = Repositories::in_mem();
        let cipher = Cipher::from_password("test_password").await?;

        let (first, second) = tokio::join!(
            ensure_autowallet(&repositories, &cipher),
            ensure_autowallet(&repositories, &cipher)
        );

        let outcomes = [first?, second?];
        assert!(outcomes.contains(&AutowalletOutcome::Generated));
        assert!(outcomes.contains(&AutowalletOutcome::Existing));
        let (private_key, network_key) = read_key_pair(&repositories).await?;
        assert!(private_key.is_some());
        assert!(network_key.is_some());
        Ok(())
    }
}
