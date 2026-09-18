// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Clear durable round state while keeping the operator identity.
//!
//! A release that changes the durable schema refuses to load an older data directory. The
//! operator must discard the old state, but the wallet key and the libp2p keypair live in the
//! same store as that state, so deleting the directory also destroys the identity that holds
//! the bond. This command removes everything except that identity pair.
//!
//! The identity is copied out as ciphertext. The password is never required, so the key material
//! is not decrypted here.

use anyhow::{bail, Context, Result};
use e3_ciphernode_builder::get_interfold_bus_handle;
use e3_config::AppConfig;
use e3_data::{Repositories, RepositoriesFactory, SledDb};
use e3_evm::EthPrivateKeyRepositoryFactory;
use e3_net::NetRepositoryFactory;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{info, warn};

use crate::fence::ProcessFence;
use crate::helpers::datastore::setup_datastore;

/// The encrypted identity pair, held while the store is rebuilt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservedIdentity {
    /// Ciphertext of the operator Ethereum private key.
    pub eth_private_key: Option<Vec<u8>>,
    /// Ciphertext of the libp2p keypair.
    pub libp2p_keypair: Option<Vec<u8>>,
}

impl PreservedIdentity {
    fn is_complete(&self) -> bool {
        self.eth_private_key.is_some() && self.libp2p_keypair.is_some()
    }

    fn is_empty(&self) -> bool {
        self.eth_private_key.is_none() && self.libp2p_keypair.is_none()
    }
}

/// What the reset did, so the caller can report it without re-reading the store.
#[derive(Debug, Clone)]
pub struct ResetOutcome {
    pub identity_restored: bool,
    pub backup_file: PathBuf,
    pub db_file: PathBuf,
    pub log_file: PathBuf,
}

/// Read the encrypted identity pair without decrypting it.
async fn read_identity(repositories: &Repositories) -> Result<PreservedIdentity> {
    Ok(PreservedIdentity {
        eth_private_key: repositories
            .eth_private_key()
            .read()
            .await
            .context("failed to read the stored operator key")?,
        libp2p_keypair: repositories
            .libp2p_keypair()
            .read()
            .await
            .context("failed to read the stored libp2p keypair")?,
    })
}

/// Write the ciphertext backup before anything is deleted, so a failed reset is recoverable.
async fn write_backup(path: &Path, identity: &PreservedIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(identity).context("failed to encode the backup")?;
    fs::write(path, encoded)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    restrict_permissions(path).await
}

#[cfg(unix)]
async fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("failed to restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
async fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

async fn remove_if_present(path: &Path) -> Result<()> {
    if !fs::try_exists(path)
        .await
        .with_context(|| format!("failed to inspect {}", path.display()))?
    {
        return Ok(());
    }
    let metadata = fs::metadata(path)
        .await
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path).await
    } else {
        fs::remove_file(path).await
    }
    .with_context(|| format!("failed to remove {}", path.display()))
}

/// Clear durable state for one node and put the identity back.
///
/// `backup_file` is written first and is left in place afterwards: it is the only copy of the
/// identity between the delete and the restore.
pub async fn execute(config: &AppConfig) -> Result<ResetOutcome> {
    let db_file = config.db_file();
    let log_file = config.log_file();

    // Refuse while the node is running. The fence is the same advisory lock `start` holds, so a
    // live process makes this fail instead of deleting state from under it. Held for the whole
    // reset, which also stops two resets from racing each other.
    let _fence = ProcessFence::acquire(&db_file, &config.name()).context(
        "could not acquire the node fence. The node is probably still running: stop it first, \
         then re-run this command",
    )?;

    let identity = {
        let bus = get_interfold_bus_handle()?;
        let store = setup_datastore(config, &bus)?;
        let identity = read_identity(&store.repositories()).await?;
        store.repositories().store.shutdown().await.ok();
        identity
    };
    // Release the sled handle before the directory is removed; a live handle would recreate it.
    SledDb::close_all_connections();

    if identity.is_empty() {
        warn!(
            "No operator identity found in {}. Nothing to preserve.",
            db_file.display()
        );
    } else if !identity.is_complete() {
        bail!(
            "The stored identity is incomplete: operator key {}, libp2p keypair {}. Refusing to \
             reset, because the missing half cannot be restored. Back up {} and investigate \
             before retrying.",
            present(&identity.eth_private_key),
            present(&identity.libp2p_keypair),
            db_file.display()
        );
    }

    let backup_file = backup_path(config);
    write_backup(&backup_file, &identity).await?;
    info!(
        "Wrote the encrypted identity backup to {}",
        backup_file.display()
    );

    remove_if_present(&db_file).await?;
    remove_if_present(&log_file).await?;
    info!("Removed {} and {}", db_file.display(), log_file.display());

    let identity_restored = if identity.is_empty() {
        false
    } else {
        restore_identity(config, &identity).await?;
        true
    };

    Ok(ResetOutcome {
        identity_restored,
        backup_file,
        db_file,
        log_file,
    })
}

/// Write the identity into the rebuilt store and read it back before reporting success.
async fn restore_identity(config: &AppConfig, identity: &PreservedIdentity) -> Result<()> {
    let bus = get_interfold_bus_handle()?;
    let store = setup_datastore(config, &bus)?;
    let repositories = store.repositories();

    let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(2);
    if let Some(key) = identity.eth_private_key.clone() {
        entries.push((e3_events::StoreKeys::eth_private_key(), key));
    }
    if let Some(keypair) = identity.libp2p_keypair.clone() {
        entries.push((e3_events::StoreKeys::libp2p_keypair(), keypair));
    }
    repositories
        .store
        .write_batch_sync(entries)
        .await
        .context("failed to restore the operator identity")?;

    let restored = read_identity(&repositories).await?;
    repositories.store.shutdown().await.ok();
    SledDb::close_all_connections();

    if restored.eth_private_key != identity.eth_private_key
        || restored.libp2p_keypair != identity.libp2p_keypair
    {
        bail!(
            "The restored identity does not match what was read before the reset. The backup is \
             intact; do not start the node."
        );
    }
    Ok(())
}

fn present(value: &Option<Vec<u8>>) -> &'static str {
    if value.is_some() {
        "present"
    } else {
        "missing"
    }
}

fn backup_path(config: &AppConfig) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let name = format!("identity-backup-{}-{stamp}.json", config.name());
    config
        .db_file()
        .parent()
        .map(|dir| dir.join(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}
