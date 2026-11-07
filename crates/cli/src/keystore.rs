// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The operator's keys, sealed with the node's password where every release has kept them: the
//! sled database at the node's `db_file`, in its `datastore` tree. The operator key signs the
//! node's transactions; the network key, an ed25519 keypair, keeps the node's peer ID. The two
//! are written together or not at all, and a store that holds only one is refused, never
//! repaired by rotating the other.

use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use anyhow::{bail, Context, Result};
use e3_crypto::Cipher;
use libp2p::{identity::Keypair, PeerId};
use std::path::Path;
use zeroize::Zeroizing;

const TREE: &str = "datastore";
const OPERATOR: &[u8] = b"//eth_private_key";
const NETWORK: &[u8] = b"//libp2p/keypair";

pub struct Keys {
    pub operator: PrivateKeySigner,
    /// The ed25519 secret of the network key.
    pub network: [u8; 32],
}

impl Keys {
    pub fn address(&self) -> Address {
        self.operator.address()
    }

    pub fn peer_id(&self) -> Result<PeerId> {
        Ok(Keypair::ed25519_from_bytes(self.network)?
            .public()
            .to_peer_id())
    }
}

/// The keys sealed at `db_file`; none when no wallet is set.
pub fn read(db_file: &Path, cipher: &Cipher) -> Result<Option<Keys>> {
    let tree = open(db_file)?;
    let (Some(operator), Some(network)) = (sealed(&tree, OPERATOR)?, sealed(&tree, NETWORK)?)
    else {
        return match (tree.contains_key(OPERATOR)?, tree.contains_key(NETWORK)?) {
            (false, false) => Ok(None),
            _ => bail!("the wallet store holds only one of the operator and network keys"),
        };
    };
    let operator = PrivateKeySigner::from_slice(&Zeroizing::new(cipher.decrypt_data(&operator)?))?;
    let keypair = Zeroizing::new(cipher.decrypt_data(&network)?);
    let network = keypair
        .get(..32)
        .context("the stored network key is not an ed25519 keypair")?
        .try_into()?;
    Ok(Some(Keys { operator, network }))
}

/// Seals `private_key` as the operator key, and the network key made from the same bytes, in
/// place of any keys there.
pub fn write(db_file: &Path, cipher: &Cipher, private_key: &[u8; 32]) -> Result<Keys> {
    let (batch, keys) = sealed_pair(cipher, private_key)?;
    let tree = open(db_file)?;
    tree.apply_batch(batch)?;
    tree.flush()?;
    Ok(keys)
}

/// Seals a new random pair unless the store holds one.
pub fn ensure(db_file: &Path, cipher: &Cipher) -> Result<()> {
    let tree = open(db_file)?;
    match (tree.contains_key(OPERATOR)?, tree.contains_key(NETWORK)?) {
        (true, true) => return Ok(()),
        (false, false) => {}
        _ => bail!("the wallet store holds only one of the operator and network keys"),
    }
    let private_key = Zeroizing::new(rand::random::<[u8; 32]>());
    let (batch, _) = sealed_pair(cipher, &private_key)?;
    // Another process may write a pair between the check and this write; keep theirs.
    let written = tree.transaction(|tx| {
        if tx.get(OPERATOR)?.is_some() || tx.get(NETWORK)?.is_some() {
            return Ok(false);
        }
        tx.apply_batch(&batch)?;
        Ok(true)
    });
    match written {
        Ok(_) => {}
        Err(sled::transaction::TransactionError::Storage(error)) => return Err(error.into()),
        Err(sled::transaction::TransactionError::Abort(())) => unreachable!("never aborts"),
    }
    tree.flush()?;
    Ok(())
}

fn sealed_pair(cipher: &Cipher, private_key: &[u8; 32]) -> Result<(sled::Batch, Keys)> {
    let operator = PrivateKeySigner::from_slice(private_key)?;
    let keypair = Keypair::ed25519_from_bytes(*private_key)?.try_into_ed25519()?;
    let mut batch = sled::Batch::default();
    let mut seal = |key: &[u8], bytes: Vec<u8>| -> Result<()> {
        let mut bytes = Zeroizing::new(bytes);
        batch.insert(key, bincode::serialize(&cipher.encrypt_data(&mut bytes)?)?);
        Ok(())
    };
    seal(OPERATOR, private_key.to_vec())?;
    seal(NETWORK, keypair.to_bytes().to_vec())?;
    let network = *private_key;
    Ok((batch, Keys { operator, network }))
}

fn open(db_file: &Path) -> Result<sled::Tree> {
    let db = sled::open(db_file).with_context(|| format!("opening {}", db_file.display()))?;
    Ok(db.open_tree(TREE)?)
}

fn sealed(tree: &sled::Tree, key: &[u8]) -> Result<Option<Vec<u8>>> {
    tree.get(key)?
        .map(|raw| Ok(bincode::deserialize::<Vec<u8>>(&raw)?))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    const OLD_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const NEW_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    /// Every node set up before v2 sealed its keys through the old store; they read back here
    /// unchanged. The old store runs in an actor system of its own, which holds the database's
    /// lock until it stops.
    #[test]
    fn keys_the_old_store_sealed_read_back_unchanged() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            format!(
                "node:\n  network: local\n  config_dir: {}\n  data_dir: {}\n",
                dir.path().join("config").display(),
                dir.path().join("data").display()
            ),
        )?;
        let config_arg = config_file.to_string_lossy().into_owned();
        let cli = Cli::parse_from(["interfold", "wallet", "get", "-c", &config_arg]);
        let config = cli.load_config()?.node;
        let (address, peer_id) = actix::System::new().block_on(async {
            e3_entrypoint::password::set::autopassword(&config).await?;
            let key = Zeroizing::new(OLD_KEY.to_string());
            e3_entrypoint::wallet::set::execute(&config, key).await
        })?;
        e3_entrypoint::helpers::datastore::close_all_connections();

        let cipher = actix::System::new().block_on(Cipher::from_file(config.key_file()))?;
        let keys = read(&config.db_file(), &cipher)?.expect("the keys the old store sealed");
        assert_eq!((keys.address(), keys.peer_id()?), (address, peer_id));
        Ok(())
    }

    /// Keys sealed here read back, with the peer ID the operator key gives; a second `ensure`
    /// keeps them.
    #[tokio::test]
    async fn keys_sealed_here_read_back_and_stay() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db_file = dir.path().join("db");
        let cipher = Cipher::from_password("test password").await?;
        let key: [u8; 32] = alloy::hex::decode(NEW_KEY)?.try_into().unwrap();
        let written = write(&db_file, &cipher, &key)?;
        let peer_id = Keypair::ed25519_from_bytes(key)?.public().to_peer_id();
        ensure(&db_file, &cipher)?;
        let keys = read(&db_file, &cipher)?.expect("the keys sealed here");
        assert_eq!(
            (keys.address(), keys.peer_id()?),
            (written.address(), peer_id)
        );
        Ok(())
    }
}
