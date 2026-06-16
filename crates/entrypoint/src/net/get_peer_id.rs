// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::helpers::datastore::get_repositories;
use anyhow::Context;
use anyhow::Result;
use e3_config::AppConfig;
use e3_crypto::Cipher;
use e3_net::NetRepositoryFactory;
use libp2p::identity::ed25519;
use libp2p::PeerId;
use zeroize::Zeroizing;

pub async fn execute(config: &AppConfig) -> Result<PeerId> {
    let repositories = get_repositories(config)?;
    let cipher = Cipher::from_file(config.key_file()).await?;
    let encrypted = repositories
        .libp2p_keypair()
        .read()
        .await?
        .context("No wallet has been set.")?;
    let mut bytes = Zeroizing::new(cipher.decrypt_data(&encrypted)?);
    let keypair: libp2p::identity::Keypair = ed25519::Keypair::try_from_bytes(&mut bytes)?.into();
    let peer_id = PeerId::from(keypair.public());
    Ok(peer_id)
}
