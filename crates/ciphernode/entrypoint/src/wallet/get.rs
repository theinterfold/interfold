// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::helpers::datastore::get_repositories;
use alloy::{primitives::FixedBytes, signers::local::PrivateKeySigner};
use alloy_primitives::Address;
use anyhow::Context;
use anyhow::Result;
use e3_ciphernode_config::NodeConfig;
use e3_crypto::Cipher;
use e3_evm::EthPrivateKeyRepositoryFactory;
use zeroize::Zeroizing;

pub async fn execute(config: &NodeConfig) -> Result<Address> {
    let repositories = get_repositories(config)?;
    let cipher = Cipher::from_file(config.key_file()).await?;
    let encrypted = repositories
        .eth_private_key()
        .read()
        .await?
        .context("No wallet has been set.")?;
    let private_key = Zeroizing::new(cipher.decrypt_data(&encrypted)?);
    let address =
        PrivateKeySigner::from_bytes(&FixedBytes::<32>::from_slice(&private_key))?.address();

    Ok(address)
}
