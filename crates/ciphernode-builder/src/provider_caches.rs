// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::signers::{k256::ecdsa::SigningKey, local::LocalSigner};
use anyhow::Result;
use e3_config::chain_config::ChainConfig;
use e3_crypto::Cipher;
use e3_data::Repositories;
use e3_evm::helpers::{
    load_signer_from_repository, ConcreteReadProvider, ConcreteWriteProvider, EthProvider,
    ProviderConfig,
};
use e3_evm::EthPrivateKeyRepositoryFactory;
use std::collections::HashMap;
use std::sync::Arc;

// Typestate marker types
pub struct ReadOnly;

pub struct WriteEnabled {
    cipher: Arc<Cipher>,
    repositories: Arc<Repositories>,
}

/// Struct to cache modules required during the ciphernode construction so that providers are only
/// constructed once.
pub struct ProviderCache<State = ReadOnly> {
    signer_cache: Option<LocalSigner<SigningKey>>,
    read_provider_cache: HashMap<ChainConfig, EthProvider<ConcreteReadProvider>>,
    write_provider_cache: HashMap<ChainConfig, EthProvider<ConcreteWriteProvider>>,
    state: State,
}

impl ProviderCache<ReadOnly> {
    pub fn new() -> Self {
        ProviderCache {
            signer_cache: None,
            read_provider_cache: HashMap::new(),
            write_provider_cache: HashMap::new(),
            state: ReadOnly,
        }
    }

    pub fn with_signer(mut self, signer: LocalSigner<SigningKey>) -> Self {
        self.signer_cache = Some(signer);
        self
    }

    pub fn from_single_read_provider(
        chain: ChainConfig,
        provider: EthProvider<ConcreteReadProvider>,
    ) -> Self {
        ProviderCache {
            signer_cache: None,
            read_provider_cache: HashMap::from([(chain, provider)]),
            write_provider_cache: HashMap::new(),
            state: ReadOnly,
        }
    }

    /// Configure the cache with cipher and repositories to enable write provider support.
    pub fn with_write_support(
        self,
        cipher: Arc<Cipher>,
        repositories: Arc<Repositories>,
    ) -> ProviderCache<WriteEnabled> {
        ProviderCache {
            signer_cache: self.signer_cache,
            read_provider_cache: self.read_provider_cache,
            write_provider_cache: self.write_provider_cache,
            state: WriteEnabled {
                cipher,
                repositories,
            },
        }
    }
}

impl Default for ProviderCache<ReadOnly> {
    fn default() -> Self {
        Self::new()
    }
}

impl<State> ProviderCache<State> {
    pub async fn ensure_read_provider(
        &mut self,
        chain: &ChainConfig,
    ) -> Result<EthProvider<ConcreteReadProvider>> {
        if let Some(cache) = self.read_provider_cache.get(chain) {
            return Ok(cache.clone());
        }

        let provider_config = ProviderConfig::for_chain(chain)?;
        let read_provider = provider_config.create_readonly_provider().await?;

        self.read_provider_cache
            .insert(chain.clone(), read_provider.clone());

        Ok(read_provider)
    }
}

impl ProviderCache<WriteEnabled> {
    pub async fn ensure_signer(&mut self) -> Result<LocalSigner<SigningKey>> {
        if let Some(ref cache) = self.signer_cache {
            return Ok(cache.clone());
        }

        let signer = load_signer_from_repository(
            self.state.repositories.eth_private_key(),
            &self.state.cipher,
        )
        .await?;

        self.signer_cache = Some(signer.clone());
        Ok(signer)
    }

    pub async fn ensure_write_provider(
        &mut self,
        chain: &ChainConfig,
    ) -> Result<EthProvider<ConcreteWriteProvider>> {
        if let Some(cache) = self.write_provider_cache.get(chain) {
            return Ok(cache.clone());
        }

        let signer = self.ensure_signer().await?;
        let provider_config = ProviderConfig::for_chain(chain)?;
        let write_provider = provider_config.create_signer_provider(&signer).await?;

        self.write_provider_cache
            .insert(chain.clone(), write_provider.clone());

        Ok(write_provider)
    }
}
