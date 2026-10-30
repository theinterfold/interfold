// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The configured chains, each enabled one resolved once to its read provider and chain ID.

use crate::{helpers::ConcreteReadProvider, EthProvider, ProviderCache};
use anyhow::Result;
use e3_config::chain_config::ChainConfig;
use e3_events::{AggregateConfig, AggregateId};
use std::{collections::HashMap, time::Duration};

/// An enabled chain, with its read provider and the chain ID that the provider reports.
pub struct EnabledChain {
    pub config: ChainConfig,
    pub chain_id: u64,
    pub provider: EthProvider<ConcreteReadProvider>,
}

/// One configured chain. The node reads an enabled chain. A disabled chain gives only its
/// configuration.
pub enum Chain {
    Enabled(EnabledChain),
    Disabled(ChainConfig),
}

impl Chain {
    pub fn config(&self) -> &ChainConfig {
        match self {
            Self::Enabled(chain) => &chain.config,
            Self::Disabled(config) => config,
        }
    }

    /// The provider's chain ID for an enabled chain, and the configured chain ID for a disabled
    /// chain.
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Self::Enabled(chain) => Some(chain.chain_id),
            Self::Disabled(config) => config.chain_id,
        }
    }

    pub fn as_enabled(&self) -> Option<&EnabledChain> {
        match self {
            Self::Enabled(chain) => Some(chain),
            Self::Disabled(_) => None,
        }
    }
}

/// The configured chains, in configuration order.
pub struct Chains(Vec<Chain>);

impl Chains {
    /// Connect to every enabled chain. Each enabled entry must be another chain, and its provider
    /// must report the configured chain ID.
    pub async fn resolve<State>(
        configs: &[ChainConfig],
        provider_cache: &mut ProviderCache<State>,
    ) -> Result<Self> {
        let mut chains = Vec::with_capacity(configs.len());
        for config in configs {
            chains.push(if config.enabled.unwrap_or(true) {
                let provider = provider_cache.ensure_read_provider(config).await?;
                Chain::Enabled(EnabledChain {
                    config: config.clone(),
                    chain_id: provider.chain_id(),
                    provider,
                })
            } else {
                Chain::Disabled(config.clone())
            });
        }
        let chains = Self(chains);
        ensure_one_entry_per_chain(
            chains
                .enabled()
                .map(|chain| (chain.config.name.as_str(), chain.chain_id)),
        )?;
        for chain in chains.enabled() {
            validate_chain_id(&chain.config, chain.chain_id)?;
        }
        Ok(chains)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Chain> {
        self.0.iter()
    }

    pub fn enabled(&self) -> impl Iterator<Item = &EnabledChain> {
        self.0.iter().filter_map(Chain::as_enabled)
    }

    pub fn disabled(&self) -> impl Iterator<Item = &ChainConfig> {
        self.0.iter().filter_map(|chain| match chain {
            Chain::Enabled(_) => None,
            Chain::Disabled(config) => Some(config),
        })
    }

    /// The chain IDs of the enabled chains, in configuration order.
    pub fn enabled_ids(&self) -> Vec<u64> {
        self.enabled().map(|chain| chain.chain_id).collect()
    }

    /// One event store aggregate per enabled chain, with the chain's finalization delay.
    pub fn aggregate_config(&self) -> AggregateConfig {
        AggregateConfig::new(
            self.enabled()
                .map(|chain| aggregate_delay(&chain.config, chain.chain_id))
                .collect(),
        )
    }
}

/// Validate chain ID matches expected configuration
pub fn validate_chain_id(chain: &ChainConfig, actual_chain_id: u64) -> Result<()> {
    if let Some(expected_chain_id) = chain.chain_id {
        if actual_chain_id != expected_chain_id {
            return Err(anyhow::anyhow!(
                "Chain '{}' validation failed: expected chain_id {}, but provider returned chain_id {}",
                chain.name, expected_chain_id, actual_chain_id
            ));
        }
    }
    Ok(())
}

/// Each enabled chain entry must be another chain. Two entries of one chain would run two readers
/// into that chain's one event log, and the health check expects one heartbeat per entry, while
/// the readers of one chain write one heartbeat file.
fn ensure_one_entry_per_chain<'a>(chains: impl IntoIterator<Item = (&'a str, u64)>) -> Result<()> {
    let mut names = HashMap::new();
    for (name, chain_id) in chains {
        if let Some(other) = names.insert(chain_id, name) {
            anyhow::bail!(
                "the enabled chains `{other}` and `{name}` are both chain {chain_id}; enable one entry per chain"
            );
        }
    }
    Ok(())
}

/// The event store aggregate of a chain and its finalization delay.
fn aggregate_delay(chain: &ChainConfig, actual_chain_id: u64) -> (AggregateId, Duration) {
    let aggregate_id = AggregateId::from_chain_id(Some(actual_chain_id));
    let finalization_ms = chain.finalization_ms.unwrap_or(0);
    (aggregate_id, Duration::from_millis(finalization_ms))
}

#[cfg(test)]
mod tests {
    use super::{aggregate_delay, ensure_one_entry_per_chain, Chains};
    use crate::ProviderCache;
    use alloy::primitives::Address;
    use e3_config::{
        chain_config::ChainConfig,
        contract::{Contract, ContractAddresses},
        rpc::RpcAuth,
    };
    use std::time::Duration;

    fn chain_with_finalization_ms(finalization_ms: Option<u64>) -> ChainConfig {
        let contract = || Contract::AddressOnly(Address::ZERO.to_string());
        ChainConfig {
            enabled: Some(true),
            name: "test".to_owned(),
            rpc_url: "http://127.0.0.1:8545".to_owned(),
            rpc_auth: RpcAuth::default(),
            contracts: ContractAddresses {
                interfold: contract(),
                ciphernode_registry: contract(),
                bonding_registry: contract(),
                e3_program: None,
                fee_token: None,
                slashing_manager: None,
                dkg_fold_attestation_verifier: None,
                faucet: None,
            },
            finalization_ms,
            chain_id: Some(1),
            ingestion_confirmations: Some(0),
            rpc_poll_interval_ms: Some(250),
            rpc_log_range_blocks: None,
            data_availability: None,
        }
    }

    #[test]
    fn aggregate_delay_preserves_large_millisecond_values_without_overflow() {
        let (_, delay) = aggregate_delay(&chain_with_finalization_ms(Some(u64::MAX)), 1);

        assert_eq!(delay, Duration::from_millis(u64::MAX));
    }

    #[test]
    fn aggregate_delay_defaults_to_zero() {
        let (_, delay) = aggregate_delay(&chain_with_finalization_ms(None), 1);

        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn two_enabled_entries_of_one_chain_are_refused() {
        assert!(ensure_one_entry_per_chain([("hardhat", 31_337), ("sepolia", 11_155_111)]).is_ok());

        let error = ensure_one_entry_per_chain([
            ("hardhat", 31_337),
            ("sepolia", 11_155_111),
            ("local", 31_337),
        ])
        .expect_err("two entries of one chain");
        assert!(
            error
                .to_string()
                .contains("`hardhat` and `local` are both chain 31337"),
            "{error:#}"
        );
    }

    /// The build resolves each enabled entry's chain ID and refuses two entries of one chain.
    #[actix::test]
    async fn the_build_refuses_two_enabled_entries_of_one_chain() -> anyhow::Result<()> {
        let anvil = alloy::node_bindings::Anvil::new().try_spawn()?;
        let entry = |name: &str| ChainConfig {
            name: name.to_owned(),
            rpc_url: anvil.endpoint(),
            chain_id: None,
            ..chain_with_finalization_ms(None)
        };

        Chains::resolve(&[entry("first")], &mut ProviderCache::new()).await?;
        let Err(error) = Chains::resolve(
            &[entry("first"), entry("second")],
            &mut ProviderCache::new(),
        )
        .await
        else {
            panic!("two enabled entries of one chain must stop the build");
        };
        assert!(
            error
                .to_string()
                .contains("`first` and `second` are both chain 31337"),
            "{error:#}"
        );
        Ok(())
    }
}
