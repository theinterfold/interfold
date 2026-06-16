// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::str::FromStr;

use alloy::{primitives::Address, providers::WalletProvider, sol};
use anyhow::{anyhow, Context, Result};
use e3_config::{chain_config::ChainConfig, AppConfig};
use e3_crypto::Cipher;
use e3_entrypoint::helpers::datastore::get_repositories;
use e3_evm::{
    helpers::{load_signer_from_repository, ConcreteWriteProvider, EthProvider, ProviderConfig},
    EthPrivateKeyRepositoryFactory,
};

mod bonding_registry_contract {
    use super::sol;

    sol!(
        #[sol(rpc)]
        BondingRegistryContract,
        "../../packages/interfold-contracts/artifacts/contracts/interfaces/IBondingRegistry.sol/IBondingRegistry.json"
    );
}

#[allow(clippy::too_many_arguments)]
mod interfold_ticket_token_contract {
    use super::sol;

    sol!(
        #[sol(rpc)]
        InterfoldTicketTokenContract,
        "../../packages/interfold-contracts/artifacts/contracts/token/InterfoldTicketToken.sol/InterfoldTicketToken.json"
    );
}

mod erc20_metadata_interface {
    use super::sol;

    sol!(
        #[sol(rpc)]
        interface IERC20Metadata {
            function balanceOf(address account) external view returns (uint256);
            function allowance(address owner, address spender) external view returns (uint256);
            function approve(address spender, uint256 amount) external returns (bool);
            function decimals() external view returns (uint8);
            function symbol() external view returns (string memory);
            function name() external view returns (string memory);
        }
    );
}

use bonding_registry_contract::BondingRegistryContract;
use erc20_metadata_interface::IERC20Metadata;
use interfold_ticket_token_contract::InterfoldTicketTokenContract;

pub(crate) struct ChainContext {
    chain_label: String,
    bonding_registry: Address,
    provider: EthProvider<ConcreteWriteProvider>,
    signer_address: Address,
}

impl ChainContext {
    pub(crate) async fn new(config: &AppConfig, selection: Option<&str>) -> Result<Self> {
        let chain = select_chain(config, selection)?;
        let bonding_registry = parse_address(chain.contracts.bonding_registry.address_str())?;

        let rpc = chain.rpc_url()?;
        let cipher = Cipher::from_file(config.key_file()).await?;
        let repositories = get_repositories(config)?;
        let signer = load_signer_from_repository(repositories.eth_private_key(), &cipher).await?;
        let provider = ProviderConfig::new(rpc, chain.rpc_auth.clone())
            .create_signer_provider(&signer)
            .await?;
        let signer_address = provider.provider().default_signer_address();

        let label = selection.unwrap_or(chain.name.as_str()).to_string();

        Ok(Self {
            chain_label: label,
            bonding_registry,
            provider,
            signer_address,
        })
    }

    fn provider_client(&self) -> ConcreteWriteProvider {
        self.provider.provider().clone()
    }

    pub(crate) fn bonding(
        &self,
    ) -> BondingRegistryContract::BondingRegistryContractInstance<ConcreteWriteProvider> {
        BondingRegistryContract::new(self.bonding_registry, self.provider_client())
    }

    pub(crate) fn operator(&self) -> Address {
        self.signer_address
    }

    pub(crate) fn chain_label(&self) -> &str {
        &self.chain_label
    }

    pub(crate) fn bonding_registry(&self) -> Address {
        self.bonding_registry
    }

    pub(crate) async fn license_token_address(&self) -> Result<Address> {
        Ok(self.bonding().getLicenseToken().call().await?)
    }

    pub(crate) async fn ticket_token_address(&self) -> Result<Address> {
        Ok(self.bonding().getTicketToken().call().await?)
    }

    pub(crate) async fn ticket_underlying_address(&self) -> Result<Address> {
        let ticket = self.ticket_token_address().await?;
        Ok(
            InterfoldTicketTokenContract::new(ticket, self.provider_client())
                .underlying()
                .call()
                .await?,
        )
    }

    pub(crate) fn erc20(
        &self,
        address: Address,
    ) -> IERC20Metadata::IERC20MetadataInstance<ConcreteWriteProvider> {
        IERC20Metadata::new(address, self.provider_client())
    }
}

fn select_chain<'a>(config: &'a AppConfig, name: Option<&str>) -> Result<&'a ChainConfig> {
    match name {
        Some(desired) => config
            .chains()
            .iter()
            .find(|c| c.name == desired)
            .ok_or_else(|| anyhow!("Chain '{}' not found in configuration", desired)),
        None => config.chains().first().ok_or_else(|| {
            anyhow!("No chains configured. Run `interfold ciphernode setup` first.")
        }),
    }
}

fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).context("Invalid address in configuration")
}
