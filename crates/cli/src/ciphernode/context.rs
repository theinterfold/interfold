// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::str::FromStr;

use alloy::{primitives::Address, providers::WalletProvider};
use anyhow::{Context, Result};
use e3_config::{AppConfig, ContractAddresses};
use e3_crypto::Cipher;
use e3_entrypoint::helpers::datastore::get_repositories;
use e3_evm::{
    fetch_operator_committees,
    helpers::{load_signer_from_repository, ConcreteWriteProvider, EthProvider, ProviderConfig},
    CommitteeScan, EthPrivateKeyRepositoryFactory, OperatorCommittee,
};

use e3_evm_contracts::{IBondingRegistry, IERC20Metadata, IInterfoldTicketToken};

use crate::helpers::chain::select_chain;

/// Directory under the node data directory for the saved committee obligation scans.
const COMMITTEE_SCAN_DIR: &str = "committee-scans";

pub(crate) struct ChainContext {
    chain_label: String,
    bonding_registry: Address,
    contracts: ContractAddresses,
    provider: EthProvider<ConcreteWriteProvider>,
    signer_address: Address,
    /// How `ciphernode status` reads the committee obligation history.
    committee_scan: CommitteeScan,
}

impl ChainContext {
    pub(crate) async fn new(config: &AppConfig, selection: Option<&str>) -> Result<Self> {
        let chain = select_chain(config, selection)?;
        let bonding_registry = parse_address(chain.contracts.bonding_registry.address_str())?;

        let cipher = Cipher::from_file(config.key_file()).await?;
        let repositories = get_repositories(config)?;
        let signer = load_signer_from_repository(repositories.eth_private_key(), &cipher).await?;
        let provider = ProviderConfig::for_chain(chain)?
            .create_signer_provider(&signer)
            .await?;
        let signer_address = provider.provider().default_signer_address();

        let label = selection.unwrap_or(chain.name.as_str()).to_string();

        Ok(Self {
            chain_label: label,
            bonding_registry,
            contracts: chain.contracts.clone(),
            provider,
            signer_address,
            committee_scan: CommitteeScan {
                max_log_window: chain.rpc_log_range_blocks()?,
                confirmations: chain.ingestion_confirmations()?,
                cache_dir: Some(config.node_data_dir().join(COMMITTEE_SCAN_DIR)),
            },
        })
    }

    fn provider_client(&self) -> ConcreteWriteProvider {
        self.provider.provider().clone()
    }

    pub(crate) fn bonding(
        &self,
    ) -> IBondingRegistry::IBondingRegistryInstance<ConcreteWriteProvider> {
        IBondingRegistry::new(self.bonding_registry, self.provider_client())
    }

    pub(crate) fn operator(&self) -> Address {
        self.signer_address
    }

    pub(crate) fn provider(&self) -> &EthProvider<ConcreteWriteProvider> {
        &self.provider
    }

    pub(crate) fn resolve_operator(&self, operator: Option<&str>) -> Result<Address> {
        operator
            .map(parse_address)
            .unwrap_or(Ok(self.signer_address))
    }

    pub(crate) fn bonding_registry(&self) -> Address {
        self.bonding_registry
    }

    pub(crate) fn chain_label(&self) -> &str {
        &self.chain_label
    }

    pub(crate) async fn ciphernode_bond_token_address(&self) -> Result<Address> {
        Ok(self.bonding().getCiphernodeBondToken().call().await?)
    }

    pub(crate) async fn ticket_token_address(&self) -> Result<Address> {
        Ok(self.bonding().getTicketToken().call().await?)
    }

    pub(crate) async fn ticket_underlying_address(&self) -> Result<Address> {
        Ok(
            IInterfoldTicketToken::new(self.ticket_token_address().await?, self.provider_client())
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

    pub(crate) async fn operator_committees(
        &self,
        operator: Address,
    ) -> Result<Vec<OperatorCommittee>> {
        fetch_operator_committees(
            &self.provider_client(),
            &self.contracts,
            operator,
            &self.committee_scan,
        )
        .await
    }
}

pub(crate) fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).context("Invalid EVM address")
}
