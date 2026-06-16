// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, Bytes, I256, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, ProviderBuilder, RootProvider,
    },
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use std::sync::Arc;

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract CRISPProgram {
        function setMerkleRoot(uint256 e3_id, uint256 _root) external;
        function getSlotIndex(uint256 e3_id, address slot_address) external view returns (int256);
        function publishInput(uint256 e3_id, bytes data) external;
    }
}

sol! {
    event InputPublished(uint256 indexed e3Id, bytes encryptedVote, uint256 index);
}

/// Type alias for read-only provider (no wallet)
pub type CRISPReadProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider<Ethereum>,
    Ethereum,
>;

/// Type alias for write provider (same as InterfoldWriteProvider)
pub type CRISPWriteProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<Ethereum>,
    Ethereum,
>;

/// CRISP contract instance for interacting with CRISPProgram
#[derive(Clone)]
pub struct CRISPContract<P = CRISPWriteProvider> {
    provider: Arc<P>,
    contract_address: Address,
}

impl CRISPContract<CRISPWriteProvider> {
    /// Create a new CRISP contract instance with write capabilities
    pub async fn new(
        http_rpc_url: &str,
        private_key: &str,
        contract_address: &str,
    ) -> Result<Self> {
        let contract_address = contract_address.parse()?;
        let signer: PrivateKeySigner = private_key.parse()?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(http_rpc_url)
            .await?;

        Ok(CRISPContract {
            provider: Arc::new(provider),
            contract_address,
        })
    }

    /// Set Merkle root on the CRISPProgram contract
    pub async fn set_merkle_root(
        &self,
        e3_id: U256,
        merkle_root: U256,
    ) -> Result<TransactionReceipt> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        let receipt = contract
            .setMerkleRoot(e3_id, merkle_root)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    // publish an input to the CRISPProgram contract
    pub async fn publish_input(&self, e3_id: U256, data: Bytes) -> Result<TransactionReceipt> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        let receipt = contract
            .publishInput(e3_id, data)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}

impl CRISPContract<CRISPReadProvider> {
    /// Create a read-only CRISP contract instance (no private key required)
    pub async fn new_read_only(http_rpc_url: &str, contract_address: &str) -> Result<Self> {
        let contract_address = contract_address.parse()?;
        let provider = ProviderBuilder::new().connect(http_rpc_url).await?;

        Ok(CRISPContract {
            provider: Arc::new(provider),
            contract_address,
        })
    }

    /// Get the slot index from a given slot address.
    /// Returns `None` when the slot is empty (contract returns -1).
    pub async fn get_slot_index_from_address(
        &self,
        e3_id: U256,
        slot_address: Address,
    ) -> Result<Option<u64>> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());

        match contract.getSlotIndex(e3_id, slot_address).call().await {
            Ok(slot_index) => {
                if slot_index < I256::ZERO {
                    Ok(None)
                } else {
                    Ok(Some(slot_index.as_u64()))
                }
            }
            Err(e) => Err(eyre::eyre!("Failed to get slot index: {}", e)),
        }
    }
}

impl<P> CRISPContract<P> {
    /// Get the contract address
    pub fn address(&self) -> &Address {
        &self.contract_address
    }
}

/// Factory for creating CRISP contract instances
pub struct CRISPContractFactory;

impl CRISPContractFactory {
    /// Create a write-capable contract
    pub async fn create_write(
        http_rpc_url: &str,
        contract_address: &str,
        private_key: &str,
    ) -> Result<CRISPContract<CRISPWriteProvider>> {
        CRISPContract::new(http_rpc_url, private_key, contract_address).await
    }

    pub async fn create_read(
        http_rpc_url: &str,
        contract_address: &str,
    ) -> Result<CRISPContract<CRISPReadProvider>> {
        CRISPContract::new_read_only(http_rpc_url, contract_address).await
    }
}
