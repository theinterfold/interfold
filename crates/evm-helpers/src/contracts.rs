// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::providers::fillers::BlobGasFiller;
use alloy::sol_types::SolValue;
use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, Bytes, B256, U256},
    providers::fillers::{
        ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    providers::{Identity, Provider, ProviderBuilder, RootProvider},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
};
use async_trait::async_trait;
use eyre::Result;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::events::E3Requested;

static NONCE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn crypto_config_id_for_param_set(param_set: u8) -> Result<B256> {
    match param_set {
        0 => Ok("0x04f3677e73b0f5066d6caf5cbd92e3fb2e38338edaf5cfc971ab28f7b684da78".parse()?),
        1 => Ok("0xd9c86e581f8291ffb5b63595600e8d096ed30b16e2e0a6634a76c22b1f58fb4e".parse()?),
        _ => Err(eyre::eyre!("unsupported BFV parameter set: {}", param_set)),
    }
}

/// Get the next pending nonce for a given address from the provider
async fn get_next_nonce<P>(provider: &P, address: Address) -> eyre::Result<u64>
where
    P: Provider<Ethereum> + Send + Sync,
{
    provider
        .get_transaction_count(address)
        .pending()
        .await
        .map_err(Into::into)
}

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    enum CommitteeSize {
        Minimum,
        Micro,
        Small,
    }

    #[derive(Debug)]
    struct E3 {
        uint256 seed;
        CommitteeSize committeeSize;
        uint256 requestBlock;
        uint256[2] inputWindow;
        bytes32 encryptionSchemeId;
        address e3Program;
        uint8 paramSet;
        bytes customParams;
        address decryptionVerifier;
        address pkVerifier;
        bytes32 committeePublicKey;
        bytes32 ciphertextOutput;
        bytes plaintextOutput;
        address requester;
        bytes32 ciphertextCommitment;
    }

    #[derive(Debug)]
    struct E3RequestParams {
        CommitteeSize committeeSize;
        uint256[2] inputWindow;
        address e3Program;
        uint8 paramSet;
        bytes computeProviderParams;
        bytes customParams;
        address expectedFeeToken;
        bytes32 expectedCryptoConfigId;
        uint256 maxFee;
    }

    #[derive(Debug, PartialEq)]
    enum E3Stage {
        None,
        Requested,
        CommitteeFinalized,
        KeyPublished,
        CiphertextReady,
        Complete,
        Failed
    }

    #[derive(Debug, PartialEq)]
    enum FailureReason {
        None,
        CommitteeFormationTimeout,
        InsufficientCommitteeMembers,
        DKGTimeout,
        DKGInvalidShares,
        NoInputsReceived,
        ComputeTimeout,
        ComputeProviderExpired,
        ComputeProviderFailed,
        RequesterCancelled,
        DecryptionTimeout,
        DecryptionInvalidShares,
        VerificationFailed
    }

    #[derive(Debug)]
    struct E3TimeoutConfig {
        uint256 dkgWindow;
        uint256 computeWindow;
        uint256 decryptionWindow;
    }

    #[derive(Debug)]
    struct E3Deadlines {
        uint256 dkgDeadline;
        uint256 computeDeadline;
        uint256 decryptionDeadline;
    }

    struct CiphertextOutputReference {
        bytes32 contentHash;
        bytes32 ciphertextCommitment;
        bytes computeProof;
        bytes availabilityProof;
    }


    #[derive(Debug)]
    #[sol(rpc)]
    contract Interfold {
        uint256 public nexte3Id = 0;
        mapping(address e3Program => bool allowed) public e3Programs;
        function request(E3RequestParams calldata requestParams) external returns (uint256 e3Id, E3 memory e3);
        function registerE3Program(address e3Program) public;
        function publishCiphertextOutput(
            uint256 e3Id,
            bytes calldata encodedOutputReference
        ) external;
        function publishPlaintextOutput(uint256 e3Id, bytes calldata data, bytes calldata proof) external returns (bool success);
        function getE3(uint256 e3Id) external view returns (E3 memory e3);
        function paramSetRegistry(uint8 paramSet) external view returns (bytes memory encodedParams);
        function getE3Quote(E3RequestParams memory request) external view returns (uint256 fee);
        function getE3Stage(uint256 e3Id) external view returns (E3Stage stage);
        function getFailureReason(uint256 e3Id) external view returns (FailureReason reason);
        function getRequester(uint256 e3Id) external view returns (address requester);
        function getDeadlines(uint256 e3Id) external view returns (E3Deadlines memory deadlines);
        function getTimeoutConfig() external view returns (E3TimeoutConfig memory config);
        function feeToken() external view returns (address token);
        function activeCryptoConfigId() external pure returns (bytes32 configId);
        function e3CryptoConfigIds(uint256 e3Id) external view returns (bytes32 configId);
    }
}

/// Trait for read-only operations on the Interfold contract
#[async_trait]
pub trait InterfoldRead {
    /// Get the next E3 ID
    async fn get_e3_id(&self) -> Result<U256>;

    /// Get the details of an E3 by ID
    async fn get_e3(&self, e3_id: U256) -> Result<E3>;

    /// Get the latest block number
    async fn get_latest_block(&self) -> Result<u64>;

    /// Check if an E3 program is enabled
    async fn is_e3_program_enabled(&self, e3_program: Address) -> Result<bool>;

    /// Get the fee quote for an E3 request
    async fn get_e3_quote(
        &self,
        committee_size: CommitteeSize,
        input_window: [U256; 2],
        e3_program: Address,
        param_set: u8,
        compute_provider_params: Bytes,
    ) -> Result<U256>;

    async fn get_e3_stage(&self, e3_id: U256) -> Result<E3Stage>;

    async fn get_failure_reason(&self, e3_id: U256) -> Result<FailureReason>;

    async fn get_requester(&self, e3_id: U256) -> Result<Address>;

    async fn get_deadlines(&self, e3_id: U256) -> Result<E3Deadlines>;

    async fn get_timeout_config(&self) -> Result<E3TimeoutConfig>;

    /// Read the circuit configuration frozen for an E3 request.
    async fn get_e3_crypto_config_id(&self, e3_id: U256) -> Result<B256>;

    /// Look up the ABI-encoded BFV parameters for a param set index
    async fn get_param_set_registry(&self, param_set: u8) -> Result<Bytes>;
}

/// Trait for write operations on the Interfold contract
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait InterfoldWrite {
    /// Request a new E3
    async fn request_e3(
        &self,
        committee_size: CommitteeSize,
        input_window: [U256; 2],
        e3_program: Address,
        param_set: u8,
        compute_provider_params: Bytes,
        custom_params: Bytes,
    ) -> Result<(TransactionReceipt, U256)>;

    /// Enable an E3 program
    async fn register_e3_program(&self, e3_program: Address) -> Result<TransactionReceipt>;

    /// Publish an externally available ciphertext output and its verified receipt.
    async fn publish_ciphertext_output(
        &self,
        e3_id: U256,
        ciphertext_output_hash: B256,
        ciphertext_commitment: B256,
        compute_proof: Bytes,
        availability_proof: Bytes,
    ) -> Result<TransactionReceipt>;

    /// Publish plaintext output
    async fn publish_plaintext_output(
        &self,
        e3_id: U256,
        data: Bytes,
        proof: Bytes,
    ) -> Result<TransactionReceipt>;
}

/// Generic type to represent different provider types
pub trait ProviderType: Clone + Send + Sync + 'static {
    type Provider: Provider + Clone + Send + Sync + 'static;
}

/// Marker type for read-only provider
#[derive(Clone)]
pub struct ReadOnly;
impl ProviderType for ReadOnly {
    type Provider = InterfoldReadOnlyProvider;
}
/// Marker type for read-write provider
#[derive(Clone)]
pub struct ReadWrite;
impl ProviderType for ReadWrite {
    type Provider = InterfoldWriteProvider;
}

/// Generic Interfold contract
#[derive(Clone)]
pub struct InterfoldContract<T: ProviderType> {
    pub provider: Arc<T::Provider>,
    pub contract_address: Address,
    pub wallet_address: Option<Address>,
    _marker: PhantomData<T>,
}

impl<R: ProviderType> InterfoldContract<R> {
    pub fn address(&self) -> &Address {
        &self.contract_address
    }
    pub fn get_provider(&self) -> Arc<R::Provider> {
        self.provider.clone()
    }
}

impl InterfoldContract<ReadWrite> {
    pub async fn new(
        http_rpc_url: &str,
        private_key: &str,
        contract_address: &str,
    ) -> Result<InterfoldContract<ReadWrite>> {
        InterfoldContractFactory::create_write(http_rpc_url, contract_address, private_key).await
    }
}

impl InterfoldContract<ReadOnly> {
    pub async fn read_only(
        http_rpc_url: &str,
        contract_address: &str,
    ) -> Result<InterfoldContract<ReadOnly>> {
        InterfoldContractFactory::create_read(http_rpc_url, contract_address).await
    }
}

/// Type alias for read-only provider
pub type InterfoldReadOnlyProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

/// Type alias for read-write provider
pub type InterfoldWriteProvider = FillProvider<
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

/// Type aliases for the two contract variants
pub type InterfoldReadContract = InterfoldContract<ReadOnly>;
pub type InterfoldWriteContract = InterfoldContract<ReadWrite>;

// Factory for creating contract instances
pub struct InterfoldContractFactory;

impl InterfoldContractFactory {
    /// Create a write-capable contract
    pub async fn create_write(
        rpc_url: &str,
        contract_address: &str,
        private_key: &str,
    ) -> Result<InterfoldContract<ReadWrite>> {
        let contract_address = contract_address.parse()?;

        let signer: PrivateKeySigner = private_key.parse()?;
        let wallet_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(rpc_url)
            .await?;

        Ok(InterfoldContract::<ReadWrite> {
            provider: Arc::new(provider),
            contract_address,
            wallet_address: Some(wallet_address),
            _marker: PhantomData,
        })
    }

    /// Create a read-only contract
    pub async fn create_read(
        rpc_url: &str,
        contract_address: &str,
    ) -> Result<InterfoldContract<ReadOnly>> {
        let contract_address = contract_address.parse()?;

        let provider = ProviderBuilder::new().connect(rpc_url).await?;

        Ok(InterfoldContract::<ReadOnly> {
            provider: Arc::new(provider),
            contract_address,
            wallet_address: None,
            _marker: PhantomData,
        })
    }
}

// Implement InterfoldRead for any InterfoldContract regardless of provider type
#[async_trait]
impl<T: Send + Sync> InterfoldRead for InterfoldContract<T>
where
    T: ProviderType,
{
    async fn get_e3_id(&self) -> Result<U256> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let e3_id = contract.nexte3Id().call().await?;
        Ok(e3_id)
    }

    async fn get_e3(&self, e3_id: U256) -> Result<E3> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let e3_return = contract.getE3(e3_id).call().await?;
        Ok(e3_return)
    }

    async fn get_latest_block(&self) -> Result<u64> {
        let block = self.provider.get_block_number().await?;
        Ok(block)
    }

    async fn is_e3_program_enabled(&self, e3_program: Address) -> Result<bool> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let enabled = contract.e3Programs(e3_program).call().await?;
        Ok(enabled)
    }

    async fn get_e3_quote(
        &self,
        committee_size: CommitteeSize,
        input_window: [U256; 2],
        e3_program: Address,
        param_set: u8,
        compute_provider_params: Bytes,
    ) -> Result<U256> {
        let e3_request = E3RequestParams {
            committeeSize: committee_size,
            inputWindow: input_window,
            e3Program: e3_program,
            paramSet: param_set,
            computeProviderParams: compute_provider_params,
            customParams: Bytes::new(),
            expectedFeeToken: Address::ZERO,
            expectedCryptoConfigId: B256::ZERO,
            maxFee: U256::ZERO,
        };

        let contract = Interfold::new(self.contract_address, &self.provider);
        let fee = contract.getE3Quote(e3_request).call().await?;
        Ok(fee)
    }

    async fn get_e3_stage(&self, e3_id: U256) -> Result<E3Stage> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let stage = contract.getE3Stage(e3_id).call().await?;
        Ok(stage)
    }

    async fn get_failure_reason(&self, e3_id: U256) -> Result<FailureReason> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let reason = contract.getFailureReason(e3_id).call().await?;
        Ok(reason)
    }

    async fn get_requester(&self, e3_id: U256) -> Result<Address> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let requester = contract.getRequester(e3_id).call().await?;
        Ok(requester)
    }

    async fn get_deadlines(&self, e3_id: U256) -> Result<E3Deadlines> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let deadlines = contract.getDeadlines(e3_id).call().await?;
        Ok(deadlines)
    }

    async fn get_timeout_config(&self) -> Result<E3TimeoutConfig> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let config = contract.getTimeoutConfig().call().await?;
        Ok(config)
    }

    async fn get_e3_crypto_config_id(&self, e3_id: U256) -> Result<B256> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        Ok(contract.e3CryptoConfigIds(e3_id).call().await?)
    }

    async fn get_param_set_registry(&self, param_set: u8) -> Result<Bytes> {
        let contract = Interfold::new(self.contract_address, &self.provider);
        let params = contract.paramSetRegistry(param_set).call().await?;
        Ok(params)
    }
}

// Implement InterfoldWrite only for contracts with ReadWrite marker
#[async_trait]
impl InterfoldWrite for InterfoldContract<ReadWrite> {
    async fn request_e3(
        &self,
        committee_size: CommitteeSize,
        input_window: [U256; 2],
        e3_program: Address,
        param_set: u8,
        compute_provider_params: Bytes,
        custom_params: Bytes,
    ) -> Result<(TransactionReceipt, U256)> {
        let _guard = NONCE_LOCK.lock().await;
        let wallet_addr = self
            .wallet_address
            .ok_or_else(|| eyre::eyre!("No wallet address configured"))?;
        let nonce = get_next_nonce(&*self.provider, wallet_addr).await?;

        let contract = Interfold::new(self.contract_address, &self.provider);
        let fee_token = contract.feeToken().call().await?;
        let crypto_config_id = crypto_config_id_for_param_set(param_set)?;

        let quote_request = E3RequestParams {
            committeeSize: committee_size,
            inputWindow: input_window,
            e3Program: e3_program,
            paramSet: param_set,
            computeProviderParams: compute_provider_params.clone(),
            customParams: custom_params.clone(),
            expectedFeeToken: fee_token,
            expectedCryptoConfigId: crypto_config_id,
            maxFee: U256::MAX,
        };
        let max_fee = contract.getE3Quote(quote_request).call().await?;
        let e3_request = E3RequestParams {
            committeeSize: committee_size,
            inputWindow: input_window,
            e3Program: e3_program,
            paramSet: param_set,
            computeProviderParams: compute_provider_params,
            customParams: custom_params,
            expectedFeeToken: fee_token,
            expectedCryptoConfigId: crypto_config_id,
            maxFee: max_fee,
        };

        let builder = contract.request(e3_request).nonce(nonce);
        let receipt = builder.send().await?.get_receipt().await?;
        e3_utils::require_successful_receipt("request E3", &receipt)?;
        let e3_id = receipt
            .logs()
            .iter()
            .filter(|log| log.address() == self.contract_address)
            .find_map(|log| log.log_decode::<E3Requested>().ok())
            .map(|log| log.inner.data.e3Id)
            .ok_or_else(|| eyre::eyre!("request E3 receipt is missing E3Requested"))?;

        Ok((receipt, e3_id))
    }

    async fn register_e3_program(&self, e3_program: Address) -> Result<TransactionReceipt> {
        let _guard = NONCE_LOCK.lock().await;
        let wallet_addr = self
            .wallet_address
            .ok_or_else(|| eyre::eyre!("No wallet address configured"))?;
        let nonce = get_next_nonce(&*self.provider, wallet_addr).await?;

        let contract = Interfold::new(self.contract_address, &self.provider);
        let builder = contract.registerE3Program(e3_program).nonce(nonce);
        let receipt = builder.send().await?.get_receipt().await?;
        e3_utils::require_successful_receipt("register E3 program", &receipt)?;

        Ok(receipt)
    }

    async fn publish_ciphertext_output(
        &self,
        e3_id: U256,
        ciphertext_output_hash: B256,
        ciphertext_commitment: B256,
        compute_proof: Bytes,
        availability_proof: Bytes,
    ) -> Result<TransactionReceipt> {
        let _guard = NONCE_LOCK.lock().await;
        let wallet_addr = self
            .wallet_address
            .ok_or_else(|| eyre::eyre!("No wallet address configured"))?;
        let nonce = get_next_nonce(&*self.provider, wallet_addr).await?;

        let contract = Interfold::new(self.contract_address, &self.provider);
        let output_reference = CiphertextOutputReference {
            contentHash: ciphertext_output_hash,
            ciphertextCommitment: ciphertext_commitment,
            computeProof: compute_proof,
            availabilityProof: availability_proof,
        };
        let receipt = contract
            .publishCiphertextOutput(e3_id, output_reference.abi_encode().into())
            .nonce(nonce)
            .send()
            .await?
            .get_receipt()
            .await?;
        e3_utils::require_successful_receipt("publish ciphertext output", &receipt)?;
        Ok(receipt)
    }

    async fn publish_plaintext_output(
        &self,
        e3_id: U256,
        data: Bytes,
        proof: Bytes,
    ) -> Result<TransactionReceipt> {
        let _guard = NONCE_LOCK.lock().await;
        let wallet_addr = self
            .wallet_address
            .ok_or_else(|| eyre::eyre!("No wallet address configured"))?;
        let nonce = get_next_nonce(&*self.provider, wallet_addr).await?;

        let contract = Interfold::new(self.contract_address, &self.provider);
        let builder = contract
            .publishPlaintextOutput(e3_id, data, proof)
            .nonce(nonce);
        let receipt = builder.send().await?.get_receipt().await?;
        e3_utils::require_successful_receipt("publish plaintext output", &receipt)?;

        Ok(receipt)
    }
}
