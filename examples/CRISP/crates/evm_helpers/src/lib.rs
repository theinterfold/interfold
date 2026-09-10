// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, Bytes, B256, I256, U256},
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
    transports::RpcError,
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
        function finalizeInput(
            uint256 e3Id,
            address slotAddress,
            bytes32 encryptedVoteCommitment,
            bytes32 encryptedVoteHash,
            uint40 parentIndexPlusOne,
            bytes availabilityProof
        ) external;
        function validateInputProof(
            uint256 e3Id,
            bytes noirProof,
            address slotAddress,
            bytes32 encryptedVoteCommitment,
            bytes32 encryptedVoteHash,
            uint40 parentIndexPlusOne
        ) external view returns (bool);
        function isInputPublished(
            uint256 e3Id,
            bytes32 encryptedVoteHash,
            bytes32 commitment,
            address slotAddress,
            uint40 parentIndexPlusOne
        ) external view returns (bool);
        function isInputCommitted(
            uint256 e3Id,
            bytes32 encryptedVoteHash,
            bytes32 commitment,
            address slotAddress,
            uint40 parentIndexPlusOne
        ) external view returns (bool);
        function inputId(
            uint256 e3Id,
            bytes32 encryptedVoteHash,
            bytes32 commitment,
            address slotAddress,
            uint40 parentIndexPlusOne
        ) external view returns (bytes32);
        function inputAvailabilityDigest(uint256 e3Id, bytes32 inputId, uint64 expiresAt) external view returns (bytes32);
        function inputAvailabilitySigner() external view returns (address);
        function INPUT_AVAILABILITY_ATTESTATION_TTL() external view returns (uint64);
        function availabilityFinalizationWindow() external view returns (uint256);
        function MIN_VOTING_DURATION() external view returns (uint256);
        function pendingInputCount(uint256 e3Id) external view returns (uint40);
        function inputCommitmentDeadline(uint256 e3Id) external view returns (uint256);
        function verify(
            uint256 e3Id,
            bytes32 ciphertextOutputHash,
            bytes32 ciphertextCommitment,
            bytes proof
        ) external view returns (bool);
        function getRoundData(uint256 e3_id) external view returns (uint256 merkleRoot, bytes32 paramsHash, uint256 numOptions, uint8 creditMode, uint256 inputRoot, uint40 numberOfVotes);
    }

    #[sol(rpc)]
    contract CiphernodeRegistryTiming {
        function randomnessRequestTimeout() external view returns (uint256);
        function sortitionSubmissionWindow() external view returns (uint256);
    }
}

sol! {
    event InputCommitted(
        uint256 indexed e3Id,
        bytes32 indexed inputId,
        address indexed slotAddress,
        bytes32 encryptedVoteCommitment,
        bytes32 encryptedVoteHash,
        uint40 parentIndexPlusOne,
        uint40 index
    );

    event InputPublished(
        uint256 indexed e3Id,
        address indexed slotAddress,
        bytes32 encryptedVoteCommitment,
        bytes32 encryptedVoteHash,
        uint32 availabilityBlock,
        uint128 availabilityLeafIndex,
        uint256 index,
        uint40 parentIndexPlusOne
    );
}

/// Why a `publishInput` dry run failed.
///
/// The two kinds blame different parties, and the relay maps them to different HTTP answers: a
/// revert is the caller's input and final, a provider failure judged nothing and is retryable.
#[derive(Debug)]
pub enum SimulateError {
    /// The node evaluated the call and the contract refused the input.
    Reverted(String),
    /// The node could not evaluate the call — transport, timeout, or RPC failure. Says nothing
    /// about whether the input is valid.
    Provider(String),
}

impl std::fmt::Display for SimulateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reverted(message) => write!(f, "contract simulation reverted: {message}"),
            Self::Provider(message) => write!(f, "contract simulation unavailable: {message}"),
        }
    }
}

impl std::error::Error for SimulateError {}

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

        eyre::ensure!(receipt.status(), "setMerkleRoot transaction reverted");

        Ok(receipt)
    }

    /// Read the Merkle root already stored for a round.
    pub async fn get_merkle_root(&self, e3_id: U256) -> Result<U256> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        let round = contract.getRoundData(e3_id).call().await?;

        Ok(round.merkleRoot)
    }

    /// Dry-run `publishInput` as an `eth_call` from the relay's own account.
    ///
    /// The relay signs and pays for whatever it is handed, so an input that would revert — a bad
    /// proof, a stale parent, a closed window — must be refused before it costs a transaction.
    /// The two failure kinds are kept apart because they blame different parties: a revert is the
    /// caller's input, a provider failure is the relay's node, and a caller must not be told
    /// their vote is invalid because an RPC timed out.
    pub async fn simulate_publish_input(
        &self,
        e3_id: U256,
        data: Bytes,
    ) -> Result<(), SimulateError> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());

        match contract.publishInput(e3_id, data).call().await {
            Ok(_) => Ok(()),
            Err(alloy::contract::Error::TransportError(RpcError::ErrorResp(payload))) => {
                // The node evaluated the call and answered with an error. Revert data — or a
                // revert-shaped message where a node strips the data — means the contract refused
                // the input. Anything else (rate limits, method errors) is the provider's problem.
                let message = payload.to_string();
                if payload.as_revert_data().is_some() || message.to_lowercase().contains("revert") {
                    Err(SimulateError::Reverted(message))
                } else {
                    Err(SimulateError::Provider(message))
                }
            }
            Err(e) => Err(SimulateError::Provider(e.to_string())),
        }
    }

    /// Dry-run `finalizeInput` before the relay pays for the transaction.
    pub async fn simulate_finalize_input(
        &self,
        e3_id: U256,
        slot_address: Address,
        encrypted_vote_commitment: B256,
        encrypted_vote_hash: B256,
        parent_index_plus_one: u64,
        availability_proof: Bytes,
    ) -> Result<(), SimulateError> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        match contract
            .finalizeInput(
                e3_id,
                slot_address,
                encrypted_vote_commitment,
                encrypted_vote_hash,
                alloy::primitives::Uint::<40, 1>::from(parent_index_plus_one),
                availability_proof,
            )
            .call()
            .await
        {
            Ok(_) => Ok(()),
            Err(alloy::contract::Error::TransportError(RpcError::ErrorResp(payload))) => {
                let message = payload.to_string();
                if payload.as_revert_data().is_some() || message.to_lowercase().contains("revert") {
                    Err(SimulateError::Reverted(message))
                } else {
                    Err(SimulateError::Provider(message))
                }
            }
            Err(error) => Err(SimulateError::Provider(error.to_string())),
        }
    }

    /// Check a ballot before its ciphertext is published to the DA layer.
    pub async fn validate_input_proof(
        &self,
        e3_id: U256,
        noir_proof: Bytes,
        slot_address: Address,
        encrypted_vote_commitment: B256,
        encrypted_vote_hash: B256,
        parent_index_plus_one: u64,
    ) -> Result<(), SimulateError> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        match contract
            .validateInputProof(
                e3_id,
                noir_proof,
                slot_address,
                encrypted_vote_commitment,
                encrypted_vote_hash,
                alloy::primitives::Uint::<40, 1>::from(parent_index_plus_one),
            )
            .call()
            .await
        {
            Ok(_) => Ok(()),
            Err(alloy::contract::Error::TransportError(RpcError::ErrorResp(payload))) => {
                let message = payload.to_string();
                if payload.as_revert_data().is_some() || message.to_lowercase().contains("revert") {
                    Err(SimulateError::Reverted(message))
                } else {
                    Err(SimulateError::Provider(message))
                }
            }
            Err(error) => Err(SimulateError::Provider(error.to_string())),
        }
    }

    /// Check whether an availability relay already submitted this exact input.
    pub async fn is_input_published(
        &self,
        e3_id: U256,
        encrypted_vote_hash: B256,
        commitment: B256,
        slot_address: Address,
        parent_index_plus_one: u64,
    ) -> Result<bool> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract
            .isInputPublished(
                e3_id,
                encrypted_vote_hash,
                commitment,
                slot_address,
                alloy::primitives::Uint::<40, 1>::from(parent_index_plus_one),
            )
            .call()
            .await?)
    }

    /// Check whether the proof commitment for an exact input is already on chain.
    pub async fn is_input_committed(
        &self,
        e3_id: U256,
        encrypted_vote_hash: B256,
        commitment: B256,
        slot_address: Address,
        parent_index_plus_one: u64,
    ) -> Result<bool> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract
            .isInputCommitted(
                e3_id,
                encrypted_vote_hash,
                commitment,
                slot_address,
                alloy::primitives::Uint::<40, 1>::from(parent_index_plus_one),
            )
            .call()
            .await?)
    }

    /// Read the CRISP-specific voter cutoff through the write provider used by the relay.
    pub async fn input_commitment_deadline(&self, e3_id: U256) -> Result<u64> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract
            .inputCommitmentDeadline(e3_id)
            .call()
            .await?
            .try_into()?)
    }

    /// Read the exact EIP-712 digest that the configured availability signer must attest.
    pub async fn input_availability_digest(
        &self,
        e3_id: U256,
        encrypted_vote_hash: B256,
        commitment: B256,
        slot_address: Address,
        parent_index_plus_one: u64,
        expires_at: u64,
    ) -> Result<B256> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        let parent = alloy::primitives::Uint::<40, 1>::from(parent_index_plus_one);
        let input_id = contract
            .inputId(e3_id, encrypted_vote_hash, commitment, slot_address, parent)
            .call()
            .await?;
        Ok(contract
            .inputAvailabilityDigest(e3_id, input_id, expires_at)
            .call()
            .await?)
    }

    /// Read the maximum lifetime of an input availability promise.
    pub async fn input_availability_attestation_ttl(&self) -> Result<u64> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract.INPUT_AVAILABILITY_ATTESTATION_TTL().call().await?)
    }

    /// Confirm that this relay's key is the signer frozen into the CRISP deployment.
    pub async fn input_availability_signer(&self) -> Result<Address> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract.inputAvailabilitySigner().call().await?)
    }

    pub async fn availability_finalization_window(&self) -> Result<U256> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract.availabilityFinalizationWindow().call().await?)
    }

    pub async fn minimum_voting_duration(&self) -> Result<U256> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract.MIN_VOTING_DURATION().call().await?)
    }

    pub async fn committee_setup_windows(&self, registry: Address) -> Result<(U256, U256)> {
        let registry = CiphernodeRegistryTiming::new(registry, self.provider.as_ref());
        Ok((
            registry.randomnessRequestTimeout().call().await?,
            registry.sortitionSubmissionWindow().call().await?,
        ))
    }

    /// Check the aggregate ciphertext and its compute proof before paying to publish it to DA.
    ///
    /// This calls the same CRISP verifier that Interfold calls after the availability receipt is
    /// ready. The earlier check prevents an unauthenticated or malformed webhook from spending
    /// the server's Avail balance on bytes that can never be accepted on Ethereum.
    pub async fn validate_compute_output(
        &self,
        e3_id: U256,
        ciphertext_output_hash: B256,
        ciphertext_commitment: B256,
        proof: Bytes,
    ) -> Result<()> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        let accepted = contract
            .verify(e3_id, ciphertext_output_hash, ciphertext_commitment, proof)
            .call()
            .await?;
        eyre::ensure!(accepted, "CRISP rejected the aggregate ciphertext proof");
        Ok(())
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

        eyre::ensure!(receipt.status(), "publishInput transaction reverted");

        Ok(receipt)
    }

    /// Finalize an input after its Avail receipt is available.
    pub async fn finalize_input(
        &self,
        e3_id: U256,
        slot_address: Address,
        encrypted_vote_commitment: B256,
        encrypted_vote_hash: B256,
        parent_index_plus_one: u64,
        availability_proof: Bytes,
    ) -> Result<TransactionReceipt> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        let receipt = contract
            .finalizeInput(
                e3_id,
                slot_address,
                encrypted_vote_commitment,
                encrypted_vote_hash,
                alloy::primitives::Uint::<40, 1>::from(parent_index_plus_one),
                availability_proof,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        eyre::ensure!(receipt.status(), "finalizeInput transaction reverted");

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

    /// The number of inputs `CRISPProgram` accepted for a round.
    ///
    /// The authority on how many there are. An indexer's own count can be short because the last
    /// finalization log can still be in flight when the deadline callback runs. Computing then
    /// would tally a subset and derive a root the contract rejects.
    pub async fn get_published_input_count(&self, e3_id: U256) -> Result<u64> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.clone());
        let round = contract.getRoundData(e3_id).call().await?;

        Ok(round.numberOfVotes.to::<u64>())
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

    /// Read the CRISP-specific voter cutoff. The Interfold input deadline remains later so
    /// already committed inputs can finish data-availability finalization.
    pub async fn input_commitment_deadline(&self, e3_id: U256) -> Result<u64> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract
            .inputCommitmentDeadline(e3_id)
            .call()
            .await?
            .try_into()?)
    }

    /// Number of accepted input proofs still waiting for a verified availability receipt.
    pub async fn pending_input_count(&self, e3_id: U256) -> Result<u64> {
        let contract = CRISPProgram::new(self.contract_address, self.provider.as_ref());
        Ok(contract.pendingInputCount(e3_id).call().await?.to::<u64>())
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
