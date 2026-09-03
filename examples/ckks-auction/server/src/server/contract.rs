// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `CkksAuctionE3Program` bindings + the ciphertext-from-calldata recovery (CRISP `evm_helpers`).

use alloy::consensus::Transaction as _;
use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use eyre::{eyre, Result};

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract CkksAuctionE3Program {
        function setBalanceRoot(uint256 e3Id, bytes32 root) external;
        function balanceRoots(uint256 e3Id) external view returns (bytes32);
        function bidCap() external view returns (uint256);
        function submissionCount(uint256 e3Id) external view returns (uint256);
        function publishInput(uint256 e3Id, bytes data) external;
    }

    /// Emitted by `CkksAppE3ProgramBase._publishThreeLegInput` once all three Honk proofs
    /// verified and the commitments bound.
    #[derive(Debug)]
    event VerifiedInputPublished(
        uint256 indexed e3Id,
        address indexed publisher,
        bytes32 ciphertextHash,
        bytes32 ct0Commitment,
        bytes32 ct1Commitment,
        bytes32 mCommitment,
        bytes32 uCommitment
    );

    /// `abi.encode(bytes ct, bytes ct0P, bytes32[] ct0Pub, bytes ct1P, bytes32[] ct1Pub, bytes appP, bytes32[] appPub)`
    struct ThreeLegEnvelope {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
        bytes appProof;
        bytes32[] appPub;
    }
}

/// Recovers the ciphertext bytes from a `publishInput(uint256,bytes)` calldata and checks that
/// they hash to the commitment the contract emitted. The chain only stores `keccak(ciphertext)`;
/// the bytes themselves live in calldata, exactly like CRISP ballots.
pub fn ciphertext_from_calldata(input: &[u8], expected_hash: B256) -> Result<Vec<u8>> {
    let call = CkksAuctionE3Program::publishInputCall::abi_decode(input)
        .map_err(|e| eyre!("calldata is not publishInput(uint256,bytes): {e}"))?;
    let envelope = ThreeLegEnvelope::abi_decode_params(&call.data)
        .map_err(|e| eyre!("bad three-leg envelope: {e}"))?;
    let ciphertext = envelope.ciphertext.to_vec();
    if keccak256(&ciphertext) != expected_hash {
        return Err(eyre!(
            "ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    Ok(ciphertext)
}

/// The wallet-filled provider type (`InterfoldWriteProvider` shape).
type WriteProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    alloy::providers::RootProvider,
>;

/// Write-capable program handle (the round opener's key).
pub struct AuctionProgram {
    provider: WriteProvider,
    address: Address,
}

impl AuctionProgram {
    pub async fn new(http_rpc_url: &str, private_key: &str, address: &str) -> Result<Self> {
        let signer: PrivateKeySigner = private_key.parse()?;
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect(http_rpc_url)
            .await?;
        Ok(Self {
            provider,
            address: address.parse()?,
        })
    }

    pub async fn set_balance_root(
        &self,
        e3_id: U256,
        root: [u8; 32],
    ) -> Result<TransactionReceipt> {
        let contract = CkksAuctionE3Program::new(self.address, &self.provider);
        let receipt = contract
            .setBalanceRoot(e3_id, B256::from(root))
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            return Err(eyre!(
                "setBalanceRoot reverted: {:?}",
                receipt.transaction_hash
            ));
        }
        Ok(receipt)
    }

    pub async fn balance_root(&self, e3_id: U256) -> Result<B256> {
        let contract = CkksAuctionE3Program::new(self.address, &self.provider);
        Ok(contract.balanceRoots(e3_id).call().await?)
    }

    pub async fn bid_cap(&self) -> Result<U256> {
        let contract = CkksAuctionE3Program::new(self.address, &self.provider);
        Ok(contract.bidCap().call().await?)
    }

    /// The calldata of a mined transaction (for `ciphertext_from_calldata`).
    pub async fn transaction_input(&self, hash: B256) -> Result<Bytes> {
        let tx = self
            .provider
            .get_transaction_by_hash(hash)
            .await?
            .ok_or_else(|| eyre!("transaction {hash} not found"))?;
        Ok(tx.inner.input().clone())
    }

    pub async fn latest_timestamp(&self) -> Result<u64> {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| eyre!("Latest block not found"))?;
        Ok(block.header.timestamp)
    }
}

/// `keccak256(ciphertext)` as the `ciphertextCommitment` for `publishCiphertextOutput`
/// (the CKKS ciphertext verifier is the mock/keccak one on the dev stack).
pub fn ciphertext_commitment(ciphertext: &[u8]) -> B256 {
    keccak256(ciphertext)
}

#[allow(dead_code)]
pub fn u256_words(words: &[B256]) -> Vec<U256> {
    words.iter().map(|w| U256::from_be_bytes(w.0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_ciphertext_from_publish_input_calldata() {
        let ciphertext = vec![7u8; 100];
        let envelope = ThreeLegEnvelope {
            ciphertext: ciphertext.clone().into(),
            ct0Proof: vec![1u8; 4].into(),
            ct0Pub: vec![B256::ZERO; 4],
            ct1Proof: vec![2u8; 4].into(),
            ct1Pub: vec![B256::ZERO; 3],
            appProof: vec![3u8; 4].into(),
            appPub: vec![B256::ZERO; 4],
        };
        let data = envelope.abi_encode_params();
        let call = CkksAuctionE3Program::publishInputCall {
            e3Id: U256::from(3),
            data: data.into(),
        };
        let input = call.abi_encode();
        let got = ciphertext_from_calldata(&input, keccak256(&ciphertext)).unwrap();
        assert_eq!(got, ciphertext);
        assert!(ciphertext_from_calldata(&input, B256::ZERO).is_err());
    }
}
