// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `CkksMatchingE3Program` bindings + the ciphertext-from-calldata recovery (CRISP `evm_helpers`).

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
    contract CkksMatchingE3Program {
        function registerRound(uint256 e3Id, address[] parties) external;
        function submissionCount(uint256 e3Id) external view returns (uint256);
        function parties(uint256 e3Id) external view returns (address[]);
        function partySlot(uint256 e3Id, address party) external view returns (uint256);
        function publishInput(uint256 e3Id, bytes data) external;
        function verifyOutput(bytes plaintextOutput) external pure returns (bool);
    }

    /// Emitted by `CkksMatchingE3Program.publishInput` once all five Honk proofs
    /// verified and the commitments bound.
    #[derive(Debug)]
    event SubmissionPublished(
        uint256 indexed e3Id,
        address indexed party,
        uint256 index,
        bytes32 vectorCiphertextHash,
        bytes32 maskCiphertextHash,
        bytes32 mCommitmentVec,
        bytes32 mCommitmentMask
    );

    /// Both Greco legs of ONE ciphertext (`CkksMatchingE3Program.GrecoPair`).
    #[derive(Debug)]
    struct GrecoPair {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
    }

    /// `abi.encode(MatchingSubmission)` — ONE nested tuple (each pair has its own
    /// head/tail offsets), what `publishInput`'s `data` carries.
    #[derive(Debug)]
    struct MatchingSubmission {
        GrecoPair vector;
        GrecoPair mask;
        bytes appProof;
        bytes32[] appPub;
    }
}

/// Recovers BOTH ciphertexts from a `publishInput(uint256,bytes)` calldata and checks
/// that they hash to the commitments the contract emitted. The chain only stores the
/// keccaks; the bytes themselves live in calldata, exactly like CRISP ballots.
pub fn ciphertexts_from_calldata(
    input: &[u8],
    expected_vec: B256,
    expected_mask: B256,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let call = CkksMatchingE3Program::publishInputCall::abi_decode(input)
        .map_err(|e| eyre!("calldata is not publishInput(uint256,bytes): {e}"))?;
    let sub = MatchingSubmission::abi_decode(&call.data)
        .map_err(|e| eyre!("bad five-leg envelope: {e}"))?;
    let v = sub.vector.ciphertext.to_vec();
    let m = sub.mask.ciphertext.to_vec();
    if keccak256(&v) != expected_vec {
        return Err(eyre!(
            "vector ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    if keccak256(&m) != expected_mask {
        return Err(eyre!(
            "mask ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    Ok((v, m))
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
pub struct MatchingProgram {
    provider: WriteProvider,
    address: Address,
}

impl MatchingProgram {
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

    /// Registers the round: `[A, B]` (slot = position = role).
    pub async fn register_round(
        &self,
        e3_id: U256,
        party_a: Address,
        party_b: Address,
    ) -> Result<TransactionReceipt> {
        let contract = CkksMatchingE3Program::new(self.address, &self.provider);
        let receipt = contract
            .registerRound(e3_id, vec![party_a, party_b])
            .send()
            .await?
            .get_receipt()
            .await?;
        if !receipt.status() {
            return Err(eyre!(
                "registerRound reverted: {:?}",
                receipt.transaction_hash
            ));
        }
        Ok(receipt)
    }

    pub async fn parties(&self, e3_id: U256) -> Result<Vec<Address>> {
        let contract = CkksMatchingE3Program::new(self.address, &self.provider);
        Ok(contract.parties(e3_id).call().await?)
    }

    /// The contract's shape check of an opened output (64 `int128` words).
    pub async fn verify_output(&self, plaintext: Vec<u8>) -> Result<bool> {
        let contract = CkksMatchingE3Program::new(self.address, &self.provider);
        Ok(contract.verifyOutput(Bytes::from(plaintext)).call().await?)
    }

    /// The calldata of a mined transaction (for `ciphertexts_from_calldata`).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(ct: Vec<u8>) -> GrecoPair {
        GrecoPair {
            ciphertext: ct.into(),
            ct0Proof: vec![1u8; 4].into(),
            ct0Pub: vec![B256::ZERO; 4],
            ct1Proof: vec![2u8; 4].into(),
            ct1Pub: vec![B256::ZERO; 3],
        }
    }

    #[test]
    fn recovers_both_ciphertexts_from_publish_input_calldata() {
        let v = vec![7u8; 100];
        let m = vec![5u8; 80];
        let sub = MatchingSubmission {
            vector: pair(v.clone()),
            mask: pair(m.clone()),
            appProof: vec![3u8; 4].into(),
            appPub: vec![B256::ZERO; 5],
        };
        // The contract does `abi.decode(data, (MatchingSubmission))`: ONE tuple value.
        let data = sub.abi_encode();
        let call = CkksMatchingE3Program::publishInputCall {
            e3Id: U256::from(3),
            data: data.into(),
        };
        let input = call.abi_encode();
        let got = ciphertexts_from_calldata(&input, keccak256(&v), keccak256(&m)).unwrap();
        assert_eq!(got, (v.clone(), m.clone()));
        assert!(ciphertexts_from_calldata(&input, B256::ZERO, keccak256(&m)).is_err());
        assert!(ciphertexts_from_calldata(&input, keccak256(&v), B256::ZERO).is_err());
    }
}
