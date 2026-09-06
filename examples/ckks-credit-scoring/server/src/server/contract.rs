// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `CkksCreditE3Program` (v2) bindings + the ciphertext-from-calldata recovery (CRISP `evm_helpers`).

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
    contract CkksCreditE3Program {
        struct Model {
            uint256 cap;
            bytes32[8] weights;
            bytes32 bias;
        }
        function registerRound(uint256 e3Id, bytes32 root, Model model, address[] applicants) external;
        function issuerRoots(uint256 e3Id) external view returns (bytes32);
        function applicationCount(uint256 e3Id) external view returns (uint256);
        function applicants(uint256 e3Id) external view returns (address[]);
        function publishInput(uint256 e3Id, bytes data) external;
    }

    /// Emitted by `CkksCreditE3Program.publishInput` once all five Honk proofs
    /// verified and the commitments bound.
    #[derive(Debug)]
    event ApplicationPublished(
        uint256 indexed e3Id,
        address indexed applicant,
        uint256 index,
        bytes32 logitCiphertextHash,
        bytes32 maskCiphertextHash,
        bytes32 mCommitmentZ,
        bytes32 mCommitmentM
    );

    /// `abi.encode(ctZ, ct0PZ, ct0PubZ, ct1PZ, ct1PubZ, ctM, ct0PM, ct0PubM, ct1PM, ct1PubM, appP, appPub)`
    struct FiveLegEnvelope {
        bytes ciphertextZ;
        bytes ct0ProofZ;
        bytes32[] ct0PubZ;
        bytes ct1ProofZ;
        bytes32[] ct1PubZ;
        bytes ciphertextM;
        bytes ct0ProofM;
        bytes32[] ct0PubM;
        bytes ct1ProofM;
        bytes32[] ct1PubM;
        bytes appProof;
        bytes32[] appPub;
    }
}

/// Recovers the TWO ciphertexts from a `publishInput(uint256,bytes)` calldata and checks that
/// they hash to the commitments the contract emitted. The chain only stores the keccaks;
/// the bytes themselves live in calldata, exactly like CRISP ballots.
pub fn ciphertexts_from_calldata(
    input: &[u8],
    expected_z: B256,
    expected_m: B256,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let call = CkksCreditE3Program::publishInputCall::abi_decode(input)
        .map_err(|e| eyre!("calldata is not publishInput(uint256,bytes): {e}"))?;
    let envelope = FiveLegEnvelope::abi_decode_params(&call.data)
        .map_err(|e| eyre!("bad five-leg envelope: {e}"))?;
    let z = envelope.ciphertextZ.to_vec();
    let m = envelope.ciphertextM.to_vec();
    if keccak256(&z) != expected_z {
        return Err(eyre!(
            "logit ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    if keccak256(&m) != expected_m {
        return Err(eyre!(
            "mask ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    Ok((z, m))
}

/// The on-chain word of a signed fixed-point model coefficient (`p − |w|` when negative).
pub fn signed_word(v: i64) -> B256 {
    let word = e3_zk_helpers::threshold::ckks_credit_validity::signed_field_bigint(v);
    let (_, be) = word.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    B256::from(out)
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
pub struct CreditProgram {
    provider: WriteProvider,
    address: Address,
}

impl CreditProgram {
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

    /// Registers the round: root + fixed-point model + applicant list (slot = position).
    pub async fn register_round(
        &self,
        e3_id: U256,
        root: [u8; 32],
        cap: u64,
        model: &ckks_credit_program::FixedPointModel,
        applicants: Vec<Address>,
    ) -> Result<TransactionReceipt> {
        let contract = CkksCreditE3Program::new(self.address, &self.provider);
        let weights: [B256; 8] = std::array::from_fn(|j| signed_word(model.weights[j] as i64));
        let m = CkksCreditE3Program::Model {
            cap: U256::from(cap),
            weights,
            bias: signed_word(model.bias as i64),
        };
        let receipt = contract
            .registerRound(e3_id, B256::from(root), m, applicants)
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

    pub async fn issuer_root(&self, e3_id: U256) -> Result<B256> {
        let contract = CkksCreditE3Program::new(self.address, &self.provider);
        Ok(contract.issuerRoots(e3_id).call().await?)
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

    #[test]
    fn recovers_both_ciphertexts_from_publish_input_calldata() {
        let z = vec![7u8; 100];
        let m = vec![9u8; 90];
        let envelope = FiveLegEnvelope {
            ciphertextZ: z.clone().into(),
            ct0ProofZ: vec![1u8; 4].into(),
            ct0PubZ: vec![B256::ZERO; 4],
            ct1ProofZ: vec![2u8; 4].into(),
            ct1PubZ: vec![B256::ZERO; 3],
            ciphertextM: m.clone().into(),
            ct0ProofM: vec![1u8; 4].into(),
            ct0PubM: vec![B256::ZERO; 4],
            ct1ProofM: vec![2u8; 4].into(),
            ct1PubM: vec![B256::ZERO; 3],
            appProof: vec![3u8; 4].into(),
            appPub: vec![B256::ZERO; 15],
        };
        let data = envelope.abi_encode_params();
        let call = CkksCreditE3Program::publishInputCall {
            e3Id: U256::from(3),
            data: data.into(),
        };
        let input = call.abi_encode();
        let got = ciphertexts_from_calldata(&input, keccak256(&z), keccak256(&m)).unwrap();
        assert_eq!(got, (z.clone(), m.clone()));
        assert!(ciphertexts_from_calldata(&input, B256::ZERO, keccak256(&m)).is_err());
        assert!(ciphertexts_from_calldata(&input, keccak256(&z), B256::ZERO).is_err());
    }

    #[test]
    fn signed_words_match_the_circuit_convention() {
        assert_eq!(
            signed_word(111411),
            B256::from(U256::from(111411u64).to_be_bytes::<32>())
        );
        // p − 150733
        assert_eq!(
            format!("{:#x}", signed_word(-150733)),
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effdb334"
        );
    }
}
