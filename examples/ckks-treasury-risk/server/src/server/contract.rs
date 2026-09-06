// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `CkksTreasuryE3Program` bindings + the ciphertext-from-calldata recovery (CRISP `evm_helpers`).

use alloy::consensus::Transaction as _;
use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use ckks_treasury_program::{FixedPointWeights, ASSETS};
use eyre::{eyre, Result};

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract CkksTreasuryE3Program {
        function registerRound(uint256 e3Id, bytes32[4] weights, address[] daos) external;
        function submissionCount(uint256 e3Id) external view returns (uint256);
        function daos(uint256 e3Id) external view returns (address[]);
        function weights(uint256 e3Id) external view returns (bytes32[4]);
        function daoSlot(uint256 e3Id, address dao) external view returns (uint256);
        function publishInput(uint256 e3Id, bytes data) external;
        function riskFromOutput(bytes plaintextOutput) external pure returns (int128);
    }

    /// Emitted by `CkksTreasuryE3Program.publishInput` once all seven Honk proofs
    /// verified and the commitments bound.
    #[derive(Debug)]
    event SubmissionPublished(
        uint256 indexed e3Id,
        address indexed dao,
        uint256 index,
        bytes32 forwardCiphertextHash,
        bytes32 reversedCiphertextHash,
        bytes32 maskCiphertextHash,
        bytes32 mCommitmentFwd,
        bytes32 mCommitmentRev,
        bytes32 mCommitmentMask
    );

    /// Both Greco legs of ONE ciphertext (`CkksTreasuryE3Program.GrecoPair`).
    #[derive(Debug)]
    struct GrecoPair {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
    }

    /// `abi.encode(TreasurySubmission)` — ONE nested tuple (each pair has its own
    /// head/tail offsets), what `publishInput`'s `data` carries.
    #[derive(Debug)]
    struct TreasurySubmission {
        GrecoPair forward;
        GrecoPair reversed;
        GrecoPair mask;
        bytes appProof;
        bytes32[] appPub;
    }
}

/// BN254 scalar field modulus (the validity leg's field).
const BN254_R: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// A signed fixed-point weight as the on-chain `bytes32` word: `p − |W|` when negative
/// (what the circuit's public `weights[a]` carries and `registerRound` stores).
pub fn weight_word(w: i32) -> B256 {
    let p = U256::from_str_radix(BN254_R, 10).expect("bn254 r");
    let v = if w >= 0 {
        U256::from(w as u32)
    } else {
        p - U256::from(w.unsigned_abs())
    };
    B256::from(v)
}

/// The four on-chain weight words of a round's fixed-point weights.
pub fn weight_words(w: &FixedPointWeights) -> [B256; ASSETS] {
    std::array::from_fn(|a| weight_word(w.0[a]))
}

/// Recovers all THREE ciphertexts from a `publishInput(uint256,bytes)` calldata and checks
/// that they hash to the commitments the contract emitted. The chain only stores the
/// keccaks; the bytes themselves live in calldata, exactly like CRISP ballots.
pub fn ciphertexts_from_calldata(
    input: &[u8],
    expected_fwd: B256,
    expected_rev: B256,
    expected_mask: B256,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let call = CkksTreasuryE3Program::publishInputCall::abi_decode(input)
        .map_err(|e| eyre!("calldata is not publishInput(uint256,bytes): {e}"))?;
    let sub = TreasurySubmission::abi_decode(&call.data)
        .map_err(|e| eyre!("bad seven-leg envelope: {e}"))?;
    let f = sub.forward.ciphertext.to_vec();
    let r = sub.reversed.ciphertext.to_vec();
    let m = sub.mask.ciphertext.to_vec();
    if keccak256(&f) != expected_fwd {
        return Err(eyre!(
            "forward ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    if keccak256(&r) != expected_rev {
        return Err(eyre!(
            "reversed ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    if keccak256(&m) != expected_mask {
        return Err(eyre!(
            "mask ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    Ok((f, r, m))
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
pub struct TreasuryProgram {
    provider: WriteProvider,
    address: Address,
}

impl TreasuryProgram {
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

    /// Registers the round: the public weights (fixed point, `p − |W|` words) and the DAO
    /// list (slot = position).
    pub async fn register_round(
        &self,
        e3_id: U256,
        weights: &FixedPointWeights,
        daos: Vec<Address>,
    ) -> Result<TransactionReceipt> {
        let contract = CkksTreasuryE3Program::new(self.address, &self.provider);
        let receipt = contract
            .registerRound(e3_id, weight_words(weights), daos)
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

    pub async fn daos(&self, e3_id: U256) -> Result<Vec<Address>> {
        let contract = CkksTreasuryE3Program::new(self.address, &self.provider);
        Ok(contract.daos(e3_id).call().await?)
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
    fn recovers_all_three_ciphertexts_from_publish_input_calldata() {
        let f = vec![7u8; 100];
        let r = vec![6u8; 90];
        let m = vec![5u8; 80];
        let sub = TreasurySubmission {
            forward: pair(f.clone()),
            reversed: pair(r.clone()),
            mask: pair(m.clone()),
            appProof: vec![3u8; 4].into(),
            appPub: vec![B256::ZERO; 9],
        };
        // The contract does `abi.decode(data, (TreasurySubmission))`: ONE tuple value.
        let data = sub.abi_encode();
        let call = CkksTreasuryE3Program::publishInputCall {
            e3Id: U256::from(3),
            data: data.into(),
        };
        let input = call.abi_encode();
        let got =
            ciphertexts_from_calldata(&input, keccak256(&f), keccak256(&r), keccak256(&m)).unwrap();
        assert_eq!(got, (f.clone(), r.clone(), m.clone()));
        assert!(
            ciphertexts_from_calldata(&input, B256::ZERO, keccak256(&r), keccak256(&m)).is_err()
        );
        assert!(
            ciphertexts_from_calldata(&input, keccak256(&f), B256::ZERO, keccak256(&m)).is_err()
        );
        assert!(
            ciphertexts_from_calldata(&input, keccak256(&f), keccak256(&r), B256::ZERO).is_err()
        );
    }

    #[test]
    fn weight_words_match_the_fixture_encoding() {
        // w = [0.5, -0.25, 1.0, 0.125] × 2^16 — the contract fixture's `weightWords`.
        let w = FixedPointWeights([32768, -16384, 65536, 8192]);
        let words = weight_words(&w);
        assert_eq!(words[0], B256::from(U256::from(32768u64)));
        let p = U256::from_str_radix(BN254_R, 10).unwrap();
        assert_eq!(words[1], B256::from(p - U256::from(16384u64)));
        assert_eq!(words[2], B256::from(U256::from(65536u64)));
        assert_eq!(words[3], B256::from(U256::from(8192u64)));
    }
}
