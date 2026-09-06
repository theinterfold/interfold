// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `CkksFedAvgE3Program` bindings + the ciphertext-from-calldata recovery (CRISP `evm_helpers`).

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
    contract CkksFedAvgE3Program {
        function registerRound(uint256 e3Id, uint256 normBound, uint256 minClients, address[] clientList) external;
        function submissionCount(uint256 e3Id) external view returns (uint256);
        function clients(uint256 e3Id) external view returns (address[]);
        function publishInput(uint256 e3Id, bytes data) external;
    }

    /// Emitted by `CkksFedAvgE3Program.publishInput` once all five Honk proofs
    /// verified and the commitments bound.
    #[derive(Debug)]
    event UpdatePublished(
        uint256 indexed e3Id,
        address indexed client,
        uint256 index,
        bytes32 gradientCiphertextHash,
        bytes32 countCiphertextHash,
        bytes32 mCommitmentGrad,
        bytes32 mCommitmentCount
    );

    /// Both Greco legs of ONE ciphertext (`CkksFedAvgE3Program.GrecoPair`).
    #[derive(Debug)]
    struct GrecoPair {
        bytes ciphertext;
        bytes ct0Proof;
        bytes32[] ct0Pub;
        bytes ct1Proof;
        bytes32[] ct1Pub;
    }

    /// `CkksFedAvgE3Program.Update` — the NESTED five-leg envelope
    /// (`abi.encode(Update)`, one tuple with two GrecoPair tuples inside).
    #[derive(Debug)]
    struct Update {
        GrecoPair gradient;
        GrecoPair count;
        bytes appProof;
        bytes32[] appPub;
    }
}

/// Recovers the TWO ciphertexts from a `publishInput(uint256,bytes)` calldata and checks that
/// they hash to the commitments the contract emitted. The chain only stores the keccaks;
/// the bytes themselves live in calldata, exactly like CRISP ballots.
pub fn ciphertexts_from_calldata(
    input: &[u8],
    expected_g: B256,
    expected_c: B256,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let call = CkksFedAvgE3Program::publishInputCall::abi_decode(input)
        .map_err(|e| eyre!("calldata is not publishInput(uint256,bytes): {e}"))?;
    let update = Update::abi_decode(&call.data).map_err(|e| eyre!("bad five-leg envelope: {e}"))?;
    let g = update.gradient.ciphertext.to_vec();
    let c = update.count.ciphertext.to_vec();
    if keccak256(&g) != expected_g {
        return Err(eyre!(
            "gradient ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    if keccak256(&c) != expected_c {
        return Err(eyre!(
            "count ciphertext in calldata does not hash to the emitted commitment"
        ));
    }
    Ok((g, c))
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
pub struct FedAvgProgram {
    provider: WriteProvider,
    address: Address,
}

impl FedAvgProgram {
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

    /// Registers the round: norm bound (`× 2^32`) + min client count + client list (slot = position).
    pub async fn register_round(
        &self,
        e3_id: U256,
        norm_bound_fixed_point: u64,
        min_clients: usize,
        clients: Vec<Address>,
    ) -> Result<TransactionReceipt> {
        let contract = CkksFedAvgE3Program::new(self.address, &self.provider);
        let receipt = contract
            .registerRound(
                e3_id,
                U256::from(norm_bound_fixed_point),
                U256::from(min_clients),
                clients,
            )
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
        let g = vec![7u8; 100];
        let c = vec![9u8; 90];
        let pair = |ct: &Vec<u8>| GrecoPair {
            ciphertext: ct.clone().into(),
            ct0Proof: vec![1u8; 4].into(),
            ct0Pub: vec![B256::ZERO; 4],
            ct1Proof: vec![2u8; 4].into(),
            ct1Pub: vec![B256::ZERO; 3],
        };
        let update = Update {
            gradient: pair(&g),
            count: pair(&c),
            appProof: vec![3u8; 4].into(),
            appPub: vec![B256::ZERO; 5],
        };
        // The contract decodes `abi.decode(data, (Update))`: a single nested tuple.
        let data = update.abi_encode();
        let call = CkksFedAvgE3Program::publishInputCall {
            e3Id: U256::from(3),
            data: data.into(),
        };
        let input = call.abi_encode();
        let got = ciphertexts_from_calldata(&input, keccak256(&g), keccak256(&c)).unwrap();
        assert_eq!(got, (g.clone(), c.clone()));
        assert!(ciphertexts_from_calldata(&input, B256::ZERO, keccak256(&c)).is_err());
        assert!(ciphertexts_from_calldata(&input, keccak256(&g), B256::ZERO).is_err());
    }
}
