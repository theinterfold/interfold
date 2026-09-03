// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chain access for the coordinator: the `CkksSalaryE3Program` relay
//! (three-leg `publishInput`), fee-token approval and the Interfold
//! request / publish calls (through `e3_sdk::evm_helpers`).

use std::sync::Arc;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolValue;
use alloy::transports::RpcError;
use e3_sdk::evm_helpers::contracts::{
    CommitteeSize, InterfoldContract, InterfoldContractFactory, InterfoldWrite, ReadWrite,
};
use eyre::{eyre, Result};

use super::models::SubmissionPayload;

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract CkksSalaryE3Program {
        function publishInput(uint256 e3Id, bytes data) external;
        function salaryCap() external view returns (uint256);
        function submissionCount(uint256 e3Id) external view returns (uint256);
        error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment);
        error WrongCap(uint256 got, uint256 want);
        error Ct0ProofInvalid();
        error Ct1ProofInvalid();
        error AppProofInvalid();
        error UCommitmentMismatch(bytes32 ct0Leg, bytes32 ct1Leg);
        error MCommitmentMismatch(bytes32 ct0Leg, bytes32 appLeg);
    }

    #[derive(Debug)]
    #[sol(rpc)]
    contract ERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address owner) external view returns (uint256);
        function mint(address to, uint256 amount) external;
    }

    /// `CkksAppE3ProgramBase.VerifiedInputPublished`.
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
}

/// Why the on-chain gate refused a relayed submission.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("this exact encryption was already submitted (on-chain DuplicateSubmission dedup for u_commitment {0})")]
    Duplicate(String),
    #[error("on-chain verification rejected the submission: {0}")]
    Reverted(String),
    #[error("chain unavailable: {0}")]
    Provider(String),
}

/// ABI-encode the three-leg envelope the program decodes:
/// `(bytes ct, bytes ct0P, bytes32[] ct0Pub, bytes ct1P, bytes32[] ct1Pub, bytes appP, bytes32[] appPub)`.
pub fn encode_three_leg_envelope(s: &SubmissionPayload) -> Result<Bytes> {
    fn hex_bytes(h: &str) -> Result<Bytes> {
        Ok(Bytes::from(hex::decode(h.trim_start_matches("0x"))?))
    }
    fn words(v: &[String]) -> Result<Vec<B256>> {
        v.iter()
            .map(|w| {
                w.parse::<B256>()
                    .map_err(|e| eyre!("bad public input {w}: {e}"))
            })
            .collect()
    }
    let tuple = (
        hex_bytes(&s.ciphertext_hex)?,
        hex_bytes(&s.ct0.proof_hex)?,
        words(&s.ct0.public_inputs)?,
        hex_bytes(&s.ct1.proof_hex)?,
        words(&s.ct1.public_inputs)?,
        hex_bytes(&s.app_leg.proof_hex)?,
        words(&s.app_leg.public_inputs)?,
    );
    Ok(Bytes::from(tuple.abi_encode_params()))
}

/// Write-capable handle bound to the relayer key.
#[derive(Clone)]
pub struct Chain {
    provider: Arc<alloy::providers::DynProvider>,
    pub wallet: Address,
    pub program: Address,
    pub interfold: InterfoldContract<ReadWrite>,
    interfold_address: Address,
    fee_token: Address,
}

impl Chain {
    pub async fn connect(
        http_rpc_url: &str,
        private_key: &str,
        program: &str,
        interfold: &str,
        fee_token: &str,
    ) -> Result<Self> {
        let signer: PrivateKeySigner = private_key.parse()?;
        let wallet_addr = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect(http_rpc_url)
            .await?
            .erased();
        let interfold_c =
            InterfoldContractFactory::create_write(http_rpc_url, interfold, private_key).await?;
        Ok(Self {
            provider: Arc::new(provider),
            wallet: wallet_addr,
            program: program.parse()?,
            interfold: interfold_c,
            interfold_address: interfold.parse()?,
            fee_token: fee_token.parse()?,
        })
    }

    pub async fn block_timestamp(&self) -> Result<u64> {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| eyre!("latest block not found"))?;
        Ok(block.header.timestamp)
    }

    async fn pending_nonce(&self) -> Result<u64> {
        Ok(self
            .provider
            .get_transaction_count(self.wallet)
            .pending()
            .await?)
    }

    pub async fn salary_cap(&self) -> Result<u64> {
        let c = CkksSalaryE3Program::new(self.program, self.provider.as_ref());
        Ok(c.salaryCap().call().await?.to::<u64>())
    }

    /// Relay a participant submission through the three-leg gate. A
    /// preflight `eth_call` surfaces the custom-error selector (a mined
    /// revert would not), then the tx is sent with a gas limit that fits
    /// three Honk verifies (~3M).
    pub async fn relay_submission(
        &self,
        e3_id: U256,
        payload: &SubmissionPayload,
    ) -> std::result::Result<TransactionReceipt, RelayError> {
        let data = encode_three_leg_envelope(payload)
            .map_err(|e| RelayError::Reverted(format!("bad submission encoding: {e}")))?;
        let c = CkksSalaryE3Program::new(self.program, self.provider.as_ref());
        let call = c.publishInput(e3_id, data).gas(29_000_000);
        if let Err(e) = call.call().await {
            log::warn!("publishInput preflight failed: {e:?}");
            return Err(classify_revert(e, payload));
        }
        // The Interfold write handle shares this wallet and manages its own
        // nonces, so never trust the filler's cached value: read `pending`.
        let nonce = self
            .provider
            .get_transaction_count(self.wallet)
            .pending()
            .await
            .map_err(|e| RelayError::Provider(e.to_string()))?;
        let receipt = call
            .nonce(nonce)
            .send()
            .await
            .map_err(|e| RelayError::Provider(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| RelayError::Provider(e.to_string()))?;
        if !receipt.status() {
            return Err(RelayError::Reverted(
                "publishInput transaction reverted".into(),
            ));
        }
        Ok(receipt)
    }

    /// Ensure the relayer holds + approved the E3 fee (mock USDC on
    /// localhost is mintable by anyone; on a real chain only approve).
    async fn ensure_fee(&self, amount: U256) -> Result<()> {
        let token = ERC20::new(self.fee_token, self.provider.as_ref());
        let balance = token.balanceOf(self.wallet).call().await?;
        if balance < amount {
            let mint = amount - balance + U256::from(1_000_000_000u64);
            let nonce = self.pending_nonce().await?;
            match token.mint(self.wallet, mint).nonce(nonce).send().await {
                Ok(p) => {
                    p.get_receipt().await?;
                }
                Err(e) => {
                    return Err(eyre!(
                        "fee token balance {balance} < {amount} and mint failed: {e}"
                    ))
                }
            }
        }
        let allowance = token
            .allowance(self.wallet, self.interfold_address)
            .call()
            .await?;
        if allowance < amount {
            let nonce = self.pending_nonce().await?;
            token
                .approve(self.interfold_address, amount)
                .nonce(nonce)
                .send()
                .await?
                .get_receipt()
                .await?;
        }
        Ok(())
    }

    /// Request a survey round through the salary program. Returns
    /// `(e3_id, tx_hash, input_window)`.
    pub async fn request_round(
        &self,
        committee_size: u8,
        param_set: u8,
        duration_secs: u64,
        compute_provider_params: Bytes,
    ) -> Result<(U256, B256, [u64; 2])> {
        let committee_size = match committee_size {
            0 => CommitteeSize::Minimum,
            1 => CommitteeSize::Micro,
            2 => CommitteeSize::Small,
            other => return Err(eyre!("invalid committee size {other}")),
        };
        // `get_e3_quote` is exposed through the read trait; the write path
        // re-quotes internally, so we only need the allowance in place.
        let now = self.block_timestamp().await?;
        let window = [now + 20, now + 20 + duration_secs];
        let quote = e3_sdk::evm_helpers::contracts::InterfoldRead::get_e3_quote(
            &self.interfold,
            committee_size,
            [U256::from(window[0]), U256::from(window[1])],
            self.program,
            param_set,
            compute_provider_params.clone(),
        )
        .await?;
        self.ensure_fee(quote).await?;
        let now = self.block_timestamp().await?;
        let window = [now + 20, now + 20 + duration_secs];
        let (receipt, e3_id) = self
            .interfold
            .request_e3(
                committee_size,
                [U256::from(window[0]), U256::from(window[1])],
                self.program,
                param_set,
                compute_provider_params,
                Bytes::new(),
            )
            .await?;
        Ok((e3_id, receipt.transaction_hash, window))
    }

    pub async fn publish_ciphertext_output(
        &self,
        e3_id: U256,
        ciphertext: Vec<u8>,
        commitment: [u8; 32],
    ) -> Result<TransactionReceipt> {
        self.interfold
            .publish_ciphertext_output(
                e3_id,
                Bytes::from(ciphertext),
                B256::from(commitment),
                Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]),
            )
            .await
    }
}

fn classify_revert(err: alloy::contract::Error, payload: &SubmissionPayload) -> RelayError {
    let u = payload
        .ct0
        .public_inputs
        .get(3)
        .cloned()
        .unwrap_or_default();
    match err {
        alloy::contract::Error::TransportError(RpcError::ErrorResp(p)) => {
            let msg = p.to_string();
            let data = p.as_revert_data().map(hex::encode).unwrap_or_default();
            // DuplicateSubmission(uint256,bytes32) selector.
            let dup_selector = hex::encode(
                &alloy::primitives::keccak256(b"DuplicateSubmission(uint256,bytes32)")[..4],
            );
            if data.starts_with(&dup_selector) || msg.contains("DuplicateSubmission") {
                RelayError::Duplicate(u)
            } else if p.as_revert_data().is_some() || msg.to_lowercase().contains("revert") {
                RelayError::Reverted(decode_known_error(&data).unwrap_or(msg))
            } else {
                RelayError::Provider(msg)
            }
        }
        other => RelayError::Provider(other.to_string()),
    }
}

/// Map the program's custom-error selectors to readable names.
fn decode_known_error(data_hex: &str) -> Option<String> {
    const KNOWN: &[&str] = &[
        "WrongCap(uint256,uint256)",
        "Ct0ProofInvalid()",
        "Ct1ProofInvalid()",
        "AppProofInvalid()",
        "UCommitmentMismatch(bytes32,bytes32)",
        "MCommitmentMismatch(bytes32,bytes32)",
        "InvalidInputEncoding()",
        "WrongPublicInputCount(uint256,uint256,uint256)",
    ];
    if data_hex.len() < 8 {
        return None;
    }
    KNOWN
        .iter()
        .find(|sig| {
            hex::encode(&alloy::primitives::keccak256(sig.as_bytes())[..4]) == data_hex[..8]
        })
        .map(|sig| sig.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_matches_the_hardhat_task_encoding() {
        let payload = SubmissionPayload {
            app: Some("salary".into()),
            param_set: Some(3),
            ciphertext_hex: "0x0102".into(),
            ct0: super::super::models::ProofLeg {
                proof_hex: "0xaa".into(),
                public_inputs: vec![format!("0x{}", "11".repeat(32)); 4],
            },
            ct1: super::super::models::ProofLeg {
                proof_hex: "0xbb".into(),
                public_inputs: vec![format!("0x{}", "22".repeat(32)); 3],
            },
            app_leg: super::super::models::ProofLeg {
                proof_hex: "0xcc".into(),
                public_inputs: vec![format!("0x{}", "33".repeat(32)); 2],
            },
        };
        let data = encode_three_leg_envelope(&payload).unwrap();
        // 7 head words + dynamic tails; decode back to check the layout.
        type Env = (Bytes, Bytes, Vec<B256>, Bytes, Vec<B256>, Bytes, Vec<B256>);
        let decoded = <Env as SolValue>::abi_decode_params(&data).unwrap();
        assert_eq!(decoded.0.as_ref(), &[1u8, 2]);
        assert_eq!(decoded.2.len(), 4);
        assert_eq!(decoded.4.len(), 3);
        assert_eq!(decoded.6.len(), 2);
    }
}
