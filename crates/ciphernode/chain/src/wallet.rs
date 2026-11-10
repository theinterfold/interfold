// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Account, Call, Estimate, RpcError};
use alloy::{
    eips::{eip1559::Eip1559Estimation, BlockId},
    network::TransactionBuilder,
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
    transports::{RpcError as TransportFailure, TransportErrorKind},
};
use alloy_primitives::{keccak256, Bytes, B256};
use e3_evm_transactions::nonce::{broadcast_refused, next_free_nonce};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, Write},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// How long a send waits for its receipt before the writer checks the chain again.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(300);

/// The operator's account on one chain over JSON-RPC. Calls run concurrently; only choosing a
/// nonce and broadcasting take turns. Whether a call goes out follows the reader's view of the
/// chain: it is checked against the confirmed head and counts as landed once its block is
/// confirmed, so no reorg the reader would survive undoes a call the writer finished. Its gas
/// follows where it will run, the newest block.
pub struct Wallet<P> {
    provider: P,
    chain_id: u64,
    /// Blocks closer to the head than this may still be replaced.
    confirmations: u64,
    nonces: Mutex<Nonces>,
}

struct Nonces {
    /// The nonces this process sent, with their send times.
    sent: BTreeMap<u64, Instant>,
    unmined: Unmined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Sent {
    nonce: u64,
    #[serde(with = "fees")]
    fees: Eip1559Estimation,
}

/// The last send of each call whose nonce the chain has not used yet, by the hash of the call's
/// target and data. It is kept in a file, so that after a restart the node still replaces a
/// transaction stuck on low fees instead of queueing behind it.
struct Unmined {
    path: PathBuf,
    sends: HashMap<B256, Sent>,
}

impl Unmined {
    fn open(path: PathBuf) -> io::Result<Self> {
        let sends = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self { path, sends })
    }

    fn get(&self, call: &B256) -> Option<Sent> {
        self.sends.get(call).copied()
    }

    fn insert(&mut self, call: B256, sent: Sent) -> io::Result<()> {
        self.sends.insert(call, sent);
        self.save()
    }

    fn remove(&mut self, call: &B256) -> io::Result<()> {
        self.sends.remove(call);
        self.save()
    }

    /// Forgets the sends whose nonces the chain used, `mined` being the account's mined count.
    fn forget_mined(&mut self, mined: u64) -> io::Result<()> {
        let before = self.sends.len();
        self.sends.retain(|_, sent| sent.nonce >= mined);
        match self.sends.len() == before {
            true => Ok(()),
            false => self.save(),
        }
    }

    fn save(&self) -> io::Result<()> {
        let partial = self.path.with_extension("partial");
        let mut file = fs::File::create(&partial)?;
        file.write_all(&serde_json::to_vec(&self.sends)?)?;
        file.sync_all()?;
        fs::rename(&partial, &self.path)?;
        match self.path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            Some(dir) => fs::File::open(dir)?.sync_all(),
            None => Ok(()),
        }
    }
}

mod fees {
    use alloy::eips::eip1559::Eip1559Estimation;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        fees: &Eip1559Estimation,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        (fees.max_fee_per_gas, fees.max_priority_fee_per_gas).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Eip1559Estimation, D::Error> {
        let (max_fee_per_gas, max_priority_fee_per_gas) = Deserialize::deserialize(deserializer)?;
        Ok(Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }
}

/// A call sent again while its last send waits replaces that transaction at higher fees, so it
/// does not queue behind a transaction stuck on low fees. Nodes take a replacement only for at
/// least a tenth more on both fees.
fn replacement(earlier: Sent, fees: Eip1559Estimation) -> Sent {
    let raise = |fee: u128| fee + fee / 4 + 1;
    let max_fee_per_gas = fees
        .max_fee_per_gas
        .max(raise(earlier.fees.max_fee_per_gas));
    let max_priority_fee_per_gas = fees
        .max_priority_fee_per_gas
        .max(raise(earlier.fees.max_priority_fee_per_gas))
        .min(max_fee_per_gas);
    Sent {
        nonce: earlier.nonce,
        fees: Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
    }
}

impl<P: Provider + WalletProvider> Wallet<P> {
    /// `unmined` is the file that keeps the sends the chain has not mined across restarts.
    pub fn new(
        provider: P,
        chain_id: u64,
        confirmations: u64,
        unmined: PathBuf,
    ) -> io::Result<Self> {
        let nonces = Nonces {
            sent: BTreeMap::new(),
            unmined: Unmined::open(unmined)?,
        };
        Ok(Self {
            provider,
            chain_id,
            confirmations,
            nonces: Mutex::new(nonces),
        })
    }

    fn request(&self, call: &Call) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(self.provider.default_signer_address())
            .with_to(call.to)
            .with_input(call.data.clone())
    }
}

/// What a call's failure says: the revert it hit, or a chain node that did not answer.
fn revert_of(error: TransportFailure<TransportErrorKind>) -> Result<Bytes, RpcError> {
    match error
        .as_error_resp()
        .and_then(|reply| reply.as_revert_data())
    {
        Some(revert) => Ok(revert),
        None => Err(RpcError::new(error)),
    }
}

impl<P: Provider + WalletProvider + Send + Sync> Account for Wallet<P> {
    async fn estimate(&self, call: &Call) -> Result<Estimate, RpcError> {
        let head = self
            .provider
            .get_block_number()
            .await
            .map_err(RpcError::new)?;
        let confirmed = BlockId::number(head.saturating_sub(self.confirmations));
        let request = self.request(call);
        if let Err(error) = self.provider.call(request.clone()).block(confirmed).await {
            return Ok(Estimate::Reverts(revert_of(error)?));
        }
        match self
            .provider
            .estimate_gas(request)
            .block(BlockId::latest())
            .await
        {
            Ok(gas) => Ok(Estimate::Gas(gas)),
            Err(error) => Ok(Estimate::NotYet(revert_of(error)?)),
        }
    }

    /// Fees are estimated before the nonce is chosen, so the turn only signs and broadcasts. An
    /// RPC node's pending count can miss a transaction that another node behind the same endpoint
    /// accepted a moment ago, so a new nonce also skips the ones this process sent recently. The
    /// turn ends before the receipt, so a slow confirmation holds up no other call.
    async fn send(&self, call: &Call, gas: u64) -> Result<bool, RpcError> {
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(RpcError::new)?;
        let account = self.provider.default_signer_address();
        let key = keccak256([call.to.as_slice(), &call.data].concat());
        let pending = {
            let mut nonces = self.nonces.lock().await;
            let mined = self
                .provider
                .get_transaction_count(account)
                .latest()
                .await
                .map_err(RpcError::new)?;
            nonces.unmined.forget_mined(mined).map_err(RpcError::new)?;
            let replaced = nonces.unmined.get(&key);
            let send = match replaced {
                Some(earlier) => replacement(earlier, fees),
                None => {
                    let count = self
                        .provider
                        .get_transaction_count(account)
                        .pending()
                        .await
                        .map_err(RpcError::new)?;
                    let nonce = next_free_nonce(&mut nonces.sent, count, Instant::now());
                    Sent { nonce, fees }
                }
            };
            nonces.sent.insert(send.nonce, Instant::now());
            // Kept before the broadcast: the node can take the transaction and lose its answer, or
            // this process can stop before the answer.
            nonces.unmined.insert(key, send).map_err(RpcError::new)?;
            let request = self
                .request(call)
                .with_gas_limit(gas)
                .with_max_fee_per_gas(send.fees.max_fee_per_gas)
                .with_max_priority_fee_per_gas(send.fees.max_priority_fee_per_gas)
                .with_chain_id(self.chain_id)
                .with_nonce(send.nonce);
            match self.provider.send_transaction(request).await {
                Ok(pending) => pending,
                Err(error) => {
                    let error = alloy::contract::Error::TransportError(error);
                    if broadcast_refused(&error) && replaced.is_none() {
                        nonces.sent.remove(&send.nonce);
                        nonces.unmined.remove(&key).map_err(RpcError::new)?;
                    }
                    return Err(RpcError::new(error));
                }
            }
        };
        let receipt = pending
            .with_required_confirmations(self.confirmations + 1)
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .map_err(RpcError::new)?;
        let mut nonces = self.nonces.lock().await;
        nonces.unmined.remove(&key).map_err(RpcError::new)?;
        Ok(receipt.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        network::EthereumWallet,
        providers::{mock::Asserter, ProviderBuilder},
        signers::local::PrivateKeySigner,
    };
    use alloy_primitives::{Address, U256};
    use serde::de::DeserializeOwned;
    use serde_json::json;

    const CONFIRMATIONS: u64 = 3;

    fn wallet(
        asserter: Asserter,
        dir: &tempfile::TempDir,
    ) -> Wallet<impl Provider + WalletProvider> {
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_mocked_client(asserter);
        Wallet::new(provider, 1, CONFIRMATIONS, dir.path().join("unmined.json")).unwrap()
    }

    fn call() -> Call {
        Call {
            label: "acknowledgeNodeRelease",
            to: Address::repeat_byte(1),
            data: Bytes::from_static(&[1]),
            gas_multiplier: 1,
        }
    }

    /// The JSON-RPC error of a call that reverted with `data`.
    fn revert_payload<Payload: DeserializeOwned>(data: &str) -> Payload {
        let payload = json!({ "code": 3, "message": "execution reverted", "data": data });
        serde_json::from_value(payload).unwrap()
    }

    /// The gas is the newest block's; the confirmed state only says whether the call goes out.
    #[tokio::test]
    async fn the_gas_comes_from_the_estimate_after_the_confirmed_state_took_the_call() {
        let (asserter, dir) = (Asserter::new(), tempfile::tempdir().unwrap());
        asserter.push_success(&U256::from(100));
        asserter.push_success(&Bytes::new());
        asserter.push_success(&U256::from(259_000));
        let estimate = wallet(asserter, &dir).estimate(&call()).await.unwrap();
        assert_eq!(estimate, Estimate::Gas(259_000));
    }

    #[tokio::test]
    async fn the_confirmed_state_refusing_a_call_is_a_revert() {
        let (asserter, dir) = (Asserter::new(), tempfile::tempdir().unwrap());
        asserter.push_success(&U256::from(100));
        asserter.push_failure(revert_payload("0x1234"));
        let estimate = wallet(asserter, &dir).estimate(&call()).await.unwrap();
        assert_eq!(
            estimate,
            Estimate::Reverts(Bytes::from_static(&[0x12, 0x34]))
        );
    }

    #[tokio::test]
    async fn the_newest_blocks_refusing_a_call_is_not_yet_a_revert() {
        let (asserter, dir) = (Asserter::new(), tempfile::tempdir().unwrap());
        asserter.push_success(&U256::from(100));
        asserter.push_success(&Bytes::new());
        asserter.push_failure(revert_payload("0x1234"));
        let estimate = wallet(asserter, &dir).estimate(&call()).await.unwrap();
        assert_eq!(
            estimate,
            Estimate::NotYet(Bytes::from_static(&[0x12, 0x34]))
        );
    }

    #[tokio::test]
    async fn a_chain_node_that_does_not_answer_is_no_verdict() {
        let (asserter, dir) = (Asserter::new(), tempfile::tempdir().unwrap());
        asserter.push_success(&U256::from(100));
        asserter.push_failure_msg("the chain node is overloaded");
        assert!(wallet(asserter, &dir).estimate(&call()).await.is_err());
    }

    fn fees(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> Eip1559Estimation {
        Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }

    #[test]
    fn a_restart_still_knows_a_stuck_send_until_its_nonce_is_mined() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unmined.json");
        let call = B256::repeat_byte(1);
        let sent = Sent {
            nonce: 7,
            fees: fees(100, 10),
        };
        Unmined::open(path.clone())
            .unwrap()
            .insert(call, sent)
            .unwrap();
        let mut reopened = Unmined::open(path.clone()).unwrap();
        assert_eq!(reopened.get(&call), Some(sent));
        reopened.forget_mined(8).unwrap();
        assert_eq!(Unmined::open(path).unwrap().get(&call), None);
    }

    /// Nodes refuse a replacement that raises either fee by less than a tenth.
    #[test]
    fn a_retry_replaces_the_stuck_transaction_at_fees_nodes_take() {
        let earlier = Sent {
            nonce: 7,
            fees: fees(100, 10),
        };
        let again = replacement(earlier, fees(90, 9));
        assert_eq!(again.nonce, 7);
        assert!(again.fees.max_fee_per_gas * 10 >= 100 * 11);
        assert!(again.fees.max_priority_fee_per_gas * 10 >= 10 * 11);
        assert_eq!(replacement(earlier, fees(500, 50)).fees, fees(500, 50));
    }
}
