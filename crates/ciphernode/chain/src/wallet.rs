// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Account, Call, Estimate, KeyChunk, OnChain, RpcError};
use alloy::{
    eips::{eip1559::Eip1559Estimation, BlockId},
    network::TransactionBuilder,
    providers::{Provider, WalletProvider},
    rpc::types::{Filter, TransactionRequest},
    transports::{RpcError as TransportFailure, TransportErrorKind},
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolEvent;
use e3_evm_contracts::ICiphernodeRegistry::CommitteePublicKeyChunkPublished;
use e3_evm_transactions::nonce::{broadcast_refused, next_free_nonce};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::{Mutex as SyncMutex, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tracing::warn;

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
    /// How many senders drive each call, by the call's hash: a send under way, or a delivery that
    /// waits to try again.
    driven: SyncMutex<HashMap<B256, usize>>,
}

struct Nonces {
    /// The nonces this process sent, with their send times.
    sent: BTreeMap<u64, Instant>,
    unmined: Unmined,
    /// The unmined nonces whose calls had no sender at the last pass.
    suspects: BTreeSet<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sent {
    nonce: u64,
    fees: Eip1559Estimation,
}

/// A transaction at a nonce the chain has not used yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Pending {
    /// The hash of the call's target and data; none for the empty transaction that frees the
    /// nonce.
    call: Option<B256>,
    #[serde(with = "fees")]
    fees: Eip1559Estimation,
    /// When it was sent last, in Unix seconds.
    at: u64,
}

/// The last send at each nonce the chain has not used yet. It is kept in a file, so that after a
/// restart the node still replaces a transaction stuck on low fees instead of queueing behind it.
struct Unmined {
    path: PathBuf,
    sends: BTreeMap<u64, Pending>,
}

impl Unmined {
    fn open(path: PathBuf) -> io::Result<Self> {
        let sends = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self { path, sends })
    }

    /// The nonce of `call`'s unmined send, and the send.
    fn of(&self, call: &B256) -> Option<(u64, Pending)> {
        let mut sends = self.sends.iter();
        let (nonce, pending) = sends.find(|(_, pending)| pending.call == Some(*call))?;
        Some((*nonce, *pending))
    }

    #[cfg(test)]
    fn insert(&mut self, nonce: u64, pending: Pending) -> io::Result<()> {
        self.sends.insert(nonce, pending);
        self.save()
    }

    async fn insert_async(&mut self, nonce: u64, pending: Pending) -> io::Result<()> {
        self.sends.insert(nonce, pending);
        self.save_async().await
    }

    /// Forgets the send at `nonce` if it still carries `call`.
    async fn landed_async(&mut self, nonce: u64, call: &B256) -> io::Result<()> {
        match self
            .sends
            .get(&nonce)
            .is_some_and(|sent| sent.call == Some(*call))
        {
            true => {
                self.sends.remove(&nonce);
                self.save_async().await
            }
            false => Ok(()),
        }
    }

    /// Forgets the sends whose nonces the chain used, `mined` being the account's mined count.
    #[cfg(test)]
    fn forget_mined(&mut self, mined: u64) -> io::Result<()> {
        let before = self.sends.len();
        self.sends.retain(|nonce, _| *nonce >= mined);
        match self.sends.len() == before {
            true => Ok(()),
            false => self.save(),
        }
    }

    async fn forget_mined_async(&mut self, mined: u64) -> io::Result<()> {
        let before = self.sends.len();
        self.sends.retain(|nonce, _| *nonce >= mined);
        match self.sends.len() == before {
            true => Ok(()),
            false => self.save_async().await,
        }
    }

    #[cfg(test)]
    fn save(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec(&self.sends)?;
        write_atomic(&self.path, &bytes)
    }

    async fn save_async(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec(&self.sends)?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || write_atomic(&path, &bytes))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
    }
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    let partial = path.with_extension("partial");
    let mut file = fs::File::create(&partial)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    fs::rename(&partial, path)?;
    match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => fs::File::open(dir)?.sync_all(),
        None => Ok(()),
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

/// Counts a call as driven for as long as it lives.
pub struct Driving<'a> {
    driven: &'a SyncMutex<HashMap<B256, usize>>,
    call: B256,
}

impl Drop for Driving<'_> {
    fn drop(&mut self) {
        let mut driven = self.driven.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(senders) = driven.get_mut(&self.call) {
            *senders -= 1;
            if *senders == 0 {
                driven.remove(&self.call);
            }
        }
    }
}

/// A call's identity in the account's records: the hash of its target and data.
fn call_hash(call: &Call) -> B256 {
    keccak256([call.to.as_slice(), &call.data].concat())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl<P> Wallet<P> {
    fn driving(&self, call: B256) -> Driving<'_> {
        let mut driven = self.driven.lock().unwrap_or_else(PoisonError::into_inner);
        *driven.entry(call).or_default() += 1;
        Driving {
            driven: &self.driven,
            call,
        }
    }

    fn driven(&self, call: Option<B256>) -> bool {
        let driven = self.driven.lock().unwrap_or_else(PoisonError::into_inner);
        call.is_some_and(|call| driven.contains_key(&call))
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
            suspects: BTreeSet::new(),
        };
        Ok(Self {
            provider,
            chain_id,
            confirmations,
            nonces: Mutex::new(nonces),
            driven: SyncMutex::new(HashMap::new()),
        })
    }

    /// Replaces the transaction at `nonce` with an empty one to the account itself, at fees a
    /// chain node takes as its replacement. Whichever of the two lands uses the nonce.
    async fn free(
        &self,
        nonces: &mut Nonces,
        account: Address,
        nonce: u64,
    ) -> Result<(), RpcError> {
        let Some(earlier) = nonces.unmined.sends.get(&nonce).copied() else {
            return Ok(());
        };
        let estimate = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(RpcError::new)?;
        let fees = replacement(
            Sent {
                nonce,
                fees: earlier.fees,
            },
            estimate,
        )
        .fees;
        let request = TransactionRequest::default()
            .with_from(account)
            .with_to(account)
            .with_value(U256::ZERO)
            .with_nonce(nonce)
            .with_chain_id(self.chain_id)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
        let gas = self
            .provider
            .estimate_gas(request.clone())
            .await
            .map_err(RpcError::new)?;
        // A delivery of the call can start during those reads. Then it keeps its transaction; a
        // delivery that starts later sends at a new nonce.
        if self.driven(earlier.call) {
            return Ok(());
        }
        let pending = Pending {
            call: None,
            fees,
            at: unix_now(),
        };
        // Kept before the broadcast, as for any send.
        nonces
            .unmined
            .insert_async(nonce, pending)
            .await
            .map_err(RpcError::new)?;
        match self
            .provider
            .send_transaction(request.with_gas_limit(gas))
            .await
        {
            Ok(_) => warn!(nonce, "freed a nonce whose call no one sends any more"),
            Err(error) => warn!(nonce, %error, "freeing a nonce failed; the next pass tries again"),
        }
        Ok(())
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
        let request = self.request(call);
        if self.confirmations == 0 {
            return match self
                .provider
                .estimate_gas(request)
                .block(BlockId::latest())
                .await
            {
                Ok(gas) => Ok(Estimate::Gas(gas)),
                Err(error) => Ok(Estimate::Reverts(revert_of(error)?)),
            };
        }
        let head = self
            .provider
            .get_block_number()
            .await
            .map_err(RpcError::new)?;
        let confirmed = BlockId::number(head.saturating_sub(self.confirmations));
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

    async fn key_chunk(&self, chunk: &KeyChunk) -> Result<OnChain, RpcError> {
        let head = self
            .provider
            .get_block_number()
            .await
            .map_err(RpcError::new)?;
        let filter = Filter::new()
            .address(chunk.registry)
            .event_signature(CommitteePublicKeyChunkPublished::SIGNATURE_HASH)
            .topic1(B256::from(chunk.e3))
            .topic2(self.provider.default_signer_address().into_word())
            .topic3(chunk.candidate)
            .from_block(chunk.since)
            .to_block(head);
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(RpcError::new)?;
        let oldest = logs
            .iter()
            .filter_map(|log| {
                let event = log.log_decode::<CommitteePublicKeyChunkPublished>().ok()?;
                (event.inner.data.chunkIndex == chunk.index).then_some(log.block_number?)
            })
            .min();
        Ok(match oldest {
            None => OnChain::Absent,
            Some(block) if block <= head.saturating_sub(self.confirmations) => OnChain::Confirmed,
            Some(_) => OnChain::Unconfirmed,
        })
    }

    async fn key_chunks(
        &self,
        first: &KeyChunk,
        count: u16,
    ) -> Option<Result<HashMap<u16, OnChain>, RpcError>> {
        let result = async {
            let head = self
                .provider
                .get_block_number()
                .await
                .map_err(RpcError::new)?;
            let filter = Filter::new()
                .address(first.registry)
                .event_signature(CommitteePublicKeyChunkPublished::SIGNATURE_HASH)
                .topic1(B256::from(first.e3))
                .topic2(self.provider.default_signer_address().into_word())
                .topic3(first.candidate)
                .from_block(first.since)
                .to_block(head);
            let logs = self
                .provider
                .get_logs(&filter)
                .await
                .map_err(RpcError::new)?;
            let mut oldest: HashMap<u16, u64> = HashMap::new();
            for log in &logs {
                let Ok(event) = log.log_decode::<CommitteePublicKeyChunkPublished>() else {
                    continue;
                };
                let index = event.inner.data.chunkIndex;
                let Some(block) = log.block_number else {
                    continue;
                };
                if index < count {
                    oldest
                        .entry(index)
                        .and_modify(|prev| *prev = (*prev).min(block))
                        .or_insert(block);
                }
            }
            let confirmed_head = head.saturating_sub(self.confirmations);
            let mut map = HashMap::with_capacity(usize::from(count));
            for index in 0..count {
                let state = match oldest.get(&index).copied() {
                    None => OnChain::Absent,
                    Some(block) if block <= confirmed_head => OnChain::Confirmed,
                    Some(_) => OnChain::Unconfirmed,
                };
                map.insert(index, state);
            }
            Ok(map)
        }
        .await;
        Some(result)
    }

    /// Fees are estimated before the nonce is chosen, so the turn only signs and broadcasts. An
    /// RPC node's pending count can miss a transaction that another node behind the same endpoint
    /// accepted a moment ago, so a new nonce also skips the ones this process sent recently. The
    /// turn ends before the receipt, so a slow confirmation holds up no other call.
    async fn send(&self, call: &Call, gas: u64) -> Result<bool, RpcError> {
        let key = call_hash(call);
        let _driving = self.driving(key);
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(RpcError::new)?;
        let account = self.provider.default_signer_address();
        let (nonce, pending) = {
            let mut nonces = self.nonces.lock().await;
            let mined = self
                .provider
                .get_transaction_count(account)
                .latest()
                .await
                .map_err(RpcError::new)?;
            nonces
                .unmined
                .forget_mined_async(mined)
                .await
                .map_err(RpcError::new)?;
            let replaced = nonces.unmined.of(&key);
            let send = match replaced {
                Some((nonce, earlier)) => replacement(
                    Sent {
                        nonce,
                        fees: earlier.fees,
                    },
                    fees,
                ),
                None => {
                    let count = self
                        .provider
                        .get_transaction_count(account)
                        .pending()
                        .await
                        .map_err(RpcError::new)?;
                    let mut nonce = next_free_nonce(&mut nonces.sent, count, Instant::now());
                    // A chain node's pending count can miss a transaction this account still
                    // keeps, as after a restart. Its nonce stays taken until it is mined or freed.
                    while nonces.unmined.sends.contains_key(&nonce)
                        || nonces.sent.contains_key(&nonce)
                    {
                        nonce += 1;
                    }
                    Sent { nonce, fees }
                }
            };
            nonces.sent.insert(send.nonce, Instant::now());
            let unmined = Pending {
                call: Some(key),
                fees: send.fees,
                at: unix_now(),
            };
            // Kept before the broadcast: the node can take the transaction and lose its answer, or
            // this process can stop before the answer.
            nonces
                .unmined
                .insert_async(send.nonce, unmined)
                .await
                .map_err(RpcError::new)?;
            let request = self
                .request(call)
                .with_gas_limit(gas)
                .with_max_fee_per_gas(send.fees.max_fee_per_gas)
                .with_max_priority_fee_per_gas(send.fees.max_priority_fee_per_gas)
                .with_chain_id(self.chain_id)
                .with_nonce(send.nonce);
            match self.provider.send_transaction(request).await {
                Ok(pending) => (send.nonce, pending),
                Err(error) => {
                    let error = alloy::contract::Error::TransportError(error);
                    if broadcast_refused(&error) && replaced.is_none() {
                        nonces.sent.remove(&send.nonce);
                        nonces
                            .unmined
                            .landed_async(send.nonce, &key)
                            .await
                            .map_err(RpcError::new)?;
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
        nonces
            .unmined
            .landed_async(nonce, &key)
            .await
            .map_err(RpcError::new)?;
        Ok(receipt.status())
    }

    fn drive(&self, call: &Call) -> impl Send + '_ {
        self.driving(call_hash(call))
    }

    /// A transaction whose call no one sends any more, because the node stopped it or no longer
    /// owes it, can sit on low fees for good, and every later transaction of the account waits
    /// behind it. Such a nonce is freed when two passes in a row find no sender for its call: a
    /// call the node starts again can come between the two.
    async fn free_abandoned(&self) -> Result<(), RpcError> {
        let account = self.provider.default_signer_address();
        let mut nonces = self.nonces.lock().await;
        let mined = self
            .provider
            .get_transaction_count(account)
            .latest()
            .await
            .map_err(RpcError::new)?;
        nonces
            .unmined
            .forget_mined_async(mined)
            .await
            .map_err(RpcError::new)?;
        let unsent: BTreeSet<u64> = nonces
            .unmined
            .sends
            .iter()
            .filter(|(_, pending)| !self.driven(pending.call))
            .map(|(nonce, _)| *nonce)
            .collect();
        let free = &unsent & &nonces.suspects;
        nonces.suspects = &unsent - &free;
        for nonce in free {
            let call = nonces.unmined.sends.get(&nonce).and_then(|sent| sent.call);
            // A sender can start in the meantime; it then sends at a new nonce.
            if !self.driven(call) {
                self.free(&mut nonces, account, nonce).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod anvil_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        network::EthereumWallet,
        providers::{mock::Asserter, ProviderBuilder},
        rpc::types::Log,
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

    fn chunk(index: u16) -> KeyChunk {
        KeyChunk {
            registry: Address::repeat_byte(9),
            e3: U256::from(7),
            candidate: B256::repeat_byte(5),
            index,
            since: 10,
        }
    }

    /// A log of the chunk at `index`, in `block`.
    fn chunk_log(index: u16, block: u64) -> Log {
        let event = CommitteePublicKeyChunkPublished {
            e3Id: U256::from(7),
            publisher: Address::repeat_byte(2),
            candidateHash: B256::repeat_byte(5),
            nodes: Vec::new(),
            pkCommitment: B256::repeat_byte(6),
            chunkIndex: index,
            chunkCount: 5,
            totalLength: 100,
            chunk: Bytes::from_static(&[1]),
        };
        Log {
            inner: alloy_primitives::Log {
                address: Address::repeat_byte(9),
                data: event.encode_log_data(),
            },
            block_number: Some(block),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_chunk_counts_once_its_block_is_confirmed() {
        let found = |logs: Vec<Log>| async move {
            let (asserter, dir) = (Asserter::new(), tempfile::tempdir().unwrap());
            asserter.push_success(&U256::from(100));
            asserter.push_success(&logs);
            wallet(asserter, &dir).key_chunk(&chunk(2)).await.unwrap()
        };
        assert_eq!(found(Vec::new()).await, OnChain::Absent);
        assert_eq!(found(vec![chunk_log(1, 50)]).await, OnChain::Absent);
        assert_eq!(found(vec![chunk_log(2, 97)]).await, OnChain::Confirmed);
        assert_eq!(found(vec![chunk_log(2, 98)]).await, OnChain::Unconfirmed);
        assert_eq!(
            found(vec![chunk_log(2, 99), chunk_log(2, 60)]).await,
            OnChain::Confirmed
        );
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
        let sent = Pending {
            call: Some(call),
            fees: fees(100, 10),
            at: 1_000,
        };
        Unmined::open(path.clone())
            .unwrap()
            .insert(7, sent)
            .unwrap();
        let mut reopened = Unmined::open(path.clone()).unwrap();
        assert_eq!(reopened.of(&call), Some((7, sent)));
        reopened.forget_mined(8).unwrap();
        assert_eq!(Unmined::open(path).unwrap().of(&call), None);
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
