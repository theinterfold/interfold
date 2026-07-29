// SPDX-License-Identifier: LGPL-3.0-only

//! Durable semantic outbox for irreversible EVM effects.
//!
//! Writers persist the full intent before RPC submission, record the exact nonce and transaction
//! hash as soon as the RPC accepts the transaction, and retain a terminal marker after receipt or
//! on-chain preflight reconciliation. The in-memory mutex serializes writers that finish out of
//! order without weakening the synchronous datastore boundary.

use std::{collections::BTreeMap, fmt::Display, sync::Arc};

use alloy::{
    network::{eip2718::Encodable2718, Ethereum, TransactionBuilder},
    primitives::{Address, B256},
    providers::{PendingTransactionBuilder, Provider, WalletProvider},
    rpc::types::TransactionRequest,
};
use anyhow::{Context, Result};
use e3_data::Repository;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::helpers::EthProvider;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvmEffectStatus {
    Intent,
    Signed {
        tx_hash: [u8; 32],
        nonce: u64,
        raw_transaction: Vec<u8>,
    },
    Dispatched {
        tx_hash: [u8; 32],
        nonce: u64,
        raw_transaction: Vec<u8>,
    },
    Terminal {
        tx_hash: Option<[u8; 32]>,
        nonce: Option<u64>,
    },
}

impl EvmEffectStatus {
    pub fn signed_transaction(&self) -> Option<([u8; 32], u64, &[u8])> {
        match self {
            Self::Signed {
                tx_hash,
                nonce,
                raw_transaction,
            }
            | Self::Dispatched {
                tx_hash,
                nonce,
                raw_transaction,
            } => Some((*tx_hash, *nonce, raw_transaction)),
            _ => None,
        }
    }

    fn terminal_from_current(&self) -> Self {
        let signed = self.signed_transaction();
        Self::Terminal {
            tx_hash: signed.map(|(hash, _, _)| hash),
            nonce: signed.map(|(_, nonce, _)| nonce),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmEffectRecord<T> {
    pub payload: T,
    pub status: EvmEffectStatus,
    pub admitted_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmEffectOutboxState<T> {
    pub entries: BTreeMap<String, EvmEffectRecord<T>>,
}

impl<T> Default for EvmEffectOutboxState<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxAdmission {
    Inserted,
    AlreadyPending,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchReconciliation {
    NotDispatched,
    Pending,
    Retry,
    Terminal,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvmOutboxSummary {
    pub pending_effects: usize,
    pub oldest_pending_age_ms: Option<u64>,
}

/// Stable outbox identity for one contract method and its semantic calldata. The readable prefix
/// supports operations, while the canonical payload digest prevents distinct effects for the same
/// E3 from aliasing one another.
pub fn semantic_effect_key<I, T>(method: &str, e3_id: &I, payload: &T) -> String
where
    I: Display + Serialize,
    T: Serialize,
{
    let digest = e3_events::EventId::hash((method, e3_id, payload));
    format!("{method}/{e3_id}/{}", hex::encode(digest.0))
}

#[derive(Clone)]
pub struct EvmEffectOutbox<T> {
    repository: Repository<EvmEffectOutboxState<T>>,
    state: Arc<Mutex<EvmEffectOutboxState<T>>>,
}

impl<T> EvmEffectOutbox<T>
where
    T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    pub async fn load(repository: Repository<EvmEffectOutboxState<T>>) -> Result<Self> {
        let state = repository
            .read()
            .await
            .context("failed to read EVM effect outbox")?
            .unwrap_or_default();
        Ok(Self {
            repository,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub async fn admit(&self, key: String, payload: T) -> Result<OutboxAdmission> {
        let mut state = self.state.lock().await;
        if let Some(record) = state.entries.get(&key) {
            return Ok(
                if matches!(record.status, EvmEffectStatus::Terminal { .. }) {
                    OutboxAdmission::AlreadyTerminal
                } else {
                    OutboxAdmission::AlreadyPending
                },
            );
        }

        let previous = state.clone();
        state.entries.insert(
            key,
            EvmEffectRecord {
                payload,
                status: EvmEffectStatus::Intent,
                admitted_at_ms: crate::operational::now_ms(),
            },
        );
        if let Err(error) = self.repository.write_sync(&state).await {
            *state = previous;
            return Err(error).context("failed to persist EVM effect intent");
        }
        Ok(OutboxAdmission::Inserted)
    }

    pub async fn mark_signed(
        &self,
        key: &str,
        nonce: u64,
        tx_hash: [u8; 32],
        raw_transaction: Vec<u8>,
    ) -> Result<()> {
        let mut replaced_intent = false;
        self.mutate(key, |record| {
            if matches!(record.status, EvmEffectStatus::Intent) {
                record.status = EvmEffectStatus::Signed {
                    tx_hash,
                    nonce,
                    raw_transaction,
                };
                replaced_intent = true;
            }
        })
        .await
        .context("failed to persist signed EVM transaction before dispatch")?;
        anyhow::ensure!(
            replaced_intent,
            "refusing to replace a non-intent EVM outbox record with a signed transaction"
        );
        Ok(())
    }

    pub async fn mark_dispatched(&self, key: &str) -> Result<()> {
        self.mutate(key, |record| {
            if let EvmEffectStatus::Signed {
                tx_hash,
                nonce,
                raw_transaction,
            } = &record.status
            {
                record.status = EvmEffectStatus::Dispatched {
                    tx_hash: *tx_hash,
                    nonce: *nonce,
                    raw_transaction: raw_transaction.clone(),
                };
            }
        })
        .await
        .context("failed to persist dispatched EVM transaction")
    }

    pub async fn mark_terminal(&self, key: &str) -> Result<()> {
        self.mutate(key, |record| {
            record.status = record.status.terminal_from_current();
        })
        .await
        .context("failed to persist terminal EVM effect")
    }

    pub async fn mark_retryable(&self, key: &str) -> Result<()> {
        self.mutate(key, |record| {
            if !matches!(record.status, EvmEffectStatus::Terminal { .. }) {
                record.status = EvmEffectStatus::Intent;
            }
        })
        .await
        .context("failed to persist retryable EVM effect")
    }

    pub async fn pending(&self) -> Vec<(String, T, EvmEffectStatus)> {
        self.state
            .lock()
            .await
            .entries
            .iter()
            .filter(|(_, record)| !matches!(record.status, EvmEffectStatus::Terminal { .. }))
            .map(|(key, record)| (key.clone(), record.payload.clone(), record.status.clone()))
            .collect()
    }

    pub async fn summary(&self, now_ms: u64) -> EvmOutboxSummary {
        let state = self.state.lock().await;
        let mut pending_effects = 0usize;
        let mut oldest_admission = None;
        for record in state
            .entries
            .values()
            .filter(|record| !matches!(record.status, EvmEffectStatus::Terminal { .. }))
        {
            pending_effects = pending_effects.saturating_add(1);
            oldest_admission = Some(
                oldest_admission.map_or(record.admitted_at_ms, |oldest: u64| {
                    oldest.min(record.admitted_at_ms)
                }),
            );
        }
        EvmOutboxSummary {
            pending_effects,
            oldest_pending_age_ms: oldest_admission.map(|admitted| now_ms.saturating_sub(admitted)),
        }
    }

    pub async fn status(&self, key: &str) -> Result<EvmEffectStatus> {
        self.state
            .lock()
            .await
            .entries
            .get(key)
            .map(|record| record.status.clone())
            .with_context(|| format!("EVM effect outbox entry not found: {key}"))
    }

    async fn mutate(
        &self,
        key: &str,
        mutation: impl FnOnce(&mut EvmEffectRecord<T>),
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let previous = state.clone();
        let record = state
            .entries
            .get_mut(key)
            .with_context(|| format!("EVM effect outbox entry not found: {key}"))?;
        mutation(record);
        if let Err(error) = self.repository.write_sync(&state).await {
            *state = previous;
            return Err(error);
        }
        Ok(())
    }
}

/// Locally fill and sign a transaction, persist its exact hash/nonce/raw bytes, and only then
/// expose it to the RPC. A restart can therefore query or rebroadcast the identical transaction
/// even if the process dies during `eth_sendRawTransaction`.
pub async fn send_prepared_transaction<P, T>(
    provider: &EthProvider<P>,
    request: TransactionRequest,
    outbox: &EvmEffectOutbox<T>,
    key: &str,
) -> Result<PendingTransactionBuilder<Ethereum>>
where
    P: Provider + WalletProvider + Clone,
    T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    let _nonce_guard = crate::helpers::transaction_nonce_guard(provider).await;
    let status = outbox.status(key).await?;
    let (tx_hash, raw_transaction) = match status.signed_transaction() {
        Some((tx_hash, _, raw_transaction)) => (B256::from(tx_hash), raw_transaction.to_vec()),
        None => {
            let rpc = provider.provider();
            let signer = rpc.default_signer_address();
            let nonce = rpc.get_transaction_count(signer).pending().await?;
            let request = fill_transaction(provider, request, signer, nonce).await?;
            let envelope = request.build(rpc.wallet()).await?;
            let tx_hash = *envelope.tx_hash();
            let raw_transaction = envelope.encoded_2718();
            outbox
                .mark_signed(key, nonce, tx_hash.into(), raw_transaction.clone())
                .await?;
            (tx_hash, raw_transaction)
        }
    };

    let pending = match provider
        .provider()
        .send_raw_transaction(&raw_transaction)
        .await
    {
        Ok(pending) => pending,
        Err(_error)
            if provider
                .provider()
                .get_transaction_by_hash(tx_hash)
                .await?
                .is_some() =>
        {
            PendingTransactionBuilder::new(provider.provider().root().clone(), tx_hash)
        }
        Err(error) => return Err(error.into()),
    };
    outbox.mark_dispatched(key).await?;
    drop(_nonce_guard);
    Ok(pending)
}

async fn fill_transaction<P>(
    provider: &EthProvider<P>,
    request: TransactionRequest,
    signer: Address,
    nonce: u64,
) -> Result<TransactionRequest>
where
    P: Provider + WalletProvider + Clone,
{
    let rpc = provider.provider();
    let mut request = request
        .with_from(signer)
        .with_nonce(nonce)
        .with_chain_id(provider.chain_id());
    let gas_limit = rpc.estimate_gas(request.clone()).await?;
    request = request.with_gas_limit(gas_limit);

    request = match rpc.estimate_eip1559_fees().await {
        Ok(fees) => request
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas),
        Err(_) => request.with_gas_price(rpc.get_gas_price().await?),
    };
    Ok(request)
}

/// Reconcile an RPC-admitted transaction before deciding whether to resubmit its semantic effect.
/// A successful receipt closes the intent, a known-pending hash remains untouched, and a dropped
/// or reverted hash is returned to the retryable intent state.
pub async fn reconcile_dispatched<P, T>(
    provider: &EthProvider<P>,
    outbox: &EvmEffectOutbox<T>,
    key: &str,
    status: &EvmEffectStatus,
) -> Result<DispatchReconciliation>
where
    P: Provider + Clone,
    T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    let Some((tx_hash, _, _)) = status.signed_transaction() else {
        return Ok(DispatchReconciliation::NotDispatched);
    };
    let tx_hash = B256::from(tx_hash);

    if let Some(receipt) = provider.provider().get_transaction_receipt(tx_hash).await? {
        if receipt.status() {
            outbox.mark_terminal(key).await?;
            return Ok(DispatchReconciliation::Terminal);
        }
        outbox.mark_retryable(key).await?;
        return Ok(DispatchReconciliation::Retry);
    }

    if provider
        .provider()
        .get_transaction_by_hash(tx_hash)
        .await?
        .is_some()
    {
        return Ok(DispatchReconciliation::Pending);
    }

    Ok(DispatchReconciliation::Retry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_data::Repositories;

    #[actix::test]
    async fn intent_dispatch_and_terminal_survive_reload() -> Result<()> {
        let repositories = Repositories::in_mem();
        let repository = Repository::new(repositories.store.scope("//test/evm_outbox"));
        let outbox = EvmEffectOutbox::load(repository.clone()).await?;

        assert_eq!(
            outbox.admit("ticket/1:7".into(), vec![1, 2, 3]).await?,
            OutboxAdmission::Inserted
        );
        outbox
            .mark_signed("ticket/1:7", 42, [0xabu8; 32], vec![4, 5, 6])
            .await?;

        let signed = EvmEffectOutbox::load(repository.clone()).await?;
        assert_eq!(
            signed.pending().await,
            vec![(
                "ticket/1:7".into(),
                vec![1, 2, 3],
                EvmEffectStatus::Signed {
                    tx_hash: [0xabu8; 32],
                    nonce: 42,
                    raw_transaction: vec![4, 5, 6],
                },
            )]
        );
        signed.mark_dispatched("ticket/1:7").await?;

        let reloaded = EvmEffectOutbox::load(repository.clone()).await?;
        assert_eq!(
            reloaded.pending().await,
            vec![(
                "ticket/1:7".into(),
                vec![1, 2, 3],
                EvmEffectStatus::Dispatched {
                    tx_hash: [0xabu8; 32],
                    nonce: 42,
                    raw_transaction: vec![4, 5, 6],
                },
            )]
        );

        reloaded.mark_terminal("ticket/1:7").await?;
        assert!(EvmEffectOutbox::load(repository)
            .await?
            .pending()
            .await
            .is_empty());
        Ok(())
    }

    #[actix::test]
    async fn duplicate_intent_never_reopens_terminal_effect() -> Result<()> {
        let repositories = Repositories::in_mem();
        let repository = Repository::new(repositories.store.scope("//test/evm_outbox_duplicate"));
        let outbox = EvmEffectOutbox::load(repository).await?;
        let key = "plaintext/1:9".to_string();

        assert_eq!(
            outbox.admit(key.clone(), 1u8).await?,
            OutboxAdmission::Inserted
        );
        outbox.mark_terminal(&key).await?;
        assert_eq!(
            outbox.admit(key, 2u8).await?,
            OutboxAdmission::AlreadyTerminal
        );
        assert!(outbox.pending().await.is_empty());
        Ok(())
    }

    #[actix::test]
    async fn summary_reports_pending_count_and_oldest_durable_age() -> Result<()> {
        let repositories = Repositories::in_mem();
        let repository = Repository::new(repositories.store.scope("//test/evm_outbox_summary"));
        let state = EvmEffectOutboxState {
            entries: BTreeMap::from([
                (
                    "oldest".to_owned(),
                    EvmEffectRecord {
                        payload: 1u8,
                        status: EvmEffectStatus::Intent,
                        admitted_at_ms: 1_000,
                    },
                ),
                (
                    "newer".to_owned(),
                    EvmEffectRecord {
                        payload: 2u8,
                        status: EvmEffectStatus::Signed {
                            tx_hash: [1; 32],
                            nonce: 1,
                            raw_transaction: vec![1],
                        },
                        admitted_at_ms: 4_000,
                    },
                ),
                (
                    "terminal".to_owned(),
                    EvmEffectRecord {
                        payload: 3u8,
                        status: EvmEffectStatus::Terminal {
                            tx_hash: None,
                            nonce: None,
                        },
                        admitted_at_ms: 500,
                    },
                ),
            ]),
        };
        repository.write_sync(&state).await?;
        let outbox = EvmEffectOutbox::load(repository).await?;

        assert_eq!(
            outbox.summary(10_000).await,
            EvmOutboxSummary {
                pending_effects: 2,
                oldest_pending_age_ms: Some(9_000),
            }
        );
        Ok(())
    }

    #[test]
    fn semantic_keys_separate_distinct_payloads() {
        let e3_id = "1:7";
        let first = semantic_effect_key("publish_plaintext", &e3_id, &vec![1u8]);
        let duplicate = semantic_effect_key("publish_plaintext", &e3_id, &vec![1u8]);
        let distinct = semantic_effect_key("publish_plaintext", &e3_id, &vec![2u8]);

        assert_eq!(first, duplicate);
        assert_ne!(first, distinct);
        assert!(first.starts_with("publish_plaintext/1:7/"));
    }
}
