// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Per-round and round-index repositories over the shared store (CRISP `repo.rs`).

use super::models::{E3FedAvg, IndexedUpdate, RoundResults, RoundStatus};
use e3_sdk::indexer::{models::E3 as InterfoldE3, DataStore, E3Repository, SharedStore};
use eyre::{eyre, Result};

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct RoundIndex {
    ids: Vec<String>,
}

pub struct RoundIndexRepository<S: DataStore> {
    store: SharedStore<S>,
}

impl<S: DataStore> RoundIndexRepository<S> {
    pub fn new(store: SharedStore<S>) -> Self {
        Self { store }
    }

    pub async fn record_round(&mut self, e3_id: &str) -> Result<()> {
        let id = e3_id.to_string();
        self.store
            .modify("_fedavg:round_index", |index: Option<RoundIndex>| {
                let mut index = index.unwrap_or_default();
                if !index.ids.contains(&id) {
                    index.ids.push(id.clone());
                }
                Some(index)
            })
            .await
            .map_err(|e| eyre!("Could not record round: {e}"))?;
        Ok(())
    }

    pub async fn round_ids(&self) -> Result<Vec<String>> {
        Ok(self
            .store
            .get::<RoundIndex>("_fedavg:round_index")
            .await
            .map_err(|e| eyre!("Could not read round index: {e}"))?
            .unwrap_or_default()
            .ids)
    }
}

pub struct FedAvgE3Repository<S: DataStore> {
    store: SharedStore<S>,
    e3_id: String,
}

impl<S: DataStore> FedAvgE3Repository<S> {
    pub fn new(store: SharedStore<S>, e3_id: impl ToString) -> Self {
        Self {
            store,
            e3_id: e3_id.to_string(),
        }
    }

    fn key(&self) -> String {
        format!("_fedavg:e3:{}", self.e3_id)
    }

    pub async fn set(&mut self, value: &E3FedAvg) -> Result<()> {
        let key = self.key();
        self.store
            .insert(&key, value)
            .await
            .map_err(|e| eyre!("Could not store round at '{key}': {e}"))?;
        Ok(())
    }

    pub async fn try_get(&self) -> Result<Option<E3FedAvg>> {
        let key = self.key();
        self.store
            .get::<E3FedAvg>(&key)
            .await
            .map_err(|e| eyre!("Could not read '{key}': {e}"))
    }

    pub async fn get(&self) -> Result<E3FedAvg> {
        self.try_get()
            .await?
            .ok_or_else(|| eyre!("No round {}", self.e3_id))
    }

    /// Atomic read-modify-write of the round record.
    pub async fn update<F>(&mut self, mut f: F) -> Result<E3FedAvg>
    where
        F: FnMut(&mut E3FedAvg) + Send,
    {
        let key = self.key();
        self.store
            .modify(&key, |current: Option<E3FedAvg>| {
                let mut round = current?;
                f(&mut round);
                Some(round)
            })
            .await
            .map_err(|e| eyre!("Could not update '{key}': {e}"))?
            .ok_or_else(|| eyre!("No round {}", self.e3_id))
    }

    pub async fn set_status(&mut self, status: RoundStatus) -> Result<()> {
        let now = now_secs();
        self.update(|r| {
            r.status = status;
            r.stage_at.push((format!("{status:?}").to_lowercase(), now));
        })
        .await?;
        Ok(())
    }

    pub async fn set_error(&mut self, error: String) -> Result<()> {
        self.update(|r| {
            r.status = RoundStatus::Failed;
            r.error = Some(error.clone());
        })
        .await?;
        Ok(())
    }

    pub async fn record_timing(&mut self, stage: &str, ms: u64) -> Result<()> {
        let stage = stage.to_string();
        self.update(|r| r.timings.push((stage.clone(), ms))).await?;
        Ok(())
    }

    /// Records an accepted update (idempotent on the on-chain index).
    pub async fn insert_update(
        &mut self,
        upd: IndexedUpdate,
        ciphertexts: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        self.update(|r| {
            if r.updates.iter().any(|b| b.index == upd.index) {
                return;
            }
            if let Some((g, c)) = &ciphertexts {
                r.ciphertexts.push((upd.index, g.clone(), c.clone()));
            }
            r.updates.push(upd.clone());
            r.updates.sort_by_key(|b| b.index);
        })
        .await?;
        Ok(())
    }

    pub async fn set_results(&mut self, results: RoundResults) -> Result<()> {
        self.update(|r| {
            r.results = Some(results.clone());
            r.status = RoundStatus::Finished;
            r.stage_at.push(("finished".into(), now_secs()));
        })
        .await?;
        Ok(())
    }

    /// The indexer's own record (exists once `CommitteePublished` landed).
    pub async fn interfold_e3(&self) -> Result<Option<InterfoldE3>> {
        let repo = E3Repository::new(self.store.clone(), &self.e3_id);
        match repo.get_e3().await {
            Ok(e3) => Ok(Some(e3)),
            Err(_) => Ok(None),
        }
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
