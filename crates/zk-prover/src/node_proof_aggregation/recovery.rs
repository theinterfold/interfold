// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable inputs and completed outputs for each node-level DKG fold.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{ensure, Context as _, Result};
use e3_data::{Repositories, Repository};
use e3_events::{
    DKGRecursiveAggregationComplete, E3id, EventContext, EventPublisher, Proof, Sequenced,
    StoreKeys,
};
use serde::{Deserialize, Serialize};

use crate::domain::node_dkg_fold::NodeDkgFoldMeta;

use super::NodeProofAggregator;

const RECOVERY_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct NodeProofRecoveryEntry {
    pub(crate) meta_present: bool,
    pub(crate) last_ec: Option<EventContext<Sequenced>>,
    pub(crate) seqs: BTreeSet<usize>,
    pub(crate) completed: Option<DKGRecursiveAggregationComplete>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NodeProofRecoveryIndex {
    pub(crate) version: u32,
    pub(crate) entries: HashMap<E3id, NodeProofRecoveryEntry>,
}

impl Default for NodeProofRecoveryIndex {
    fn default() -> Self {
        Self {
            version: RECOVERY_VERSION,
            entries: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NodeProofRecovery {
    pub(crate) index: NodeProofRecoveryIndex,
    pub(crate) meta: HashMap<E3id, NodeDkgFoldMeta>,
    pub(crate) proofs: HashMap<E3id, BTreeMap<usize, Proof>>,
}

fn index_repository(repositories: &Repositories) -> Repository<NodeProofRecoveryIndex> {
    Repository::new(
        repositories
            .store
            .scope(StoreKeys::node_dkg_fold_recovery()),
    )
}

pub(super) fn proof_repository(
    repositories: &Repositories,
    e3_id: &E3id,
    seq: usize,
) -> Repository<Proof> {
    Repository::new(
        repositories
            .store
            .scope(StoreKeys::node_dkg_inner_proof(e3_id, seq)),
    )
}

pub(super) fn meta_repository(
    repositories: &Repositories,
    e3_id: &E3id,
) -> Repository<NodeDkgFoldMeta> {
    Repository::new(
        repositories
            .store
            .scope(StoreKeys::node_dkg_fold_meta(e3_id)),
    )
}

impl NodeProofRecovery {
    pub(crate) async fn load(
        repositories: &Repositories,
        active_e3_ids: &HashSet<E3id>,
    ) -> Result<Self> {
        let mut index = index_repository(repositories)
            .read()
            .await?
            .unwrap_or_default();
        ensure!(
            index.version == RECOVERY_VERSION,
            "unsupported node DKG fold recovery version {}",
            index.version
        );
        let stale: Vec<_> = index
            .entries
            .iter()
            .filter(|(e3_id, _)| !active_e3_ids.contains(*e3_id))
            .map(|(e3_id, entry)| (e3_id.clone(), entry.clone()))
            .collect();
        for (e3_id, entry) in stale {
            let ec = entry.last_ec.as_ref().with_context(|| {
                format!("stale persisted DKG fold has no event context for E3 {e3_id}")
            })?;
            for seq in entry.seqs {
                repositories
                    .store
                    .scope(StoreKeys::node_dkg_inner_proof(&e3_id, seq))
                    .write_with_context(&Option::<Proof>::None, ec)?;
            }
            if entry.meta_present {
                repositories
                    .store
                    .scope(StoreKeys::node_dkg_fold_meta(&e3_id))
                    .write_with_context(&Option::<NodeDkgFoldMeta>::None, ec)?;
            }
            index.entries.remove(&e3_id);
            index_repository(repositories).write_with_context(&index, ec)?;
        }
        let mut meta = HashMap::new();
        let mut proofs = HashMap::new();
        for (e3_id, entry) in &index.entries {
            ensure!(
                entry.last_ec.is_some(),
                "persisted DKG fold has no event context for E3 {e3_id}"
            );
            if entry.meta_present {
                let value = meta_repository(repositories, e3_id)
                    .read()
                    .await?
                    .with_context(|| {
                        format!("missing persisted DKG fold metadata for E3 {e3_id}")
                    })?;
                meta.insert(e3_id.clone(), value);
            }
            let mut by_seq = BTreeMap::new();
            for &seq in &entry.seqs {
                let proof = proof_repository(repositories, e3_id, seq)
                    .read()
                    .await?
                    .with_context(|| format!("missing persisted DKG proof {seq} for E3 {e3_id}"))?;
                by_seq.insert(seq, proof);
            }
            proofs.insert(e3_id.clone(), by_seq);
        }
        Ok(Self {
            index,
            meta,
            proofs,
        })
    }
}

impl NodeProofAggregator {
    pub(super) fn resume_recovered(&mut self) {
        let completed: Vec<_> = self
            .recovery_index
            .entries
            .values()
            .filter_map(|entry| entry.completed.clone().zip(entry.last_ec.clone()))
            .collect();
        for (output, ec) in completed {
            if let Err(error) = self.bus.publish(output.clone(), ec) {
                tracing::error!(
                    "could not re-publish completed DKG fold for E3 {}: {error}",
                    output.e3_id
                );
            }
        }
        let pending: Vec<_> = self.states.keys().cloned().collect();
        for e3_id in pending {
            self.try_dispatch_node_dkg_fold(&e3_id);
        }
    }

    pub(super) fn clear_recovery(&mut self, e3_id: &E3id, ec: &EventContext<Sequenced>) {
        self.states.remove(e3_id);
        self.pending_inner_proofs.remove(e3_id);
        self.fold_correlation
            .retain(|_, pending_id| pending_id != e3_id);
        let Some(entry) = self.recovery_index.entries.remove(e3_id) else {
            return;
        };
        let Some(repositories) = &self.recovery_repositories else {
            return;
        };
        for seq in entry.seqs {
            let store = repositories
                .store
                .scope(StoreKeys::node_dkg_inner_proof(e3_id, seq));
            if let Err(error) = store.write_with_context(&Option::<Proof>::None, ec) {
                tracing::error!("could not clear DKG proof {seq} for E3 {e3_id}: {error}");
            }
        }
        if entry.meta_present {
            let store = repositories
                .store
                .scope(StoreKeys::node_dkg_fold_meta(e3_id));
            if let Err(error) = store.write_with_context(&Option::<NodeDkgFoldMeta>::None, ec) {
                tracing::error!("could not clear DKG fold metadata for E3 {e3_id}: {error}");
            }
        }
        if let Err(error) =
            index_repository(repositories).write_with_context(&self.recovery_index, ec)
        {
            tracing::error!("could not clear DKG fold recovery for E3 {e3_id}: {error}");
        }
    }

    pub(super) fn persist_meta(
        &mut self,
        e3_id: &E3id,
        meta: &NodeDkgFoldMeta,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(repositories) = &self.recovery_repositories else {
            return Ok(());
        };
        let mut index = self.recovery_index.clone();
        let entry = index.entries.entry(e3_id.clone()).or_default();
        if !entry.meta_present {
            meta_repository(repositories, e3_id).write_with_context(meta, ec)?;
            entry.meta_present = true;
        }
        entry.last_ec = Some(ec.clone());
        index_repository(repositories).write_with_context(&index, ec)?;
        self.recovery_index = index;
        Ok(())
    }

    pub(super) fn persist_proof(
        &mut self,
        e3_id: &E3id,
        seq: usize,
        proof: &Proof,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(repositories) = &self.recovery_repositories else {
            return Ok(());
        };
        proof_repository(repositories, e3_id, seq).write_with_context(proof, ec)?;
        let mut index = self.recovery_index.clone();
        let entry = index.entries.entry(e3_id.clone()).or_default();
        entry.seqs.insert(seq);
        entry.last_ec = Some(ec.clone());
        index_repository(repositories).write_with_context(&index, ec)?;
        self.recovery_index = index;
        Ok(())
    }

    pub(super) fn persist_completed(
        &mut self,
        output: &DKGRecursiveAggregationComplete,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(repositories) = &self.recovery_repositories else {
            return Ok(());
        };
        let mut index = self.recovery_index.clone();
        let entry = index.entries.entry(output.e3_id.clone()).or_default();
        ensure!(
            entry
                .completed
                .as_ref()
                .is_none_or(|existing| existing == output),
            "conflicting completed DKG fold for E3 {}",
            output.e3_id
        );
        entry.completed = Some(output.clone());
        entry.last_ec = Some(ec.clone());
        index_repository(repositories).write_with_context(&index, ec)?;
        self.recovery_index = index;
        Ok(())
    }
}
