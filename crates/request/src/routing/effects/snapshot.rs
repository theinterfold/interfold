// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{ContextRepositoryFactory, DkgFoldAttestationContextRepositoryFactory};
use anyhow::Context as _;
use e3_data::{Repositories, RepositoriesFactory};
use e3_events::{DkgFoldAttestationContext, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION};
use tracing::warn;

#[derive(Serialize, Deserialize)]
pub struct E3RouterSnapshot {
    pub(crate) contexts: Vec<E3id>,
    pub(crate) completed: HashSet<E3id>,
}

pub async fn load_dkg_fold_attestation_contexts(
    repositories: &Repositories,
) -> Result<HashMap<E3id, DkgFoldAttestationContext>> {
    let router = repositories.router();
    let context_ids = match repositories.request_router_checkpoint().read().await? {
        Some(checkpoint) => checkpoint.contexts,
        None => {
            let Some(snapshot) = router.read().await? else {
                return Ok(HashMap::new());
            };
            snapshot.contexts
        }
    };

    let context_repositories = router.repositories();
    let mut contexts = HashMap::new();
    for e3_id in context_ids {
        let Some(event) = context_repositories
            .context(&e3_id)
            .repositories()
            .dkg_fold_attestation_context(&e3_id)
            .read()
            .await?
        else {
            warn!(
                e3_id = %e3_id,
                "Disabled DKG attestation recovery because the active E3 has no saved context"
            );
            continue;
        };
        ensure!(
            event.schema_version == DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
            "unsupported DKG fold attestation context schema version {} for E3 {}",
            event.schema_version,
            e3_id
        );
        contexts.insert(e3_id, event.context);
    }
    Ok(contexts)
}

impl Snapshot for E3Router {
    type Snapshot = E3RouterSnapshot;

    fn snapshot(&self) -> Result<Self::Snapshot> {
        Ok(Self::Snapshot {
            contexts: self.contexts.keys().cloned().collect(),
            completed: self.completed.clone(),
        })
    }
}

#[async_trait]
impl FromSnapshotWithParams for E3Router {
    type Params = E3RouterParams;

    async fn from_snapshot(params: Self::Params, snapshot: Self::Snapshot) -> Result<Self> {
        let mut contexts = HashMap::new();
        let repositories = params.store.repositories();

        for e3_id in snapshot.contexts {
            let context_snapshot = repositories
                .context(&e3_id)
                .read()
                .await?
                .with_context(|| {
                    format!(
                        "request router snapshot references E3 {e3_id}, but its context snapshot is missing"
                    )
                })?;

            contexts.insert(
                e3_id.clone(),
                E3Context::from_snapshot(
                    E3ContextParams {
                        repository: repositories.context(&e3_id),
                        e3_id: e3_id.clone(),
                        extensions: params.extensions.clone(),
                    },
                    context_snapshot,
                )
                .await?,
            );
        }

        Ok(E3Router {
            contexts,
            completed: snapshot.completed,
            extensions: params.extensions,
            buffer: EventBuffer::default(),
            bus: params.bus,
            store: params.store,
            replay_cursors: params.replay_cursors,
            recovery_store: params.recovery_store,
            recovered_selections: params.recovered_selections,
            teardown_deadlines: params.teardown_deadlines,
            teardown_grace: params.teardown_grace,
        })
    }
}
