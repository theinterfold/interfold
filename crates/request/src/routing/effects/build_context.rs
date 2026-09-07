// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::CiphernodeSelected;

/// Builder for [`E3Router`].
pub struct E3RouterBuilder {
    pub bus: BusHandle,
    pub extensions: Vec<Box<dyn E3Extension>>,
    pub recovered_selections: Vec<CiphernodeSelected>,
    pub recovery_store: Repository<RequestRouterCheckpoint>,
    pub store: Repository<E3RouterSnapshot>,
    pub teardown_grace: std::time::Duration,
}

impl E3RouterBuilder {
    pub fn with(mut self, listener: Box<dyn E3Extension>) -> Self {
        self.extensions.push(listener);
        self
    }

    /// Override how long a slashably-failed E3's context is kept for its accusation window.
    pub fn with_teardown_grace(mut self, grace: std::time::Duration) -> Self {
        self.teardown_grace = grace;
        self
    }

    /// Restore local committee-selection effects without creating another durable protocol event.
    pub fn with_recovered_selections(
        mut self,
        recovered_selections: Vec<CiphernodeSelected>,
    ) -> Self {
        self.recovered_selections = recovered_selections;
        self
    }

    pub async fn build(self) -> Result<Addr<E3Router>> {
        let recovered_selections = self.recovered_selections;
        let legacy_snapshot: Option<E3RouterSnapshot> = self.store.read().await?;
        let recovery_store = self.recovery_store;
        let recovery_checkpoint = recovery_store.read().await?;
        let (snapshot, replay_cursors, teardown_deadlines) = match recovery_checkpoint {
            Some(checkpoint) => (
                Some(E3RouterSnapshot {
                    contexts: checkpoint.contexts,
                    completed: checkpoint.completed,
                }),
                checkpoint.replay_cursors,
                checkpoint.teardown_deadlines,
            ),
            None => (legacy_snapshot, HashMap::new(), HashMap::new()),
        };
        let params = E3RouterParams {
            extensions: self.extensions.into(),
            bus: self.bus.clone(),
            store: self.store.clone(),
            replay_cursors,
            recovery_store,
            recovered_selections,
            teardown_deadlines,
            teardown_grace: self.teardown_grace,
        };

        let router = match snapshot {
            Some(snapshot) => E3Router::from_snapshot(params, snapshot).await?,
            None => E3Router::from_params(params),
        };
        for selection in &router.recovered_selections {
            ensure!(
                router.completed.contains(&selection.e3_id)
                    || router.contexts.contains_key(&selection.e3_id),
                "cannot restore local selection for E3 {}: request-router context is missing",
                selection.e3_id
            );
        }

        let addr = router.start();
        self.bus.subscribe(EventType::All, addr.clone().recipient());
        Ok(addr)
    }
}
