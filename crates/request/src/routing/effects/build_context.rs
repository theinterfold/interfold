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
    pub teardown_grace: Duration,
    pub complete_on_restart: HashSet<E3id>,
}

struct RecipientExtension {
    key: &'static str,
    inner: Box<dyn E3Extension>,
}

#[async_trait]
impl E3Extension for RecipientExtension {
    fn expected_recipient(&self) -> Option<&'static str> {
        Some(self.key)
    }

    fn on_event(&self, context: &mut E3Context, event: &InterfoldEvent) {
        self.inner.on_event(context, event);
    }

    async fn hydrate(
        &self,
        context: &mut E3Context,
        snapshot: &crate::E3ContextSnapshot,
    ) -> Result<()> {
        self.inner.hydrate(context, snapshot).await
    }
}

impl E3RouterBuilder {
    /// Install an extension and register its recipient for deferred delivery.
    pub fn with_recipient(self, key: &'static str, extension: Box<dyn E3Extension>) -> Self {
        self.with(Box::new(RecipientExtension {
            key,
            inner: extension,
        }))
    }

    pub fn with(mut self, listener: Box<dyn E3Extension>) -> Self {
        self.extensions.push(listener);
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

    /// Set how long a slashably-failed E3 keeps its context before teardown.
    pub fn with_teardown_grace(mut self, teardown_grace: Duration) -> Self {
        self.teardown_grace = teardown_grace;
        self
    }

    /// Set the finished E3s whose restored contexts complete at `EffectsEnabled` without resuming.
    pub fn with_complete_on_restart(mut self, complete_on_restart: HashSet<E3id>) -> Self {
        self.complete_on_restart = complete_on_restart;
        self
    }

    pub async fn build(self) -> Result<Addr<E3Router>> {
        let recovered_selections = self.recovered_selections;
        let legacy_snapshot: Option<E3RouterSnapshot> = self.store.read().await?;
        let recovery_store = self.recovery_store;
        let recovery_checkpoint = recovery_store.read().await?;
        let (snapshot, replay_cursors) = match recovery_checkpoint {
            Some(checkpoint) => (
                Some(E3RouterSnapshot {
                    contexts: checkpoint.contexts,
                    completed: checkpoint.completed,
                }),
                checkpoint.replay_cursors,
            ),
            None => (legacy_snapshot, HashMap::new()),
        };
        let params = E3RouterParams {
            extensions: self.extensions.into(),
            bus: self.bus.clone(),
            store: self.store.clone(),
            replay_cursors,
            recovery_store,
            recovered_selections,
            teardown_grace: self.teardown_grace,
            complete_on_restart: self.complete_on_restart,
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
