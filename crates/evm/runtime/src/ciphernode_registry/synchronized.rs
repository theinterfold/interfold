// SPDX-License-Identifier: LGPL-3.0-only

//! Local synchronized publication through the registry writer's existing replay/nonce owners.

use super::*;
use e3_events::{EventSource, SynchronizedDkgPublicationReady};
use e3_request::canonical_key::{CanonicalPublicKey, CanonicalPublicKeys};

#[path = "synchronized/effects.rs"]
mod effects;
#[path = "synchronized/recovery.rs"]
mod recovery;
pub use effects::publish_synchronized_committee_definition;
pub use recovery::recover_synchronized_publications;

#[cfg(test)]
#[path = "synchronized/tests.rs"]
mod tests;

impl<P: Provider + WalletProvider + Clone + 'static> CiphernodeRegistrySolWriter<P> {
    pub(super) fn accept_synchronized_definition(
        &mut self,
        intent: SynchronizedDkgPublicationReady,
        source: EventSource,
    ) -> Result<()> {
        anyhow::ensure!(
            source == EventSource::Local,
            "publication intent must be local"
        );
        if self.settled_keys.contains(&intent.e3_id)
            || self.synchronized_settled.contains(&intent.e3_id)
            || self.canonical_keys.public_key(&intent.e3_id).is_some()
        {
            return Ok(());
        }
        self.validate_synchronized_intent(&intent)?;
        self.synchronized_publication
            .record(intent.e3_id.clone(), intent);
        Ok(())
    }

    fn validate_synchronized_intent(
        &self,
        intent: &SynchronizedDkgPublicationReady,
    ) -> Result<CanonicalPublicKey> {
        validate_synchronized_intent(&self.canonical_keys, self.provider.chain_id(), intent)
    }

    pub(super) fn try_start_synchronized(&mut self, id: &E3id, ctx: &mut actix::Context<Self>) {
        let Some(selection) = self.canonical_keys.synchronized_selection(id) else {
            return;
        };
        if selection.params_profile.ensure_admission_enabled().is_err() {
            return;
        }
        self.try_start_synchronized_definition(id, ctx);
    }

    fn try_start_synchronized_definition(&mut self, id: &E3id, ctx: &mut actix::Context<Self>) {
        if self.settled_keys.contains(id)
            || self.synchronized_settled.contains(id)
            || self.canonical_keys.public_key(id).is_some()
        {
            self.synchronized_publication.finish(id, true);
            return;
        }
        if let Some(intent) = self.synchronized_publication.start(id) {
            ctx.notify(SubmitSynchronizedPublication(intent));
        }
    }

    pub(super) fn route_synchronized_publication(
        &mut self,
        source: EventSource,
        intent: SynchronizedDkgPublicationReady,
        ctx: &mut actix::Context<Self>,
    ) {
        if intent.e3_id.chain_id() != self.provider.chain_id()
            || intent.params_profile.ensure_admission_enabled().is_err()
        {
            return;
        }
        let id = intent.e3_id.clone();
        match self.accept_synchronized_definition(intent, source) {
            Ok(()) => self.try_start_synchronized(&id, ctx),
            Err(error) => self.bus.err(EType::Evm, error),
        }
    }
}

fn validate_synchronized_intent(
    keys: &CanonicalPublicKeys,
    chain: u64,
    intent: &SynchronizedDkgPublicationReady,
) -> Result<CanonicalPublicKey> {
    anyhow::ensure!(
        intent.e3_id.chain_id() == chain,
        "publication belongs to another chain"
    );
    let selection = keys
        .synchronized_selection(&intent.e3_id)
        .context("publication has no confirmed selection")?;
    let context = keys
        .synchronized_context(&intent.e3_id)
        .context("publication has no frozen context")?;
    let candidate = selection.validate_publication(context, intent)?;
    if let Some(confirmed) = keys.get(&intent.e3_id) {
        anyhow::ensure!(
            confirmed == candidate,
            "publication differs from confirmed authority"
        );
    }
    Ok(candidate)
}

#[derive(Message)]
#[rtype(result = "()")]
struct SubmitSynchronizedPublication(SynchronizedDkgPublicationReady);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SubmitSynchronizedPublication>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(
        &mut self,
        command: SubmitSynchronizedPublication,
        _: &mut Self::Context,
    ) -> Self::Result {
        let intent = command.0;
        let id = intent.e3_id.clone();
        if !self.effects_enabled
            || !self.synchronized_publication.contains(&id)
            || self.settled_keys.contains(&id)
            || self.synchronized_settled.contains(&id)
            || self.canonical_keys.public_key(&id).is_some()
        {
            self.synchronized_publication.finish(&id, true);
            return Box::pin(async {}.into_actor(self));
        }
        let candidate = match self.validate_synchronized_intent(&intent) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.synchronized_publication.finish(&id, true);
                self.bus.err(EType::Evm, error);
                return Box::pin(async {}.into_actor(self));
            }
        };
        let provider = self.provider.clone();
        let bus = self.bus.clone();
        Box::pin(
            async move {
                let result = effects::publish_validated(provider, &intent, &candidate).await;
                match result {
                    Ok(_) => (id, true),
                    Err(error) => {
                        let terminal =
                            super::effects::committee_publication_error_is_terminal(&error)
                                || effects::is_terminal(&error);
                        bus.err(EType::Evm, error);
                        (id, terminal)
                    }
                }
            }
            .into_actor(self)
            .map(|(id, terminal), actor, ctx| {
                actor.synchronized_publication.finish(&id, terminal);
                if terminal {
                    actor.synchronized_settled.insert(id);
                } else {
                    ctx.run_later(
                        crate::helpers::PUBLICATION_RETRY_DELAY,
                        move |actor, ctx| {
                            actor.try_start_synchronized(&id, ctx);
                        },
                    );
                }
            }),
        )
    }
}
