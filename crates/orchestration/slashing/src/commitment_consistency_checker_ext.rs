// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! E3Extension that wires up the [`CommitmentConsistencyChecker`] per-E3
//! when the committee is finalized, and recreates it during restart hydration.
//!
//! Follows the same lifecycle pattern as [`AccusationManagerExtension`]:
//! listens for [`CommitteeFinalized`], creates the actor, and registers it
//! in the [`E3Context`] so it receives routed events.

use crate::actors::commitment_consistency_checker::CommitmentConsistencyChecker;
use crate::domain::commitment_consistency::{
    CommitmentConsistencySnapshot, LbfvCommitmentConsistencySnapshot,
};
use crate::repo::{CommitmentConsistencyRepositoryFactory, PathRepository};
use crate::CommitmentLink;
use actix::Actor;
use anyhow::{Context as _, Result};
use async_trait::async_trait;
use e3_committee::CiphernodesCommitteeSize;
use e3_data::{DataStore, RepositoriesFactory};
use e3_events::{BusHandle, E3id, Event, InterfoldEvent, InterfoldEventData};
use e3_fhe_params::BfvProfile;
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};
use tracing::{error, info};

type LinksFactory = Box<
    dyn Fn(BfvProfile, CiphernodesCommitteeSize) -> Result<Vec<Box<dyn CommitmentLink>>>
        + Send
        + Sync,
>;

pub struct CommitmentConsistencyCheckerExtension {
    bus: BusHandle,
    /// Factory that builds links for the exact protocol profile and committee.
    links_factory: LinksFactory,
    /// Backing store for the per-E3 checker state.
    store: DataStore,
}

impl CommitmentConsistencyCheckerExtension {
    pub fn create(
        bus: &BusHandle,
        store: &DataStore,
        links_factory: impl Fn(BfvProfile, CiphernodesCommitteeSize) -> Result<Vec<Box<dyn CommitmentLink>>>
            + Send
            + Sync
            + 'static,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            links_factory: Box::new(links_factory),
            store: store.clone(),
        })
    }

    /// The saved state of an E3, in the layout of its proving path.
    fn snapshot_repository(
        &self,
        e3_id: &E3id,
        params_profile: BfvProfile,
    ) -> PathRepository<CommitmentConsistencySnapshot, LbfvCommitmentConsistencySnapshot> {
        let repositories = self.store.repositories();
        if e3_fhe_params::is_lbfv_path(params_profile.threshold_preset()) {
            PathRepository::Lbfv(repositories.commitment_consistency_lbfv(e3_id))
        } else {
            PathRepository::Trbfv(repositories.commitment_consistency(e3_id))
        }
    }

    fn start_checker(
        &self,
        ctx: &mut E3Context,
        restored: Option<LbfvCommitmentConsistencySnapshot>,
    ) -> Result<()> {
        if ctx
            .get_event_recipient("commitment_consistency_checker")
            .is_some()
        {
            return Ok(());
        }

        let e3_id = ctx.e3_id.clone();

        let meta = ctx
            .get_dependency(META_KEY)
            .context("E3Meta not available; cannot start CommitmentConsistencyChecker")?;

        info!("Starting CommitmentConsistencyChecker for E3 {}", e3_id);

        let committee =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)
                .with_context(|| {
                    format!(
                        "unknown committee thresholds M={}, N={} for E3 {e3_id}",
                        meta.threshold_m, meta.threshold_n
                    )
                })?;
        let links = (self.links_factory)(meta.params_profile, committee)?;
        let committee_h = committee.values().h;
        // The request router owns delivery and lifetime for this per-E3 actor. Subscribing it to
        // the global bus as well would deliver every event twice and keep the actor alive after
        // the E3 context is removed.
        let repo = self.snapshot_repository(&e3_id, meta.params_profile);
        let addr = CommitmentConsistencyChecker::new(
            &self.bus,
            e3_id,
            links,
            committee_h,
            meta.params_profile.threshold_preset(),
        )
        .with_snapshot(repo, restored)?
        .start();

        ctx.set_event_recipient("commitment_consistency_checker", Some(addr.into()));
        Ok(())
    }
}

#[async_trait]
impl E3Extension for CommitmentConsistencyCheckerExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        let InterfoldEventData::CommitteeFinalized(data) = evt.get_data() else {
            return;
        };

        if data.e3_id != ctx.e3_id {
            return;
        }

        if let Err(err) = self.start_checker(ctx, None) {
            error!(
                e3_id = %ctx.e3_id,
                error = %err,
                "Cannot start CommitmentConsistencyChecker"
            );
        }
    }

    async fn hydrate(&self, ctx: &mut E3Context, _snapshot: &E3ContextSnapshot) -> Result<()> {
        if let Some(meta) = ctx.get_dependency(META_KEY) {
            let restored = self
                .snapshot_repository(&ctx.e3_id, meta.params_profile)
                .read_checked()
                .await?;
            self.start_checker(ctx, restored)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::{Actor, Context, Handler};
    use e3_data::{DataStore, InMemStore, RepositoriesFactory};
    use e3_events::{
        hlc_factory::HlcFactory, E3id, EventBus, EventBusConfig, Seed, Sequencer,
        StoreEventRequested,
    };
    use e3_request::{ContextRepositoryFactory, E3ContextParams, E3Meta};
    use e3_utils::ArcBytes;
    use std::sync::Arc;

    struct StoreSink;

    impl Actor for StoreSink {
        type Context = Context<Self>;
    }

    impl Handler<StoreEventRequested> for StoreSink {
        type Result = ();

        fn handle(&mut self, _: StoreEventRequested, _: &mut Self::Context) {}
    }

    fn test_bus() -> BusHandle {
        let event_bus = EventBus::new(EventBusConfig { deduplicate: true }).start();
        let store = StoreSink.start();
        let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
        BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("checker-hydrate-test")
    }

    fn test_meta() -> E3Meta {
        E3Meta {
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0; 32]),
            params_profile: e3_fhe_params::BfvProfile::SsInsecure64,
            crypto_config_id: [0; 32],
            params: ArcBytes::from_bytes(&[]),
            error_size: ArcBytes::from_bytes(&[]),
        }
    }

    fn test_store() -> DataStore {
        DataStore::from_in_mem(&InMemStore::new(false).start())
    }

    fn test_context(store: &DataStore, e3_id: E3id) -> E3Context {
        let repositories = store.repositories();
        E3Context::from_params(E3ContextParams {
            repository: repositories.context(&e3_id),
            e3_id,
            extensions: Arc::new(Vec::new()),
        })
    }

    #[actix::test]
    async fn hydrate_recreates_checker_when_meta_was_recovered() -> Result<()> {
        let bus = test_bus();
        let store = test_store();
        let extension =
            CommitmentConsistencyCheckerExtension::create(&bus, &store, |_, _| Ok(Vec::new()));
        let e3_id = E3id::new("0", 31337);
        let mut ctx = test_context(&store, e3_id.clone());
        ctx.set_dependency(META_KEY, test_meta());
        assert!(ctx
            .get_event_recipient("commitment_consistency_checker")
            .is_none());

        let snapshot = E3ContextSnapshot {
            e3_id,
            recipients: vec![],
            dependencies: vec!["meta".to_string()],
        };

        extension.hydrate(&mut ctx, &snapshot).await?;

        assert!(ctx
            .get_event_recipient("commitment_consistency_checker")
            .is_some());

        Ok(())
    }

    #[actix::test]
    async fn hydrate_without_meta_leaves_checker_unset() -> Result<()> {
        let bus = test_bus();
        let store = test_store();
        let extension =
            CommitmentConsistencyCheckerExtension::create(&bus, &store, |_, _| Ok(Vec::new()));
        let e3_id = E3id::new("0", 31337);
        let mut ctx = test_context(&store, e3_id.clone());
        let snapshot = E3ContextSnapshot {
            e3_id,
            recipients: vec![],
            dependencies: vec![],
        };

        extension.hydrate(&mut ctx, &snapshot).await?;

        assert!(ctx
            .get_event_recipient("commitment_consistency_checker")
            .is_none());

        Ok(())
    }
}
