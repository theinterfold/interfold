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
use anyhow::Result;
use async_trait::async_trait;
use e3_events::{BusHandle, CommitmentLink, Event, InterfoldEvent, InterfoldEventData};
use e3_fhe_params::BfvPreset;
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{error, info};

type LinksFactory = Box<dyn Fn(BfvPreset) -> Vec<Box<dyn CommitmentLink>> + Send + Sync>;

pub struct CommitmentConsistencyCheckerExtension {
    bus: BusHandle,
    /// Factory that builds commitment links for a given BFV preset.
    links_factory: LinksFactory,
}

impl CommitmentConsistencyCheckerExtension {
    pub fn create(
        bus: &BusHandle,
        links_factory: impl Fn(BfvPreset) -> Vec<Box<dyn CommitmentLink>> + Send + Sync + 'static,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            links_factory: Box::new(links_factory),
        })
    }

    fn start_checker(&self, ctx: &mut E3Context) {
        if ctx
            .get_event_recipient("commitment_consistency_checker")
            .is_some()
        {
            return;
        }

        let e3_id = ctx.e3_id.clone();

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            error!("E3Meta not available; cannot start CommitmentConsistencyChecker");
            return;
        };

        info!("Starting CommitmentConsistencyChecker for E3 {}", e3_id);

        let links = (self.links_factory)(meta.params_preset);
        let committee_h =
            match CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n) {
                Ok(size) => size.values().h,
                Err(err) => {
                    error!(
                        %e3_id,
                        threshold_m = meta.threshold_m,
                        threshold_n = meta.threshold_n,
                        error = %err,
                        "Unknown committee size; cannot start CommitmentConsistencyChecker"
                    );
                    return;
                }
            };
        let addr = CommitmentConsistencyChecker::setup(&self.bus, e3_id, links, committee_h);

        ctx.set_event_recipient("commitment_consistency_checker", Some(addr.into()));
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

        self.start_checker(ctx);
    }

    async fn hydrate(&self, ctx: &mut E3Context, _snapshot: &E3ContextSnapshot) -> Result<()> {
        if ctx.get_dependency(META_KEY).is_some() {
            self.start_checker(ctx);
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
            params_preset: BfvPreset::InsecureThreshold512,
            params: ArcBytes::from_bytes(&[]),
            error_size: ArcBytes::from_bytes(&[]),
            proof_aggregation_enabled: false,
        }
    }

    fn test_context(e3_id: E3id) -> E3Context {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
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
        let extension = CommitmentConsistencyCheckerExtension::create(&bus, |_| Vec::new());
        let e3_id = E3id::new("0", 31337);
        let mut ctx = test_context(e3_id.clone());
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
        let extension = CommitmentConsistencyCheckerExtension::create(&bus, |_| Vec::new());
        let e3_id = E3id::new("0", 31337);
        let mut ctx = test_context(e3_id.clone());
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
