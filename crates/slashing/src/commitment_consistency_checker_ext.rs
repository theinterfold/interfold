// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! E3Extension that wires up the [`CommitmentConsistencyChecker`] per-E3
//! when the committee is finalized.
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
}

#[async_trait]
impl E3Extension for CommitmentConsistencyCheckerExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        let InterfoldEventData::CommitteeFinalized(data) = evt.get_data() else {
            return;
        };

        if ctx
            .get_event_recipient("commitment_consistency_checker")
            .is_some()
        {
            return;
        }

        let e3_id = data.e3_id.clone();

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            error!("E3Meta not available — cannot start CommitmentConsistencyChecker");
            return;
        };

        info!("Starting CommitmentConsistencyChecker for E3 {}", e3_id);

        let links = (self.links_factory)(meta.params_preset);
        let committee_h =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)
                .expect("committee size must be canonical at CommitteeFinalized")
                .values()
                .h;
        let addr = CommitmentConsistencyChecker::setup(&self.bus, e3_id, links, committee_h);

        ctx.set_event_recipient("commitment_consistency_checker", Some(addr.into()));
    }

    async fn hydrate(&self, _ctx: &mut E3Context, _snapshot: &E3ContextSnapshot) -> Result<()> {
        Ok(())
    }
}
