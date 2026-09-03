// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! E3Extension that wires up the [`AccusationManager`] per-E3 when the
//! committee is finalized.
//!
//! Listens for [`CommitteeFinalized`], derives the on-chain accusation quorum
//! from the circuit threshold in [`E3Meta`], parses committee addresses, and
//! starts the actor with full context.

use std::collections::HashMap;

use crate::actors::accusation_manager::AccusationManager;
use actix::Actor;
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use async_trait::async_trait;
use e3_events::{BusHandle, Committee, E3id, Event, InterfoldEvent, InterfoldEventData};
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{error, info, warn};

/// Convert the compiled polynomial threshold `T` and committee size `N` into
/// the honest-party count `H` used by `SlashingManager` as its vote quorum.
///
/// `E3Meta.threshold_m` intentionally carries `T` for circuit selection, while
/// the on-chain committee request and slashing contract use `H = T + 1`. Keep
/// both values separate so accusation voting agrees with Solidity without
/// breaking ZK re-verification artifact resolution.
fn accusation_vote_quorum(threshold_t: usize, committee_n: usize) -> Result<usize> {
    Ok(
        CiphernodesCommitteeSize::from_threshold(threshold_t, committee_n)?
            .values()
            .h,
    )
}

pub struct AccusationManagerExtension {
    bus: BusHandle,
    signer: PrivateKeySigner,
    /// On-chain `SlashingManager` address (EIP-712 `verifyingContract` for vote sigs).
    slashing_manager: Address,
    /// Per-chain off-chain freshness window (seconds), read from
    /// `CiphernodeRegistry.accusationVoteValidity()` at process startup.
    /// Looked up by `e3_id.chain_id()` when each per-E3 actor starts;
    /// governance changes require a node restart to take effect (same lifecycle
    /// contract as `slashing_manager`).
    vote_validity_secs_by_chain: HashMap<u64, u64>,
    /// Clock-skew allowance for peer accusation deadlines.
    accusation_deadline_skew_secs: u64,
    /// Active finalized committees loaded before request contexts hydrate.
    persisted_committees: HashMap<E3id, Committee>,
}

impl AccusationManagerExtension {
    pub fn create(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        vote_validity_secs_by_chain: HashMap<u64, u64>,
        accusation_deadline_skew_secs: u64,
        persisted_committees: HashMap<E3id, Committee>,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            signer: signer.clone(),
            slashing_manager,
            vote_validity_secs_by_chain,
            accusation_deadline_skew_secs,
            persisted_committees,
        })
    }

    fn vote_validity_secs_for(&self, chain_id: u64) -> u64 {
        match self.vote_validity_secs_by_chain.get(&chain_id) {
            Some(&secs) => secs,
            None => {
                warn!(
                    chain_id,
                    "no accusationVoteValidity configured for chain; accusation votes will not be stamped"
                );
                0
            }
        }
    }

    fn start_manager(&self, ctx: &mut E3Context, committee: &[String]) {
        if ctx.get_event_recipient("accusation_manager").is_some() {
            return;
        }

        let e3_id = ctx.e3_id.clone();
        let mut committee_addresses = Vec::with_capacity(committee.len());
        for node in committee {
            match node.parse::<Address>() {
                Ok(address) => committee_addresses.push(address),
                Err(error) => {
                    error!(
                        %e3_id,
                        node,
                        %error,
                        "Cannot start AccusationManager because a committee address is invalid"
                    );
                    return;
                }
            }
        }

        if committee_addresses.is_empty() {
            error!(%e3_id, "Cannot start AccusationManager because the committee is empty");
            return;
        }

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            error!(%e3_id, "Cannot start AccusationManager because E3 metadata is unavailable");
            return;
        };
        let circuit_threshold_t = meta.threshold_m;
        let vote_quorum_h = match accusation_vote_quorum(meta.threshold_m, meta.threshold_n) {
            Ok(quorum) => quorum,
            Err(error) => {
                error!(
                    %e3_id,
                    threshold_t = meta.threshold_m,
                    committee_n = meta.threshold_n,
                    %error,
                    "Cannot start AccusationManager for an unknown committee size"
                );
                return;
            }
        };

        info!(
            %e3_id,
            committee_members = committee_addresses.len(),
            circuit_threshold_t,
            vote_quorum_h,
            "Starting AccusationManager"
        );

        let vote_validity_secs = self.vote_validity_secs_for(e3_id.chain_id());
        // The request router owns delivery and lifetime for this per-E3 actor. A global bus
        // subscription would deliver each event twice and retain completed actors forever.
        let addr = AccusationManager::new_with_quorum(
            &self.bus,
            e3_id,
            self.signer.clone(),
            self.slashing_manager,
            committee_addresses,
            circuit_threshold_t,
            vote_quorum_h,
            vote_validity_secs,
            self.accusation_deadline_skew_secs,
            meta.params_preset,
        )
        .start();

        ctx.set_event_recipient("accusation_manager", Some(addr.into()));
    }
}

#[async_trait]
impl E3Extension for AccusationManagerExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        let InterfoldEventData::CommitteeFinalized(data) = evt.get_data() else {
            return;
        };

        if data.e3_id != ctx.e3_id {
            return;
        }
        self.start_manager(ctx, &data.committee);
    }

    /// Recreate the per-E3 actor so this node can process new accusations after a restart.
    /// In-flight vote state remains ephemeral and expires at the signed accusation deadline.
    async fn hydrate(&self, ctx: &mut E3Context, _snapshot: &E3ContextSnapshot) -> Result<()> {
        if let Some(committee) = self.persisted_committees.get(&ctx.e3_id) {
            let members = committee.members().to_vec();
            self.start_manager(ctx, &members);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::{Context, Handler};
    use e3_data::{DataStore, InMemStore, RepositoriesFactory};
    use e3_events::{
        hlc_factory::HlcFactory, EventBus, EventBusConfig, Seed, Sequencer, StoreEventRequested,
    };
    use e3_fhe_params::BfvPreset;
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
        BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("accusation-hydrate-test")
    }

    fn test_context(e3_id: E3id) -> E3Context {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id,
            extensions: Arc::new(Vec::new()),
        })
    }

    fn test_meta() -> E3Meta {
        E3Meta {
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0; 32]),
            params_preset: BfvPreset::InsecureThreshold512,
            params: ArcBytes::default(),
            error_size: ArcBytes::default(),
            scheme: Default::default(),
        }
    }

    #[test]
    fn accusation_quorum_matches_canonical_on_chain_committee_thresholds() {
        for (threshold_t, committee_n, expected_h) in [(1, 3, 2), (4, 9, 5), (9, 19, 10)] {
            assert_eq!(
                accusation_vote_quorum(threshold_t, committee_n).unwrap(),
                expected_h
            );
        }
    }

    #[test]
    fn accusation_quorum_rejects_unknown_committee_parameters() {
        assert!(accusation_vote_quorum(2, 3).is_err());
    }

    #[actix::test]
    async fn hydration_recreates_the_accusation_manager() -> Result<()> {
        let e3_id = E3id::new("7", 31337);
        let committee = Committee::new(vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333".to_string(),
        ]);
        let extension = AccusationManagerExtension::create(
            &test_bus(),
            PrivateKeySigner::random(),
            Address::repeat_byte(0x44),
            HashMap::from([(31337, 300)]),
            30,
            HashMap::from([(e3_id.clone(), committee)]),
        );
        let mut context = test_context(e3_id.clone());
        context.set_dependency(META_KEY, test_meta());
        let snapshot = E3ContextSnapshot {
            e3_id,
            recipients: Vec::new(),
            dependencies: vec!["meta".to_string()],
        };

        extension.hydrate(&mut context, &snapshot).await?;

        assert!(context.get_event_recipient("accusation_manager").is_some());
        Ok(())
    }
}
