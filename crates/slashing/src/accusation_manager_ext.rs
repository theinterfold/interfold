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
use crate::repo::AccusationVotesRepositoryFactory;
use crate::workflow::accusation_voting::AccusationVotesSnapshot;
use actix::Actor;
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use async_trait::async_trait;
use e3_committee::CiphernodesCommitteeSize;
use e3_data::{DataStore, RepositoriesFactory};
use e3_events::{BusHandle, Committee, E3id, Event, InterfoldEvent, InterfoldEventData};
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};
use tracing::{error, info, warn};

/// Convert the compiled polynomial threshold `T` and committee size `N` into
/// the honest-party count `H` used by `SlashingManager` as its vote quorum.
///
/// `E3Meta.threshold_m` intentionally carries `T` for circuit selection, while
/// the on-chain committee request and slashing contract use the configured
/// honest-party count `H`. Keep both values separate because `H` can exceed
/// `T + 1` and accusation voting must still agree with Solidity without
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
    /// Per-chain on-chain `SlashingManager` address (EIP-712 `verifyingContract`
    /// for vote signatures). Looked up by `e3_id.chain_id()` when each per-E3
    /// actor starts.
    slashing_managers_by_chain: HashMap<u64, Address>,
    /// Per-chain off-chain freshness window (seconds), read from
    /// `CiphernodeRegistry.accusationVoteValidity()` at process startup.
    /// Looked up by `e3_id.chain_id()` when each per-E3 actor starts;
    /// governance changes require a node restart to take effect (same lifecycle
    /// contract as `slashing_managers_by_chain`).
    vote_validity_secs_by_chain: HashMap<u64, u64>,
    /// Clock-skew allowance for peer accusation deadlines.
    accusation_deadline_skew_secs: u64,
    /// Active finalized committees loaded before request contexts hydrate.
    persisted_committees: HashMap<E3id, Committee>,
    /// Holds each E3's saved vote state.
    store: DataStore,
}

impl AccusationManagerExtension {
    pub fn create(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        slashing_managers_by_chain: HashMap<u64, Address>,
        vote_validity_secs_by_chain: HashMap<u64, u64>,
        accusation_deadline_skew_secs: u64,
        persisted_committees: HashMap<E3id, Committee>,
        store: &DataStore,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            signer: signer.clone(),
            slashing_managers_by_chain,
            vote_validity_secs_by_chain,
            accusation_deadline_skew_secs,
            persisted_committees,
            store: store.clone(),
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

    /// Start the per-E3 manager. `effects_enabled` is false for a manager that startup rebuilds:
    /// it holds local accusations until `EffectsEnabled`, after the replayed event log.
    fn start_manager(
        &self,
        ctx: &mut E3Context,
        committee: &[String],
        effects_enabled: bool,
        saved_votes: Option<AccusationVotesSnapshot>,
    ) {
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

        // The vote domain names the SlashingManager of the E3's own chain. The manager of
        // another chain gives signatures that this chain's contract rejects.
        let Some(&slashing_manager) = self.slashing_managers_by_chain.get(&e3_id.chain_id()) else {
            error!(
                %e3_id,
                chain_id = e3_id.chain_id(),
                "Cannot start AccusationManager because the E3 chain has no SlashingManager"
            );
            return;
        };

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
        let manager = AccusationManager::new_with_quorum(
            &self.bus,
            e3_id,
            self.signer.clone(),
            slashing_manager,
            committee_addresses,
            circuit_threshold_t,
            vote_quorum_h,
            vote_validity_secs,
            self.accusation_deadline_skew_secs,
            meta.params_preset,
        );
        let manager = if effects_enabled {
            manager
        } else {
            manager.hold_accusations_until_effects()
        };
        let votes_repo = self.store.repositories().accusation_votes(&ctx.e3_id);
        let manager = match manager.with_saved_votes(votes_repo, saved_votes) {
            Ok(manager) => manager,
            Err(error) => {
                error!(e3_id = %ctx.e3_id, %error, "Cannot restore the saved accusation votes");
                return;
            }
        };
        let addr = manager.start();

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
        // Replay of a committee that the restored context lacks starts the manager before
        // `EffectsEnabled`; it then holds local accusations like a restored manager.
        let effects_enabled = ctx.effects_enabled();
        self.start_manager(ctx, &data.committee, effects_enabled, None);
    }

    /// Recreate the per-E3 actor so this node can process new accusations after a restart. It
    /// restores the saved vote state, and holds local accusations until `EffectsEnabled`.
    async fn hydrate(&self, ctx: &mut E3Context, _snapshot: &E3ContextSnapshot) -> Result<()> {
        if let Some(committee) = self.persisted_committees.get(&ctx.e3_id) {
            let members = committee.members().to_vec();
            let repo = self.store.repositories().accusation_votes(&ctx.e3_id);
            let saved_votes = DataStore::from(&repo)
                .read_checked::<AccusationVotesSnapshot>()
                .await?;
            if let Some(saved_votes) = &saved_votes {
                saved_votes.validate()?;
            }
            self.start_manager(ctx, &members, false, saved_votes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::accusation_voting::AccusationVoting;
    use actix::{Context, Handler};
    use e3_data::{DataStore, InMemStore, RepositoriesFactory};
    use e3_events::{
        hlc_factory::HlcFactory, AccusationVote, CommitmentConsistencyViolation, EffectsEnabled,
        EventBus, EventBusConfig, EventConstructorWithTimestamp, EventSource, GetEvents, ProofType,
        Seed, Sequencer, StoreEventRequested, StoreEventResponse, Unsequenced,
    };
    use e3_fhe_params::BfvPreset;
    use e3_request::{ContextRepositoryFactory, E3ContextParams, E3Meta};
    use e3_utils::ArcBytes;
    use std::sync::Arc;

    /// Gives each published event the next sequence number, so the bus delivers it.
    #[derive(Default)]
    struct SequencingStore {
        next_seq: u64,
    }

    impl Actor for SequencingStore {
        type Context = Context<Self>;
    }

    impl Handler<StoreEventRequested> for SequencingStore {
        type Result = ();

        fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) {
            let StoreEventRequested { event, sender } = msg;
            self.next_seq += 1;
            sender
                .try_send(StoreEventResponse(event.into_sequenced(self.next_seq)))
                .expect("the sequencer accepts the stored event");
        }
    }

    fn test_bus() -> BusHandle {
        let event_bus = EventBus::new(EventBusConfig { deduplicate: true }).start();
        let store = SequencingStore::default().start();
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
            params_preset: BfvPreset::InsecureThreshold64,
            params: ArcBytes::default(),
            error_size: ArcBytes::default(),
        }
    }

    #[test]
    fn accusation_quorum_matches_canonical_on_chain_committee_thresholds() {
        for (threshold_t, committee_n, expected_h) in [(1, 3, 2), (4, 9, 5), (9, 19, 14)] {
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
    async fn hydration_recreates_the_accusation_manager_only_on_chains_with_a_slashing_manager(
    ) -> Result<()> {
        let e3_id = E3id::new("7", 31337);
        // Same E3 index on a chain that has no SlashingManager.
        let unmapped_e3_id = E3id::new("7", 11155111);
        let committee = Committee::new(vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333".to_string(),
        ]);
        let extension = AccusationManagerExtension::create(
            &test_bus(),
            PrivateKeySigner::random(),
            HashMap::from([(31337, Address::repeat_byte(0x44))]),
            HashMap::from([(31337, 300), (11155111, 300)]),
            30,
            HashMap::from([
                (e3_id.clone(), committee.clone()),
                (unmapped_e3_id.clone(), committee),
            ]),
            &DataStore::from_in_mem(&InMemStore::new(false).start()),
        );

        for (id, expect_manager) in [(e3_id, true), (unmapped_e3_id, false)] {
            let mut context = test_context(id.clone());
            context.set_dependency(META_KEY, test_meta());
            let snapshot = E3ContextSnapshot {
                e3_id: id.clone(),
                recipients: Vec::new(),
                dependencies: vec!["meta".to_string()],
            };

            extension.hydrate(&mut context, &snapshot).await?;

            assert_eq!(
                context.get_event_recipient("accusation_manager").is_some(),
                expect_manager,
                "unexpected accusation_manager recipient for {id}"
            );
        }
        Ok(())
    }

    /// Startup rebuilds the manager before it replays the event log. A local input from the log
    /// signs an accusation only once effects run.
    #[actix::test]
    async fn a_rebuilt_manager_accuses_only_after_effects_enabled() -> Result<()> {
        let bus = test_bus();
        let history = bus.history();
        let e3_id = E3id::new("7", 31337);
        let me = PrivateKeySigner::random();
        let accused = Address::repeat_byte(0x22);
        let committee = Committee::new(vec![
            me.address().to_string(),
            accused.to_string(),
            Address::repeat_byte(0x33).to_string(),
        ]);
        let extension = AccusationManagerExtension::create(
            &bus,
            me,
            HashMap::from([(31337, Address::repeat_byte(0x44))]),
            HashMap::from([(31337, 300)]),
            30,
            HashMap::from([(e3_id.clone(), committee.clone())]),
            &DataStore::from_in_mem(&InMemStore::new(false).start()),
        );
        let mut context = test_context(e3_id.clone());
        context.set_dependency(META_KEY, test_meta());
        let snapshot = E3ContextSnapshot {
            e3_id: e3_id.clone(),
            recipients: Vec::new(),
            dependencies: vec!["meta".to_string()],
        };
        extension.hydrate(&mut context, &snapshot).await?;
        let manager = context
            .get_event_recipient("accusation_manager")
            .expect("hydration starts the manager");
        let accused_party_id = committee
            .party_id_for(&accused.to_string())
            .expect("accused member");
        let event = |data: e3_events::InterfoldEventData, seq: u64| {
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                data,
                None,
                seq as u128,
                None,
                EventSource::Local,
            )
            .into_sequenced(seq)
        };
        let accusations = || async {
            let events = history.send(GetEvents::new()).await?;
            Ok::<_, anyhow::Error>(
                events
                    .into_iter()
                    .filter(|event| {
                        matches!(
                            event.get_data(),
                            InterfoldEventData::ProofFailureAccusation(_)
                        )
                    })
                    .count(),
            )
        };

        manager
            .send(event(
                CommitmentConsistencyViolation {
                    e3_id: e3_id.clone(),
                    accused_address: accused,
                    accused_party_id,
                    proof_type: ProofType::C1PkGeneration,
                    data_hash: [7; 32],
                    evidence: Default::default(),
                }
                .into(),
                1,
            ))
            .await?;
        actix::clock::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(accusations().await?, 0, "accused before EffectsEnabled");

        manager.send(event(EffectsEnabled::new().into(), 2)).await?;
        actix::clock::timeout(std::time::Duration::from_secs(5), async {
            while accusations().await? == 0 {
                actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        assert_eq!(accusations().await?, 1);
        Ok(())
    }

    /// Replay of a `CommitteeFinalized` that the restored context lacks starts the manager before
    /// `EffectsEnabled`. A local input from the log then signs an accusation only once effects run.
    #[actix::test]
    async fn a_manager_that_replay_starts_accuses_only_after_effects_enabled() -> Result<()> {
        let bus = test_bus();
        let history = bus.history();
        let e3_id = E3id::new("8", 31337);
        let me = PrivateKeySigner::random();
        let accused = Address::repeat_byte(0x22);
        let members = vec![
            me.address().to_string(),
            accused.to_string(),
            Address::repeat_byte(0x33).to_string(),
        ];
        let extension = AccusationManagerExtension::create(
            &bus,
            me,
            HashMap::from([(31337, Address::repeat_byte(0x44))]),
            HashMap::from([(31337, 300)]),
            30,
            HashMap::new(),
            &DataStore::from_in_mem(&InMemStore::new(false).start()),
        );
        let mut context = test_context(e3_id.clone());
        context.set_dependency(META_KEY, test_meta());
        // The router's context before `EffectsEnabled`.
        context.set_effects_enabled(false);
        let event = |data: e3_events::InterfoldEventData, seq: u64| {
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                data,
                None,
                seq as u128,
                None,
                EventSource::Local,
            )
            .into_sequenced(seq)
        };
        extension.on_event(
            &mut context,
            &event(
                e3_events::CommitteeFinalized {
                    e3_id: e3_id.clone(),
                    committee: members.clone(),
                    scores: Vec::new(),
                    chain_id: 31337,
                }
                .into(),
                1,
            ),
        );
        let manager = context
            .get_event_recipient("accusation_manager")
            .expect("the committee starts the manager");
        let accused_party_id = Committee::new(members)
            .party_id_for(&accused.to_string())
            .expect("accused member");
        let accusations = || async {
            let events = history.send(GetEvents::new()).await?;
            Ok::<_, anyhow::Error>(
                events
                    .into_iter()
                    .filter(|event| {
                        matches!(
                            event.get_data(),
                            InterfoldEventData::ProofFailureAccusation(_)
                        )
                    })
                    .count(),
            )
        };

        manager
            .send(event(
                CommitmentConsistencyViolation {
                    e3_id: e3_id.clone(),
                    accused_address: accused,
                    accused_party_id,
                    proof_type: ProofType::C1PkGeneration,
                    data_hash: [7; 32],
                    evidence: Default::default(),
                }
                .into(),
                2,
            ))
            .await?;
        actix::clock::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(accusations().await?, 0, "accused before EffectsEnabled");

        manager.send(event(EffectsEnabled::new().into(), 3)).await?;
        actix::clock::timeout(std::time::Duration::from_secs(5), async {
            while accusations().await? == 0 {
                actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        assert_eq!(accusations().await?, 1);
        Ok(())
    }

    /// A restart keeps an accusation's tally and evidence: a vote that arrives after the restart
    /// completes the quorum with this node's vote from before it, and the quorum carries the
    /// evidence that the slash proposal needs.
    #[actix::test]
    async fn a_restarted_manager_keeps_the_votes_of_a_pending_accusation() -> Result<()> {
        use alloy::signers::SignerSync;

        let bus = test_bus();
        let history = bus.history();
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let e3_id = E3id::new("7", 31337);
        let slashing_manager = Address::repeat_byte(0x44);
        let me = PrivateKeySigner::random();
        let voter = PrivateKeySigner::random();
        let accused = Address::repeat_byte(0x22);
        let committee = Committee::new(vec![
            me.address().to_string(),
            voter.address().to_string(),
            accused.to_string(),
        ]);
        let accused_party_id = committee
            .party_id_for(&accused.to_string())
            .expect("accused member");
        let event = |data: e3_events::InterfoldEventData, seq: u64| {
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                data,
                None,
                seq as u128,
                None,
                EventSource::Local,
            )
            .into_sequenced(seq)
        };
        // Each run hydrates its manager from the same store, as a restart does.
        let start = || async {
            let extension = AccusationManagerExtension::create(
                &bus,
                me.clone(),
                HashMap::from([(31337, slashing_manager)]),
                HashMap::from([(31337, 300)]),
                30,
                HashMap::from([(e3_id.clone(), committee.clone())]),
                &store,
            );
            let mut context = test_context(e3_id.clone());
            context.set_dependency(META_KEY, test_meta());
            let snapshot = E3ContextSnapshot {
                e3_id: e3_id.clone(),
                recipients: Vec::new(),
                dependencies: vec!["meta".to_string()],
            };
            extension.hydrate(&mut context, &snapshot).await?;
            let manager = context
                .get_event_recipient("accusation_manager")
                .cloned()
                .expect("hydration starts the manager");
            manager.send(event(EffectsEnabled::new().into(), 1)).await?;
            Ok::<_, anyhow::Error>(manager)
        };
        let published = |matches: fn(&e3_events::InterfoldEventData) -> bool| {
            let history = history.clone();
            async move {
                let events = history.send(GetEvents::new()).await?;
                Ok::<_, anyhow::Error>(
                    events
                        .into_iter()
                        .filter(|event| matches(event.get_data()))
                        .map(|event| event.into_data())
                        .collect::<Vec<_>>(),
                )
            }
        };

        let before_restart = start().await?;
        before_restart
            .send(event(
                CommitmentConsistencyViolation {
                    e3_id: e3_id.clone(),
                    accused_address: accused,
                    accused_party_id,
                    proof_type: ProofType::C1PkGeneration,
                    data_hash: [7; 32],
                    evidence: alloy::primitives::Bytes::from(vec![0x11; 32]),
                }
                .into(),
                2,
            ))
            .await?;
        let accusation = actix::clock::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let accusations =
                    published(|data| matches!(data, InterfoldEventData::ProofFailureAccusation(_)))
                        .await?;
                if let Some(InterfoldEventData::ProofFailureAccusation(accusation)) =
                    accusations.into_iter().next()
                {
                    return Ok::<_, anyhow::Error>(accusation);
                }
                actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await??;

        let after_restart = start().await?;
        let mut vote = AccusationVote {
            e3_id: e3_id.clone(),
            accusation_id: AccusationVoting::accusation_id(&accusation),
            voter: voter.address(),
            data_hash: accusation.data_hash,
            issued_at: accusation.issued_at,
            deadline: accusation.deadline,
            signature: ArcBytes::default(),
        };
        let digest = AccusationVoting::vote_digest(&vote, slashing_manager);
        vote.signature = ArcBytes::from_bytes(&voter.sign_hash_sync(&digest.into())?.as_bytes());
        after_restart.send(event(vote.into(), 3)).await?;

        let quorum = actix::clock::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let quorums = published(|data| {
                    matches!(data, InterfoldEventData::AccusationQuorumReached(_))
                })
                .await?;
                if let Some(InterfoldEventData::AccusationQuorumReached(quorum)) =
                    quorums.into_iter().next()
                {
                    return Ok::<_, anyhow::Error>(quorum);
                }
                actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await??;
        assert_eq!(quorum.votes_for.len(), 2);
        assert_eq!(
            quorum.evidence,
            alloy::primitives::Bytes::from(vec![0x11; 32])
        );
        Ok(())
    }
}
