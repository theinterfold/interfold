// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use actix::{Actor, Context, Handler, ResponseFuture};
use e3_fhe_params::BfvProfile;
use e3_request::E3Meta;
use e3_utils::ArcBytes;
use std::sync::{Arc, Mutex};

struct TrackedQueries {
    inner: Recipient<EventStoreQueryBy<SeqAgg>>,
    queries: Arc<Mutex<Vec<HashMap<AggregateId, u64>>>>,
}

impl Actor for TrackedQueries {
    type Context = Context<Self>;
}

impl Handler<EventStoreQueryBy<SeqAgg>> for TrackedQueries {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, query: EventStoreQueryBy<SeqAgg>, _: &mut Context<Self>) -> Self::Result {
        self.queries.lock().unwrap().push(query.query().clone());
        let inner = self.inner.clone();
        Box::pin(async move {
            inner.send(query).await.unwrap();
        })
    }
}

/// Runs the sortition restart backfill with no slashing-writer stores to fill.
async fn backfill_restart_state(
    repositories: &e3_data::Repositories,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    chain_ids: &[u64],
) -> Result<CommitteeFinalizerRecoveryState> {
    let (_, checkpoint) = SortitionRestartBackfill::load(repositories, eventstore, chain_ids)
        .await?
        .backfill(eventstore, &HashSet::new())
        .await?;
    checkpoint.commit().await
}

#[actix::test]
async fn ticket_backfill_skips_checked_prefixes_and_retries_incomplete_reads() -> Result<()> {
    use crate::SortitionRecoveryState;
    use e3_events::{E3Requested, EventPublisher, TicketGenerated, TicketId};
    let aggregate = AggregateId::from_chain_id(Some(1));
    let system = e3_event_system::EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
            aggregate,
            std::time::Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("checked-ticket-prefix");
    let repos = e3_data::Repositories::from(system.store()?);
    let e3_id = E3id::new("1", 1);
    repos
        .e3_lifecycle()
        .write_sync(&HashMap::from([(e3_id.clone(), E3Stage::Requested)]))
        .await?;
    repos
        .sortition_recovery()
        .write_sync(&SortitionRecoveryState {
            seeds: HashMap::from([(e3_id.clone(), Seed([1; 32]))]),
            ..Default::default()
        })
        .await?;
    repos
        .committee_finalizer_recovery()
        .write_sync(&CommitteeFinalizerRecoveryState::default())
        .await?;
    bus.publish_without_context(E3Requested {
        e3_id: e3_id.clone(),
        ..Default::default()
    })?;
    bus.flush_event_pipeline().await?;
    repos.aggregate_seq(aggregate).write_sync(&1).await?;
    let queries = Arc::new(Mutex::new(Vec::new()));
    let reader = TrackedQueries {
        inner: system.eventstore_reader()?.seq(),
        queries: queries.clone(),
    }
    .start()
    .recipient();
    let recovered = backfill_restart_state(&repos, &reader, &[1]).await?;
    assert!(!recovered.tickets.contains_key(&e3_id));
    assert_eq!(queries.lock().unwrap()[0][&aggregate], 1);
    assert_eq!(
        repos.restart_input_cursors().read().await?.unwrap()[&e3_id],
        1
    );

    queries.lock().unwrap().clear();
    backfill_restart_state(&repos, &reader, &[1]).await?;
    assert!(
        queries.lock().unwrap().is_empty(),
        "unchanged restart must not scan again"
    );

    repos.aggregate_seq(aggregate).write_sync(&2).await?;
    assert!(backfill_restart_state(&repos, &reader, &[1]).await.is_err());
    assert_eq!(queries.lock().unwrap()[0][&aggregate], 2);
    assert_eq!(
        repos.restart_input_cursors().read().await?.unwrap()[&e3_id],
        1,
        "failed reads must not advance the checkpoint"
    );
    let ticket = TicketGenerated {
        e3_id: e3_id.clone(),
        ticket_id: TicketId::Score(9),
        node: alloy::primitives::Address::repeat_byte(1).to_string(),
        party_index: Some(0),
    };
    bus.publish_without_context(ticket.clone())?;
    bus.flush_event_pipeline().await?;
    let recovered = backfill_restart_state(&repos, &reader, &[1]).await?;
    assert_eq!(recovered.tickets[&e3_id], ticket);
    assert_eq!(
        repos.restart_input_cursors().read().await?.unwrap()[&e3_id],
        2
    );

    let next_e3 = E3id::new("2", 1);
    repos
        .e3_lifecycle()
        .write_sync(&HashMap::from([
            (e3_id.clone(), E3Stage::Complete),
            (next_e3.clone(), E3Stage::Requested),
        ]))
        .await?;
    queries.lock().unwrap().clear();
    backfill_restart_state(&repos, &reader, &[1]).await?;
    assert_eq!(
        queries.lock().unwrap()[0][&aggregate],
        1,
        "a new E3 must not inherit another E3's checked prefix"
    );
    let checked = repos.restart_input_cursors().read().await?.unwrap();
    assert!(
        !checked.contains_key(&e3_id),
        "terminal checkpoints must be pruned"
    );
    assert_eq!(checked[&next_e3], 2);
    Ok(())
}

#[test]
fn existing_seed_is_authoritative() {
    let e3_id = E3id::new("1", 1);
    let existing = Seed([1; 32]);
    let mut seeds = HashMap::from([(e3_id.clone(), existing)]);

    backfill_missing_seeds(&mut seeds, HashMap::from([(e3_id.clone(), Seed([2; 32]))]));

    assert_eq!(seeds.get(&e3_id), Some(&existing));
}

#[actix::test]
async fn admission_backfill_preserves_existing_owner_state_and_restart_history() -> Result<()> {
    use crate::{BondOwnerState, NodeState, NodeStateStore};
    use alloy::primitives::Address;
    use e3_events::{AdmissionChange, AdmissionPolicy, AdmissionUpdated, EventPublisher};
    let aggregate = AggregateId::from_chain_id(None);
    let system = e3_event_system::EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
            aggregate,
            std::time::Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("admission-backfill");
    let repositories = e3_data::Repositories::from(system.store()?);
    let operator = Address::repeat_byte(1);
    let start = AdmissionUpdated {
        chain_id: 1,
        timepoint: 10,
        change: AdmissionChange::Started {
            operator: operator.to_string(),
        },
    };
    bus.publish_without_context(start.clone())?;
    bus.publish_without_context(AdmissionUpdated {
        chain_id: 1,
        timepoint: 20,
        change: AdmissionChange::Policy(AdmissionPolicy {
            cooldown_enabled: true,
            cooldown_duration: 100,
            ..Default::default()
        }),
    })?;
    bus.flush_event_pipeline().await?;
    repositories.aggregate_seq(aggregate).write_sync(&2).await?;
    let mut owners = BondOwnerState::default();
    owners.chains.entry(1).or_default();
    repositories
        .sortition_bond_owners()
        .write_sync(&owners)
        .await?;
    let owner_bytes = bincode::serialize(&owners)?;
    let reader = system.eventstore_reader()?.seq();
    backfill_restart_state(&repositories, &reader, &[1]).await?;
    let store = repositories.sortition_admission();
    let mut state = store.read().await?.unwrap();
    state.validate()?;
    let nodes = NodeStateStore {
        nodes: HashMap::from([(operator.to_string(), NodeState::default())]),
        ..Default::default()
    };
    assert_eq!(state.filter(1, 19, &nodes).nodes.len(), 1);
    assert_eq!(state.filter(1, 109, &nodes).nodes.len(), 0);
    assert_eq!(state.filter(1, 110, &nodes).nodes.len(), 1);
    assert_eq!(
        owner_bytes,
        bincode::serialize(&repositories.sortition_bond_owners().read().await?.unwrap())?
    );
    state.record(&AdmissionUpdated {
        timepoint: 200,
        ..start
    })?;
    store.write_sync(&state).await?;
    backfill_restart_state(&repositories, &reader, &[1]).await?;
    let state = store.read().await?.unwrap();
    assert_eq!(state.filter(1, 250, &nodes).nodes.len(), 0);
    assert_eq!(state.filter(1, 150, &nodes).nodes.len(), 1);
    Ok(())
}

#[test]
fn committee_address_casing_is_equivalent() {
    let lower = Committee::new(vec!["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned()]);
    let upper = Committee::new(vec!["0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD".to_owned()]);

    assert!(committees_match(&lower, &upper));
}

#[actix::test]
async fn owner_backfill_preserves_legacy_snapshots_and_restarts() -> Result<()> {
    use crate::NodeStateRepositoryFactory;
    use alloy::primitives::Address;
    use e3_events::{BondOwnerSet, BondOwnerSetAt, EventPublisher};

    let chain = AggregateId::from_chain_id(None);
    let system = e3_event_system::EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
            chain,
            std::time::Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("owner-backfill");
    let repositories = e3_data::Repositories::from(system.store()?);
    let node = Address::from([1; 20]);
    let original = Address::from([2; 20]);
    let replacement = Address::from([3; 20]);
    let event = BondOwnerSet {
        operator: node.to_string(),
        bond_owner: original.to_string(),
        chain_id: 1,
    };
    bus.publish_without_context(BondOwnerSetAt {
        owner: event.clone(),
        timepoint: 10,
    })?;
    bus.flush_event_pipeline().await?;
    repositories.aggregate_seq(chain).write_sync(&1).await?;
    let mut legacy = crate::NodeStateStore::default();
    legacy.nodes.insert(
        node.to_string(),
        crate::NodeState {
            active_jobs: 1,
            ..Default::default()
        },
    );
    repositories
        .node_state()
        .write_sync(&HashMap::from([(1, legacy)]))
        .await?;
    let before = bincode::serialize(&repositories.node_state().read().await?.unwrap())?;

    let reader = system.eventstore_reader()?.seq();
    backfill_restart_state(&repositories, &reader, &[1]).await?;
    let owners_store = repositories.sortition_bond_owners();
    let mut owners = owners_store.read().await?.unwrap();
    owners.validate()?;
    assert_eq!(owners.owner_at(1, node, u64::MAX), Some(original));
    assert_eq!(owners.owner_at(1, node, 9), None);
    assert_eq!(owners.owner_at(1, node, 10), Some(original));
    assert_eq!(
        before,
        bincode::serialize(&repositories.node_state().read().await?.unwrap())?
    );

    // Simulate a later live update committed with its aggregate snapshot. Backfill must
    // preserve it instead of rebuilding an existing projection from an older prefix.
    let later = owners.chains[&1][&node].last().unwrap().timepoint + 1;
    owners.record(
        &BondOwnerSet {
            bond_owner: replacement.to_string(),
            ..event
        },
        later,
    )?;
    owners_store.write_sync(&owners).await?;
    backfill_restart_state(&repositories, &reader, &[1]).await?;
    assert_eq!(
        owners_store
            .read()
            .await?
            .unwrap()
            .owner_at(1, node, u64::MAX),
        Some(replacement)
    );

    owners.schema_version += 1;
    owners_store.write_sync(&owners).await?;
    let error = backfill_restart_state(&repositories, &reader, &[1])
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported bond-owner snapshot schema"));
    Ok(())
}

#[actix::test]
async fn legacy_owner_events_do_not_become_chain_time_checkpoints() -> Result<()> {
    use alloy::primitives::Address;
    use e3_events::{BondOwnerSet, EventPublisher};

    let aggregate = AggregateId::from_chain_id(None);
    let system = e3_event_system::EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
            aggregate,
            std::time::Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("legacy-owner-time");
    let repositories = e3_data::Repositories::from(system.store()?);
    let operator = Address::from([1; 20]);
    bus.publish_without_context(BondOwnerSet {
        operator: operator.to_string(),
        bond_owner: Address::from([2; 20]).to_string(),
        chain_id: 1,
    })?;
    bus.flush_event_pipeline().await?;
    repositories.aggregate_seq(aggregate).write_sync(&1).await?;
    backfill_restart_state(&repositories, &system.eventstore_reader()?.seq(), &[1]).await?;
    let owners = repositories.sortition_bond_owners().read().await?.unwrap();
    assert_eq!(owners.owner_at(1, operator, u64::MAX), None);
    Ok(())
}

#[test]
fn startup_reconciles_committees() {
    let selector_only = E3id::new("1", 1);
    let finalized_only = E3id::new("2", 1);
    let terminal = E3id::new("3", 1);
    let metadata = || E3Meta {
        threshold_m: 1,
        threshold_n: 3,
        seed: Seed([0; 32]),
        params_profile: BfvProfile::SsInsecure64,
        crypto_config_id: [0; 32],
        params: ArcBytes::default(),
        error_size: ArcBytes::default(),
    };
    let committee = Committee::new(vec![
        "0x1111111111111111111111111111111111111111".to_string()
    ]);
    let mut selector = CiphernodeSelectorState {
        e3_cache: HashMap::from([
            (selector_only.clone(), metadata()),
            (finalized_only.clone(), metadata()),
            (terminal.clone(), metadata()),
        ]),
        committees: HashMap::from([
            (selector_only.clone(), committee.clone()),
            (terminal.clone(), committee.clone()),
        ]),
        ..Default::default()
    };
    let mut finalized = HashMap::from([
        (finalized_only.clone(), committee.clone()),
        (terminal.clone(), committee.clone()),
    ]);

    assert_eq!(
        reconcile_committee_snapshots(
            &mut selector,
            &mut finalized,
            &HashMap::from([(terminal.clone(), E3Stage::Complete)]),
        )
        .unwrap(),
        (true, true)
    );
    assert_eq!(selector.committees.get(&finalized_only), Some(&committee));
    assert_eq!(finalized.get(&selector_only), Some(&committee));
    assert!(!selector.e3_cache.contains_key(&terminal));
    assert!(!finalized.contains_key(&terminal));
}

#[test]
fn startup_recovers_local_selection() {
    let e3_id = E3id::new("8", 1);
    let address = "0x1111111111111111111111111111111111111111";
    let profile = BfvProfile::SsInsecure64;
    let (params, _) = profile.build_pair().unwrap();
    let metadata = E3Meta {
        threshold_m: 1,
        threshold_n: 3,
        seed: Seed([7; 32]),
        params_profile: profile,
        crypto_config_id: profile
            .crypto_config_id(e3_committee::CiphernodesCommitteeSize::Minimum)
            .unwrap()
            .into(),
        params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&params)),
        error_size: ArcBytes::from_bytes(&[3, 4]),
    };
    // The local node is not first, so its party id comes from its committee slot.
    let members = vec![
        "0x2222222222222222222222222222222222222222".to_owned(),
        address.to_uppercase(),
        "0x3333333333333333333333333333333333333333".to_owned(),
    ];
    let mut selector = CiphernodeSelectorState {
        e3_cache: HashMap::from([(e3_id.clone(), metadata.clone())]),
        committees: HashMap::from([(e3_id.clone(), Committee::new(members.clone()))]),
        ..Default::default()
    };

    let selections = recovered_ciphernode_selections(&selector, address).unwrap();

    assert_eq!(selections.len(), 1);
    assert_eq!(selections[0].e3_id, e3_id);
    assert_eq!(selections[0].party_id, 1);
    assert_eq!(selections[0].committee, members);
    assert_eq!(selections[0].threshold_m, metadata.threshold_m);
    assert_eq!(selections[0].params, metadata.params);
    assert_eq!(selections[0].params_profile, metadata.params_profile);
    assert_eq!(selections[0].crypto_config_id, metadata.crypto_config_id);

    selector.e3_cache.get_mut(&e3_id).unwrap().params_profile = BfvProfile::SyncDecInsecure64;
    assert!(recovered_ciphernode_selections(&selector, address)
        .unwrap_err()
        .root_cause()
        .to_string()
        .contains("disabled"));
}

#[test]
fn startup_rejects_selection_with_an_inconsistent_saved_configuration() {
    let e3_id = E3id::new("10", 1);
    let address = "0x1111111111111111111111111111111111111111";
    let profile = BfvProfile::SsInsecure64;
    let (params, _) = profile.build_pair().unwrap();
    let metadata = E3Meta {
        threshold_m: 1,
        threshold_n: 3,
        seed: Seed([7; 32]),
        params_profile: profile,
        crypto_config_id: [42; 32],
        params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&params)),
        error_size: ArcBytes::default(),
    };
    let selector = CiphernodeSelectorState {
        e3_cache: HashMap::from([(e3_id.clone(), metadata.clone())]),
        committees: HashMap::from([(e3_id.clone(), Committee::new(vec![address.to_owned()]))]),
        ..Default::default()
    };
    let error = recovered_ciphernode_selections(&selector, address)
        .expect_err("a retained selection must not carry an unchecked configuration ID");
    assert!(format!("{error:#}").contains(&e3_id.to_string()));
    assert_eq!(selector.e3_cache.get(&e3_id), Some(&metadata));
}

#[test]
fn startup_rejects_committee_conflicts() {
    let e3_id = E3id::new("9", 1);
    let mut selector = CiphernodeSelectorState {
        e3_cache: HashMap::from([(
            e3_id.clone(),
            E3Meta {
                threshold_m: 1,
                threshold_n: 3,
                seed: Seed([0; 32]),
                params_profile: BfvProfile::SsInsecure64,
                crypto_config_id: [0; 32],
                params: ArcBytes::default(),
                error_size: ArcBytes::default(),
            },
        )]),
        committees: HashMap::from([(
            e3_id.clone(),
            Committee::new(vec!["0x1111111111111111111111111111111111111111".to_owned()]),
        )]),
        ..Default::default()
    };
    let mut finalized = HashMap::from([(
        e3_id,
        Committee::new(vec!["0x2222222222222222222222222222222222222222".to_owned()]),
    )]);

    let error =
        reconcile_committee_snapshots(&mut selector, &mut finalized, &HashMap::new()).unwrap_err();

    assert!(error.to_string().contains("snapshots disagree"));
}
