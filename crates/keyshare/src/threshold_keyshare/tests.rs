// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::actors::decryption_key_shared_collector::DecryptionKeySharedCollectionFailed;
use actix::{Actor, Addr, Handler};
use alloy::primitives::Address;
use anyhow::Result;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository};
use e3_events::{
    hlc_factory::HlcFactory, BusHandle, E3Stage, E3id, EventBus, EventBusConfig, FailureReason,
    HistoryCollector, InterfoldEvent, InterfoldEventData, PersistEvent, Sequencer, TakeEvents,
};
use e3_fhe_params::DEFAULT_BFV_PRESET;
use std::sync::Arc;

#[derive(Default)]
struct TestEventStore {
    next_seq: u64,
}

impl Actor for TestEventStore {
    type Context = actix::Context<Self>;
}

impl Handler<PersistEvent> for TestEventStore {
    type Result = anyhow::Result<Option<InterfoldEvent>>;

    fn handle(&mut self, msg: PersistEvent, _: &mut Self::Context) -> Self::Result {
        let seq = self.next_seq;
        self.next_seq += 1;
        Ok(Some(msg.0.into_sequenced(seq)))
    }
}

fn test_bus() -> (BusHandle, Addr<HistoryCollector<InterfoldEvent>>) {
    let event_bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
    let store = TestEventStore::default().start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    let bus = BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("test-keyshare");
    let history = bus.history();
    (bus, history)
}

fn test_state() -> Persistable<ThresholdKeyshareState> {
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    repo.send(None)
}

async fn start_actor() -> Result<(
    Addr<ThresholdKeyshare>,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    let (bus, history) = test_bus();
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state: test_state(),
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
    })
    .start();

    Ok((actor, history, E3id::new("42", 1)))
}

async fn next_event(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<InterfoldEvent> {
    let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(!result.timed_out, "timed out waiting for an event");
    Ok(result.events.pop().expect("expected one event"))
}

async fn next_events(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    count: usize,
) -> Result<Vec<InterfoldEvent>> {
    let result = history
        .send(TakeEvents::<InterfoldEvent>::new(count))
        .await?;
    assert!(!result.timed_out, "timed out waiting for events");
    assert_eq!(result.events.len(), count, "expected {count} events");
    Ok(result.events)
}

#[actix::test]
async fn encryption_key_collection_failure_preserves_telemetry_and_emits_e3_failed() -> Result<()> {
    let (actor, history, e3_id) = start_actor().await?;
    let failure = EncryptionKeyCollectionFailed {
        e3_id,
        reason: "missing encryption keys".to_string(),
        missing_parties: vec![2, 3],
    };

    actor.send(failure.clone()).await?;

    let mut events = next_events(&history, 2).await?;
    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::EncryptionKeyCollectionFailed(data) if data == failure
    ));

    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == failure.e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGTimeout
    ));

    Ok(())
}

#[actix::test]
async fn threshold_share_collection_failure_preserves_telemetry_and_emits_e3_failed() -> Result<()>
{
    let (actor, history, e3_id) = start_actor().await?;
    let failure = ThresholdShareCollectionFailed {
        e3_id,
        reason: "missing threshold shares".to_string(),
        missing_parties: vec![4, 5],
    };

    actor.send(failure.clone()).await?;

    let mut events = next_events(&history, 2).await?;
    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ThresholdShareCollectionFailed(data) if data == failure
    ));

    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == failure.e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGTimeout
    ));

    Ok(())
}

#[actix::test]
async fn decryption_key_shared_collection_failure_emits_e3_failed() -> Result<()> {
    let (actor, history, e3_id) = start_actor().await?;
    let failure = DecryptionKeySharedCollectionFailed {
        e3_id,
        reason: "missing decryption key shares".to_string(),
        missing_parties: vec![6, 7],
    };

    actor.send(failure.clone()).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == failure.e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DecryptionTimeout
    ));

    Ok(())
}
