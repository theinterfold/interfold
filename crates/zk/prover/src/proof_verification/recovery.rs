// SPDX-License-Identifier: LGPL-3.0-only

//! Rebuild unresolved C0 inputs from the event log, including the snapshotted prefix.

use super::{dkg_has_ended, validate_received_key};
use actix::Recipient;
use anyhow::Result;
use e3_committee::{CiphernodesCommitteeSize, Committee};
use e3_events::{
    AggregateId, E3id, EncryptionKeyReceived, EventContextAccessors, EventContextSeq, EventSource,
    EventStoreQueryBy, InterfoldEventData, ProofType, SeqAgg, TypedEvent,
};
use e3_request::E3Meta;
use std::collections::{HashMap, HashSet};

pub(crate) async fn recover_pending_verifications(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregates: &[AggregateId],
    active_e3s: &HashSet<E3id>,
    committees: &HashMap<E3id, Committee>,
    metadata: &HashMap<E3id, E3Meta>,
) -> Result<Vec<TypedEvent<EncryptionKeyReceived>>> {
    let mut pending: HashMap<(E3id, u64), TypedEvent<EncryptionKeyReceived>> = HashMap::new();
    let mut closed = HashSet::new();
    if active_e3s.is_empty() {
        return Ok(Vec::new());
    }
    for aggregate in aggregates.iter().copied() {
        crate::retained_journal::visit(eventstore, aggregate, "C0 recovery", |event| {
            let source = event.source();
            let (data, ec) = event.into_components();
            match data {
                InterfoldEventData::EncryptionKeyReceived(input)
                    if active_e3s.contains(&input.e3_id) && !closed.contains(&input.e3_id) =>
                {
                    let key = (input.e3_id.clone(), input.key.party_id);
                    if pending.contains_key(&key) {
                        return Ok(());
                    }
                    let Some(meta) = metadata.get(&input.e3_id) else {
                        return Ok(());
                    };
                    let Some(signer) = committees
                        .get(&input.e3_id)
                        .and_then(|committee| {
                            committee
                                .members()
                                .get(usize::try_from(input.key.party_id).ok()?)
                        })
                        .and_then(|address| address.parse().ok())
                    else {
                        return Ok(());
                    };
                    if CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)
                        .is_ok()
                        && meta.params_profile.admission_enabled()
                        && validate_received_key(&input, &signer, meta.params_profile).is_ok()
                    {
                        pending.insert(key, TypedEvent::new(input, ec));
                    }
                }
                InterfoldEventData::EncryptionKeyCreated(output)
                    if source == EventSource::Local && output.external =>
                {
                    let key = (output.e3_id, output.key.party_id);
                    if pending
                        .get(&key)
                        .is_some_and(|input| input.key == output.key)
                    {
                        pending.remove(&key);
                    }
                }
                InterfoldEventData::ProofVerificationFailed(output)
                    if source == EventSource::Local && output.proof_type == ProofType::C0PkBfv =>
                {
                    let key = (output.e3_id, output.accused_party_id);
                    if pending.get(&key).is_some_and(|input| {
                        input.key.signed_payload.as_ref() == Some(&output.signed_payload)
                    }) {
                        pending.remove(&key);
                    }
                }
                InterfoldEventData::E3RequestComplete(output)
                    if active_e3s.contains(&output.e3_id) =>
                {
                    pending.retain(|(e3_id, _), _| e3_id != &output.e3_id);
                    closed.insert(output.e3_id);
                }
                InterfoldEventData::E3StageChanged(output)
                    if source == EventSource::Evm
                        && active_e3s.contains(&output.e3_id)
                        && dkg_has_ended(&output.new_stage) =>
                {
                    pending.retain(|(e3_id, _), _| e3_id != &output.e3_id);
                    closed.insert(output.e3_id);
                }
                _ => {}
            }
            Ok(())
        })
        .await?;
    }
    let mut inputs: Vec<_> = pending.into_values().collect();
    inputs.sort_by_key(|input| (input.aggregate_id(), input.seq()));
    Ok(inputs)
}

#[cfg(test)]
#[path = "recovery_sequence_tests.rs"]
mod tests;
