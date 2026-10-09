// SPDX-License-Identifier: LGPL-3.0-only

//! Rebuild key authority from confirmed registry observations before domain delivery.

use actix::{Actor, Context, Handler, Recipient};
use alloy::{
    primitives::{Address, Bytes, B256, U256},
    sol_types::{SolEvent, SolValue},
};
use anyhow::{ensure, Context as _, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    prelude::*, AggregateId, BusHandle, CommitteePublished, CorrelationId, E3Requested, E3id,
    EventSource, EventStoreQueryBy, EventStoreQueryResponse, InterfoldEvent, InterfoldEventData,
    PublicKeyAggregated, SeqAgg, SubscribePreFanout,
};
use e3_request::canonical_key::{CanonicalPublicKey, CanonicalPublicKeys};
use e3_utils::{actix::channel, ArcBytes};
use std::collections::{HashMap, HashSet};

use crate::{
    actors::data_availability::{KeyAssembly, MAX_PUBLIC_KEY_BYTES},
    ICiphernodeRegistry,
};

type Candidate = (E3id, String, [u8; 32]);

pub struct CanonicalKeyProjection {
    keys: CanonicalPublicKeys,
    interfold_addresses: HashMap<u64, Address>,
    requests: HashMap<E3id, E3Requested>,
    assemblies: HashMap<Candidate, KeyAssembly>,
    publications: HashMap<E3id, CommitteePublished>,
    candidates: HashMap<E3id, Vec<PublicKeyAggregated>>,
    closed: HashMap<E3id, bool>,
    hydrating_contexts: HashSet<E3id>,
}

impl CanonicalKeyProjection {
    pub fn new(keys: CanonicalPublicKeys, interfold_addresses: HashMap<u64, Address>) -> Self {
        Self {
            keys,
            interfold_addresses,
            requests: HashMap::new(),
            assemblies: HashMap::new(),
            publications: HashMap::new(),
            candidates: HashMap::new(),
            closed: HashMap::new(),
            hydrating_contexts: HashSet::new(),
        }
    }

    /// Scan the full retained log, including the prefix covered by actor snapshots.
    pub async fn recover(
        &mut self,
        store: &Recipient<EventStoreQueryBy<SeqAgg>>,
        aggregates: &[AggregateId],
        hydrating_contexts: HashSet<E3id>,
    ) -> Result<()> {
        self.hydrating_contexts = hydrating_contexts;
        for aggregate in aggregates {
            let mut cursor = 1;
            loop {
                let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
                store
                    .send(
                        EventStoreQueryBy::<SeqAgg>::new(
                            CorrelationId::new(),
                            HashMap::from([(*aggregate, cursor)]),
                            recipient,
                        )
                        .with_limit(1024)
                        .with_max_bytes(16 * 1024 * 1024),
                    )
                    .await?;
                let events = response
                    .await
                    .context("key recovery query had no response")?
                    .into_events()?;
                if events.is_empty() {
                    break;
                }
                for event in events {
                    ensure!(
                        event.aggregate_id() == *aggregate && event.seq() == cursor,
                        "key recovery event-store sequence gap"
                    );
                    cursor += 1;
                    self.observe(&event)?;
                }
            }
        }
        self.hydrating_contexts.clear();
        Ok(())
    }

    pub async fn attach(self, bus: &BusHandle) -> Result<()> {
        bus.event_bus()
            .send(SubscribePreFanout::new(self.start().recipient()))
            .await?;
        Ok(())
    }

    /// Terminal chain observations remain authoritative when snapshot cursors skip their replay.
    pub fn confirmed_terminal_e3s(&self) -> HashSet<E3id> {
        self.closed
            .iter()
            .filter(|(_, confirmed)| **confirmed)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn observe(&mut self, event: &InterfoldEvent) -> Result<()> {
        // Only the configured chain ingestion pipeline can establish authority. Its EVM events
        // have already passed the chain's confirmation policy and watched-contract filter.
        let chain_fact = event.source() == EventSource::Evm && event.block().is_some();
        let terminal = match event.get_data() {
            InterfoldEventData::E3StageChanged(data)
                if chain_fact && data.new_stage.is_terminal() =>
            {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::E3Failed(data) if chain_fact => Some(data.e3_id.clone()),
            InterfoldEventData::E3RequestComplete(data) if event.source() != EventSource::Net => {
                Some(data.e3_id.clone())
            }
            _ => None,
        };
        if let Some(id) = terminal {
            // An older context snapshot still needs its rosters to hydrate before terminal replay.
            if self.hydrating_contexts.contains(&id) {
                self.keys.forget_bytes(&id);
            } else {
                self.keys.remove(&id);
            }
            self.requests.remove(&id);
            self.publications.remove(&id);
            self.candidates.remove(&id);
            self.assemblies.retain(|candidate, _| candidate.0 != id);
            self.closed
                .entry(id)
                .and_modify(|confirmed| *confirmed |= chain_fact)
                .or_insert(chain_fact);
            return Ok(());
        }
        if event
            .get_e3_id()
            .is_some_and(|id| self.closed.contains_key(&id))
        {
            return Ok(());
        }
        match event.get_data() {
            InterfoldEventData::CiphertextOutputPublished(output)
                if (chain_fact || event.source() == EventSource::Local)
                    && self.requests.contains_key(&output.e3_id) =>
            {
                self.keys
                    .remember_ciphertexts(&output.e3_id, &output.ciphertext_output)?;
            }
            InterfoldEventData::E3Requested(request) if chain_fact => {
                if self
                    .interfold_addresses
                    .contains_key(&request.e3_id.chain_id())
                {
                    self.requests
                        .entry(request.e3_id.clone())
                        .or_insert_with(|| request.clone());
                }
            }
            InterfoldEventData::EvmLogObserved(log)
                if chain_fact
                    && log.contract == "CiphernodeRegistry"
                    && log.event_name == "CommitteeProofPublished" =>
            {
                let topics = log
                    .topics
                    .iter()
                    .map(|topic| topic.parse::<B256>())
                    .collect::<Result<Vec<_>, _>>()?;
                if topics.first()
                    != Some(&ICiphernodeRegistry::CommitteeProofPublished::SIGNATURE_HASH)
                {
                    return Ok(());
                }
                let decoded = ICiphernodeRegistry::CommitteeProofPublished::decode_raw_log(
                    topics, &log.data,
                )?;
                let id = E3id::new(decoded.e3Id.to_string(), log.chain_id);
                ensure!(
                    log.e3_id.as_ref() == Some(&id)
                        && event.aggregate_id().to_chain_id() == Some(log.chain_id),
                    "registry key observation has inconsistent request identity"
                );
                self.record_proof(&id, decoded.nodes, decoded.pkCommitment.0, &decoded.proof)?;
                self.restore_bytes(&id)?;
            }
            InterfoldEventData::CommitteePublicKeyChunkPublished(chunk) if chain_fact => {
                let Some(request) = self.requests.get(&chunk.e3_id) else {
                    return Ok(());
                };
                if self.keys.public_key(&chunk.e3_id).is_some()
                    || !KeyAssembly::event_shape_is_valid(chunk)
                {
                    return Ok(());
                }
                let nodes = chunk
                    .nodes
                    .iter()
                    .map(|node| node.parse::<Address>())
                    .collect::<Result<Vec<_>, _>>()?;
                let publisher = chunk.publisher.parse::<Address>()?;
                if nodes.len() != request.threshold_n || !nodes.contains(&publisher) {
                    return Ok(());
                }
                // The registry admits one candidate per publisher. Retain the same bound on replay.
                if self.assemblies.keys().any(|key| {
                    key.0 == chunk.e3_id
                        && key.1 == chunk.publisher
                        && key.2 != chunk.candidate_hash
                }) {
                    return Ok(());
                }
                let key = (
                    chunk.e3_id.clone(),
                    chunk.publisher.clone(),
                    chunk.candidate_hash,
                );
                let assembly = self
                    .assemblies
                    .entry(key)
                    .or_insert_with(|| KeyAssembly::new(chunk));
                if !assembly.insert(chunk) {
                    return Ok(());
                }
                self.restore_bytes(&chunk.e3_id)?;
            }
            InterfoldEventData::CommitteePublished(publication)
                if event.source() != EventSource::Net =>
            {
                if !self.requests.contains_key(&publication.e3_id) {
                    return Ok(());
                }
                // Legacy chain publications include the verified proof; chunk-derived ones do not.
                if chain_fact && !publication.proof.is_empty() {
                    let (_, inputs) = <(Bytes, Vec<B256>)>::abi_decode_params(&publication.proof)?;
                    let commitment = inputs.last().context("empty committee proof inputs")?.0;
                    let nodes = publication
                        .nodes
                        .iter()
                        .map(|node| node.parse::<Address>())
                        .collect::<Result<Vec<_>, _>>()?;
                    self.record_proof(&publication.e3_id, nodes, commitment, &publication.proof)?;
                }
                self.publications
                    .entry(publication.e3_id.clone())
                    .or_insert_with(|| publication.clone());
                self.restore_bytes(&publication.e3_id)?;
            }
            InterfoldEventData::PublicKeyAggregated(publication) => {
                if let Some(key) = self.keys.get(&publication.e3_id) {
                    if key.accepts(publication) {
                        self.keys
                            .remember_key(&publication.e3_id, publication.pubkey.clone())?;
                    }
                } else if let Some(request) = self.requests.get(&publication.e3_id) {
                    // Early gossip supplies candidate bytes only. It never supplies authority.
                    let candidates = self
                        .candidates
                        .entry(publication.e3_id.clone())
                        .or_default();
                    if publication.pubkey.len() <= MAX_PUBLIC_KEY_BYTES
                        && publication.committee_addresses.len() == request.threshold_n
                        && publication.honest_committee_addresses.len() <= request.threshold_n
                        && candidates.len() < request.threshold_n
                    {
                        let mut candidate = publication.clone();
                        candidate.nodes = Default::default();
                        candidate.dkg_aggregator_proof = None;
                        candidate.dkg_attestation_bundle = None;
                        if !candidates.contains(&candidate) {
                            candidates.push(candidate);
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn record_proof(
        &mut self,
        id: &E3id,
        committee: Vec<Address>,
        commitment: [u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        let Some(request) = self.requests.get(id) else {
            return Ok(());
        };
        let committee_size =
            CiphernodesCommitteeSize::from_threshold(request.threshold_m, request.threshold_n)?;
        let h = committee_size.values().h;
        let (_, inputs) = <(Bytes, Vec<B256>)>::abi_decode_params(proof)?;
        ensure!(
            inputs.len() == 6 + 3 * h && inputs.last() == Some(&B256::from(commitment)),
            "registry proof does not match the key commitment or committee size"
        );
        ensure!(
            committee.len() == request.threshold_n
                && committee.iter().all(|node| !node.is_zero())
                && committee.windows(2).all(|nodes| nodes[0] < nodes[1]),
            "registry committee is not ordered"
        );
        let party_ids = inputs[2..2 + h]
            .iter()
            .map(|id| usize::try_from(U256::from_be_bytes(id.0)))
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            party_ids.windows(2).all(|ids| ids[0] < ids[1])
                && party_ids.iter().all(|id| *id < committee.len()),
            "registry party IDs are not ordered committee slots"
        );
        let honest_committee = party_ids.iter().map(|id| committee[*id]).collect();
        self.keys.insert(
            id.clone(),
            CanonicalPublicKey {
                pk_commitment: commitment,
                committee,
                honest_committee,
                params_preset: request.params_preset,
                committee_size,
                interfold_address: self.interfold_addresses[&id.chain_id()],
                sk_agg_commits: inputs[5 + h..5 + 2 * h].iter().map(|v| v.0).collect(),
                esm_agg_commits: inputs[5 + 2 * h..5 + 3 * h].iter().map(|v| v.0).collect(),
            },
        )
    }

    fn restore_bytes(&mut self, id: &E3id) -> Result<()> {
        let Some(key) = self.keys.get(id) else {
            return Ok(());
        };
        if let Some(publication) = self.publications.remove(id) {
            let nodes = publication
                .nodes
                .iter()
                .map(|node| node.parse::<Address>())
                .collect::<Result<Vec<_>, _>>()?;
            if nodes == key.committee && key.validate_key(&publication.public_key).is_ok() {
                self.keys.remember_key(id, publication.public_key)?;
            }
        }
        if let Some(candidates) = self.candidates.remove(id) {
            for candidate in candidates {
                if key.accepts(&candidate) {
                    self.keys.remember_key(id, candidate.pubkey)?;
                    break;
                }
            }
        }
        for (candidate, assembly) in &self.assemblies {
            if &candidate.0 != id {
                continue;
            }
            let Some(bytes) = assembly.validated_bytes(candidate.2, key.params_preset) else {
                continue;
            };
            if assembly.matches_authority(&key.committee, key.pk_commitment) {
                self.keys.remember_key(id, ArcBytes::from_bytes(&bytes))?;
                break;
            }
        }
        if self.keys.public_key(id).is_some() {
            self.assemblies.retain(|candidate, _| &candidate.0 != id);
        }
        Ok(())
    }
}

impl Actor for CanonicalKeyProjection {
    type Context = Context<Self>;
}
impl Handler<InterfoldEvent> for CanonicalKeyProjection {
    type Result = ();
    fn handle(&mut self, event: InterfoldEvent, _: &mut Self::Context) {
        if let Err(error) = self.observe(&event) {
            tracing::warn!(%error, "Rejected inconsistent chain key observation");
        }
    }
}

#[cfg(test)]
#[path = "canonical_key/tests.rs"]
mod tests;
