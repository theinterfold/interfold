// SPDX-License-Identifier: LGPL-3.0-only

//! Synchronized dealer phase in the existing node collector. Local inputs are journaled by the
//! event pipeline; this phase's exclusive, flushed record fences compute and result publication.

use super::NodeProofAggregator;
use crate::synchronized::dealer::DealerPlan;
use actix::{ActorFutureExt, AsyncContext, Context, WrapFuture};
use alloy::primitives::Address;
use anyhow::{ensure, Context as _, Result};
use e3_committee::{CiphernodesCommitteeSize, Committee};
use e3_data::{Repositories, Repository};
use e3_events::{
    ComputeRequest, ComputeResponseKind, DKGInnerProofReady, E3id, EventContext,
    EventContextAccessors, EventPublisher, EventSource, InterfoldEventData, Sequenced, StoreKeys,
    SynchronizedDealerProofReady, SynchronizedDkgProofResponse, ZkRequest, ZkResponse,
};
use e3_fhe_params::BfvDecryptionProtocol;
use e3_request::E3Meta;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DealerRecord {
    version: u8,
    plan: Option<DealerPlan>,
    proofs: BTreeMap<usize, DKGInnerProofReady>,
    completed: Option<SynchronizedDealerProofReady>,
    ec: EventContext<Sequenced>,
}

#[derive(Default)]
pub(crate) struct DealerCollection {
    pub metadata: HashMap<E3id, E3Meta>,
    pub committees: HashMap<E3id, Committee>,
    pub ended: HashSet<E3id>,
    pub records: HashMap<E3id, DealerRecord>,
    dirty: HashSet<E3id>,
    // One alternate per provisional C3 slot. Both occurrences are already in the event journal;
    // replay rebuilds this buffer without changing the snapshot schema.
    alternate_c3: HashMap<E3id, BTreeMap<usize, DKGInnerProofReady>>,
    in_flight: HashMap<E3id, ComputeRequest>,
    published: HashSet<E3id>,
    pending: HashMap<E3id, PendingPublication>,
    publication_retries: HashMap<E3id, actix::SpawnHandle>,
    pub(super) effects: bool,
}

struct PendingPublication {
    events: VecDeque<InterfoldEventData>,
    ec: EventContext<Sequenced>,
    failures: u32,
}

impl PendingPublication {
    fn new<const N: usize>(events: [InterfoldEventData; N], ec: &EventContext<Sequenced>) -> Self {
        Self {
            events: events.into(),
            ec: ec.clone(),
            failures: 0,
        }
    }
}

impl DealerCollection {
    pub(crate) fn new(
        mut metadata: HashMap<E3id, E3Meta>,
        mut committees: HashMap<E3id, Committee>,
        ended: HashSet<E3id>,
        records: HashMap<E3id, DealerRecord>,
    ) -> Self {
        metadata.retain(|_, meta| {
            meta.params_profile.protocol() == BfvDecryptionProtocol::Synchronized
        });
        committees.retain(|id, _| metadata.contains_key(id));
        Self {
            metadata,
            committees,
            ended,
            records,
            ..Self::default()
        }
    }

    pub(crate) fn inner_proofs(&self) -> HashMap<E3id, BTreeMap<usize, e3_events::Proof>> {
        self.records
            .iter()
            .map(|(id, record)| {
                (
                    id.clone(),
                    record
                        .proofs
                        .iter()
                        .filter(|(&seq, _)| {
                            seq < 3 || (record.plan.is_some() && record.proofs.contains_key(&2))
                        })
                        .map(|(&seq, input)| (seq, input.proof.clone()))
                        .collect(),
                )
            })
            .collect()
    }
}

pub(crate) fn repository(repositories: &Repositories, id: &E3id) -> Repository<DealerRecord> {
    Repository::new(
        repositories
            .store
            .scope(StoreKeys::synchronized_dkg_dealer(id)),
    )
}

pub(crate) async fn recover(
    repositories: &Repositories,
    metadata: &HashMap<E3id, E3Meta>,
    ended: &HashSet<E3id>,
) -> Result<HashMap<E3id, DealerRecord>> {
    let mut records = HashMap::new();
    for (id, meta) in metadata {
        if meta.params_profile.protocol() != BfvDecryptionProtocol::Synchronized {
            continue;
        }
        if ended.contains(id) {
            e3_data::DataStore::from(repository(repositories, id))
                .remove_sync()
                .await?;
            continue;
        }
        if let Some(mut record) = e3_data::DataStore::from(repository(repositories, id))
            .read_checked::<DealerRecord>()
            .await?
        {
            meta.validate_configuration()?;
            if let Some(plan) = &record.plan {
                let config = plan.config()?;
                record.qualify_c3(id, &config, BTreeMap::new())?;
            }
            record.validate(id, meta)?;
            records.insert(id.clone(), record);
        }
    }
    Ok(records)
}

impl NodeProofAggregator {
    /// Returns true only for synchronized local work handled here. SS routing remains separate.
    pub(super) fn route_dealer(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        match data {
            InterfoldEventData::E3Requested(request) if ec.source() == EventSource::Evm => {
                let meta = E3Meta::from(request);
                if meta.params_profile.protocol() == BfvDecryptionProtocol::Synchronized
                    && meta.validate_identity().is_ok()
                {
                    self.dealer
                        .metadata
                        .entry(request.e3_id.clone())
                        .or_insert(meta);
                }
            }
            InterfoldEventData::CommitteeFinalized(committee)
                if ec.source() == EventSource::Evm
                    && self.dealer.metadata.contains_key(&committee.e3_id) =>
            {
                let mut committee = committee.clone();
                committee.sort_by_address();
                self.dealer
                    .committees
                    .entry(committee.e3_id)
                    .or_insert_with(|| Committee::new(committee.committee));
            }
            InterfoldEventData::EffectsEnabled(_) if ec.source() == EventSource::Local => {
                self.dealer.effects = true;
                for id in self.dealer.records.keys().cloned().collect::<Vec<_>>() {
                    self.persist_dealer(&id, ctx);
                }
            }
            _ => {}
        }
        let Some(id) = data.get_e3_id() else {
            return false;
        };
        let synchronized = self.dealer.metadata.get(&id).is_some_and(|meta| {
            meta.params_profile.protocol() == BfvDecryptionProtocol::Synchronized
        });
        if !synchronized {
            return false;
        }
        let terminal = match data {
            InterfoldEventData::E3StageChanged(stage) => {
                ec.source() == EventSource::Evm
                    && crate::domain::proof_verification::dkg_has_ended(&stage.new_stage)
            }
            InterfoldEventData::E3Failed(_) | InterfoldEventData::E3RequestComplete(_) => {
                matches!(ec.source(), EventSource::Local | EventSource::Evm)
            }
            _ => false,
        };
        if terminal {
            self.dealer.ended.insert(id.clone());
            self.dealer.records.remove(&id);
            self.dealer.dirty.remove(&id);
            self.dealer.alternate_c3.remove(&id);
            self.dealer.in_flight.remove(&id);
            self.dealer.published.remove(&id);
            self.dealer.pending.remove(&id);
            if let Some(retry) = self.dealer.publication_retries.remove(&id) {
                ctx.cancel_future(retry);
            }
            if let Some(repositories) = &self.recovery_repositories {
                let store = e3_data::DataStore::from(repository(repositories, &id));
                ctx.wait(async move { store.remove_sync().await }.into_actor(self).map(
                    move |result, _, _| {
                        if let Err(error) = result {
                            tracing::error!(%id, %error, "could not retire synchronized dealer record");
                        }
                    },
                ));
            }
            return true;
        }
        let is_work = matches!(
            data,
            InterfoldEventData::ThresholdSharePending(_)
                | InterfoldEventData::DKGInnerProofReady(_)
                | InterfoldEventData::ComputeResponse(_)
                | InterfoldEventData::ComputeRequestError(_)
        );
        if !is_work {
            return false;
        }
        if ec.source() != EventSource::Local || self.dealer.ended.contains(&id) {
            return true;
        }
        // No test-only proof-skip switch or restored record can enable this runtime path.
        if let Err(error) = self.dealer.metadata[&id].validate_configuration() {
            tracing::debug!(%id, %error, "synchronized dealer admission refused");
            return true;
        }
        if let Err(error) = self.drive_dealer_input(data, ec, ctx) {
            tracing::error!(%id, %error, "local synchronized dealer input rejected");
        }
        true
    }

    fn drive_dealer_input(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let id = data.get_e3_id().context("dealer input missing E3")?;
        if self.accept_dealer_input(data, ec)? {
            self.dealer.dirty.insert(id.clone());
        }
        // An unchanged input may redrive a previously failed write, but must not reflush an
        // acknowledged snapshot. Publication refusal is driven by its own timer.
        if self.dealer.dirty.contains(&id) {
            self.persist_dealer_definition(&id, ctx);
        }
        Ok(())
    }

    fn validate_dealer_authority(&self, id: &E3id, plan: &DealerPlan) -> Result<()> {
        self.validate_synchronized_authority(id, plan.profile, plan.committee, &plan.context)
    }

    pub(super) fn validate_synchronized_authority(
        &self,
        id: &E3id,
        profile: e3_fhe_params::BfvProfile,
        size: CiphernodesCommitteeSize,
        context: &e3_events::SynchronizedProofContext,
    ) -> Result<()> {
        let meta = self
            .dealer
            .metadata
            .get(id)
            .context("dealer has no request authority")?;
        let committee = self
            .dealer
            .committees
            .get(id)
            .context("dealer has no finalized committee")?;
        let members = committee
            .members()
            .iter()
            .map(|member| member.parse::<Address>())
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            profile == meta.params_profile
                && size
                    == CiphernodesCommitteeSize::from_threshold(
                        meta.threshold_m,
                        meta.threshold_n
                    )?
                && context.setup.crypto_config_id.as_slice() == meta.crypto_config_id
                && members.len() == size.values().n
                && members.windows(2).all(|pair| pair[0] < pair[1])
                && members.get(context.party_id as usize) == Some(&self.signer.address())
                && context.setup.committee_hash
                    == e3_committee_hash::hash_committee_addresses(&members),
            "dealer plan differs from canonical request/committee/local owner"
        );
        Ok(())
    }

    fn accept_dealer_input(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
    ) -> Result<bool> {
        let id = data.get_e3_id().context("dealer input missing E3")?;
        ensure!(
            ec.source() == EventSource::Local,
            "dealer input must be local"
        );
        ensure!(!self.dealer.ended.contains(&id), "dealer DKG has ended");
        if self
            .dealer
            .records
            .get(&id)
            .is_some_and(|record| record.completed.is_some())
        {
            return Ok(false);
        }
        match data {
            InterfoldEventData::ThresholdSharePending(input) => {
                let plan = DealerPlan::from_pending(input)?;
                self.validate_dealer_authority(&id, &plan)?;
                let record = self
                    .dealer
                    .records
                    .entry(id.clone())
                    .or_insert_with(|| DealerRecord::new(ec.clone()));
                ensure!(
                    record.plan.as_ref().is_none_or(|old| old == &plan),
                    "conflicting dealer plan"
                );
                if record.plan.is_some() {
                    return Ok(false);
                }
                let config = plan.config()?;
                // Early leaves cannot reserve a slot against the native plan across restarts.
                record
                    .proofs
                    .retain(|_, proof| plan.decode_leaf(&id, &config, proof).is_ok());
                record.plan = Some(plan);
                if record.proofs.contains_key(&2) {
                    let alternatives = self.dealer.alternate_c3.remove(&id).unwrap_or_default();
                    record.qualify_c3(&id, &config, alternatives)?;
                }
                record.ec = ec.clone();
            }
            InterfoldEventData::DKGInnerProofReady(input) => {
                if !matches!(
                    input.proof.circuit,
                    CircuitName::PkGeneration
                        | CircuitName::SkShareComputation
                        | CircuitName::ShareEncryption
                ) {
                    return Ok(false);
                }
                let meta = &self.dealer.metadata[&id];
                let committee = self
                    .dealer
                    .committees
                    .get(&id)
                    .context("early dealer leaf has no committee")?;
                ensure!(
                    committee.party_id_for(&self.signer.address().to_string())
                        == Some(input.party_id),
                    "early dealer leaf belongs to another local owner"
                );
                let size =
                    CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)?;
                let config = Configs::for_profile(meta.params_profile, size)?;
                ensure!(
                    input.seq > 0
                        && input.seq <= 2 + (size.values().n - 1) * config.threshold.moduli().len(),
                    "early dealer leaf outside bounded C1-C3 slots"
                );
                let expected = match input.seq {
                    1 => CircuitName::PkGeneration,
                    2 => CircuitName::SkShareComputation,
                    _ => CircuitName::ShareEncryption,
                };
                ensure!(
                    input.proof.circuit == expected,
                    "early dealer leaf has the wrong circuit"
                );
                let public = PublicSignals::decode(&config, expected, &input.proof.public_signals)?;
                if input.seq <= 2 {
                    ensure!(
                        public.party_id().map(u64::from) == Some(input.party_id),
                        "early dealer leaf owner differs"
                    );
                }
                let record = self
                    .dealer
                    .records
                    .entry(id.clone())
                    .or_insert_with(|| DealerRecord::new(ec.clone()));
                if let Some(plan) = &record.plan {
                    plan.validate_leaf_statement(&id, &config, input, &public)?;
                    if let Some(c2) = record.proofs.get(&2).filter(|_| input.seq >= 3) {
                        let sharing = plan.decode_leaf(&id, &config, c2)?;
                        plan.validate_c3_message(&config, input.seq, &public, &sharing)?;
                    }
                }
                if let Some(old) = record.proofs.get(&input.seq) {
                    if old.party_id == input.party_id
                        && old.proof.circuit == input.proof.circuit
                        && old.proof.public_signals == input.proof.public_signals
                    {
                        return Ok(false); // Keep the original randomized proof bytes.
                    }
                    ensure!(
                        input.seq >= 3
                            && (record.plan.is_none() || !record.proofs.contains_key(&2)),
                        "conflicting dealer leaf statement"
                    );
                    let alternatives = self.dealer.alternate_c3.entry(id).or_default();
                    let alternate = alternatives
                        .entry(input.seq)
                        .or_insert_with(|| input.clone());
                    ensure!(
                        alternate.proof.public_signals == input.proof.public_signals,
                        "provisional C3 slot already has an alternate"
                    );
                    return Ok(false);
                }
                record.proofs.insert(input.seq, input.clone());
                if input.seq == 2 && record.plan.is_some() {
                    let alternatives = self.dealer.alternate_c3.remove(&id).unwrap_or_default();
                    record.qualify_c3(&id, &config, alternatives)?;
                }
                record.ec = ec.clone();
            }
            InterfoldEventData::ComputeResponse(response) => {
                let Some(request) = self.dealer.in_flight.get(&id) else {
                    return Ok(false);
                };
                ensure!(
                    response.correlation_id == request.correlation_id,
                    "stale dealer response"
                );
                let ComputeResponseKind::Zk(ZkResponse::SynchronizedDkg(
                    SynchronizedDkgProofResponse::Dealer { proof },
                )) = &response.response
                else {
                    anyhow::bail!("unexpected dealer worker response");
                };
                let record = self
                    .dealer
                    .records
                    .get_mut(&id)
                    .context("missing dealer record")?;
                let plan = record.plan.as_ref().context("missing dealer plan")?;
                plan.validate_result(&id, &record.proofs, proof)?;
                record.completed = Some(SynchronizedDealerProofReady {
                    e3_id: id.clone(),
                    context: plan.context.clone(),
                    proof: proof.clone(),
                });
                record.ec = ec.clone();
                self.dealer.in_flight.remove(&id);
            }
            InterfoldEventData::ComputeRequestError(error) => {
                // Keep the complete exact request/correlation for worker retries. On restart a
                // fresh correlation is allocated; late responses from the old boot cannot win.
                if let Some(request) = self.dealer.in_flight.get(&id) {
                    ensure!(
                        error.request() == request,
                        "dealer compute error belongs to another request"
                    );
                    tracing::error!(%id, %error, "dealer worker failed locally; exact inputs retained");
                }
                return Ok(false);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn persist_dealer(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if self
            .dealer
            .metadata
            .get(id)
            .is_none_or(|meta| meta.validate_configuration().is_err())
        {
            return;
        }
        self.persist_dealer_definition(id, ctx);
    }

    fn persist_dealer_definition(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if !self.dealer.effects || self.dealer.ended.contains(id) {
            return;
        }
        let Some(record) = self.dealer.records.get(id).cloned() else {
            return;
        };
        if let Some(plan) = &record.plan {
            if let Err(error) = self.validate_dealer_authority(id, plan) {
                tracing::error!(%id, %error, "saved dealer plan rejected");
                return;
            }
        }
        self.dealer.dirty.insert(id.clone());
        self.flush_dealer_record(id, record, ctx);
    }

    fn flush_dealer_record(&mut self, id: &E3id, record: DealerRecord, ctx: &mut Context<Self>) {
        let Some(repositories) = &self.recovery_repositories else {
            return;
        };
        let repository = repository(repositories, id);
        let id = id.clone();
        ctx.wait(
            async move { repository.write_sync(&record).await }
                .into_actor(self)
                .map(move |result, actor, ctx| match result {
                    Ok(()) => {
                        actor.dealer.dirty.remove(&id);
                        actor.drive_dealer_publication(&id, ctx);
                    }
                    Err(error) => {
                        tracing::error!(%id, %error, "dealer persistence failed; effects withheld")
                    }
                }),
        );
    }

    /// Called only after admission and the exclusive record's flush acknowledgment.
    fn publish_dealer_work(&mut self, id: &E3id) -> bool {
        if !self.dealer.effects || self.dealer.ended.contains(id) {
            return true;
        }
        if self.dealer.pending.contains_key(id) {
            return self.publish_pending_dealer(id);
        }
        let Some(record) = self.dealer.records.get(id) else {
            return true;
        };
        if let Some(output) = &record.completed {
            if !self.dealer.published.contains(id) {
                let signed = match e3_events::SynchronizedDkgProofPublished::sign(
                    id.clone(),
                    output.context.clone(),
                    e3_events::SynchronizedDkgProofRole::Dealer,
                    output.proof.clone(),
                    &self.signer,
                ) {
                    Ok(signed) => signed,
                    Err(error) => {
                        tracing::error!(%id, %error, "dealer output signing failed");
                        return true;
                    }
                };
                self.dealer.pending.insert(
                    id.clone(),
                    PendingPublication::new([output.clone().into(), signed.into()], &record.ec),
                );
            }
        } else if !self.dealer.in_flight.contains_key(id) {
            let Some(plan) = &record.plan else {
                return true;
            };
            if record.proofs.len() != plan.circuits.len() {
                return true;
            }
            let work = match plan.request(id, &record.proofs) {
                Ok(work) => work,
                Err(error) => {
                    tracing::error!(%id, %error, "saved dealer leaves rejected");
                    return true;
                }
            };
            if let Some(work) = work {
                let request = ComputeRequest::zk(
                    ZkRequest::SynchronizedDkg(Box::new(work)),
                    e3_events::CorrelationId::new(),
                    id.clone(),
                );
                self.dealer.pending.insert(
                    id.clone(),
                    PendingPublication::new([request.into()], &record.ec),
                );
            }
        }
        self.publish_pending_dealer(id)
    }

    fn publish_pending_dealer(&mut self, id: &E3id) -> bool {
        let Some(pending) = self.dealer.pending.get_mut(id) else {
            return true;
        };
        while let Some(event) = pending.events.front() {
            if let Err(error) = self.bus.publish(event.clone(), pending.ec.clone()) {
                pending.failures = pending.failures.saturating_add(1);
                if pending.failures == 1 {
                    tracing::warn!(%id, %error, "dealer publication refused; exact pending effect retained");
                }
                return false;
            }
            if let InterfoldEventData::ComputeRequest(request) = event {
                self.dealer.in_flight.insert(id.clone(), request.clone());
            }
            if matches!(event, InterfoldEventData::SynchronizedDkgProofPublished(_)) {
                self.dealer.published.insert(id.clone());
            }
            pending.events.pop_front();
        }
        self.dealer.pending.remove(id);
        true
    }

    fn drive_dealer_publication(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if !self.dealer.publication_retries.contains_key(id) && !self.publish_dealer_work(id) {
            let retry_id = id.clone();
            let delay = e3_utils::backoff_delay(
                Duration::from_secs(1),
                self.dealer.pending[id].failures,
                Duration::from_secs(30),
            );
            let handle = ctx.run_later(delay, move |actor, ctx| {
                actor.dealer.publication_retries.remove(&retry_id);
                actor.drive_dealer_publication(&retry_id, ctx);
            });
            self.dealer.publication_retries.insert(id.clone(), handle);
        }
    }
}

impl DealerRecord {
    fn qualify_c3(
        &mut self,
        id: &E3id,
        config: &Configs,
        alternatives: BTreeMap<usize, DKGInnerProofReady>,
    ) -> Result<()> {
        let Some(plan) = &self.plan else {
            return Ok(());
        };
        let Some(c2) = self.proofs.get(&2) else {
            return Ok(());
        };
        if self.completed.is_none() {
            let sharing = plan.decode_leaf(id, config, c2)?;
            let qualified = |leaf: &DKGInnerProofReady| {
                plan.decode_leaf(id, config, leaf)
                    .and_then(|public| {
                        plan.validate_c3_message(config, leaf.seq, &public, &sharing)
                    })
                    .is_ok()
            };
            self.proofs.retain(|&seq, leaf| seq < 3 || qualified(leaf));
            for (seq, leaf) in alternatives {
                if let std::collections::btree_map::Entry::Vacant(slot) = self.proofs.entry(seq) {
                    if qualified(&leaf) {
                        slot.insert(leaf);
                    }
                }
            }
        }
        Ok(())
    }

    fn new(ec: EventContext<Sequenced>) -> Self {
        Self {
            version: 1,
            plan: None,
            proofs: BTreeMap::new(),
            completed: None,
            ec,
        }
    }

    fn validate(&self, id: &E3id, meta: &E3Meta) -> Result<()> {
        ensure!(self.version == 1, "unsupported synchronized dealer record");
        meta.validate_identity()?;
        if let Some(plan) = &self.plan {
            ensure!(
                plan.profile == meta.params_profile
                    && plan.committee
                        == CiphernodesCommitteeSize::from_threshold(
                            meta.threshold_m,
                            meta.threshold_n
                        )?,
                "saved dealer plan differs from request"
            );
            plan.validate_leaves(id, &self.proofs)?;
            if let Some(output) = &self.completed {
                ensure!(
                    &output.e3_id == id && output.context == plan.context,
                    "saved dealer output context differs"
                );
                plan.validate_result(id, &self.proofs, &output.proof)?;
            }
        } else {
            ensure!(self.completed.is_none(), "dealer result without a plan");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "dealer_tests.rs"]
mod tests;
