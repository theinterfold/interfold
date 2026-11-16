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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

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
    in_flight: HashMap<E3id, ComputeRequest>,
    published: HashSet<E3id>,
    effects: bool,
}

impl DealerCollection {
    pub(crate) fn new(
        metadata: HashMap<E3id, E3Meta>,
        committees: HashMap<E3id, Committee>,
        ended: HashSet<E3id>,
        records: HashMap<E3id, DealerRecord>,
    ) -> Self {
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
        if let Some(record) = e3_data::DataStore::from(repository(repositories, id))
            .read_checked::<DealerRecord>()
            .await?
        {
            meta.validate_configuration()?;
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
                if meta.validate_identity().is_ok() {
                    self.dealer
                        .metadata
                        .entry(request.e3_id.clone())
                        .or_insert(meta);
                }
            }
            InterfoldEventData::CommitteeFinalized(committee)
                if ec.source() == EventSource::Evm =>
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
            self.dealer.in_flight.remove(&id);
            self.dealer.published.remove(&id);
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
        if let Err(error) = self.accept_dealer_input(data, ec) {
            tracing::error!(%id, %error, "local synchronized dealer input rejected");
            return true;
        }
        self.persist_dealer(&id, ctx);
        true
    }

    fn validate_dealer_authority(&self, id: &E3id, plan: &DealerPlan) -> Result<()> {
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
            plan.profile == meta.params_profile
                && plan.committee
                    == CiphernodesCommitteeSize::from_threshold(
                        meta.threshold_m,
                        meta.threshold_n
                    )?
                && plan.context.setup.crypto_config_id.as_slice() == meta.crypto_config_id
                && members.len() == plan.committee.values().n
                && members.windows(2).all(|pair| pair[0] < pair[1])
                && members.get(plan.context.party_id as usize) == Some(&self.signer.address())
                && plan.context.setup.committee_hash
                    == e3_committee_hash::hash_committee_addresses(&members),
            "dealer plan differs from canonical request/committee/local owner"
        );
        Ok(())
    }

    fn accept_dealer_input(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
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
            return Ok(());
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
                for proof in record.proofs.values() {
                    plan.validate_leaf(&id, proof)?;
                }
                record.plan = Some(plan);
                record.ec = ec.clone();
            }
            InterfoldEventData::DKGInnerProofReady(input) => {
                use e3_zk_config::CircuitName;
                if !matches!(
                    input.proof.circuit,
                    CircuitName::PkGeneration
                        | CircuitName::SkShareComputation
                        | CircuitName::ShareEncryption
                ) {
                    return Ok(());
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
                let config =
                    e3_zk_config::synchronized::Configs::for_profile(meta.params_profile, size)?;
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
                let public = e3_zk_config::synchronized::public_signals::PublicSignals::decode(
                    &config,
                    expected,
                    &input.proof.public_signals,
                )?;
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
                    plan.validate_leaf(&id, input)?;
                }
                if let Some(old) = record.proofs.get(&input.seq) {
                    ensure!(
                        old.party_id == input.party_id
                            && old.proof.circuit == input.proof.circuit
                            && old.proof.public_signals == input.proof.public_signals,
                        "conflicting dealer leaf statement"
                    );
                    return Ok(()); // Keep the original randomized proof bytes.
                }
                record.proofs.insert(input.seq, input.clone());
                record.ec = ec.clone();
            }
            InterfoldEventData::ComputeResponse(response) => {
                let Some(request) = self.dealer.in_flight.get(&id) else {
                    return Ok(());
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
            }
            _ => {}
        }
        Ok(())
    }

    fn persist_dealer(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if !self.dealer.effects || self.dealer.ended.contains(id) {
            return;
        }
        let Some(record) = self.dealer.records.get(id).cloned() else {
            return;
        };
        let Some(meta) = self.dealer.metadata.get(id) else {
            return;
        };
        if meta.validate_configuration().is_err() {
            return;
        }
        if let Some(plan) = &record.plan {
            if let Err(error) = self.validate_dealer_authority(id, plan) {
                tracing::error!(%id, %error, "saved dealer plan rejected");
                return;
            }
        }
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
                .map(move |result, actor, _| match result {
                    Ok(()) => actor.publish_dealer_work(&id),
                    Err(error) => {
                        tracing::error!(%id, %error, "dealer persistence failed; effects withheld")
                    }
                }),
        );
    }

    /// Called only after admission and the exclusive record's flush acknowledgment.
    fn publish_dealer_work(&mut self, id: &E3id) {
        if !self.dealer.effects || self.dealer.ended.contains(id) {
            return;
        }
        let Some(record) = self.dealer.records.get(id) else {
            return;
        };
        if let Some(output) = &record.completed {
            if !self.dealer.published.contains(id) {
                match self.bus.publish(output.clone(), record.ec.clone()) {
                    Ok(_) => {
                        self.dealer.published.insert(id.clone());
                    }
                    Err(error) => tracing::error!(%id, %error, "dealer output publication failed"),
                }
            }
        } else if !self.dealer.in_flight.contains_key(id) {
            let Some(plan) = &record.plan else { return };
            let work = match plan.request(id, &record.proofs) {
                Ok(work) => work,
                Err(error) => {
                    tracing::error!(%id, %error, "saved dealer leaves rejected");
                    return;
                }
            };
            if let Some(work) = work {
                let request = ComputeRequest::zk(
                    ZkRequest::SynchronizedDkg(Box::new(work)),
                    e3_events::CorrelationId::new(),
                    id.clone(),
                );
                match self.bus.publish(request.clone(), record.ec.clone()) {
                    Ok(_) => {
                        self.dealer.in_flight.insert(id.clone(), request);
                    }
                    Err(error) => {
                        tracing::error!(%id, %error, "dealer dispatch failed; inputs retained")
                    }
                }
            }
        }
    }
}

impl DealerRecord {
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
            for (&seq, proof) in &self.proofs {
                ensure!(seq == proof.seq, "saved dealer slot differs");
                plan.validate_leaf(id, proof)?;
            }
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
