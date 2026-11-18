// SPDX-License-Identifier: LGPL-3.0-only

//! Recipient phase of the node collector. Peer authorship precedes slot admission; only native
//! keyshare intent fixes the roster. Exclusive flushed records fence all dispatch/publication.

use super::NodeProofAggregator;
use crate::synchronized::recipient::RecipientPlan;
use actix::{ActorFutureExt, AsyncContext, Context, SpawnHandle, WrapFuture};
use alloy::primitives::Address;
use anyhow::{ensure, Context as _, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_data::{Repositories, Repository};
use e3_events::*;
use e3_fhe_params::BfvDecryptionProtocol;
use e3_request::E3Meta;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::Duration,
};

// Bound activated repairs, not identical deliveries, for each fixed dealer slot in this boot.
const MAX_JOIN_REPAIRS_PER_DEALER: u8 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RecipientRecord {
    version: u8,
    plan: Option<RecipientPlan>,
    leaves: BTreeMap<usize, DKGInnerProofReady>,
    dealers: BTreeMap<u32, SynchronizedDkgProofPublished>,
    completed: Option<SynchronizedRecipientProofReady>,
    ec: EventContext<Sequenced>,
}

#[derive(Default)]
pub(crate) struct RecipientCollection {
    pub records: HashMap<E3id, RecipientRecord>,
    in_flight: HashMap<E3id, ComputeRequest>,
    published: HashSet<E3id>,
    local_published: HashSet<E3id>,
    unflushed: HashSet<E3id>,
    flush_retries: HashMap<E3id, EffectRetry>,
    delivery_retries: HashMap<E3id, EffectRetry>,
    work_retries: HashMap<E3id, SpawnHandle>,
    invalid_work: HashSet<E3id>,
    failed_work: HashSet<E3id>,
    repairs: HashMap<E3id, BTreeMap<u32, SynchronizedDkgProofPublished>>,
    repair_counts: HashMap<E3id, BTreeMap<u32, u8>>,
}

#[derive(Default)]
struct EffectRetry {
    timer: Option<SpawnHandle>,
    failures: u32,
}

impl EffectRetry {
    fn failed(&mut self) -> bool {
        self.failures = self.failures.saturating_add(1);
        self.failures == 1
    }

    fn delay(&self) -> Duration {
        e3_utils::backoff_delay(
            Duration::from_secs(1),
            self.failures,
            Duration::from_secs(30),
        )
    }
}

pub(crate) fn repository(repositories: &Repositories, id: &E3id) -> Repository<RecipientRecord> {
    Repository::new(
        repositories
            .store
            .scope(StoreKeys::synchronized_dkg_recipient(id)),
    )
}

pub(crate) async fn recover(
    repositories: &Repositories,
    metadata: &HashMap<E3id, E3Meta>,
    ended: &HashSet<E3id>,
) -> Result<HashMap<E3id, RecipientRecord>> {
    let mut records = HashMap::new();
    for (id, meta) in metadata {
        if meta.params_profile.protocol() != BfvDecryptionProtocol::Synchronized {
            continue;
        }
        let store = e3_data::DataStore::from(repository(repositories, id));
        if ended.contains(id) {
            store.remove_sync().await?;
        } else if let Some(record) = store.read_checked::<RecipientRecord>().await? {
            meta.validate_configuration()?;
            record.validate()?;
            if let Some(plan) = &record.plan {
                ensure!(
                    plan.inputs.e3_id == *id
                        && plan.inputs.params_profile == meta.params_profile
                        && plan.inputs.committee_size
                            == CiphernodesCommitteeSize::from_threshold(
                                meta.threshold_m,
                                meta.threshold_n
                            )?,
                    "saved recipient plan differs from canonical request"
                );
            }
            ensure!(
                record.leaves.values().all(|leaf| leaf.e3_id == *id)
                    && record.dealers.values().all(|dealer| dealer.e3_id == *id),
                "saved recipient inputs belong to another request"
            );
            records.insert(id.clone(), record);
        }
    }
    Ok(records)
}

impl RecipientCollection {
    pub(crate) fn from_records(records: HashMap<E3id, RecipientRecord>) -> Self {
        Self {
            records,
            ..Self::default()
        }
    }

    pub(crate) fn inner_proofs(&self) -> HashMap<E3id, BTreeMap<usize, Proof>> {
        self.records
            .iter()
            .map(|(id, record)| {
                (
                    id.clone(),
                    record
                        .leaves
                        .iter()
                        .map(|(&seq, leaf)| (seq, leaf.proof.clone()))
                        .collect(),
                )
            })
            .collect()
    }
}

impl NodeProofAggregator {
    pub(super) fn route_synchronized(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        let dealer = self.route_dealer(data, ec, ctx);
        let recipient = self.route_recipient(data, ec, ctx);
        dealer || recipient
    }

    fn route_recipient(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        if matches!(data, InterfoldEventData::EffectsEnabled(_))
            && ec.source() == EventSource::Local
        {
            for id in self.recipient.records.keys().cloned().collect::<Vec<_>>() {
                self.persist_recipient(&id, ctx);
            }
        }
        let Some(id) = data.get_e3_id() else {
            return false;
        };
        let Some(meta) = self.dealer.metadata.get(&id) else {
            return false;
        };
        if meta.params_profile.protocol() != BfvDecryptionProtocol::Synchronized {
            return false;
        }
        if self.dealer.ended.contains(&id) {
            if let Some(retry) = self
                .recipient
                .flush_retries
                .remove(&id)
                .and_then(|retry| retry.timer)
            {
                ctx.cancel_future(retry);
            }
            if let Some(retry) = self
                .recipient
                .delivery_retries
                .remove(&id)
                .and_then(|retry| retry.timer)
            {
                ctx.cancel_future(retry);
            }
            if let Some(retry) = self.recipient.work_retries.remove(&id) {
                ctx.cancel_future(retry);
            }
            self.recipient.records.remove(&id);
            self.recipient.in_flight.remove(&id);
            self.recipient.published.remove(&id);
            self.recipient.local_published.remove(&id);
            self.recipient.invalid_work.remove(&id);
            self.recipient.failed_work.remove(&id);
            self.recipient.repairs.remove(&id);
            self.recipient.repair_counts.remove(&id);
            self.recipient.unflushed.remove(&id);
            if let Some(repositories) = &self.recovery_repositories {
                let store = e3_data::DataStore::from(repository(repositories, &id));
                ctx.wait(
                    async move { store.remove_sync().await }
                        .into_actor(self)
                        .map(|result, _, _| {
                            if let Err(error) = result {
                                tracing::error!(%error, "recipient retirement failed");
                            }
                        }),
                );
            }
            return true;
        }
        if !matches!(
            data,
            InterfoldEventData::SynchronizedRecipientInputsReady(_)
                | InterfoldEventData::SynchronizedDkgProofPublished(_)
                | InterfoldEventData::DKGInnerProofReady(_)
                | InterfoldEventData::ComputeResponse(_)
                | InterfoldEventData::ComputeRequestError(_)
        ) {
            return false;
        }
        if meta.validate_configuration().is_err() {
            return true;
        }
        match self.accept_recipient_input(data, ec) {
            Ok(changed) => {
                if !self.recipient.in_flight.contains_key(&id)
                    || self.recipient.invalid_work.contains(&id)
                {
                    if let Some(timer) = self.recipient.work_retries.remove(&id) {
                        ctx.cancel_future(timer);
                    }
                }
                if changed {
                    self.persist_recipient(&id, ctx);
                }
            }
            Err(error) => {
                tracing::debug!(%id, %error, "synchronized recipient input rejected");
            }
        }
        true
    }

    fn validate_recipient_authority(&self, plan: &RecipientPlan) -> Result<()> {
        let input = &plan.inputs;
        self.validate_synchronized_authority(
            &input.e3_id,
            input.params_profile,
            input.committee_size,
            &input.context,
        )
    }

    fn authenticate_dealer(&self, message: &SynchronizedDkgProofPublished) -> Result<()> {
        ensure!(
            message.role == SynchronizedDkgProofRole::Dealer,
            "not a dealer join"
        );
        let meta = self
            .dealer
            .metadata
            .get(&message.e3_id)
            .context("missing request")?;
        let committee = self
            .dealer
            .committees
            .get(&message.e3_id)
            .context("missing committee")?;
        let members = committee
            .members()
            .iter()
            .map(|member| member.parse::<Address>())
            .collect::<Result<Vec<_>, _>>()?;
        let size = CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)?;
        ensure!(
            members.len() == size.values().n
                && members.windows(2).all(|pair| pair[0] < pair[1])
                && message.context.setup.committee_hash
                    == e3_committee_hash::hash_committee_addresses(&members)
                && message.context.setup.crypto_config_id.as_slice() == meta.crypto_config_id
                && members.get(message.context.party_id as usize)
                    == Some(&message.recover_address()?),
            "dealer signer does not own this canonical committee slot"
        );
        let config = Configs::for_profile(meta.params_profile, size)?;
        let binding =
            crate::synchronized::request_binding(&config, &message.context, &message.e3_id)?;
        let public = PublicSignals::decode(
            &config,
            CircuitName::NodeFold,
            &message.proof.public_signals,
        )?;
        ensure!(
            public.binding() == Some(binding)
                && public.party_id() == Some(message.context.party_id),
            "dealer statement identity differs"
        );
        Ok(())
    }

    fn accept_recipient_input(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
    ) -> Result<bool> {
        let id = data.get_e3_id().context("missing recipient E3")?;
        ensure!(!self.dealer.ended.contains(&id), "recipient DKG has ended");
        let peer = matches!(data, InterfoldEventData::SynchronizedDkgProofPublished(_));
        ensure!(
            peer || ec.source() == EventSource::Local,
            "recipient intent/result must be local"
        );
        if self
            .recipient
            .records
            .get(&id)
            .is_some_and(|r| r.completed.is_some())
        {
            return Ok(false);
        }
        match data {
            InterfoldEventData::SynchronizedRecipientInputsReady(input) => {
                let plan = RecipientPlan::new(input.clone())?;
                self.validate_recipient_authority(&plan)?;
                let record = self
                    .recipient
                    .records
                    .entry(id)
                    .or_insert_with(|| RecipientRecord::new(ec.clone()));
                ensure!(
                    record.plan.as_ref().is_none_or(|old| old == &plan),
                    "native C4 roster is already fixed"
                );
                if record.plan.is_some() {
                    return Ok(false);
                }
                // Early rows have authorship but no authority to choose the native setup/roster.
                record
                    .dealers
                    .retain(|_, dealer| plan.validate_dealer(dealer).is_ok());
                record
                    .leaves
                    .retain(|_, leaf| plan.validate_leaf(leaf).is_ok());
                record.plan = Some(plan);
                record.ec = ec.clone();
            }
            InterfoldEventData::SynchronizedDkgProofPublished(message) => {
                if message.role != SynchronizedDkgProofRole::Dealer {
                    return Ok(false);
                }
                self.authenticate_dealer(message)?;
                let record = self
                    .recipient
                    .records
                    .entry(id.clone())
                    .or_insert_with(|| RecipientRecord::new(ec.clone()));
                if let Some(plan) = &record.plan {
                    plan.validate_dealer(message)?;
                }
                if let Some(old) = record.dealers.get(&message.context.party_id) {
                    if old.context == message.context
                        // NodeFold's only local-artifact anchor is field 3. Preserve every
                        // statement field while allowing its authenticated genealogy repair.
                        && old.proof.public_signals[..3 * 32]
                            == message.proof.public_signals[..3 * 32]
                        && old.proof.public_signals[4 * 32..]
                            == message.proof.public_signals[4 * 32..]
                    {
                        if old.proof == message.proof {
                            return Ok(false);
                        }
                        // Authorship is not proof validity; repaired candidates must still pass
                        // the batch/genealogy and recursive verification boundaries.
                    } else {
                        ensure!(
                            record.plan.is_none(),
                            "conflicting authenticated dealer join"
                        );
                    }
                    let slot = message.context.party_id;
                    if self
                        .recipient
                        .repair_counts
                        .get(&id)
                        .and_then(|counts| counts.get(&slot))
                        .is_some_and(|&count| count >= MAX_JOIN_REPAIRS_PER_DEALER)
                    {
                        return Ok(false);
                    }
                    if self.recipient.in_flight.contains_key(&id) {
                        // Never invalidate a running join merely because an authenticated
                        // candidate differs. Keep at most one alternate per fixed slot.
                        self.recipient
                            .repairs
                            .entry(id.clone())
                            .or_default()
                            .insert(slot, message.clone());
                        return self.promote_recipient_repairs(&id, ec);
                    }
                }
                record
                    .dealers
                    .insert(message.context.party_id, message.clone());
                record.ec = ec.clone();
            }
            InterfoldEventData::DKGInnerProofReady(leaf) => {
                if !matches!(
                    leaf.proof.circuit,
                    CircuitName::PkBfv
                        | CircuitName::SkShareComputation
                        | CircuitName::DkgShareDecryption
                ) {
                    return Ok(false);
                }
                let committee = self
                    .dealer
                    .committees
                    .get(&id)
                    .context("missing local committee")?;
                ensure!(
                    committee.party_id_for(&self.signer.address().to_string())
                        == Some(leaf.party_id),
                    "recipient leaf belongs to another owner"
                );
                let meta = &self.dealer.metadata[&id];
                let size =
                    CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)?;
                let config = Configs::for_profile(meta.params_profile, size)?;
                let seq =
                    crate::synchronized::recipient::leaf_sequence(&config, leaf.proof.circuit)?;
                ensure!(leaf.seq == seq, "wrong recipient leaf slot");
                let public =
                    PublicSignals::decode(&config, leaf.proof.circuit, &leaf.proof.public_signals)?;
                if leaf.proof.circuit != CircuitName::PkBfv {
                    ensure!(
                        public.party_id().map(u64::from) == Some(leaf.party_id),
                        "recipient public owner differs"
                    );
                }
                let record = self
                    .recipient
                    .records
                    .entry(id)
                    .or_insert_with(|| RecipientRecord::new(ec.clone()));
                if let Some(plan) = &record.plan {
                    plan.validate_leaf(leaf)?;
                }
                if let Some(old) = record.leaves.get(&leaf.seq) {
                    ensure!(
                        old.proof.public_signals == leaf.proof.public_signals,
                        "conflicting local recipient leaf"
                    );
                    return Ok(false);
                }
                record.leaves.insert(leaf.seq, leaf.clone());
                record.ec = ec.clone();
            }
            InterfoldEventData::ComputeResponse(response) => {
                let Some(request) = self.recipient.in_flight.get(&id) else {
                    return Ok(false);
                };
                ensure!(
                    response.correlation_id == request.correlation_id,
                    "stale recipient response"
                );
                let ComputeResponseKind::Zk(ZkResponse::SynchronizedDkg(
                    SynchronizedDkgProofResponse::Recipient { proof, setup },
                )) = &response.response
                else {
                    anyhow::bail!("unexpected recipient response");
                };
                let record = self
                    .recipient
                    .records
                    .get_mut(&id)
                    .context("missing recipient record")?;
                let plan = record.plan.as_ref().context("missing recipient plan")?;
                let ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)) = &request.request
                else {
                    anyhow::bail!("unexpected recipient request");
                };
                plan.validate_result(work, proof, setup)?;
                record.completed = Some(SynchronizedRecipientProofReady {
                    e3_id: id.clone(),
                    context: plan.inputs.context.clone(),
                    proof: proof.clone(),
                    setup: setup.clone(),
                });
                record.ec = ec.clone();
                self.recipient.in_flight.remove(&id);
                self.recipient.failed_work.remove(&id);
                self.recipient.invalid_work.remove(&id);
                self.recipient.repairs.remove(&id);
                self.recipient.repair_counts.remove(&id);
            }
            InterfoldEventData::ComputeRequestError(error) => {
                if let Some(request) = self.recipient.in_flight.get(&id) {
                    ensure!(
                        error.request() == request,
                        "recipient error has another request"
                    );
                    if matches!(
                        error.get_err(),
                        ComputeRequestErrorKind::Zk(ZkError::InvalidParams(_))
                    ) {
                        self.recipient.invalid_work.insert(id.clone());
                    }
                    self.recipient.failed_work.insert(id.clone());
                    tracing::error!(%id, %error, "recipient join failed; exact request and authenticated candidates retained, not a peer-invalid verdict");
                    return self.promote_recipient_repairs(&id, ec);
                }
                return Ok(false);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn promote_recipient_repairs(
        &mut self,
        id: &E3id,
        ec: &EventContext<Sequenced>,
    ) -> Result<bool> {
        if !self.recipient.failed_work.contains(id) {
            return Ok(false);
        }
        let Some(repairs) = self.recipient.repairs.get(id) else {
            return Ok(false);
        };
        let record = self
            .recipient
            .records
            .get_mut(id)
            .context("missing recipient record")?;
        let plan = record.plan.as_ref().context("missing recipient plan")?;
        let mut dealers = record.dealers.clone();
        dealers.extend(repairs.clone());
        // A conflicting tree must not displace a coherent active batch. A complete compatible
        // repair set can still be made eligible by later arrivals from the other slots.
        let mut slots = repairs.keys().copied().collect::<Vec<_>>();
        if !matches!(plan.request(&record.leaves, &dealers), Ok(Some(_))) {
            // A pending genealogy change from one slot cannot block an unrelated byte-only
            // repair. Try just the rows that preserve the currently coherent genealogy.
            dealers.clone_from(&record.dealers);
            slots.retain(|slot| {
                let proof = &repairs[slot].proof;
                proof.public_signals[3 * 32..4 * 32]
                    == record.dealers[slot].proof.public_signals[3 * 32..4 * 32]
            });
            dealers.extend(slots.iter().map(|slot| (*slot, repairs[slot].clone())));
            if slots.is_empty() || !matches!(plan.request(&record.leaves, &dealers), Ok(Some(_))) {
                return Ok(false);
            }
        }
        let counts = self.recipient.repair_counts.entry(id.clone()).or_default();
        let retained = self
            .recipient
            .repairs
            .get_mut(id)
            .expect("recipients have repairs");
        for slot in slots {
            *counts.entry(slot).or_default() += 1;
            retained.remove(&slot);
        }
        record.dealers = dealers;
        record.ec = ec.clone();
        if retained.is_empty() {
            self.recipient.repairs.remove(id);
        }
        self.recipient.failed_work.remove(id);
        self.recipient.in_flight.remove(id);
        self.recipient.invalid_work.remove(id);
        Ok(true)
    }

    fn persist_recipient(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if !self.dealer.effects || self.dealer.ended.contains(id) {
            return;
        }
        if self
            .dealer
            .metadata
            .get(id)
            .is_none_or(|meta| meta.validate_configuration().is_err())
        {
            return;
        }
        let Some(record) = self.recipient.records.get(id).cloned() else {
            return;
        };
        self.flush_recipient_record(id, record, ctx);
    }

    fn validate_recipient_record(&self, id: &E3id, record: &RecipientRecord) -> Result<()> {
        record.validate()?;
        if let Some(plan) = &record.plan {
            ensure!(&plan.inputs.e3_id == id, "recipient record E3 differs");
            self.validate_recipient_authority(plan)?;
        }
        for dealer in record.dealers.values() {
            ensure!(&dealer.e3_id == id, "dealer record E3 differs");
            self.authenticate_dealer(dealer)?;
        }
        Ok(())
    }

    fn flush_recipient_record(
        &mut self,
        id: &E3id,
        record: RecipientRecord,
        ctx: &mut Context<Self>,
    ) {
        self.recipient.unflushed.insert(id.clone());
        // Every writer, including a pending retry, must revalidate its current snapshot.
        if let Err(error) = self.validate_recipient_record(id, &record) {
            tracing::error!(%id, %error, "saved recipient input rejected");
            return;
        }
        let Some(repositories) = &self.recovery_repositories else {
            return;
        };
        let repository = repository(repositories, id);
        let id = id.clone();
        ctx.wait(async move { repository.write_sync(&record).await }.into_actor(self).map(move |result, actor, ctx| {
            match result {
                Ok(()) => {
                    actor.recipient.unflushed.remove(&id);
                    if let Some(retry) = actor.recipient.flush_retries.remove(&id).and_then(|retry| retry.timer) {
                        ctx.cancel_future(retry);
                    }
                    actor.drive_recipient_delivery(&id, ctx);
                }
                Err(error) => {
                    if actor.recipient.flush_retries.entry(id.clone()).or_default().failed() {
                        tracing::warn!(%id, %error, "recipient flush failed; effects withheld until retry succeeds");
                    }
                    actor.retry_recipient_flush(&id, ctx);
                }
            }
        }));
    }

    fn retry_recipient_flush(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        let state = self.recipient.flush_retries.entry(id.clone()).or_default();
        if state.timer.is_some() {
            return;
        }
        let retry_id = id.clone();
        state.timer = Some(ctx.run_later(state.delay(), move |actor, ctx| {
            if let Some(state) = actor.recipient.flush_retries.get_mut(&retry_id) {
                state.timer = None;
            }
            if !actor.dealer.effects || actor.dealer.ended.contains(&retry_id) {
                return;
            }
            // Retry the latest retained record, not a snapshot superseded by another input.
            if let Some(record) = actor.recipient.records.get(&retry_id).cloned() {
                actor.flush_recipient_record(&retry_id, record, ctx);
            }
        }));
    }

    fn drive_recipient_delivery(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if self.recipient.unflushed.contains(id)
            || self
                .recipient
                .delivery_retries
                .get(id)
                .is_some_and(|state| state.timer.is_some())
        {
            return;
        }
        match self.publish_recipient_work(id) {
            Ok(()) => {
                self.recipient.delivery_retries.remove(id);
                self.retry_recipient_work(id, ctx);
            }
            Err(error) => {
                let state = self
                    .recipient
                    .delivery_retries
                    .entry(id.clone())
                    .or_default();
                if state.failed() {
                    tracing::warn!(%id, %error, "recipient publication refused; flushed progress retained");
                }
                let retry_id = id.clone();
                state.timer = Some(ctx.run_later(state.delay(), move |actor, ctx| {
                    if let Some(state) = actor.recipient.delivery_retries.get_mut(&retry_id) {
                        state.timer = None;
                    }
                    actor.drive_recipient_delivery(&retry_id, ctx);
                }));
            }
        }
    }

    fn retry_recipient_work(&mut self, id: &E3id, ctx: &mut Context<Self>) {
        if !self.recipient.in_flight.contains_key(id) || self.recipient.invalid_work.contains(id) {
            if let Some(retry) = self.recipient.work_retries.remove(id) {
                ctx.cancel_future(retry);
            }
            return;
        }
        if self.recipient.work_retries.contains_key(id) {
            return;
        }
        let id = id.clone();
        let retry_id = id.clone();
        let retry = ctx.run_later(Duration::from_secs(60), move |actor, ctx| {
            actor.recipient.work_retries.remove(&retry_id);
            if !actor.dealer.effects || actor.dealer.ended.contains(&retry_id) {
                return;
            }
            if actor.recipient.invalid_work.contains(&retry_id) {
                return;
            }
            if let Err(error) = actor.redrive_recipient_work(&retry_id) {
                tracing::error!(%retry_id, %error, "recipient redelivery failed; live correlation retained");
            }
            actor.retry_recipient_work(&retry_id, ctx);
        });
        self.recipient.work_retries.insert(id, retry);
    }

    fn redrive_recipient_work(&mut self, id: &E3id) -> Result<()> {
        if self.recipient.unflushed.contains(id) {
            return Ok(());
        }
        let Some(current) = self.recipient.in_flight.get(id) else {
            return Ok(());
        };
        let record = self
            .recipient
            .records
            .get(id)
            .context("missing recipient record")?;
        self.validate_recipient_record(id, record)?;
        let plan = record.plan.as_ref().context("missing recipient plan")?;
        let work = plan.request(&record.leaves, &record.dealers)?;
        ensure!(
            record.completed.is_none()
                && work.is_some_and(|work| current.request
                    == ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(Box::new(work)))),
            "recipient redelivery differs from flushed work"
        );
        let mut request = current.clone();
        request.correlation_id = CorrelationId::new();
        // The compute gate reuses success and waits for queued/running work to finish. Keep the
        // current correlation until bus admission succeeds, including when admission is saturated.
        self.bus.publish(request.clone(), record.ec.clone())?;
        self.recipient.in_flight.insert(id.clone(), request);
        self.recipient.failed_work.remove(id);
        Ok(())
    }

    fn publish_recipient_work(&mut self, id: &E3id) -> Result<()> {
        if !self.dealer.effects || self.dealer.ended.contains(id) {
            return Ok(());
        }
        let Some(record) = self.recipient.records.get(id) else {
            return Ok(());
        };
        if let Some(output) = &record.completed {
            if !self.recipient.published.contains(id) {
                let signed = SynchronizedDkgProofPublished::sign(
                    id.clone(),
                    output.context.clone(),
                    SynchronizedDkgProofRole::Recipient,
                    output.proof.clone(),
                    &self.signer,
                )?;
                if !self.recipient.local_published.contains(id) {
                    self.bus.publish(output.clone(), record.ec.clone())?;
                    self.recipient.local_published.insert(id.clone());
                }
                self.bus.publish(signed, record.ec.clone())?;
                self.recipient.published.insert(id.clone());
            }
        } else if !self.recipient.in_flight.contains_key(id) {
            let Some(plan) = &record.plan else {
                return Ok(());
            };
            if let Some(work) = plan.request(&record.leaves, &record.dealers)? {
                let request = ComputeRequest::zk(
                    ZkRequest::SynchronizedDkg(Box::new(work)),
                    CorrelationId::new(),
                    id.clone(),
                );
                self.bus.publish(request.clone(), record.ec.clone())?;
                self.recipient.in_flight.insert(id.clone(), request);
            }
        }
        Ok(())
    }
}

impl RecipientRecord {
    fn new(ec: EventContext<Sequenced>) -> Self {
        Self {
            version: 1,
            plan: None,
            leaves: BTreeMap::new(),
            dealers: BTreeMap::new(),
            completed: None,
            ec,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported recipient recovery version");
        for (&seq, leaf) in &self.leaves {
            ensure!(seq == leaf.seq, "saved recipient slot differs");
        }
        for (&id, dealer) in &self.dealers {
            ensure!(id == dealer.context.party_id, "saved dealer slot differs");
        }
        if let Some(plan) = &self.plan {
            RecipientPlan::new(plan.inputs.clone())?;
            let work = plan.request(&self.leaves, &self.dealers)?;
            if let Some(output) = &self.completed {
                ensure!(
                    output.e3_id == plan.inputs.e3_id && output.context == plan.inputs.context,
                    "saved recipient result identity differs"
                );
                plan.validate_result(
                    &work.context("completed recipient has missing inputs")?,
                    &output.proof,
                    &output.setup,
                )?;
            }
        } else {
            ensure!(
                self.completed.is_none(),
                "recipient result without native intent"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "recipient_tests.rs"]
mod tests;
