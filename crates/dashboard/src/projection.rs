// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure EventStore-to-dashboard projection.

use e3_events::{
    hlc::HlcTimestamp, E3Stage, Event, EventContextAccessors, EventContextSeq, EventSource,
    InterfoldEvent, InterfoldEventData,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const LARGE_ARRAY: usize = 96;
const STRING_PREVIEW: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum E3Phase {
    Request,
    Committee,
    DkgSetup,
    DkgShares,
    KeyPublication,
    Computation,
    Decryption,
    Settlement,
}

impl E3Phase {
    pub const ALL: [Self; 8] = [
        Self::Request,
        Self::Committee,
        Self::DkgSetup,
        Self::DkgShares,
        Self::KeyPublication,
        Self::Computation,
        Self::Decryption,
        Self::Settlement,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Committee => "Committee formation",
            Self::DkgSetup => "DKG · C0",
            Self::DkgShares => "DKG · C1–C4",
            Self::KeyPublication => "Key publication · C5",
            Self::Computation => "Encrypted computation",
            Self::Decryption => "Decryption · C6–C7",
            Self::Settlement => "Output & rewards",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventView {
    pub seq: u64,
    pub aggregate_id: usize,
    pub timestamp_us: u64,
    pub logical_counter: u32,
    pub producer_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<u64>,
    pub source: String,
    pub producer: String,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e3_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<E3Phase>,
    pub severity: EventSeverity,
    pub event_id: String,
    pub causation_id: String,
    pub origin_id: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceCounts {
    pub local: usize,
    pub net: usize,
    pub evm: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhaseView {
    pub id: E3Phase,
    pub label: &'static str,
    pub state: &'static str,
    pub event_count: usize,
    pub sources: SourceCounts,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommitteeMemberView {
    pub address: String,
    pub party_id: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<String>,
    pub expelled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketView {
    pub node: String,
    pub ticket_id: u64,
    pub score: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RewardView {
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub amount: String,
    pub claimed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct E3Summary {
    pub e3_id: String,
    pub chain_id: u64,
    pub status: String,
    pub current_phase: E3Phase,
    pub event_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub committee_size: usize,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct E3Trace {
    #[serde(flatten)]
    pub summary: E3Summary,
    pub phases: Vec<PhaseView>,
    pub committee: Vec<CommitteeMemberView>,
    pub tickets: Vec<TicketView>,
    pub rewards: Vec<RewardView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Value>,
    pub events: Vec<EventView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ChainOperatorView {
    pub chain_id: u64,
    pub registered_nodes: usize,
    pub active_nodes: usize,
    pub operator_registered: bool,
    pub operator_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_bond: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_unlock_at: Option<u64>,
    pub rewards_credited: Vec<RewardView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProtocolOverview {
    pub chains: Vec<ChainOperatorView>,
    pub e3_total: usize,
    pub e3_active: usize,
    pub e3_completed: usize,
    pub e3_failed: usize,
    pub events_observed: usize,
}

#[derive(Default)]
struct ChainState {
    registered: BTreeSet<String>,
    active: BTreeSet<String>,
    ticket_balance: Option<String>,
    license_bond: Option<String>,
    exit_unlock_at: Option<u64>,
    rewards: Vec<RewardView>,
}

#[derive(Default)]
struct E3State {
    e3_id: String,
    chain_id: u64,
    events: Vec<EventView>,
    status: String,
    current_phase: Option<E3Phase>,
    committee: Vec<String>,
    scores: Vec<String>,
    tickets: Vec<TicketView>,
    expelled: BTreeSet<String>,
    rewards: Vec<RewardView>,
    failure: Option<Value>,
    failed_phase: Option<E3Phase>,
    first_seen_us: u64,
    last_seen_us: u64,
}

#[derive(Default)]
pub struct TelemetryProjection {
    local_address: String,
    events: Vec<EventView>,
    e3s: BTreeMap<String, E3State>,
    chains: BTreeMap<u64, ChainState>,
}

impl TelemetryProjection {
    pub fn new(local_address: impl Into<String>) -> Self {
        Self {
            local_address: normalize_address(&local_address.into()),
            ..Self::default()
        }
    }

    pub fn apply(&mut self, event: InterfoldEvent) {
        let view = project_event(&event, &self.local_address);
        self.apply_operator_state(event.get_data());
        if let Some(e3_id) = view.e3_id.clone() {
            self.apply_e3_state(&e3_id, event.get_data(), &view);
        }
        self.events.push(view);
    }

    pub fn summaries(&self) -> Vec<E3Summary> {
        let mut summaries: Vec<_> = self.e3s.values().map(summary).collect();
        summaries.sort_by(|a, b| b.last_seen_us.cmp(&a.last_seen_us));
        summaries
    }

    pub fn trace(&self, e3_id: &str) -> Option<E3Trace> {
        self.e3s.get(e3_id).map(trace)
    }

    pub fn recent_events(&self, limit: usize) -> Vec<EventView> {
        self.events.iter().rev().take(limit).cloned().collect()
    }

    pub fn overview(&self) -> ProtocolOverview {
        let summaries = self.summaries();
        ProtocolOverview {
            chains: self
                .chains
                .iter()
                .map(|(chain_id, state)| ChainOperatorView {
                    chain_id: *chain_id,
                    registered_nodes: state.registered.len(),
                    active_nodes: state.active.len(),
                    operator_registered: state.registered.contains(&self.local_address),
                    operator_active: state.active.contains(&self.local_address),
                    ticket_balance: state.ticket_balance.clone(),
                    license_bond: state.license_bond.clone(),
                    exit_unlock_at: state.exit_unlock_at,
                    rewards_credited: state.rewards.clone(),
                })
                .collect(),
            e3_total: summaries.len(),
            e3_active: summaries
                .iter()
                .filter(|summary| summary.status == "active")
                .count(),
            e3_completed: summaries
                .iter()
                .filter(|summary| summary.status == "complete")
                .count(),
            e3_failed: summaries
                .iter()
                .filter(|summary| summary.status == "failed")
                .count(),
            events_observed: self.events.len(),
        }
    }

    fn apply_operator_state(&mut self, data: &InterfoldEventData) {
        match data {
            InterfoldEventData::CiphernodeAdded(event) => {
                self.chains
                    .entry(event.chain_id)
                    .or_default()
                    .registered
                    .insert(normalize_address(&event.address));
            }
            InterfoldEventData::CiphernodeRemoved(event) => {
                let state = self.chains.entry(event.chain_id).or_default();
                let address = normalize_address(&event.address);
                state.registered.remove(&address);
                state.active.remove(&address);
            }
            InterfoldEventData::OperatorActivationChanged(event) => {
                let state = self.chains.entry(event.chain_id).or_default();
                let operator = normalize_address(&event.operator);
                if event.active {
                    state.active.insert(operator);
                } else {
                    state.active.remove(&operator);
                }
            }
            InterfoldEventData::TicketBalanceUpdated(event)
                if normalize_address(&event.operator) == self.local_address =>
            {
                self.chains
                    .entry(event.chain_id)
                    .or_default()
                    .ticket_balance = Some(event.new_balance.to_string());
            }
            InterfoldEventData::LicenseBondUpdated(event)
                if normalize_address(&event.operator) == self.local_address =>
            {
                self.chains.entry(event.chain_id).or_default().license_bond =
                    Some(event.new_bond.to_string());
            }
            InterfoldEventData::CiphernodeDeregistrationRequested(event)
                if normalize_address(&event.operator) == self.local_address =>
            {
                self.chains
                    .entry(event.chain_id)
                    .or_default()
                    .exit_unlock_at = Some(event.unlock_at);
            }
            InterfoldEventData::RewardCredited(event)
                if normalize_address(&event.account) == self.local_address =>
            {
                self.chains
                    .entry(event.e3_id.chain_id())
                    .or_default()
                    .rewards
                    .push(RewardView {
                        account: event.account.clone(),
                        token: Some(event.token.clone()),
                        amount: event.amount.clone(),
                        claimed: false,
                    });
            }
            InterfoldEventData::RewardClaimed(event)
                if normalize_address(&event.account) == self.local_address =>
            {
                let state = self.chains.entry(event.e3_id.chain_id()).or_default();
                if let Some(reward) = state.rewards.iter_mut().rev().find(|reward| {
                    normalize_address(&reward.account) == self.local_address
                        && reward.token.as_deref() == Some(event.token.as_str())
                        && reward.amount == event.amount
                }) {
                    reward.claimed = true;
                }
            }
            _ => {}
        }
    }

    fn apply_e3_state(&mut self, e3_id: &str, data: &InterfoldEventData, view: &EventView) {
        let chain_id = e3_id
            .split_once(':')
            .and_then(|(chain, _)| chain.parse().ok())
            .unwrap_or(0);
        let state = self.e3s.entry(e3_id.to_owned()).or_insert_with(|| E3State {
            e3_id: e3_id.to_owned(),
            chain_id,
            status: "active".to_owned(),
            first_seen_us: view.timestamp_us,
            ..E3State::default()
        });
        state.first_seen_us = state.first_seen_us.min(view.timestamp_us);
        state.last_seen_us = state.last_seen_us.max(view.timestamp_us);
        if state.status != "failed" {
            if let Some(phase) = view.phase {
                state.current_phase = Some(
                    state
                        .current_phase
                        .map_or(phase, |current| current.max(phase)),
                );
            }
        }

        match data {
            InterfoldEventData::CommitteeFinalized(event) => {
                state.committee = event.committee.clone();
                state.scores = event.scores.clone();
            }
            InterfoldEventData::CommitteePublished(event) if state.committee.is_empty() => {
                state.committee = event.nodes.clone();
            }
            InterfoldEventData::TicketSubmitted(event) => state.tickets.push(TicketView {
                node: event.node.clone(),
                ticket_id: event.ticket_id,
                score: event.score.clone(),
            }),
            InterfoldEventData::CommitteeMemberExpelled(event) => {
                state
                    .expelled
                    .insert(normalize_address(&event.node.to_string()));
            }
            InterfoldEventData::E3Failed(event) => {
                state.status = "failed".to_owned();
                state.failed_phase = view.phase;
                state.failure = Some(json!({
                    "failed_at_stage": event.failed_at_stage,
                    "reason": event.reason,
                }));
            }
            InterfoldEventData::CommitteeFormationFailed(event) => {
                state.status = "failed".to_owned();
                state.failed_phase = Some(E3Phase::Committee);
                state.failure = Some(json!({
                    "reason": "CommitteeFormationFailed",
                    "nodes_submitted": event.nodes_submitted,
                    "threshold_required": event.threshold_required,
                }));
            }
            InterfoldEventData::E3RequestComplete(_)
            | InterfoldEventData::PlaintextOutputPublished(_) => {
                state.status = "complete".to_owned();
            }
            InterfoldEventData::E3StageChanged(event) => match event.new_stage {
                E3Stage::Complete => state.status = "complete".to_owned(),
                E3Stage::Failed => {
                    let failed_phase = stage_phase(&event.previous_stage);
                    state.status = "failed".to_owned();
                    state.failed_phase = Some(failed_phase);
                    state.current_phase = Some(failed_phase);
                }
                _ => {}
            },
            InterfoldEventData::RewardsDistributed(event) => {
                state.rewards = event
                    .nodes
                    .iter()
                    .zip(&event.amounts)
                    .map(|(account, amount)| RewardView {
                        account: account.clone(),
                        token: None,
                        amount: amount.clone(),
                        claimed: false,
                    })
                    .collect();
            }
            InterfoldEventData::RewardCredited(event) => {
                state.rewards.push(RewardView {
                    account: event.account.clone(),
                    token: Some(event.token.clone()),
                    amount: event.amount.clone(),
                    claimed: false,
                });
            }
            InterfoldEventData::RewardClaimed(event) => {
                if let Some(reward) = state.rewards.iter_mut().rev().find(|reward| {
                    normalize_address(&reward.account) == normalize_address(&event.account)
                        && reward.token.as_deref() == Some(event.token.as_str())
                        && reward.amount == event.amount
                }) {
                    reward.claimed = true;
                }
            }
            _ => {}
        }
        state.events.push(view.clone());
    }
}

fn project_event(event: &InterfoldEvent, local_address: &str) -> EventView {
    let timestamp = HlcTimestamp::from(event.ts());
    let source = match event.source() {
        EventSource::Local => "local",
        EventSource::Net => "network",
        EventSource::Evm => "evm",
    };
    let producer = match (event.source(), event.get_data()) {
        (EventSource::Local, _) => local_address.to_owned(),
        (EventSource::Evm, InterfoldEventData::EvmLogObserved(observed)) => {
            observed.contract.clone()
        }
        (EventSource::Evm, _) => "on-chain contract".to_owned(),
        (EventSource::Net, _) => format!("node:{:08x}", timestamp.node),
    };
    let event_type = match event.get_data() {
        InterfoldEventData::EvmLogObserved(observed) => {
            format!("{}::{}", observed.contract, observed.event_name)
        }
        _ => event.event_type(),
    };
    EventView {
        seq: event.clone().seq(),
        aggregate_id: event.aggregate_id().to_usize(),
        timestamp_us: timestamp.ts,
        logical_counter: timestamp.counter,
        producer_fingerprint: format!("{:08x}", timestamp.node),
        block: event.block(),
        source: source.to_owned(),
        producer,
        event_type,
        e3_id: event.get_e3_id().map(|id| id.to_string()),
        phase: phase(event.get_data()),
        severity: severity(event.get_data()),
        event_id: event.id().to_string(),
        causation_id: event.causation_id().to_string(),
        origin_id: event.origin_id().to_string(),
        payload: compact_payload(event.get_data()),
    }
}

fn phase(data: &InterfoldEventData) -> Option<E3Phase> {
    use E3Phase as P;
    use InterfoldEventData as E;
    match data {
        E::E3Requested(_) => Some(P::Request),
        E::CommitteeRequested(_)
        | E::CiphernodeSelected(_)
        | E::TicketGenerated(_)
        | E::TicketSubmitted(_)
        | E::CommitteeFinalizeRequested(_)
        | E::CommitteeFinalized(_)
        | E::CommitteeFormationFailed(_)
        | E::CommitteeMemberExpelled(_)
        | E::CommitteeViabilityUpdated(_) => Some(P::Committee),
        E::EncryptionKeyPending(_)
        | E::EncryptionKeyCreated(_)
        | E::EncryptionKeyReceived(_)
        | E::EncryptionKeyCollectionFailed(_) => Some(P::DkgSetup),
        E::ThresholdSharePending(_)
        | E::ThresholdShareCreated(_)
        | E::ThresholdShareCollectionFailed(_)
        | E::DkgProofSigned(_)
        | E::ShareVerificationDispatched(_)
        | E::ShareVerificationComplete(_)
        | E::DecryptionKeyShared(_)
        | E::DKGInnerProofReady(_)
        | E::DKGRecursiveAggregationComplete(_)
        | E::CommitmentConsistencyCheckRequested(_)
        | E::CommitmentConsistencyCheckComplete(_)
        | E::CommitmentConsistencyViolation(_) => Some(P::DkgShares),
        E::KeyshareCreated(_)
        | E::PkGenerationProofSigned(_)
        | E::PkAggregationProofPending(_)
        | E::PkAggregationProofSigned(_)
        | E::PublicKeyAggregated(_)
        | E::CommitteePublished(_) => Some(P::KeyPublication),
        E::InputPublished(_)
        | E::ComputeRequest(_)
        | E::ComputeResponse(_)
        | E::ComputeRequestError(_)
        | E::CiphertextOutputPublished(_) => Some(P::Computation),
        E::DecryptionShareProofsPending(_)
        | E::DecryptionShareProofSigned(_)
        | E::ShareDecryptionProofPending(_)
        | E::DecryptionshareCreated(_)
        | E::AggregationProofPending(_)
        | E::AggregationProofSigned(_)
        | E::PlaintextAggregated(_) => Some(P::Decryption),
        E::PlaintextOutputPublished(_)
        | E::RewardsDistributed(_)
        | E::RewardCredited(_)
        | E::RewardClaimed(_)
        | E::E3RequestComplete(_)
        | E::CommitteeActivationChanged(_) => Some(P::Settlement),
        E::E3StageChanged(event) => Some(match event.new_stage {
            E3Stage::None | E3Stage::Requested => P::Request,
            E3Stage::CommitteeFinalized => P::Committee,
            E3Stage::KeyPublished => P::KeyPublication,
            E3Stage::CiphertextReady => P::Computation,
            E3Stage::Complete | E3Stage::Failed => P::Settlement,
        }),
        E::E3Failed(event) => Some(match event.failed_at_stage {
            E3Stage::None | E3Stage::Requested => P::Request,
            E3Stage::CommitteeFinalized => P::DkgShares,
            E3Stage::KeyPublished => P::Computation,
            E3Stage::CiphertextReady => P::Decryption,
            E3Stage::Complete | E3Stage::Failed => P::Settlement,
        }),
        E::ProofVerificationFailed(event) => {
            Some(proof_phase(format!("{:?}", event.proof_type).as_str()))
        }
        E::ProofVerificationPassed(event) => {
            Some(proof_phase(format!("{:?}", event.proof_type).as_str()))
        }
        E::SignedProofFailed(event) => {
            Some(proof_phase(format!("{:?}", event.proof_type).as_str()))
        }
        E::ProofFailureAccusation(_)
        | E::AccusationVote(_)
        | E::AccusationQuorumReached(_)
        | E::SlashExecuted(_) => Some(P::DkgShares),
        E::EvmLogObserved(event) => match event.event_name.as_str() {
            "CommitteeFormed" | "CommitteeFinalized" => Some(P::Committee),
            "TreasuryCredited"
            | "TreasuryClaimed"
            | "SlashedFundsEscrowed"
            | "SlashedFundsEscrowedToRefund"
            | "RoutingFailed"
            | "E3FailureProcessed"
            | "SlashProposed" => Some(P::Settlement),
            _ => None,
        },
        _ => None,
    }
}

fn proof_phase(proof: &str) -> E3Phase {
    if proof.contains("C6") || proof.contains("C7") || proof.contains("Decryption") {
        E3Phase::Decryption
    } else if proof.contains("C5") || proof.contains("Pk") {
        E3Phase::KeyPublication
    } else {
        E3Phase::DkgShares
    }
}

fn stage_phase(stage: &E3Stage) -> E3Phase {
    match stage {
        E3Stage::None | E3Stage::Requested => E3Phase::Request,
        E3Stage::CommitteeFinalized => E3Phase::DkgShares,
        E3Stage::KeyPublished => E3Phase::Computation,
        E3Stage::CiphertextReady => E3Phase::Decryption,
        E3Stage::Complete | E3Stage::Failed => E3Phase::Settlement,
    }
}

fn severity(data: &InterfoldEventData) -> EventSeverity {
    use InterfoldEventData as E;
    match data {
        E::InterfoldError(_)
        | E::E3Failed(_)
        | E::CommitteeFormationFailed(_)
        | E::ProofVerificationFailed(_)
        | E::SignedProofFailed(_)
        | E::ThresholdShareCollectionFailed(_)
        | E::EncryptionKeyCollectionFailed(_)
        | E::ComputeRequestError(_)
        | E::CommitmentConsistencyViolation(_) => EventSeverity::Error,
        E::ProofFailureAccusation(_)
        | E::AccusationVote(_)
        | E::AccusationQuorumReached(_)
        | E::SlashExecuted(_)
        | E::CommitteeMemberExpelled(_) => EventSeverity::Warn,
        E::EvmLogObserved(event) if !event.known => EventSeverity::Warn,
        _ if phase(data).is_some() => EventSeverity::Info,
        _ => EventSeverity::Debug,
    }
}

fn compact_payload(data: &InterfoldEventData) -> Value {
    let serialized = serde_json::to_value(data)
        .unwrap_or_else(|error| json!({ "serialization_error": error.to_string() }));
    let payload = match serialized {
        Value::Object(mut object) if object.len() == 1 => object
            .remove(&data.event_type())
            .unwrap_or(Value::Object(object)),
        other => other,
    };
    compact_value(payload)
}

fn compact_value(value: Value) -> Value {
    match value {
        Value::Array(values) if values.len() > LARGE_ARRAY => {
            let length = values.len();
            let preview = values
                .into_iter()
                .take(12)
                .map(compact_value)
                .collect::<Vec<_>>();
            json!({
                "kind": "large_array",
                "length": length,
                "preview": preview,
                "truncated": true,
            })
        }
        Value::Array(values) => Value::Array(values.into_iter().map(compact_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, compact_value(value)))
                .collect::<Map<_, _>>(),
        ),
        Value::String(value) if value.len() > STRING_PREVIEW => json!({
            "kind": "large_string",
            "length": value.len(),
            "preview": &value[..safe_boundary(&value, STRING_PREVIEW)],
            "truncated": true,
        }),
        other => other,
    }
}

fn safe_boundary(value: &str, maximum: usize) -> usize {
    let mut boundary = maximum.min(value.len());
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn summary(state: &E3State) -> E3Summary {
    E3Summary {
        e3_id: state.e3_id.clone(),
        chain_id: state.chain_id,
        status: state.status.clone(),
        current_phase: state.current_phase.unwrap_or(E3Phase::Request),
        event_count: state.events.len(),
        error_count: state
            .events
            .iter()
            .filter(|event| event.severity == EventSeverity::Error)
            .count(),
        warning_count: state
            .events
            .iter()
            .filter(|event| event.severity == EventSeverity::Warn)
            .count(),
        committee_size: state.committee.len(),
        first_seen_us: state.first_seen_us,
        last_seen_us: state.last_seen_us,
    }
}

fn trace(state: &E3State) -> E3Trace {
    let current = state.current_phase.unwrap_or(E3Phase::Request);
    let phases = E3Phase::ALL
        .into_iter()
        .map(|phase| {
            let events: Vec<_> = state
                .events
                .iter()
                .filter(|event| event.phase == Some(phase))
                .collect();
            let source_count =
                |source: &str| events.iter().filter(|event| event.source == source).count();
            let phase_state = if state.status == "failed" {
                let failed_phase = state.failed_phase.unwrap_or(current);
                if phase == failed_phase {
                    "failed"
                } else if phase < failed_phase {
                    "complete"
                } else {
                    "pending"
                }
            } else if phase < current || (phase == current && state.status == "complete") {
                "complete"
            } else if phase == current {
                "active"
            } else {
                "pending"
            };
            PhaseView {
                id: phase,
                label: phase.label(),
                state: phase_state,
                event_count: events.len(),
                sources: SourceCounts {
                    local: source_count("local"),
                    net: source_count("network"),
                    evm: source_count("evm"),
                },
                errors: events
                    .iter()
                    .filter(|event| event.severity == EventSeverity::Error)
                    .count(),
                warnings: events
                    .iter()
                    .filter(|event| event.severity == EventSeverity::Warn)
                    .count(),
            }
        })
        .collect();
    E3Trace {
        summary: summary(state),
        phases,
        committee: state
            .committee
            .iter()
            .enumerate()
            .map(|(party_id, address)| CommitteeMemberView {
                address: address.clone(),
                party_id,
                score: state.scores.get(party_id).cloned(),
                expelled: state.expelled.contains(&normalize_address(address)),
            })
            .collect(),
        tickets: state.tickets.clone(),
        rewards: state.rewards.clone(),
        failure: state.failure.clone(),
        events: state.events.clone(),
    }
}

fn normalize_address(value: &str) -> String {
    value.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        EventConstructorWithTimestamp, RewardClaimed, RewardCredited, RewardsDistributed,
        Unsequenced,
    };

    #[test]
    fn compacts_large_payloads_at_unicode_boundaries() {
        let value = Value::String("é".repeat(400));
        let compact = compact_value(value);
        assert_eq!(compact["truncated"], true);
        assert!(compact["preview"].as_str().is_some());
    }

    #[test]
    fn phases_are_stable_and_ordered() {
        assert_eq!(E3Phase::ALL[0], E3Phase::Request);
        assert_eq!(E3Phase::ALL[7], E3Phase::Settlement);
        assert!(E3Phase::DkgSetup < E3Phase::DkgShares);
    }

    #[test]
    fn failure_leaves_later_phases_pending() {
        let state = E3State {
            e3_id: "1:1".into(),
            chain_id: 1,
            status: "failed".into(),
            current_phase: Some(E3Phase::Committee),
            failed_phase: Some(E3Phase::Committee),
            ..E3State::default()
        };
        let trace = trace(&state);
        assert_eq!(trace.phases[0].state, "complete");
        assert_eq!(trace.phases[1].state, "failed");
        assert_eq!(trace.phases[2].state, "pending");
    }

    #[test]
    fn eventstore_replay_rebuilds_the_same_projection() {
        let e3_id = e3_events::E3id::new("9", 31337);
        let account = "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65";
        let token = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
        let events = vec![
            replay_event(
                RewardsDistributed {
                    e3_id: e3_id.clone(),
                    nodes: vec![account.into()],
                    amounts: vec!["42".into()],
                }
                .into(),
                1,
                10,
            ),
            replay_event(
                RewardCredited {
                    e3_id: e3_id.clone(),
                    account: account.into(),
                    token: token.into(),
                    amount: "42".into(),
                }
                .into(),
                2,
                20,
            ),
            replay_event(
                RewardClaimed {
                    e3_id,
                    account: account.into(),
                    token: token.into(),
                    amount: "42".into(),
                }
                .into(),
                3,
                30,
            ),
        ];

        let mut live = TelemetryProjection::new(account);
        let mut rebuilt = TelemetryProjection::new(account);
        for event in &events {
            live.apply(event.clone());
        }
        for event in events {
            rebuilt.apply(event);
        }

        assert_eq!(
            serde_json::to_value(live.overview()).unwrap(),
            serde_json::to_value(rebuilt.overview()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(live.summaries()).unwrap(),
            serde_json::to_value(rebuilt.summaries()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(live.trace("31337:9")).unwrap(),
            serde_json::to_value(rebuilt.trace("31337:9")).unwrap()
        );
    }

    fn replay_event(data: InterfoldEventData, seq: u64, timestamp: u128) -> InterfoldEvent {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            None,
            timestamp,
            Some(100 + seq),
            EventSource::Evm,
        )
        .into_sequenced(seq)
    }
}
