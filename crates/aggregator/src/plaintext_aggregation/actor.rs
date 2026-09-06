// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use crate::workflow::threshold_plaintext_aggregation::{
    build_decryption_aggregation_jobs, format_decrypted_plaintext, ThresholdPlaintextAggregation,
};
use actix::prelude::*;
use alloy::primitives::Address;
use anyhow::{anyhow, bail, ensure, Result};
use e3_data::Persistable;
use e3_events::{
    prelude::*, trap, AggregationInputsReady, AggregationPhase, AggregationProofPending,
    AggregationProofSigned, AggregatorChanged, BusHandle, CommitteeMemberExcluded,
    CommitteeMemberExpelled, ComputeRequest, ComputeRequestError, ComputeRequestErrorKind,
    ComputeResponse, ComputeResponseKind, CorrelationId, DecryptedSharesAggregationProofRequest,
    DecryptionAggregationRequest, DecryptionshareCreated, Die, E3Failed, E3Stage, E3id, EType,
    EventContext, FailureReason, InterfoldEvent, InterfoldEventData, PlaintextAggregated, Proof,
    Sequenced, ShareVerificationComplete, ShareVerificationDispatched, SignedProofPayload,
    TypedEvent, VerificationKind, ZkRequest, ZkResponse,
};
use e3_fhe_params::BfvPreset;
use e3_sortition::{E3CommitteeContainsRequest, E3CommitteeContainsResponse, Sortition};
use e3_trbfv::{
    calculate_threshold_decryption::CalculateThresholdDecryptionRequest, TrBFVConfig, TrBFVRequest,
    TrBFVResponse,
};
use e3_utils::NotifySync;
use e3_utils::{utility_types::ArcBytes, MAILBOX_LIMIT};
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{debug, info, trace, warn};

// Threshold-plaintext aggregation state machine + pure transition logic now live in
// `crate::workflow::threshold_plaintext_aggregation`; re-exported here to preserve the public path
// `e3_aggregator::threshold_plaintext_aggregator::*` (and the crate-level glob re-export).
pub use crate::workflow::threshold_plaintext_aggregation::{
    Collecting, Complete, Computing, GeneratingC7Proof, ThresholdPlaintextAggregatorRecoveryState,
    ThresholdPlaintextAggregatorState, VerifyingC6, THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
};

/// Process-local effect state. Persisted protocol progression remains in
/// `ThresholdPlaintextAggregatorState`; these values are reconstructed or
/// redriven from replayed facts.
#[derive(Default)]
struct PendingDecryptionWork {
    /// Honest parties' C6 inner proofs (sorted by party id) for [`ZkRequest::DecryptionAggregation`].
    honest_c6_proofs_for_agg: Option<Vec<(u64, Vec<Proof>)>>,
    /// In-flight threshold decryption request.
    threshold_decryption_correlation: Option<CorrelationId>,
    /// In-flight decryption aggregation request.
    decryption_aggregation_correlation: Option<CorrelationId>,
    /// C7 proofs stored while waiting for decryption aggregation.
    c7_proofs_pending: Option<Vec<Proof>>,
    /// DecryptionAggregator outputs (set when ZK completes).
    decryption_aggregator_proofs: Option<Vec<Proof>>,
    /// Last event context, reused for ZK and final publish.
    last_ec: Option<EventContext<Sequenced>>,
}

pub struct ThresholdPlaintextAggregator {
    bus: BusHandle,
    sortition: Addr<Sortition>,
    e3_id: E3id,
    params_preset: BfvPreset,
    /// Chain-bound program scheme (program address => protocol). CKKS
    /// shares arrive proof-less and are aggregated directly (no C6/C7).
    scheme: e3_events::E3Scheme,
    committee_size: CiphernodesCommitteeSize,
    proof_aggregation_enabled: bool,
    state: Persistable<ThresholdPlaintextAggregatorState>,
    recovery: Persistable<ThresholdPlaintextAggregatorRecoveryState>,
    /// Full registered committee (`topNodes`, length `N`) for decryption-aggregator
    /// `committee_hash_*` inputs. Same value as `PublicKeyAggregated.committee_addresses`.
    committee_addresses: Vec<Address>,
    /// Canonical honest subset from DKG (length `H ≤ N`, from
    /// `PublicKeyAggregated.honest_committee_addresses`). Drives share-collection
    /// gating (expects one share from each H party) and sender checks after sortition.
    honest_committee_addresses: Vec<Address>,
    is_aggregator: bool,
    effects_enabled: bool,
    pending: PendingDecryptionWork,
    /// CKKS: the E3 decryption domain the C7-CKKS proof is bound to
    /// (interfold address, committee hash, published-key commitment). The
    /// C7-CKKS prover FAILS CLOSED when this is `None`.
    pub(crate) ckks_decryption_domain: Option<e3_committee_hash::DecryptionDomainContext>,
}

pub struct ThresholdPlaintextAggregatorParams {
    pub bus: BusHandle,
    pub sortition: Addr<Sortition>,
    pub e3_id: E3id,
    pub params_preset: BfvPreset,
    pub scheme: e3_events::E3Scheme,
    pub committee_size: CiphernodesCommitteeSize,
    pub proof_aggregation_enabled: bool,
    pub initial_is_aggregator: bool,
    pub effects_enabled: bool,
    /// Full committee from `PublicKeyAggregated.committee_addresses` (length `N`).
    /// Used for `committee_hash_*` payload binding to on-chain `topNodes`.
    pub committee_addresses: Vec<Address>,
    /// Honest committee from `PublicKeyAggregated.honest_committee_addresses`
    /// (length `H`). Roster for decryption-share collection and sender gating.
    pub honest_committee_addresses: Vec<Address>,
    pub recovery: Persistable<ThresholdPlaintextAggregatorRecoveryState>,
    /// CKKS C7 decryption domain; `None` for BFV or when not yet resolvable.
    pub ckks_decryption_domain: Option<e3_committee_hash::DecryptionDomainContext>,
}

pub(crate) fn new_threshold_plaintext_recovery(
    ec: EventContext<Sequenced>,
) -> ThresholdPlaintextAggregatorRecoveryState {
    ThresholdPlaintextAggregatorRecoveryState {
        last_ec: Some(ec),
        ..Default::default()
    }
}

fn node_owns_committee_party_slot(
    committee: &[Address],
    honest_committee: &[Address],
    node: &str,
    party_id: u64,
) -> bool {
    let Some(expected) = usize::try_from(party_id)
        .ok()
        .and_then(|index| committee.get(index))
    else {
        return false;
    };
    Address::from_str(node)
        .ok()
        .is_some_and(|address| &address == expected && honest_committee.contains(&address))
}

impl ThresholdPlaintextAggregator {
    pub fn new(
        params: ThresholdPlaintextAggregatorParams,
        state: Persistable<ThresholdPlaintextAggregatorState>,
    ) -> Self {
        let recovered = params.recovery.get().unwrap_or_default();
        ThresholdPlaintextAggregator {
            bus: params.bus,
            sortition: params.sortition,
            e3_id: params.e3_id,
            params_preset: params.params_preset,
            scheme: params.scheme,
            committee_size: params.committee_size,
            proof_aggregation_enabled: params.proof_aggregation_enabled,
            state,
            recovery: params.recovery,
            committee_addresses: params.committee_addresses,
            honest_committee_addresses: params.honest_committee_addresses,
            is_aggregator: params.initial_is_aggregator,
            effects_enabled: params.effects_enabled,
            pending: PendingDecryptionWork {
                honest_c6_proofs_for_agg: (!recovered.honest_c6_proofs.is_empty())
                    .then_some(recovered.honest_c6_proofs),
                c7_proofs_pending: recovered.c7_proofs,
                decryption_aggregator_proofs: recovered.decryption_aggregator_proofs,
                last_ec: recovered.last_ec.clone(),
                ..Default::default()
            },
            ckks_decryption_domain: params.ckks_decryption_domain,
        }
    }

    /// Length of the canonical honest subset (`H`), not on-chain committee size `N`.
    /// Share collection waits for one decryption share from each address in
    /// `honest_committee_addresses` (sortition membership is checked separately).
    fn aggregated_committee_n(&self) -> u64 {
        self.honest_committee_addresses.len() as u64
    }

    /// True when `node` owns `party_id` in the full canonical committee and is part of the honest
    /// subset selected during DKG. Membership without the slot check permits a real member to
    /// relabel a share under another party ID.
    fn node_owns_aggregated_pk_party_slot(&self, node: &str, party_id: u64) -> bool {
        node_owns_committee_party_slot(
            &self.committee_addresses,
            &self.honest_committee_addresses,
            node,
            party_id,
        )
    }

    fn aggregation_inputs_ready(&self) -> bool {
        matches!(
            self.state.get(),
            Some(
                ThresholdPlaintextAggregatorState::VerifyingC6(_)
                    | ThresholdPlaintextAggregatorState::Computing(_)
                    | ThresholdPlaintextAggregatorState::GeneratingC7Proof(_)
                    | ThresholdPlaintextAggregatorState::Complete(_)
            )
        )
    }

    fn can_run_aggregation_effects(&self) -> bool {
        self.effects_enabled && self.is_aggregator
    }

    fn publish_inputs_ready(&self, ec: EventContext<Sequenced>) -> Result<()> {
        if !self.effects_enabled || !self.aggregation_inputs_ready() {
            return Ok(());
        }
        self.bus.publish(
            AggregationInputsReady {
                e3_id: self.e3_id.clone(),
                phase: AggregationPhase::Plaintext,
            },
            ec,
        )?;
        Ok(())
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
