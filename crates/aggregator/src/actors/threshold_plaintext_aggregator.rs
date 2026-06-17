// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::time::Duration;

use crate::domain::threshold_plaintext_aggregation::{
    build_decryption_aggregation_jobs, format_decrypted_plaintext, ThresholdPlaintextAggregation,
};
use actix::prelude::*;
use actix::SpawnHandle;
use alloy::primitives::Address;
use anyhow::{anyhow, bail, ensure, Result};
use e3_data::Persistable;
use e3_events::{
    prelude::*, trap, AggregationProofPending, AggregationProofSigned, BusHandle,
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

/// Env var overriding the decryption-share collection timeout (seconds).
const DECRYPTION_COLLECTION_TIMEOUT_ENV: &str = "E3_DECRYPTION_COLLECTION_TIMEOUT_SECS";
/// Default wall-clock budget for collecting the honest committee's decryption shares before the
/// round is failed loudly. Without this bound a single absent honest member stalls the decryption
/// round forever (the collector waits for all `H` honest shares with no fallback).
const DEFAULT_DECRYPTION_COLLECTION_TIMEOUT_SECS: u64 = 1800;

/// Resolve the decryption-share collection timeout, honouring the env override.
fn decryption_collection_timeout() -> Duration {
    match std::env::var(DECRYPTION_COLLECTION_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(secs) => {
            info!(
                "Decryption-share collection timeout overridden via {}={}s",
                DECRYPTION_COLLECTION_TIMEOUT_ENV, secs
            );
            Duration::from_secs(secs)
        }
        None => Duration::from_secs(DEFAULT_DECRYPTION_COLLECTION_TIMEOUT_SECS),
    }
}

/// Internal self-message fired when the decryption-share collection window elapses.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
struct DecryptionCollectionTimeout;

// Threshold-plaintext aggregation state machine + pure transition logic now live in
// `crate::domain::threshold_plaintext_aggregation`; re-exported here to preserve the public path
// `e3_aggregator::threshold_plaintext_aggregator::*` (and the crate-level glob re-export).
pub use crate::domain::threshold_plaintext_aggregation::{
    Collecting, Complete, Computing, GeneratingC7Proof, ThresholdPlaintextAggregatorState,
    VerifyingC6,
};

pub struct ThresholdPlaintextAggregator {
    bus: BusHandle,
    sortition: Addr<Sortition>,
    e3_id: E3id,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    proof_aggregation_enabled: bool,
    state: Persistable<ThresholdPlaintextAggregatorState>,
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
    /// Full registered committee (`topNodes`, length `N`) for decryption-aggregator
    /// `committee_hash_*` inputs. Same value as `PublicKeyAggregated.committee_addresses`.
    committee_addresses: Vec<Address>,
    /// Canonical honest subset from DKG (length `H ≤ N`, from
    /// `PublicKeyAggregated.honest_committee_addresses`). Drives share-collection
    /// gating (expects one share from each H party) and sender checks after sortition.
    honest_committee_addresses: Vec<Address>,
    /// Timer handle for the decryption-share collection timeout (cancelled when the actor stops).
    timeout_handle: Option<SpawnHandle>,
    /// Most recent inbound event context, used as the causal parent for the `E3Failed` event
    /// emitted if the collection window elapses while still collecting shares.
    timeout_ec: Option<EventContext<Sequenced>>,
}

pub struct ThresholdPlaintextAggregatorParams {
    pub bus: BusHandle,
    pub sortition: Addr<Sortition>,
    pub e3_id: E3id,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
    pub proof_aggregation_enabled: bool,
    /// Full committee from `PublicKeyAggregated.committee_addresses` (length `N`).
    /// Used for `committee_hash_*` payload binding to on-chain `topNodes`.
    pub committee_addresses: Vec<Address>,
    /// Honest committee from `PublicKeyAggregated.honest_committee_addresses`
    /// (length `H`). Roster for decryption-share collection and sender gating.
    pub honest_committee_addresses: Vec<Address>,
}

impl ThresholdPlaintextAggregator {
    pub fn new(
        params: ThresholdPlaintextAggregatorParams,
        state: Persistable<ThresholdPlaintextAggregatorState>,
    ) -> Self {
        ThresholdPlaintextAggregator {
            bus: params.bus,
            sortition: params.sortition,
            e3_id: params.e3_id,
            params_preset: params.params_preset,
            committee_size: params.committee_size,
            proof_aggregation_enabled: params.proof_aggregation_enabled,
            state,
            honest_c6_proofs_for_agg: None,
            threshold_decryption_correlation: None,
            decryption_aggregation_correlation: None,
            c7_proofs_pending: None,
            decryption_aggregator_proofs: None,
            last_ec: None,
            committee_addresses: params.committee_addresses,
            honest_committee_addresses: params.honest_committee_addresses,
            timeout_handle: None,
            timeout_ec: None,
        }
    }

    /// Length of the canonical honest subset (`H`), not on-chain committee size `N`.
    /// Share collection waits for one decryption share from each address in
    /// `honest_committee_addresses` (sortition membership is checked separately).
    fn aggregated_committee_n(&self) -> u64 {
        self.honest_committee_addresses.len() as u64
    }

    /// True when `node` is in `PublicKeyAggregated.honest_committee_addresses`.
    fn node_in_aggregated_pk_committee(&self, node: &str) -> bool {
        Address::from_str(node)
            .ok()
            .is_some_and(|addr| self.honest_committee_addresses.contains(&addr))
    }

    pub fn add_share(
        &mut self,
        party_id: u64,
        share: Vec<ArcBytes>,
        signed_decryption_proofs: Vec<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let required_shares = self.aggregated_committee_n();
        ensure!(
            required_shares > 0,
            "honest committee addresses must not be empty before collecting decryption shares"
        );
        self.state.try_mutate(ec, |state| {
            ThresholdPlaintextAggregation::add_share(
                state,
                party_id,
                share.clone(),
                signed_decryption_proofs.clone(),
                required_shares,
            )
        })
    }

    pub fn handle_member_expelled(
        &mut self,
        party_id: u64,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let required_shares = self.aggregated_committee_n();
        self.state.try_mutate(ec, |state| {
            ThresholdPlaintextAggregation::handle_member_expelled(state, party_id, required_shares)
        })
    }

    /// Dispatch C6 proof verification through ShareVerificationActor.
    pub fn dispatch_c6_verification(
        &mut self,
        c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let party_proofs = ThresholdPlaintextAggregation::plan_c6_dispatch(c6_proofs);

        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: self.e3_id.clone(),
                kind: VerificationKind::ThresholdDecryptionProofs,
                share_proofs: party_proofs,
                decryption_proofs: vec![],
                pre_dishonest: BTreeSet::new(),
                params_preset: self.params_preset,
                committee_size: self.committee_size,
            },
            ec,
        )?;
        Ok(())
    }

    /// Handle ShareVerificationComplete for C6: filter dishonest parties, transition to Computing.
    pub fn handle_c6_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.kind != VerificationKind::ThresholdDecryptionProofs {
            return Ok(());
        }

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        let state: VerifyingC6 = self
            .state
            .get()
            .ok_or(anyhow!("Could not get state"))?
            .try_into()?;

        let mut dishonest_parties = msg.dishonest_parties.clone();
        if !dishonest_parties.is_empty() {
            warn!(
                "C6 verification: {} dishonest parties filtered: {:?}",
                dishonest_parties.len(),
                dishonest_parties
            );
        }

        // Filter shares to only honest parties
        let mut honest_shares: Vec<(u64, Vec<ArcBytes>)> = state
            .shares
            .iter()
            .filter(|(id, _)| !dishonest_parties.contains(id))
            .map(|(id, s)| (*id, s.clone()))
            .collect();

        if honest_shares.len() <= state.threshold_m as usize {
            warn!(
                "Not enough honest shares after C6 verification: {} honest shares, {} required",
                honest_shares.len(),
                state.threshold_m + 1
            );
            return self.fail_decryption_round(ec);
        }

        // Verify each honest party's raw decryption share matches the
        // d_commitment attested by their verified C6 proof. Catches the attack
        // where a node sends a valid C6 proof for share d_A but broadcasts
        // different bytes d_B.
        let share_mismatch_parties =
            ThresholdPlaintextAggregation::verify_shares_match_c6_commitments(
                self.params_preset,
                &honest_shares,
                &state.c6_proofs,
            );
        if !share_mismatch_parties.is_empty() {
            warn!(
                "C6 share-commitment mismatch for {} parties: {:?} — excluding from aggregation",
                share_mismatch_parties.len(),
                share_mismatch_parties,
            );

            dishonest_parties.extend(&share_mismatch_parties);
            honest_shares.retain(|(id, _)| !share_mismatch_parties.contains(id));
            if honest_shares.len() <= state.threshold_m as usize {
                warn!(
                    "Not enough honest shares after d_commitment check: {} honest, {} required",
                    honest_shares.len(),
                    state.threshold_m + 1
                );
                return self.fail_decryption_round(ec);
            }
        }

        info!(
            "C6 verification passed: {} honest parties, transitioning to Computing",
            honest_shares.len(),
        );

        // Collect honest C6 inner proofs (from signed payloads) for DecryptionAggregation.
        // BTreeMap iteration yields ascending party_id, matching the slot layout
        // used by honest_shares above and enforced by decryption_aggregator.nr.
        let honest_c6: Vec<(u64, Vec<Proof>)> = state
            .c6_proofs
            .iter()
            .filter(|(id, _)| !dishonest_parties.contains(id))
            .map(|(id, signed)| {
                (
                    *id,
                    signed.iter().map(|s| s.payload.proof.clone()).collect(),
                )
            })
            .collect();

        // Publish ComputeRequest before transitioning state so a publish
        // failure leaves us in VerifyingC6 (retryable) rather than
        // Computing (no retry path).
        // TrBFV scheme size stays N (`threshold_n`); only the share roster is restricted to the
        // H canonical honest parties in `PublicKeyAggregated` (see `node_in_aggregated_pk_committee`).
        let trbfv_config =
            TrBFVConfig::new(state.params.clone(), state.threshold_n, state.threshold_m);

        let correlation_id = CorrelationId::new();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateThresholdDecryption(CalculateThresholdDecryptionRequest {
                ciphertexts: state.ciphertext_output.clone(),
                trbfv_config,
                d_share_polys: honest_shares.clone(),
            }),
            correlation_id,
            self.e3_id.clone(),
        );
        self.bus.publish(event, ec.clone())?;

        self.honest_c6_proofs_for_agg = Some(honest_c6);
        self.threshold_decryption_correlation = Some(correlation_id);

        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregatorState::Computing(Computing {
                shares: honest_shares,
                ciphertext_output: state.ciphertext_output,
                threshold_m: state.threshold_m,
                threshold_n: state.threshold_n,
                params: state.params,
            }))
        })?;

        self.last_ec = Some(ec.clone());

        Ok(())
    }

    /// Publish AggregationProofPending for C7 proof generation through ProofRequestActor.
    pub fn dispatch_c7_proof_request(
        &mut self,
        shares: Vec<(u64, Vec<ArcBytes>)>,
        plaintext: Vec<ArcBytes>,
        threshold_m: u64,
        threshold_n: u64,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.bus.publish(
            AggregationProofPending {
                e3_id: self.e3_id.clone(),
                proof_request: DecryptedSharesAggregationProofRequest {
                    d_share_polys: shares.clone(),
                    plaintext: plaintext.clone(),
                    params_preset: self.params_preset,
                    threshold_m,
                    threshold_n,
                    committee_size: self.committee_size,
                },
                plaintext,
                shares,
            },
            ec,
        )?;
        Ok(())
    }

    /// Handle AggregationProofSigned: store C7 proofs and wait for C6 fold before publishing.
    pub fn handle_aggregation_proof_signed(
        &mut self,
        msg: TypedEvent<AggregationProofSigned>,
        _ctx: &mut Context<Self>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        let state: GeneratingC7Proof = self
            .state
            .get()
            .ok_or(anyhow!("Could not get state"))?
            .try_into()?;

        // Extract raw proofs from signed payloads for PlaintextAggregated
        let proofs: Vec<_> = msg
            .signed_proofs
            .iter()
            .map(|sp| sp.payload.proof.clone())
            .collect();

        if proofs.len() != state.plaintext.len() {
            warn!(
                "C7 proof count mismatch: got {} proofs for {} ciphertext indices",
                proofs.len(),
                state.plaintext.len()
            );
            return self.fail_decryption_round(ec);
        }

        info!("C7 proof signed — awaiting DecryptionAggregation...");
        self.c7_proofs_pending = Some(proofs);
        self.last_ec = Some(ec.clone());
        self.maybe_start_decryption_aggregation(&ec)?;
        self.try_publish_complete()
    }

    fn maybe_start_decryption_aggregation(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
        if self.c7_proofs_pending.is_none() {
            return Ok(());
        }
        if self.decryption_aggregator_proofs.is_some()
            || self.decryption_aggregation_correlation.is_some()
        {
            return Ok(());
        }
        if !self.proof_aggregation_enabled {
            if self.decryption_aggregator_proofs.is_none() {
                self.decryption_aggregator_proofs = Some(Vec::new());
            }
            return Ok(());
        }
        self.dispatch_decryption_aggregation(ec)
    }

    fn dispatch_decryption_aggregation(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
        if self.committee_addresses.is_empty() {
            warn!(
                e3_id = %self.e3_id,
                "DecryptionAggregation: committee addresses missing at aggregator construction"
            );
            return self.fail_decryption_round(ec.clone());
        }

        let Some(c7_proofs) = self.c7_proofs_pending.as_ref() else {
            return Ok(());
        };
        if self.decryption_aggregator_proofs.is_some() {
            return Ok(());
        }
        if self.decryption_aggregation_correlation.is_some() {
            return Ok(());
        }
        if !self.proof_aggregation_enabled {
            self.decryption_aggregator_proofs = Some(Vec::new());
            return Ok(());
        }
        let Some(honest_c6) = self.honest_c6_proofs_for_agg.as_ref() else {
            warn!(
                e3_id = %self.e3_id,
                "DecryptionAggregation deferred: honest C6 proofs not retained on aggregator"
            );
            return Ok(());
        };
        // With proof aggregation enabled we must have a complete C6 set; otherwise we'd publish
        // `decryption_aggregator_proofs = Vec::new()`, which downstream consumers interpret as
        // "aggregation disabled". Fail loudly instead so the missing shares are surfaced.
        if honest_c6.is_empty() || honest_c6.iter().any(|(_, w)| w.is_empty()) {
            warn!(
                "DecryptionAggregation: honest C6 inner proofs missing while proof aggregation is enabled"
            );
            return self.fail_decryption_round(ec.clone());
        }
        let state: GeneratingC7Proof = self
            .state
            .get()
            .ok_or(anyhow!("Could not get state"))?
            .try_into()?;
        // C6Fold witness width is `T + 1` (same `T` as `threshold_m`). C7 is only proven for the
        // first `T + 1` parties after sorting by party id (`handle_decrypted_shares_aggregation_proof`
        // truncates); fold slot indices must stay in `0..T+1` and use that same party subset.
        let c6_total_slots = state.threshold_m as usize + 1;
        if honest_c6.len() < c6_total_slots {
            warn!(
                "DecryptionAggregation needs at least {} honest C6 parties, have {}",
                c6_total_slots,
                honest_c6.len()
            );
            return self.fail_decryption_round(ec.clone());
        }
        let num_ct = c7_proofs.len();
        let Some(jobs) = build_decryption_aggregation_jobs(c7_proofs, honest_c6, c6_total_slots)
        else {
            return self.fail_decryption_round(ec.clone());
        };
        let corr = CorrelationId::new();
        info!(
            e3_id = %self.e3_id,
            num_jobs = num_ct,
            c6_slots = c6_total_slots,
            "DecryptionAggregation: publishing Zk compute request"
        );
        self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::DecryptionAggregation(DecryptionAggregationRequest {
                    c6_total_slots,
                    jobs,
                    committee_addresses: self.committee_addresses.clone(),
                    params_preset: self.params_preset,
                    committee_size: self.committee_size,
                }),
                corr,
                self.e3_id.clone(),
            ),
            ec.clone(),
        )?;
        self.decryption_aggregation_correlation = Some(corr);
        Ok(())
    }

    pub fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        ensure!(
            msg.e3_id == self.e3_id,
            "PlaintextAggregator should never receive incorrect e3_id msgs"
        );

        let correlation_id = msg.correlation_id;
        match msg.response {
            // TrBFV threshold decryption response -> transition to GeneratingC7Proof
            ComputeResponseKind::TrBFV(TrBFVResponse::CalculateThresholdDecryption(response)) => {
                if self.threshold_decryption_correlation.as_ref() != Some(&correlation_id) {
                    return Ok(());
                }
                self.threshold_decryption_correlation = None;
                info!("Received TrBFV threshold decryption response");
                let plaintext = response.plaintext;

                let state: Computing = self
                    .state
                    .get()
                    .ok_or(anyhow!("Could not get state"))?
                    .try_into()?;

                let shares = state.shares.clone();
                let threshold_m = state.threshold_m;
                let threshold_n = state.threshold_n;

                // Publish pending event before transitioning state so a publish
                // failure leaves us in Computing (retryable) rather than
                // GeneratingC7Proof (no retry path).
                self.dispatch_c7_proof_request(
                    shares.clone(),
                    plaintext.clone(),
                    threshold_m,
                    threshold_n,
                    ec.clone(),
                )?;

                // Transition to GeneratingC7Proof
                self.state.try_mutate(&ec, |_| {
                    Ok(ThresholdPlaintextAggregatorState::GeneratingC7Proof(
                        GeneratingC7Proof {
                            threshold_m,
                            threshold_n,
                            shares,
                            plaintext,
                        },
                    ))
                })?;
            }

            ComputeResponseKind::Zk(ZkResponse::DecryptionAggregation(resp)) => {
                if self.decryption_aggregation_correlation.as_ref() == Some(&correlation_id) {
                    self.decryption_aggregation_correlation = None;
                    // Worker must return one DecryptionAggregator proof per pending C7 ciphertext.
                    if let Some(c7_proofs) = self.c7_proofs_pending.as_ref() {
                        if resp.proofs.len() != c7_proofs.len() {
                            warn!(
                                "DecryptionAggregation response proof count {} != expected {}",
                                resp.proofs.len(),
                                c7_proofs.len()
                            );
                            return self.fail_decryption_round(ec);
                        }
                    }
                    self.decryption_aggregator_proofs = Some(resp.proofs);
                    self.try_publish_complete()?;
                }
            }

            _ => {
                // Not a response we handle — ignore
            }
        }
        let _ = ctx;
        Ok(())
    }

    fn fail_decryption_round(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CiphertextReady,
                reason: FailureReason::DecryptionInvalidShares,
            },
            ec,
        )?;

        self.honest_c6_proofs_for_agg = None;
        self.threshold_decryption_correlation = None;
        self.decryption_aggregation_correlation = None;
        self.c7_proofs_pending = None;
        self.decryption_aggregator_proofs = None;

        Ok(())
    }

    fn handle_compute_request_error(&mut self, msg: TypedEvent<ComputeRequestError>) -> Result<()> {
        let (msg, ec) = msg.into_components();
        if msg.request().e3_id != self.e3_id {
            return Ok(());
        }

        let threshold_decryption_failed =
            self.threshold_decryption_correlation.as_ref() == Some(msg.correlation_id());
        let decryption_aggregation_failed =
            self.decryption_aggregation_correlation.as_ref() == Some(msg.correlation_id());

        if !threshold_decryption_failed && !decryption_aggregation_failed {
            return Ok(());
        }

        // Surface the structured threshold-BFV failure when present so the implicated party and
        // failure mode are visible in logs. Slashing/accusation stays driven by the C6 proof
        // verification path; this is diagnostics only.
        if let ComputeRequestErrorKind::TrBFV(trbfv_err) = msg.get_err() {
            let failure = trbfv_err.failure();
            match &failure.threshold {
                Some(threshold) => warn!(
                    e3_id = %self.e3_id,
                    kind = ?threshold.kind,
                    party_id = ?threshold.party_id,
                    "threshold decryption failed with structured error: {}",
                    threshold.message,
                ),
                None => warn!(
                    e3_id = %self.e3_id,
                    "threshold decryption failed: {}",
                    failure.message,
                ),
            }
        }

        self.fail_decryption_round(ec)
    }

    /// Publish `PlaintextAggregated` when both C7 proofs and decryption aggregation are complete.
    fn try_publish_complete(&mut self) -> Result<()> {
        let Some(c7_proofs) = self.c7_proofs_pending.clone() else {
            return Ok(());
        };
        let dec_ready = self.decryption_aggregator_proofs.is_some()
            && self.decryption_aggregation_correlation.is_none();
        if !dec_ready {
            return Ok(());
        }

        let state: GeneratingC7Proof = self
            .state
            .get()
            .ok_or_else(|| anyhow!("Expected GeneratingC7Proof state"))?
            .try_into()?;

        let ec = self
            .last_ec
            .clone()
            .ok_or_else(|| anyhow!("No EventContext for publish"))?;

        info!("C7 + decryption_aggregator proofs ready — publishing PlaintextAggregated");

        let decrypted_output = format_decrypted_plaintext(&state.plaintext);

        let decryption_aggregator_proofs = self
            .decryption_aggregator_proofs
            .clone()
            .unwrap_or_default();
        // Keep c7_proofs for invariant check; they are subsumed by the decryption_aggregator proof.
        let _ = c7_proofs;
        let event = PlaintextAggregated {
            decrypted_output,
            e3_id: self.e3_id.clone(),
            decryption_aggregator_proofs,
        };

        info!("Dispatching plaintext event {:?}", event);
        self.bus.publish(event, ec.clone())?;

        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregatorState::Complete(Complete {
                decrypted: state.plaintext,
                shares: state.shares,
            }))
        })?;

        Ok(())
    }
}

impl Actor for ThresholdPlaintextAggregator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        // Bound the decryption-share collection phase so a missing honest member cannot stall the
        // round indefinitely. On expiry the round is failed loudly (see the timeout handler).
        let timeout = decryption_collection_timeout();
        info!(
            e3_id = %self.e3_id,
            ?timeout,
            "ThresholdPlaintextAggregator started; scheduling decryption-share collection timeout"
        );
        self.timeout_handle = Some(ctx.notify_later(DecryptionCollectionTimeout, timeout));
    }
}

impl Handler<DecryptionCollectionTimeout> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, _: DecryptionCollectionTimeout, ctx: &mut Self::Context) -> Self::Result {
        self.timeout_handle = None;

        // Only fail while still collecting shares; once we have transitioned past `Collecting`
        // (VerifyingC6/Computing/…) the round is progressing and the timer is a no-op.
        let Some(ThresholdPlaintextAggregatorState::Collecting(collecting)) = self.state.get()
        else {
            debug!(
                e3_id = %self.e3_id,
                "Decryption-share collection timeout fired but round already progressed past collection; ignoring"
            );
            return;
        };

        let collected = collecting.shares.len();
        let required = self.aggregated_committee_n();
        warn!(
            e3_id = %self.e3_id,
            collected,
            required,
            "Decryption-share collection timed out with {collected}/{required} honest shares; failing E3 round (DecryptionTimeout)"
        );

        let Some(ec) = self.timeout_ec.clone() else {
            warn!(
                e3_id = %self.e3_id,
                "No event context captured for decryption timeout; cannot emit E3Failed. Stopping aggregator."
            );
            ctx.stop();
            return;
        };

        if let Err(e) = self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CiphertextReady,
                reason: FailureReason::DecryptionTimeout,
            },
            ec,
        ) {
            warn!(
                e3_id = %self.e3_id,
                error = %e,
                "Failed to publish E3Failed on decryption-share collection timeout"
            );
        }

        ctx.stop();
    }
}

impl Handler<InterfoldEvent> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::DecryptionshareCreated(data) => {
                ctx.notify(TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(_) => self.notify_sync(ctx, Die),
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AggregationProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<DecryptionshareCreated>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionshareCreated>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let Some(ThresholdPlaintextAggregatorState::Collecting(Collecting { .. })) =
                    self.state.get()
                else {
                    debug!(state=?self.state, "Aggregator has been closed for collecting so ignoring this event.");
                    return Ok(());
                };
                let node = msg.node.clone();
                let e3_id = msg.e3_id.clone();
                let request = E3CommitteeContainsRequest::new(e3_id, node, msg, ctx.address());
                self.sortition.try_send(request)?;
                Ok(())
            },
        )
    }
}

impl Handler<E3CommitteeContainsResponse<TypedEvent<DecryptionshareCreated>>>
    for ThresholdPlaintextAggregator
{
    type Result = ();
    fn handle(
        &mut self,
        msg: E3CommitteeContainsResponse<TypedEvent<DecryptionshareCreated>>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let e3_id = &msg.e3_id;
                if *e3_id != self.e3_id {
                    bail!("Wrong e3_id sent to aggregator. This should not happen.")
                };

                if !msg.is_found_in_committee() {
                    trace!("Node {} not found in finalized committee", &msg.node);
                    return Ok(());
                };
                if !self.node_in_aggregated_pk_committee(&msg.node) {
                    trace!(
                        "Node {} not in PublicKeyAggregated honest subset — ignoring decryption share",
                        &msg.node
                    );
                    return Ok(());
                }

                // Trust the party_id from the event - it's based on CommitteeFinalized order
                // which is the authoritative source of truth for party IDs
                let (
                    DecryptionshareCreated {
                        party_id,
                        decryption_share,
                        signed_decryption_proofs,
                        ..
                    },
                    ec,
                ) = msg.into_inner().into_components();

                // Capture the latest context so a subsequent collection timeout can emit
                // `E3Failed` with a sensible causal parent.
                self.timeout_ec = Some(ec.clone());
                self.add_share(party_id, decryption_share, signed_decryption_proofs, &ec)?;

                // If we transitioned to VerifyingC6, dispatch C6 verification
                // using the proofs persisted in state
                if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                    self.state.get()
                {
                    self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
                }

                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_response(msg, ctx),
        )
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for ThresholdPlaintextAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_request_error(msg),
        )
    }
}

impl Handler<TypedEvent<CommitteeMemberExpelled>> for ThresholdPlaintextAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExpelled>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let (msg, ec) = msg.into_components();
                let Some(party_id) = msg.party_id else {
                    return Ok(());
                };

                self.handle_member_expelled(party_id, &ec)?;

                if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                    self.state.get()
                {
                    self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
                }

                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<ShareVerificationComplete>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_c6_verification_complete(msg),
        )
    }
}

impl Handler<TypedEvent<AggregationProofSigned>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AggregationProofSigned>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_aggregation_proof_signed(msg, ctx),
        )
    }
}

impl Handler<Die> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_data::{AutoPersist, DataStore, InMemStore, PersistableData, Repository};
    use e3_events::{
        CircuitName, Committee, ComputeRequestErrorKind, HistoryCollector, Seed, TakeEvents,
        Unsequenced, ZkError,
    };
    use e3_fhe_params::{encode_bfv_params, BfvParamSet, DEFAULT_BFV_PRESET};
    use e3_sortition::{
        CiphernodeSelector, CiphernodeSelectorState, NodeStateStore, SortitionBackend,
        SortitionParams,
    };
    use e3_test_helpers::get_common_setup;
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
        EventContext::<Unsequenced>::from(data.into()).sequence(0)
    }

    fn test_persistable<T: PersistableData>(value: T) -> Persistable<T> {
        let repo = Repository::<T>::new(DataStore::from_in_mem(&InMemStore::new(false).start()));
        repo.to_connector().send(Some(value))
    }

    fn test_params() -> ArcBytes {
        ArcBytes::from_bytes(&encode_bfv_params(
            &BfvParamSet::from(DEFAULT_BFV_PRESET).build_arc(),
        ))
    }

    fn dummy_proof(circuit: CircuitName) -> Proof {
        Proof::new(
            circuit,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&[2]),
        )
    }

    fn computing_state() -> ThresholdPlaintextAggregatorState {
        ThresholdPlaintextAggregatorState::Computing(Computing {
            threshold_m: 1,
            threshold_n: 2,
            shares: vec![(0, vec![ArcBytes::from_bytes(&[7])])],
            ciphertext_output: vec![ArcBytes::from_bytes(&[8])],
            params: test_params(),
        })
    }

    fn verifying_c6_state() -> ThresholdPlaintextAggregatorState {
        ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
            threshold_m: 1,
            threshold_n: 2,
            shares: BTreeMap::from([
                (0, vec![ArcBytes::from_bytes(&[7])]),
                (1, vec![ArcBytes::from_bytes(&[8])]),
            ]),
            c6_proofs: BTreeMap::new(),
            ciphertext_output: vec![ArcBytes::from_bytes(&[9])],
            params: test_params(),
        })
    }

    fn generating_c7_state() -> ThresholdPlaintextAggregatorState {
        ThresholdPlaintextAggregatorState::GeneratingC7Proof(GeneratingC7Proof {
            threshold_m: 1,
            threshold_n: 2,
            shares: vec![(0, vec![ArcBytes::from_bytes(&[7])])],
            plaintext: vec![ArcBytes::from_bytes(&[9])],
        })
    }

    fn collecting_state() -> ThresholdPlaintextAggregatorState {
        ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m: 1,
            threshold_n: 2,
            shares: BTreeMap::new(),
            c6_proofs: BTreeMap::new(),
            seed: Seed([0u8; 32]),
            ciphertext_output: vec![ArcBytes::from_bytes(&[9])],
            params: test_params(),
        })
    }

    fn start_sortition(bus: &BusHandle) -> Addr<Sortition> {
        let selector = CiphernodeSelector::new(
            bus,
            test_persistable(CiphernodeSelectorState::default()),
            "node-1",
        )
        .start();

        Sortition::new(SortitionParams {
            bus: bus.clone(),
            backends: test_persistable(HashMap::<u64, SortitionBackend>::new()),
            node_state: test_persistable(HashMap::<u64, NodeStateStore>::new()),
            finalized_committees: test_persistable(HashMap::<E3id, Committee>::new()),
            ciphernode_selector: selector,
            address: "node-1".to_string(),
        })
        .start()
    }

    fn test_committee_address() -> Address {
        "0x0000000000000000000000000000000000000001"
            .parse()
            .expect("test address")
    }

    async fn build_plaintext_aggregator(
        initial_state: ThresholdPlaintextAggregatorState,
        proof_aggregation_enabled: bool,
    ) -> Result<(
        ThresholdPlaintextAggregator,
        Addr<HistoryCollector<InterfoldEvent>>,
        E3id,
    )> {
        let (bus, _rng, _seed, _params, _crp, _errors, history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
        let e3_id = E3id::new("42", 1);
        let aggregator = ThresholdPlaintextAggregator::new(
            ThresholdPlaintextAggregatorParams {
                bus: bus.clone(),
                sortition: start_sortition(&bus),
                e3_id: e3_id.clone(),
                params_preset: BfvPreset::InsecureThreshold512,
                committee_size: CiphernodesCommitteeSize::Minimum,
                proof_aggregation_enabled,
                committee_addresses: vec![test_committee_address()],
                honest_committee_addresses: vec![test_committee_address()],
            },
            test_persistable(initial_state),
        );

        Ok((aggregator, history, e3_id))
    }

    async fn next_event(
        history: &Addr<HistoryCollector<InterfoldEvent>>,
    ) -> Result<InterfoldEvent> {
        let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    #[actix::test]
    async fn decryption_collection_timeout_fails_round_while_collecting() -> Result<()> {
        let (mut aggregator, history, e3_id) =
            build_plaintext_aggregator(collecting_state(), true).await?;
        // A captured context is required so the timeout can emit E3Failed with a causal parent.
        aggregator.timeout_ec = Some(test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CiphertextReady,
            reason: FailureReason::None,
        }));
        let addr = aggregator.start();

        addr.send(DecryptionCollectionTimeout).await?;

        let event = next_event(&history).await?;
        assert!(
            matches!(
                event.into_data(),
                InterfoldEventData::E3Failed(data)
                    if data.reason == FailureReason::DecryptionTimeout
            ),
            "expected E3Failed with DecryptionTimeout when collection window elapses"
        );
        Ok(())
    }

    #[actix::test]
    async fn threshold_decryption_compute_error_emits_e3_failed() -> Result<()> {
        let correlation_id = CorrelationId::new();
        let (mut aggregator, history, e3_id) =
            build_plaintext_aggregator(computing_state(), true).await?;
        aggregator.threshold_decryption_correlation = Some(correlation_id);

        let request = ComputeRequest::trbfv(
            TrBFVRequest::CalculateThresholdDecryption(CalculateThresholdDecryptionRequest {
                ciphertexts: vec![ArcBytes::from_bytes(&[8])],
                trbfv_config: TrBFVConfig::new(test_params(), 2, 1),
                d_share_polys: vec![(0, vec![ArcBytes::from_bytes(&[7])])],
            }),
            correlation_id,
            e3_id.clone(),
        );

        aggregator.handle_compute_request_error(TypedEvent::new(
            ComputeRequestError::new(
                ComputeRequestErrorKind::TrBFV(e3_trbfv::TrBFVError::CalculateThresholdDecryption(
                    "boom".into(),
                )),
                request,
            ),
            test_ctx(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::None,
                reason: FailureReason::None,
            }),
        ))?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CiphertextReady
                    && data.reason == FailureReason::DecryptionInvalidShares
        ));
        assert!(aggregator.threshold_decryption_correlation.is_none());

        Ok(())
    }

    #[actix::test]
    async fn insufficient_honest_c6_shares_emit_e3_failed() -> Result<()> {
        let (mut aggregator, history, e3_id) =
            build_plaintext_aggregator(verifying_c6_state(), true).await?;

        aggregator.handle_c6_verification_complete(TypedEvent::new(
            ShareVerificationComplete {
                e3_id: e3_id.clone(),
                kind: VerificationKind::ThresholdDecryptionProofs,
                dishonest_parties: BTreeSet::from([1]),
            },
            test_ctx(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::None,
                reason: FailureReason::None,
            }),
        ))?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CiphertextReady
                    && data.reason == FailureReason::DecryptionInvalidShares
        ));

        Ok(())
    }

    #[actix::test]
    async fn decryption_aggregation_compute_error_emits_e3_failed() -> Result<()> {
        let correlation_id = CorrelationId::new();
        let (mut aggregator, history, e3_id) =
            build_plaintext_aggregator(generating_c7_state(), true).await?;
        aggregator.c7_proofs_pending = Some(vec![dummy_proof(CircuitName::PkAggregation)]);
        aggregator.honest_c6_proofs_for_agg = Some(vec![(
            0,
            vec![dummy_proof(CircuitName::ThresholdShareDecryption)],
        )]);
        aggregator.decryption_aggregation_correlation = Some(correlation_id);
        aggregator.last_ec = Some(test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        }));

        let request = ComputeRequest::zk(
            ZkRequest::DecryptionAggregation(DecryptionAggregationRequest {
                c6_total_slots: 1,
                jobs: Vec::new(),
                committee_addresses: vec![test_committee_address()],
                params_preset: BfvPreset::InsecureThreshold512,
                committee_size: CiphernodesCommitteeSize::Minimum,
            }),
            correlation_id,
            e3_id.clone(),
        );

        aggregator.handle_compute_request_error(TypedEvent::new(
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("boom".to_string())),
                request,
            ),
            test_ctx(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::None,
                reason: FailureReason::None,
            }),
        ))?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CiphertextReady
                    && data.reason == FailureReason::DecryptionInvalidShares
        ));
        assert!(aggregator.decryption_aggregation_correlation.is_none());
        assert!(aggregator.c7_proofs_pending.is_none());

        Ok(())
    }

    #[actix::test]
    async fn missing_c6_inner_proofs_emit_e3_failed() -> Result<()> {
        let (mut aggregator, history, e3_id) =
            build_plaintext_aggregator(generating_c7_state(), true).await?;
        aggregator.c7_proofs_pending = Some(vec![dummy_proof(CircuitName::PkAggregation)]);
        aggregator.honest_c6_proofs_for_agg = Some(vec![
            (0, vec![]),
            (1, vec![dummy_proof(CircuitName::ThresholdShareDecryption)]),
        ]);

        let ec = test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        });
        aggregator.dispatch_decryption_aggregation(&ec)?;

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CiphertextReady
                    && data.reason == FailureReason::DecryptionInvalidShares
        ));
        assert!(aggregator.honest_c6_proofs_for_agg.is_none());
        assert!(aggregator.decryption_aggregation_correlation.is_none());
        assert!(aggregator.c7_proofs_pending.is_none());
        assert!(aggregator.decryption_aggregator_proofs.is_none());

        Ok(())
    }

    #[actix::test]
    async fn proof_aggregation_disabled_marks_decryption_aggregator_ready() -> Result<()> {
        let (mut aggregator, _history, _e3_id) =
            build_plaintext_aggregator(generating_c7_state(), false).await?;
        aggregator.c7_proofs_pending = Some(vec![dummy_proof(CircuitName::PkAggregation)]);
        let ec = test_ctx(E3Failed {
            e3_id: aggregator.e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        });

        aggregator.dispatch_decryption_aggregation(&ec)?;
        assert!(aggregator
            .decryption_aggregator_proofs
            .as_ref()
            .is_some_and(|p| p.is_empty()));
        assert!(aggregator.decryption_aggregation_correlation.is_none());

        Ok(())
    }
}
