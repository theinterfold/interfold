// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::{BTreeMap, BTreeSet};

use actix::prelude::*;
use alloy::primitives::Address;
use anyhow::{anyhow, bail, ensure, Result};
use e3_data::Persistable;
use e3_events::{
    prelude::*, trap, AggregationProofPending, AggregationProofSigned, BusHandle, CircuitName,
    CommitteeMemberExpelled, ComputeRequest, ComputeRequestError, ComputeResponse,
    ComputeResponseKind, CorrelationId, DecryptedSharesAggregationProofRequest,
    DecryptionAggregationJobRequest, DecryptionAggregationRequest, DecryptionshareCreated, Die,
    E3Failed, E3Stage, E3id, EType, EnclaveEvent, EnclaveEventData, EventContext, FailureReason,
    PartyProofsToVerify, PlaintextAggregated, Proof, Seed, Sequenced, ShareVerificationComplete,
    ShareVerificationDispatched, SignedProofPayload, TypedEvent, VerificationKind, ZkRequest,
    ZkResponse,
};
use e3_fhe_params::BfvPreset;
use e3_sortition::{E3CommitteeContainsRequest, E3CommitteeContainsResponse, Sortition};
use e3_trbfv::{
    calculate_threshold_decryption::CalculateThresholdDecryptionRequest, TrBFVConfig, TrBFVRequest,
    TrBFVResponse,
};
use e3_utils::NotifySync;
use e3_utils::{utility_types::ArcBytes, MAILBOX_LIMIT};
use e3_zk_helpers::circuits::commitments::compute_threshold_decryption_share_commitment;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS;
use e3_zk_helpers::threshold::share_decryption::{Bits as C6Bits, Bounds as C6Bounds};
use e3_zk_helpers::Computation;
use tracing::{debug, info, trace, warn};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Collecting {
    threshold_m: u64,
    threshold_n: u64,
    shares: BTreeMap<u64, Vec<ArcBytes>>,
    /// Signed raw C6 proofs for ShareVerification.
    c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    seed: Seed,
    ciphertext_output: Vec<ArcBytes>,
    params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyingC6 {
    threshold_m: u64,
    threshold_n: u64,
    shares: BTreeMap<u64, Vec<ArcBytes>>,
    c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    ciphertext_output: Vec<ArcBytes>,
    params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Computing {
    threshold_m: u64,
    threshold_n: u64,
    shares: Vec<(u64, Vec<ArcBytes>)>,
    ciphertext_output: Vec<ArcBytes>,
    params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneratingC7Proof {
    threshold_m: u64,
    threshold_n: u64,
    shares: Vec<(u64, Vec<ArcBytes>)>,
    plaintext: Vec<ArcBytes>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Complete {
    decrypted: Vec<ArcBytes>,
    shares: Vec<(u64, Vec<ArcBytes>)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ThresholdPlaintextAggregatorState {
    Collecting(Collecting),
    VerifyingC6(VerifyingC6),
    Computing(Computing),
    GeneratingC7Proof(GeneratingC7Proof),
    Complete(Complete),
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Collecting {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Collecting(s) => Ok(s),
            _ => bail!("PlaintextState was expected to be Collecting but it was not."),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for VerifyingC6 {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::VerifyingC6(s) => Ok(s),
            _ => bail!("Inconsistent state: expected VerifyingC6"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Computing {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Computing(s) => Ok(s),
            _ => bail!("Inconsistent state: expected Computing"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for GeneratingC7Proof {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::GeneratingC7Proof(s) => Ok(s),
            _ => bail!("Inconsistent state: expected GeneratingC7Proof"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Complete {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Complete(s) => Ok(s),
            _ => bail!("Inconsistent state: expected Complete"),
        }
    }
}

impl ThresholdPlaintextAggregatorState {
    pub fn init(
        threshold_m: u64,
        threshold_n: u64,
        seed: Seed,
        ciphertext_output: Vec<ArcBytes>,
        params: ArcBytes,
    ) -> Self {
        ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m,
            threshold_n,
            shares: BTreeMap::new(),
            c6_proofs: BTreeMap::new(),
            seed,
            ciphertext_output,
            params,
        })
    }
}

pub struct ThresholdPlaintextAggregator {
    bus: BusHandle,
    sortition: Addr<Sortition>,
    e3_id: E3id,
    params_preset: BfvPreset,
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
    /// Ordered committee (`topNodes`) for decryption-aggregator `committee_hash_*` inputs.
    committee_addresses: Vec<Address>,
}

pub struct ThresholdPlaintextAggregatorParams {
    pub bus: BusHandle,
    pub sortition: Addr<Sortition>,
    pub e3_id: E3id,
    pub params_preset: BfvPreset,
    pub proof_aggregation_enabled: bool,
    /// Finalized committee from `PublicKeyAggregated.nodes` (parsed once at construction).
    pub committee_addresses: Vec<Address>,
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
            proof_aggregation_enabled: params.proof_aggregation_enabled,
            state,
            honest_c6_proofs_for_agg: None,
            threshold_decryption_correlation: None,
            decryption_aggregation_correlation: None,
            c7_proofs_pending: None,
            decryption_aggregator_proofs: None,
            last_ec: None,
            committee_addresses: params.committee_addresses,
        }
    }

    pub fn add_share(
        &mut self,
        party_id: u64,
        share: Vec<ArcBytes>,
        signed_decryption_proofs: Vec<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(ec, |state| {
            info!("Adding share for party_id={}", party_id);
            let current: Collecting = state.clone().try_into()?;
            let ciphertext_output = current.ciphertext_output;
            let threshold_m = current.threshold_m;
            let threshold_n = current.threshold_n;
            let params = current.params.clone();
            let mut shares = current.shares;
            let mut c6_proofs = current.c6_proofs;

            info!("pushing to share collection {} {:?}", party_id, share);
            shares.insert(party_id, share);
            c6_proofs.insert(party_id, signed_decryption_proofs);

            let collected = shares.len() as u64;
            info!(
                party_id,
                collected,
                threshold_n,
                remaining = threshold_n.saturating_sub(collected),
                "ThresholdPlaintextAggregator: decryption share received ({collected}/{threshold_n}), {} still needed",
                threshold_n.saturating_sub(collected)
            );

            if collected < threshold_n {
                return Ok(ThresholdPlaintextAggregatorState::Collecting(Collecting {
                    params,
                    threshold_n,
                    threshold_m,
                    ciphertext_output,
                    shares,
                    c6_proofs,
                    seed: current.seed,
                }));
            }

            info!(
                "Changing state to VerifyingC6 because received all {} shares...",
                threshold_n
            );

            Ok(ThresholdPlaintextAggregatorState::VerifyingC6(
                VerifyingC6 {
                    shares,
                    c6_proofs,
                    ciphertext_output,
                    threshold_m,
                    threshold_n,
                    params,
                },
            ))
        })
    }

    pub fn handle_member_expelled(
        &mut self,
        party_id: u64,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(ec, |state| {
            let ThresholdPlaintextAggregatorState::Collecting(current) = state else {
                return Ok(state);
            };

            let mut shares = current.shares;
            let mut c6_proofs = current.c6_proofs;
            let mut threshold_n = current.threshold_n;

            shares.remove(&party_id);
            c6_proofs.remove(&party_id);

            if threshold_n > 0 {
                threshold_n -= 1;
            }

            if threshold_n < current.threshold_m {
                warn!(
                    "ThresholdPlaintextAggregator: threshold_n ({}) < threshold_m ({}) after expulsion",
                    threshold_n, current.threshold_m
                );
                return Ok(ThresholdPlaintextAggregatorState::Collecting(Collecting {
                    threshold_m: current.threshold_m,
                    threshold_n,
                    shares,
                    c6_proofs,
                    seed: current.seed,
                    ciphertext_output: current.ciphertext_output,
                    params: current.params,
                }));
            }

            if (shares.len() as u64) < threshold_n || threshold_n == 0 {
                return Ok(ThresholdPlaintextAggregatorState::Collecting(Collecting {
                    threshold_m: current.threshold_m,
                    threshold_n,
                    shares,
                    c6_proofs,
                    seed: current.seed,
                    ciphertext_output: current.ciphertext_output,
                    params: current.params,
                }));
            }

            Ok(ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
                threshold_m: current.threshold_m,
                threshold_n,
                shares,
                c6_proofs,
                ciphertext_output: current.ciphertext_output,
                params: current.params,
            }))
        })
    }

    /// Dispatch C6 proof verification through ShareVerificationActor.
    pub fn dispatch_c6_verification(
        &mut self,
        c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let party_proofs: Vec<PartyProofsToVerify> = c6_proofs
            .into_iter()
            .map(|(party_id, signed_proofs)| PartyProofsToVerify {
                sender_party_id: party_id,
                signed_proofs,
            })
            .collect();

        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: self.e3_id.clone(),
                kind: VerificationKind::ThresholdDecryptionProofs,
                share_proofs: party_proofs,
                decryption_proofs: vec![],
                pre_dishonest: BTreeSet::new(),
                params_preset: self.params_preset,
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
            self.verify_shares_match_c6_commitments(&honest_shares, &state.c6_proofs);
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
        let trbfv_config =
            TrBFVConfig::new(state.params.clone(), state.threshold_n, state.threshold_m);

        let correlation_id = CorrelationId::new();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateThresholdDecryption(
                CalculateThresholdDecryptionRequest {
                    ciphertexts: state.ciphertext_output.clone(),
                    trbfv_config,
                    d_share_polys: honest_shares.clone(),
                }
                .into(),
            ),
            correlation_id.clone(),
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

    /// Verify that each honest party's raw decryption share bytes match the
    /// `d_commitment` output in their verified C6 proof. Returns party IDs
    /// that failed the check.
    fn verify_shares_match_c6_commitments(
        &self,
        honest_shares: &[(u64, Vec<ArcBytes>)],
        c6_proofs: &BTreeMap<u64, Vec<SignedProofPayload>>,
    ) -> BTreeSet<u64> {
        let mut mismatched = BTreeSet::new();

        let Ok((threshold_params, _)) = e3_fhe_params::build_pair_for_preset(self.params_preset)
        else {
            warn!("Could not build BFV params for d_commitment check — skipping");
            return mismatched;
        };

        // Reuse the same Bounds/Bits computation that C6 codegen uses,
        // so d_native_bit stays in sync if the formula ever changes.
        let Ok(bounds) = C6Bounds::compute(self.params_preset, &()) else {
            warn!("Could not compute bounds for d_commitment check — skipping");
            return mismatched;
        };
        let Ok(bits) = C6Bits::compute(self.params_preset, &bounds) else {
            warn!("Could not compute bits for d_commitment check — skipping");
            return mismatched;
        };
        let d_native_bit = bits.d_native_bit;

        let max_k = MAX_MSG_NON_ZERO_COEFFS;
        let c6_output_layout = CircuitName::ThresholdShareDecryption.output_layout();

        for (party_id, shares) in honest_shares {
            let Some(proofs) = c6_proofs.get(party_id) else {
                warn!(
                    "No C6 proofs for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let Some(first_proof) = proofs.first() else {
                warn!(
                    "Empty C6 proof list for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let Some(c6_d_bytes) = c6_output_layout
                .extract_field(&first_proof.payload.proof.public_signals, "d_commitment")
            else {
                warn!(
                    "Could not extract d_commitment from C6 proof for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };

            let Some(share_bytes) = shares.first() else {
                warn!(
                    "No share bytes for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let Ok(poly) = e3_trbfv::helpers::try_poly_from_bytes(share_bytes, &threshold_params)
            else {
                warn!(
                    "Could not deserialize share for party {} — marking as mismatched",
                    party_id
                );
                mismatched.insert(*party_id);
                continue;
            };
            let crt = e3_polynomial::CrtPolynomial::from_fhe_polynomial(&poly);

            // C6 public `d_commitment` hashes native truncated limbs (same layout as C7), not
            // reversed+centered witness `d`.
            let computed = compute_threshold_decryption_share_commitment(&crt, d_native_bit, max_k);

            // Convert to big-endian 32-byte padded format matching
            // Barretenberg's public_signals encoding.
            let (_, be_bytes) = computed.to_bytes_be();
            let mut computed_padded = [0u8; 32];
            let start = 32usize.saturating_sub(be_bytes.len());
            computed_padded[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);

            if computed_padded != c6_d_bytes {
                warn!(
                    "d_commitment mismatch for party {}: raw share commitment differs from C6 proof output",
                    party_id
                );
                mismatched.insert(*party_id);
            }
        }

        mismatched
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
                    params_preset: self.params_preset.clone(),
                    threshold_m,
                    threshold_n,
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
        ctx: &mut Context<Self>,
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
        let mut jobs = Vec::with_capacity(num_ct);
        for ct_idx in 0..num_ct {
            let mut c6_inner_proofs = Vec::with_capacity(c6_total_slots);
            let c6_slot_indices: Vec<u32> = (0..c6_total_slots as u32).collect();
            for (_, wps) in honest_c6.iter().take(c6_total_slots) {
                let Some(p) = wps.get(ct_idx) else {
                    warn!("C6 inner proof missing for party at ct index {}", ct_idx);
                    return self.fail_decryption_round(ec.clone());
                };
                c6_inner_proofs.push(p.clone());
            }
            jobs.push(DecryptionAggregationJobRequest {
                c6_inner_proofs,
                c6_slot_indices,
                c7_proof: c7_proofs[ct_idx].clone(),
            });
        }
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

        let len = MAX_MSG_NON_ZERO_COEFFS * 8;
        let decrypted_output: Vec<ArcBytes> = state
            .plaintext
            .iter()
            .map(|pt| {
                let mut bytes = pt.extract_bytes();
                if bytes.len() >= len {
                    bytes.truncate(len);
                } else {
                    bytes.resize(len, 0);
                }
                ArcBytes::from_bytes(&bytes)
            })
            .collect();

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
    }
}

impl Handler<EnclaveEvent> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, msg: EnclaveEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            EnclaveEventData::DecryptionshareCreated(data) => ctx.notify(TypedEvent::new(data, ec)),
            EnclaveEventData::E3RequestComplete(_) => self.notify_sync(ctx, Die),
            EnclaveEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::CommitteeMemberExpelled(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            EnclaveEventData::AggregationProofSigned(data) => {
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
        Committee, ComputeRequestErrorKind, HistoryCollector, TakeEvents, Unsequenced, ZkError,
    };
    use e3_fhe_params::{encode_bfv_params, BfvParamSet, DEFAULT_BFV_PRESET};
    use e3_sortition::{
        CiphernodeSelector, CiphernodeSelectorState, NodeStateStore, SortitionBackend,
        SortitionParams,
    };
    use e3_test_helpers::get_common_setup;
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    fn test_ctx(data: impl Into<EnclaveEventData>) -> EventContext<Sequenced> {
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
        Addr<HistoryCollector<EnclaveEvent>>,
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
                proof_aggregation_enabled,
                committee_addresses: vec![test_committee_address()],
            },
            test_persistable(initial_state),
        );

        Ok((aggregator, history, e3_id))
    }

    async fn next_event(history: &Addr<HistoryCollector<EnclaveEvent>>) -> Result<EnclaveEvent> {
        let mut result = history.send(TakeEvents::<EnclaveEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    #[actix::test]
    async fn threshold_decryption_compute_error_emits_e3_failed() -> Result<()> {
        let correlation_id = CorrelationId::new();
        let (mut aggregator, history, e3_id) =
            build_plaintext_aggregator(computing_state(), true).await?;
        aggregator.threshold_decryption_correlation = Some(correlation_id.clone());

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
                    "boom".to_string(),
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
            EnclaveEventData::E3Failed(data)
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
            EnclaveEventData::E3Failed(data)
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
        aggregator.decryption_aggregation_correlation = Some(correlation_id.clone());
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
            EnclaveEventData::E3Failed(data)
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
            EnclaveEventData::E3Failed(data)
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
