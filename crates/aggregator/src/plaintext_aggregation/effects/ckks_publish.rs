// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS plaintext-aggregation effect: synchronous threshold decryption +
//! C7-CKKS proof dispatch + canonical fixed-point publication (see
//! `plaintext_aggregation::ckks` for the determinism contract).
//!
//! Flow (mirrors BFV: C6 verify → compute → C7 → publish):
//! 1. `dispatch_c6_verification` routes CKKS shares through the SAME
//!    ShareVerificationActor round as BFV when proofs are present;
//! 2. `handle_c6_verification_complete` branches here with the dishonest
//!    set filtered out;
//! 3. we aggregate synchronously (pure Rust — no async trbfv pipeline),
//!    dispatch `AggregationProofPending` for the C7-CKKS proof, and
//!    publish `PlaintextAggregated` when the signed proof returns (via the
//!    shared `handle_aggregation_proof_signed` → GeneratingC7Proof path).
//!
//! Proof-free postures (`CkksProofPosture::c6/c7` for non-canonical param
//! sets) and in-process test paths without a zk stack publish
//! synchronously with a placeholder proof.

use super::super::*;
use crate::workflow::threshold_plaintext_aggregation::ckks::aggregate_ckks_plaintext;
use e3_events::CircuitName;
use e3_trckks::TrCkksConfig;
use std::collections::BTreeSet;

impl ThresholdPlaintextAggregator {
    /// Aggregate the collected CKKS decryption shares; then either publish
    /// directly (no-proof test path) or dispatch the C7-CKKS proof request
    /// and let the shared C7 flow publish.
    pub(in crate::actors::threshold_plaintext_aggregator) fn ckks_aggregate_and_publish(
        &mut self,
        ec: EventContext<Sequenced>,
        dishonest_parties: BTreeSet<u64>,
        via_verification: bool,
    ) -> Result<()> {
        let state: VerifyingC6 = self
            .state
            .get()
            .ok_or_else(|| anyhow!("Expected VerifyingC6 state"))?
            .try_into()?;

        let config = TrCkksConfig::new(state.params.clone(), state.threshold_n, state.threshold_m);

        // One decryption share per party per ciphertext output; the CKKS
        // round publishes exactly one evaluated ciphertext.
        let ciphertext = state
            .ciphertext_output
            .first()
            .ok_or_else(|| anyhow!("CKKS round has no ciphertext output"))?;
        // PARTY-ID BASES: DecryptionshareCreated carries the CHAIN party id
        // (0-based committee slot); Shamir reconstruction needs the 1-based
        // x-coordinate the DKG dealt against (x = slot + 1; x = 0 is the
        // secret itself). Convert at this seam, mirroring the keyshare
        // shell's boundary conversion. Dishonest parties (failed C6) are
        // excluded before aggregation.
        let shares: Vec<(u64, ArcBytes)> = state
            .shares
            .iter()
            .filter(|(party_id, _)| !dishonest_parties.contains(party_id))
            .map(|(party_id, per_output)| {
                per_output
                    .first()
                    .cloned()
                    .map(|s| (*party_id + 1, s))
                    .ok_or_else(|| anyhow!("party {party_id} supplied an empty share vector"))
            })
            .collect::<Result<_>>()?;
        if shares.len() <= state.threshold_m as usize {
            warn!(
                "Not enough honest CKKS shares: {} honest, {} required",
                shares.len(),
                state.threshold_m + 1
            );
            return self.fail_decryption_round(ec);
        }

        info!(
            "Aggregating CKKS plaintext from {} decryption shares...",
            shares.len()
        );
        let decrypted = aggregate_ckks_plaintext(&config, shares.clone(), ciphertext)?;

        let shares_for_state: Vec<(u64, Vec<ArcBytes>)> = shares
            .iter()
            .map(|(pid, s)| (*pid, vec![s.clone()]))
            .collect();

        // No-proof test path (in-process suites without the zk stack —
        // C6 round never ran because no proofs arrived): publish
        // synchronously with the placeholder, as before. When shares DID
        // carry verified C6 proofs, the real C7-CKKS round runs below even
        // if recursive aggregation is disabled (BFV parity: C7 leaf
        // proofs are always generated; only the recursive fold is gated).
        //
        // NOTE: the placeholder below is accepted ONLY by MockDecryptionVerifier.
        // A deployment that registers the real `CkksDecryptionVerifier` for the
        // CKKS scheme id (which `deployInterfold.ts` now always does) rejects it,
        // so this branch cannot silently publish an unverified plaintext there.
        if !via_verification {
            let event = PlaintextAggregated {
                decrypted_output: vec![decrypted.clone()],
                e3_id: self.e3_id.clone(),
                // Mock decryption verifiers accept a non-empty placeholder
                // (same convention as the BFV test path). public_signals
                // must be a multiple of 32 bytes for the EVM writer's
                // calldata packing — one zero word.
                decryption_aggregator_proofs: vec![Proof {
                    circuit: CircuitName::DecryptionAggregator,
                    data: ArcBytes::from_bytes(&[1]),
                    public_signals: ArcBytes::from_bytes(&[0u8; 32]),
                }],
            };
            self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.decryption_aggregator_proofs =
                    Some(event.decryption_aggregator_proofs.clone());
                recovery.last_ec = Some(ec.clone());
                Ok(recovery)
            })?;
            info!("Dispatching CKKS plaintext event {:?}", event);
            self.bus.publish(event, ec.clone())?;
            self.state.try_mutate(&ec, |_| {
                Ok(ThresholdPlaintextAggregatorState::Complete(Complete {
                    decrypted: vec![decrypted],
                    shares: shares_for_state,
                }))
            })?;
            return Ok(());
        }

        // Real path: dispatch the C7-CKKS proof request; the shared
        // AggregationProofSigned flow (GeneratingC7Proof state) publishes
        // once the signed proof returns.
        info!(
            "Dispatching C7-CKKS proof request over {} shares",
            shares.len()
        );
        self.bus.publish(
            AggregationProofPending {
                e3_id: self.e3_id.clone(),
                proof_request: DecryptedSharesAggregationProofRequest {
                    scheme: e3_events::E3Scheme::Ckks,
                    d_share_polys: shares_for_state.clone(),
                    plaintext: vec![decrypted.clone()],
                    params_preset: self.params_preset,
                    threshold_m: state.threshold_m,
                    threshold_n: state.threshold_n,
                    committee_size: self.committee_size,
                    ckks_params: Some(state.params.clone()),
                    // Domain binding for the on-chain C7-CKKS check. The
                    // prover fails closed if this is None — an unbound
                    // aggregation proof is never emitted.
                    ckks_decryption_domain: self.ckks_decryption_domain,
                    ckks_ciphertext_bytes: state.ciphertext_output.clone(),
                },
                plaintext: vec![decrypted.clone()],
                shares: shares_for_state.clone(),
            },
            ec.clone(),
        )?;

        self.pending.last_ec = Some(ec.clone());
        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregatorState::GeneratingC7Proof(
                GeneratingC7Proof {
                    threshold_m: state.threshold_m,
                    threshold_n: state.threshold_n,
                    shares: shares_for_state.clone(),
                    plaintext: vec![decrypted.clone()],
                },
            ))
        })?;
        Ok(())
    }
}
