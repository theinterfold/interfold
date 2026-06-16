// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Plain, synchronous domain logic for public-key aggregation.
//!
//! This module holds the [`PublicKeyAggregatorState`] state machine plus the pure
//! transition/decision functions used by the `PublicKeyAggregator` actor. Nothing here
//! touches actix, `Persistable`, or the event bus: the actor feeds inputs in, gets a
//! next-state or a [decision](C1Dispatch)/[`HonestSelection`] back, and performs the
//! persistence/publish/dispatch side effects itself.

use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Context as _, Result};
use e3_events::{
    CircuitName, E3id, OrderedSet, PartyProofsToVerify, Proof, Seed, SignedDkgFoldAttestation,
    SignedProofPayload,
};
use e3_fhe::Fhe;
use e3_utils::ArcBytes;
use e3_zk_helpers::cap_honest_party_ids;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::extract_node_fold_agg_commits;
use std::collections::{BTreeSet, HashMap};
use tracing::{error, info, warn};

/// Circuit honest-party count `H` for the committee `(threshold_m, threshold_n)`.
pub(crate) fn committee_h_for(threshold_m: usize, threshold_n: usize) -> Result<usize> {
    Ok(
        CiphernodesCommitteeSize::from_threshold(threshold_m, threshold_n)
            .with_context(|| {
                format!("unknown committee for threshold_m={threshold_m} threshold_n={threshold_n}")
            })?
            .values()
            .h,
    )
}

/// Public-signal key for the aggregated PK commitment in `CircuitName::PkAggregation` (C5).
/// Must stay in lock-step with the Noir circuit's output ABI declaration.
const C5_PK_COMMITMENT_FIELD: &str = "commitment";

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_dkg_fold_attestation(
    e3_id: &E3id,
    party_id: u64,
    proof: &Proof,
    attestation: &SignedDkgFoldAttestation,
    expected_node: &str,
    committee_n: usize,
    committee_h: usize,
    n_moduli: usize,
) -> Result<()> {
    ensure!(
        attestation.payload.e3_id == *e3_id,
        "attestation e3_id mismatch"
    );
    ensure!(
        attestation.payload.party_id == party_id,
        "attestation party_id mismatch"
    );
    let expected: Address = expected_node
        .parse()
        .with_context(|| format!("invalid committee node address {expected_node}"))?;
    ensure!(
        attestation.verify_signer(&expected)?,
        "fold attestation signer does not match committee node for party {party_id}"
    );
    let (extracted_party, commits) =
        extract_node_fold_agg_commits(proof, committee_n, committee_h, n_moduli)
            .map_err(|e| anyhow!("{e}"))?;
    ensure!(extracted_party == party_id, "NodeFold party_id mismatch");
    ensure!(
        commits == attestation.payload.agg_commits,
        "NodeFold commits do not match signed attestation"
    );
    Ok(())
}

/// Extract the hash-based aggregated PK commitment from the signed C5 proof.
/// This is the last public signal of `CircuitName::PkAggregation`.
pub(crate) fn extract_pk_commitment(c5_proof: &Proof) -> Result<[u8; 32]> {
    let layout = CircuitName::PkAggregation.output_layout();
    let bytes = layout
        .extract_field(&c5_proof.public_signals, C5_PK_COMMITMENT_FIELD)
        .ok_or_else(|| anyhow::anyhow!("C5 proof is missing `commitment` public signal"))?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "C5 `commitment` public signal must be 32 bytes"
        ));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Outcome of cross-checking each honest party's keyshare against its signed C1
/// `pk_commitment` public signal.
pub(crate) struct C1CommitmentAudit {
    /// Parties whose keyshare does not recompute to their signed C1 commitment, paired
    /// with the proof for `SignedProofFailed` reporting.
    pub mismatched: Vec<(u64, SignedProofPayload)>,
    /// Parties that carried no C1 proof at all (defensive — normally already dishonest).
    pub missing_proof: Vec<u64>,
}

/// Recompute each honest party's `pk_commitment` from its keyshare bytes and compare it
/// against the `pk_commitment` public signal in the party's signed C1 proof. Pure: the
/// actor publishes `SignedProofFailed` for `mismatched` and folds both result sets into
/// `dishonest_parties`.
pub(crate) fn check_c1_keyshare_commitments(
    entries: &[(u64, String, ArcBytes, Option<SignedProofPayload>)],
    fhe: &Fhe,
) -> C1CommitmentAudit {
    let mut mismatched = Vec::new();
    let mut missing_proof = Vec::new();
    for (party_id, _node, ks, c1) in entries {
        let Some(signed_proof) = c1.as_ref() else {
            warn!(
                "Party {} has no C1 proof but was not marked dishonest",
                party_id
            );
            missing_proof.push(*party_id);
            continue;
        };
        let ok = match e3_zk_helpers::compute_pk_commitment_from_keyshare_bytes(
            ks,
            &fhe.params,
            &fhe.crp,
        ) {
            Ok(computed) => signed_proof
                .payload
                .proof
                .extract_output("pk_commitment")
                .is_some_and(|extracted| extracted[..] == computed[..]),
            Err(e) => {
                warn!(
                    "Failed to compute pk_commitment for party {}: {}",
                    party_id, e
                );
                false
            }
        };
        if !ok {
            mismatched.push((*party_id, signed_proof.clone()));
        }
    }
    C1CommitmentAudit {
        mismatched,
        missing_proof,
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PublicKeyAggregatorState {
    Collecting {
        /// Live committee size after expulsions; used only to decide when enough keyshares arrived.
        threshold_n: usize,
        threshold_m: usize,
        /// Canonical on-chain / circuit committee size N (unchanged after expulsion).
        circuit_committee_n: usize,
        /// Canonical honest-party count H for circuit public IO.
        circuit_committee_h: usize,
        keyshares: OrderedSet<ArcBytes>,
        /// C1 proofs collected from KeyshareCreated events, indexed by insertion order
        /// (matches `submission_order`).
        c1_proofs: Vec<Option<SignedProofPayload>>,
        seed: Seed,
        nodes: OrderedSet<String>,
        /// Insertion-ordered (real sortition `party_id`, node, keyshare) triples.
        /// Index matches `c1_proofs`. The real `party_id` comes from `KeyshareCreated`
        /// and must be used for all downstream circuit slot indexing — arrival order
        /// is non-deterministic and does not match sortition's committee position.
        submission_order: Vec<(u64, String, ArcBytes)>,
    },
    VerifyingC1 {
        /// Insertion-ordered (party_id, node, keyshare) triples from Collecting.
        submission_order: Vec<(u64, String, ArcBytes)>,
        threshold_m: usize,
        /// Canonical on-chain / circuit committee size N (for `committee_h` lookup).
        circuit_committee_n: usize,
        /// Canonical honest-party count H for circuit public IO.
        circuit_committee_h: usize,
        /// C1 proofs in the same insertion order as `submission_order`.
        c1_proofs: Vec<Option<SignedProofPayload>>,
        /// Real party_ids that submitted no C1 proof — treated as dishonest.
        no_proof_parties: Vec<u64>,
    },
    GeneratingC5Proof {
        public_key: ArcBytes,
        keyshare_bytes: Vec<ArcBytes>,
        nodes: OrderedSet<String>,
        /// Registered node address per sortition `party_id` for the **full** committee
        /// (all `N` parties that submitted a keyshare, honest or not). Honest-only lookups
        /// must intersect with `honest_party_ids`.
        party_nodes: HashMap<u64, String>,
        /// DKG recursive proofs per party (restart-critical).
        dkg_node_proofs: HashMap<u64, Option<Proof>>,
        /// Per-party fold attestations collected with honest DKG folds.
        dkg_fold_attestations: HashMap<u64, SignedDkgFoldAttestation>,
        honest_party_ids: BTreeSet<u64>,
        dishonest_parties: BTreeSet<u64>,
        /// Circuit committee size N (NodeFold / DKG public IO layout).
        circuit_committee_n: usize,
        /// Circuit honest-party count H (NodeFold / DKG public IO layout).
        circuit_committee_h: usize,
        /// In-flight [`ZkRequest::DkgAggregation`], if any.
        dkg_aggregation_correlation: Option<e3_events::CorrelationId>,
        /// Result from [`ZkResponse::DkgAggregation`] (replaces pairwise `FoldProofs`).
        dkg_aggregated_proof: Option<Proof>,
        c5_proof_pending: Option<Proof>,
        last_ec: Option<e3_events::EventContext<e3_events::Sequenced>>,
        /// Accumulated nodes_fold proof after `nodes_fold_completed_slots` streaming steps.
        nodes_fold_accumulator: Option<Proof>,
        /// Number of slots folded so far; equals the next slot index to dispatch.
        nodes_fold_completed_slots: u32,
        /// Correlation ID of the in-flight [`ZkRequest::NodesFoldStep`], if any.
        nodes_fold_step_correlation: Option<e3_events::CorrelationId>,
    },
    Complete {
        public_key: ArcBytes,
        keyshares: OrderedSet<ArcBytes>,
        nodes: OrderedSet<String>,
        /// Ascending `party_id` order (matches on-chain `topNodes` after finalize sort).
        committee_addresses: Vec<Address>,
        /// Honest subset (H entries) for decryption-share gating after restart.
        honest_committee_addresses: Vec<Address>,
    },
}

impl PublicKeyAggregatorState {
    /// Ordered `topNodes` when the committee set is known (post–committee formation).
    pub fn committee_nodes(&self) -> Option<&OrderedSet<String>> {
        match self {
            PublicKeyAggregatorState::Collecting { nodes, .. } if !nodes.is_empty() => Some(nodes),
            PublicKeyAggregatorState::GeneratingC5Proof { nodes, .. } => Some(nodes),
            PublicKeyAggregatorState::Complete { nodes, .. } => Some(nodes),
            _ => None,
        }
    }

    pub fn committee_addresses(&self) -> Option<&[Address]> {
        match self {
            PublicKeyAggregatorState::Complete {
                committee_addresses,
                ..
            } if !committee_addresses.is_empty() => Some(committee_addresses.as_slice()),
            _ => None,
        }
    }

    pub fn honest_committee_addresses(&self) -> Option<&[Address]> {
        match self {
            PublicKeyAggregatorState::Complete {
                honest_committee_addresses,
                ..
            } if !honest_committee_addresses.is_empty() => {
                Some(honest_committee_addresses.as_slice())
            }
            _ => None,
        }
    }

    pub fn init(threshold_n: usize, threshold_m: usize, seed: Seed) -> Self {
        let circuit_committee_h = committee_h_for(threshold_m, threshold_n)
            .unwrap_or_else(|e| panic!("invalid committee at init: {e}"));
        PublicKeyAggregatorState::Collecting {
            threshold_n,
            threshold_m,
            circuit_committee_n: threshold_n,
            circuit_committee_h,
            keyshares: OrderedSet::new(),
            c1_proofs: Vec::new(),
            seed,
            nodes: OrderedSet::new(),
            submission_order: Vec::new(),
        }
    }
}

/// Decision returned by [`PublicKeyAggregation::plan_c1_dispatch`]: which parties have a C1
/// proof to verify and which submitted a keyshare without one (treated as dishonest).
pub(crate) struct C1Dispatch {
    pub party_proofs: Vec<PartyProofsToVerify>,
    pub no_proof_parties: Vec<u64>,
}

/// Outcome of [`PublicKeyAggregation::select_honest_set`].
pub(crate) enum HonestSelection {
    /// Too few honest parties cleared C1 — caller must fail the E3.
    Fail,
    /// Enough honest parties — proceed to aggregation with this honest set.
    Proceed {
        honest_entries: Vec<(u64, String, ArcBytes, Option<SignedProofPayload>)>,
        honest_party_ids: BTreeSet<u64>,
    },
}

/// Plain, synchronous domain service for public-key aggregation decisions.
pub(crate) struct PublicKeyAggregation;

impl PublicKeyAggregation {
    /// Add a keyshare to a `Collecting` state, returning the next state. When all `N`
    /// committee keyshares have arrived this transitions to `VerifyingC1`. Submitting a
    /// `party_id` that already has a keyshare is idempotent (state is returned unchanged).
    pub(crate) fn add_keyshare(
        mut state: PublicKeyAggregatorState,
        keyshare: ArcBytes,
        node: String,
        party_id: u64,
        c1_proof: Option<SignedProofPayload>,
    ) -> Result<PublicKeyAggregatorState> {
        let PublicKeyAggregatorState::Collecting {
            threshold_n,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            keyshares,
            c1_proofs,
            nodes,
            submission_order,
            ..
        } = &mut state
        else {
            return Err(anyhow::anyhow!("Can only add keyshare in Collecting state"));
        };

        if submission_order.iter().any(|(pid, _, _)| *pid == party_id) {
            return Ok(state);
        }

        keyshares.insert(keyshare.clone());
        c1_proofs.push(c1_proof);
        nodes.insert(node.clone());
        info!(
            "add_keyshare: node={node} party_id={party_id} (arrival slot={})",
            submission_order.len()
        );
        submission_order.push((party_id, node, keyshare));
        let n = *threshold_n;
        let m = *threshold_m;
        let committee_n = *circuit_committee_n;
        let committee_h = *circuit_committee_h;
        let unique_parties = submission_order.len();
        info!(
            "PublicKeyAggregator got keyshares {unique_parties}/{n} distinct parties (circuit_n={committee_n}, committee_h={committee_h})"
        );
        // Collect all N committee keyshares before C1. C5 then requires exactly H honest
        // proofs afterward (micro had N=H so waiting for H was equivalent).
        if unique_parties >= n {
            info!(
                "Collected keyshares from {unique_parties} distinct parties (>= live_n={n}, circuit_n={committee_n}), transitioning to VerifyingC1..."
            );
            return Ok(PublicKeyAggregatorState::VerifyingC1 {
                submission_order: std::mem::take(submission_order),
                threshold_m: m,
                circuit_committee_n: committee_n,
                circuit_committee_h: committee_h,
                c1_proofs: std::mem::take(c1_proofs),
                no_proof_parties: Vec::new(),
            });
        }

        Ok(state)
    }

    /// Split the collected keyshare submissions into parties with a C1 proof to verify and
    /// parties that submitted no proof (treated as dishonest by the caller).
    pub(crate) fn plan_c1_dispatch(
        submission_order: &[(u64, String, ArcBytes)],
        c1_proofs: &[Option<SignedProofPayload>],
    ) -> C1Dispatch {
        let mut party_proofs = Vec::new();
        let mut no_proof_parties = Vec::new();

        for ((party_id, _, _), proof_opt) in submission_order.iter().zip(c1_proofs.iter()) {
            match proof_opt {
                Some(proof) => {
                    party_proofs.push(PartyProofsToVerify {
                        sender_party_id: *party_id,
                        signed_proofs: vec![proof.clone()],
                    });
                }
                None => {
                    warn!(
                        "Party {} submitted keyshare without C1 proof — treating as dishonest",
                        party_id
                    );
                    no_proof_parties.push(*party_id);
                }
            }
        }

        C1Dispatch {
            party_proofs,
            no_proof_parties,
        }
    }

    /// Select the canonical honest set after C1 (ZK + commitment) filtering.
    ///
    /// Sorts the honest entries by real `party_id`, fails closed when fewer than `circuit_h`
    /// parties cleared C1, caps the honest set to the `circuit_h` lowest `party_id`s, and
    /// fails again if `<= threshold_m` parties remain. Logging mirrors the original handler.
    pub(crate) fn select_honest_set(
        e3_id: &E3id,
        mut honest_entries: Vec<(u64, String, ArcBytes, Option<SignedProofPayload>)>,
        dishonest_parties: &BTreeSet<u64>,
        circuit_h: usize,
        threshold_m: usize,
        collected: usize,
    ) -> HonestSelection {
        // Sort by real party_id ascending so honest_keyshares / honest_nodes /
        // honest_party_ids all share the same ordering used by NodeFold rows
        // and by the circuit's slot indexing in `dkg_aggregator.nr`.
        honest_entries.sort_by_key(|(pid, _, _, _)| *pid);

        if !dishonest_parties.is_empty() {
            warn!(
                "Total dishonest parties (ZK + commitment): {:?}",
                dishonest_parties
            );
        }

        // Fail closed when fewer than H parties cleared C1 — C5 cannot be witnessed.
        if honest_entries.len() < circuit_h {
            error!(
                "C5 requires {circuit_h} honest parties with valid C1 proofs; only {} honest after verification (collected {collected}, dishonest: {:?})",
                honest_entries.len(),
                dishonest_parties
            );
            return HonestSelection::Fail;
        }

        // The C5 PkAggregation circuit is parameterised by a fixed honest-party count H.
        // When more than H parties cleared C1, select the H lowest party_ids as the
        // canonical honest set; the remainder stay in the full committee.
        let pre_cap_len = honest_entries.len();
        let honest_party_ids =
            cap_honest_party_ids(circuit_h, honest_entries.iter().map(|(pid, _, _, _)| *pid));
        if pre_cap_len > circuit_h {
            info!(
                "Capping honest set from {pre_cap_len} to circuit_h={circuit_h} for E3 {e3_id} (extras remain in full committee)"
            );
            honest_entries.retain(|(pid, _, _, _)| honest_party_ids.contains(pid));
        }

        // Defensive: should hold after truncation above; guard against future refactors.
        if honest_entries.len() <= threshold_m {
            error!(
                "Not enough honest parties after filtering: {} (need > {})",
                honest_entries.len(),
                threshold_m
            );
            return HonestSelection::Fail;
        }

        HonestSelection::Proceed {
            honest_entries,
            honest_party_ids,
        }
    }

    /// Apply a committee-member expulsion to a `Collecting` state, keeping the parallel
    /// collections aligned and transitioning to `VerifyingC1` when enough keyshares remain.
    pub(crate) fn handle_member_expelled(
        mut state: PublicKeyAggregatorState,
        node: &str,
    ) -> Result<PublicKeyAggregatorState> {
        let PublicKeyAggregatorState::Collecting {
            threshold_n,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            keyshares,
            c1_proofs,
            nodes,
            submission_order,
            ..
        } = &mut state
        else {
            return Ok(state);
        };

        let node_str = node.to_string();

        // Find the expelled node's index in submission_order and remove from
        // all parallel collections so they stay aligned.
        if let Some(idx) = submission_order.iter().position(|(_, n, _)| n == &node_str) {
            let (_, _, expelled_keyshare) = submission_order.remove(idx);
            keyshares.remove(&expelled_keyshare);
            c1_proofs.remove(idx);
        }

        nodes.remove(&node_str);

        if *threshold_n > 0 {
            *threshold_n -= 1;
            info!(
                "PublicKeyAggregator: reduced threshold_n to {} after expelling {}",
                threshold_n, node
            );
        }

        if *threshold_n < *threshold_m {
            warn!(
                "PublicKeyAggregator: threshold_n ({}) < threshold_m ({}) after expulsion — committee unviable",
                threshold_n, threshold_m
            );
            return Ok(state);
        }

        if keyshares.len() == *threshold_n && *threshold_n > 0 {
            let m = *threshold_m;
            let committee_n = *circuit_committee_n;
            let committee_h = *circuit_committee_h;
            info!("PublicKeyAggregator: enough keyshares after expulsion, transitioning to VerifyingC1");
            return Ok(PublicKeyAggregatorState::VerifyingC1 {
                submission_order: std::mem::take(submission_order),
                threshold_m: m,
                circuit_committee_n: committee_n,
                circuit_committee_h: committee_h,
                c1_proofs: std::mem::take(c1_proofs),
                no_proof_parties: Vec::new(),
            });
        }

        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks(byte: u8) -> ArcBytes {
        ArcBytes::from_bytes(&[byte])
    }

    fn collecting(threshold_n: usize, threshold_m: usize) -> PublicKeyAggregatorState {
        PublicKeyAggregatorState::init(threshold_n, threshold_m, Seed([0u8; 32]))
    }

    #[test]
    fn add_keyshare_below_threshold_stays_collecting() {
        // minimum committee maps (m=1, n=3) -> needs 3 parties.
        let state = collecting(3, 1);
        let next = PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None)
            .expect("add ok");
        match next {
            PublicKeyAggregatorState::Collecting {
                submission_order, ..
            } => assert_eq!(submission_order.len(), 1),
            _ => panic!("expected Collecting"),
        }
    }

    #[test]
    fn add_keyshare_duplicate_party_is_idempotent() {
        let state = collecting(3, 1);
        let state =
            PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None).unwrap();
        let state =
            PublicKeyAggregation::add_keyshare(state, ks(9), "node-0".into(), 0, None).unwrap();
        match state {
            PublicKeyAggregatorState::Collecting {
                submission_order,
                keyshares,
                ..
            } => {
                assert_eq!(submission_order.len(), 1, "duplicate party ignored");
                assert_eq!(keyshares.len(), 1);
            }
            _ => panic!("expected Collecting"),
        }
    }

    #[test]
    fn add_keyshare_reaching_threshold_transitions_to_verifying_c1() {
        let mut state = collecting(3, 1);
        for pid in 0..3u64 {
            state = PublicKeyAggregation::add_keyshare(
                state,
                ks(pid as u8),
                format!("node-{pid}"),
                pid,
                None,
            )
            .unwrap();
        }
        match state {
            PublicKeyAggregatorState::VerifyingC1 {
                submission_order,
                circuit_committee_n,
                circuit_committee_h,
                threshold_m,
                ..
            } => {
                assert_eq!(submission_order.len(), 3);
                assert_eq!(circuit_committee_n, 3);
                assert_eq!(circuit_committee_h, 2);
                assert_eq!(threshold_m, 1);
            }
            _ => panic!("expected VerifyingC1"),
        }
    }

    #[test]
    fn add_keyshare_wrong_state_errors() {
        let state = PublicKeyAggregatorState::VerifyingC1 {
            submission_order: vec![],
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            c1_proofs: vec![],
            no_proof_parties: vec![],
        };
        let err = PublicKeyAggregation::add_keyshare(state, ks(1), "n".into(), 0, None);
        assert!(err.is_err());
    }

    #[test]
    fn plan_c1_dispatch_splits_proofs_and_missing() {
        let submission_order = vec![
            (0u64, "node-0".to_string(), ks(1)),
            (1u64, "node-1".to_string(), ks(2)),
        ];
        // party 0 has no proof, party 1 has one
        let c1_proofs: Vec<Option<SignedProofPayload>> = vec![None, None];
        let plan = PublicKeyAggregation::plan_c1_dispatch(&submission_order, &c1_proofs);
        // both None -> both treated as no-proof
        assert_eq!(plan.no_proof_parties, vec![0, 1]);
        assert!(plan.party_proofs.is_empty());
    }

    #[test]
    fn select_honest_set_fails_below_circuit_h() {
        let e3_id = E3id::new("1", 1);
        let honest = vec![(0u64, "n0".to_string(), ks(1), None)];
        let sel =
            PublicKeyAggregation::select_honest_set(&e3_id, honest, &BTreeSet::new(), 3, 1, 1);
        assert!(matches!(sel, HonestSelection::Fail));
    }

    #[test]
    fn select_honest_set_caps_to_circuit_h_and_sorts() {
        let e3_id = E3id::new("1", 1);
        // 4 honest, circuit_h = 3 -> cap to lowest-3 party_ids {0,1,2}, sorted ascending.
        let honest = vec![
            (3u64, "n3".to_string(), ks(4), None),
            (1u64, "n1".to_string(), ks(2), None),
            (0u64, "n0".to_string(), ks(1), None),
            (2u64, "n2".to_string(), ks(3), None),
        ];
        let sel =
            PublicKeyAggregation::select_honest_set(&e3_id, honest, &BTreeSet::new(), 3, 1, 4);
        match sel {
            HonestSelection::Proceed {
                honest_entries,
                honest_party_ids,
            } => {
                let ids: Vec<u64> = honest_entries.iter().map(|(p, _, _, _)| *p).collect();
                assert_eq!(ids, vec![0, 1, 2]);
                assert_eq!(honest_party_ids, BTreeSet::from([0, 1, 2]));
            }
            HonestSelection::Fail => panic!("expected Proceed"),
        }
    }

    #[test]
    fn select_honest_set_fails_when_at_or_below_threshold_m() {
        let e3_id = E3id::new("1", 1);
        // 3 honest, circuit_h = 3 but threshold_m = 3 -> len <= m -> Fail.
        let honest = vec![
            (0u64, "n0".to_string(), ks(1), None),
            (1u64, "n1".to_string(), ks(2), None),
            (2u64, "n2".to_string(), ks(3), None),
        ];
        let sel =
            PublicKeyAggregation::select_honest_set(&e3_id, honest, &BTreeSet::new(), 3, 3, 3);
        assert!(matches!(sel, HonestSelection::Fail));
    }

    #[test]
    fn handle_member_expelled_removes_and_reduces_threshold() {
        let mut state = collecting(3, 1);
        for pid in 0..2u64 {
            state = PublicKeyAggregation::add_keyshare(
                state,
                ks(pid as u8),
                format!("node-{pid}"),
                pid,
                None,
            )
            .unwrap();
        }
        // expel node-0; threshold_n 3 -> 2, keyshares now 1 (< 2) -> stays Collecting
        let state = PublicKeyAggregation::handle_member_expelled(state, "node-0").unwrap();
        match state {
            PublicKeyAggregatorState::Collecting {
                threshold_n,
                submission_order,
                nodes,
                ..
            } => {
                assert_eq!(threshold_n, 2);
                assert_eq!(submission_order.len(), 1);
                assert!(!nodes.contains(&"node-0".to_string()));
            }
            _ => panic!("expected Collecting"),
        }
    }

    #[test]
    fn handle_member_expelled_transitions_when_enough_remain() {
        // Collecting with n=2, m=1, two keyshares present; expel one ->
        // threshold_n 1, keyshares 1 == n -> VerifyingC1.
        let state = PublicKeyAggregatorState::Collecting {
            threshold_n: 2,
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            keyshares: OrderedSet::from(vec![ks(10), ks(11)]),
            c1_proofs: vec![None, None],
            seed: Seed([0u8; 32]),
            nodes: OrderedSet::from(vec!["node-0".to_string(), "node-1".to_string()]),
            submission_order: vec![
                (0, "node-0".to_string(), ks(10)),
                (1, "node-1".to_string(), ks(11)),
            ],
        };
        let next = PublicKeyAggregation::handle_member_expelled(state, "node-0").unwrap();
        match next {
            PublicKeyAggregatorState::VerifyingC1 {
                circuit_committee_n,
                circuit_committee_h,
                submission_order,
                ..
            } => {
                assert_eq!(circuit_committee_n, 3);
                assert_eq!(circuit_committee_h, 2);
                assert_eq!(submission_order.len(), 1);
            }
            _ => panic!("expected VerifyingC1"),
        }
    }
}
