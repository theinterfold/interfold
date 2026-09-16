// SPDX-License-Identifier: LGPL-3.0-only

//! Pure public-key aggregation decisions and state transitions.

use super::*;

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
    /// Buffer a keyshare until the accepted C4 roster has supplied all H keyshares.
    /// Reusing a `party_id` or receiving a keyshare after collection is idempotent.
    pub(crate) fn add_keyshare(
        mut state: PublicKeyAggregatorState,
        keyshare: ArcBytes,
        node: String,
        party_id: u64,
        c1_proof: Option<SignedProofPayload>,
        selected_roster: Option<&BTreeSet<u64>>,
    ) -> Result<PublicKeyAggregatorState> {
        let PublicKeyAggregatorState::Collecting {
            keyshares,
            c1_proofs,
            nodes,
            submission_order,
            ..
        } = &mut state
        else {
            return Ok(state);
        };

        if !submission_order.iter().any(|(pid, _, _)| *pid == party_id) {
            keyshares.insert(keyshare.clone());
            c1_proofs.push(c1_proof);
            nodes.insert(node.clone());
            info!(
                "add_keyshare: node={node} party_id={party_id} (arrival slot={})",
                submission_order.len()
            );
            submission_order.push((party_id, node, keyshare));
        }
        Self::begin_selected_c1(state, selected_roster)
    }

    /// Start C1 only after every member of the accepted dealer roster submitted.
    pub(crate) fn begin_selected_c1(
        mut state: PublicKeyAggregatorState,
        selected_roster: Option<&BTreeSet<u64>>,
    ) -> Result<PublicKeyAggregatorState> {
        let Some(selected) = selected_roster else {
            return Ok(state);
        };
        let PublicKeyAggregatorState::Collecting {
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            submission_order,
            c1_proofs,
            canonical_party_nodes,
            ..
        } = &mut state
        else {
            return Ok(state);
        };
        anyhow::ensure!(
            selected.len() == *circuit_committee_h
                && selected.iter().all(|&id| id < *circuit_committee_n as u64),
            "invalid selected DKG roster for C1 aggregation"
        );
        let mut selected_submissions = Vec::with_capacity(selected.len());
        let mut selected_proofs = Vec::with_capacity(selected.len());
        for (entry, proof) in submission_order.iter().zip(c1_proofs.iter()) {
            if selected.contains(&entry.0) {
                selected_submissions.push(entry.clone());
                selected_proofs.push(proof.clone());
            }
        }
        if selected_submissions.len() < selected.len() {
            return Ok(state);
        }
        Ok(PublicKeyAggregatorState::VerifyingC1 {
            submission_order: selected_submissions,
            threshold_m: *threshold_m,
            circuit_committee_n: *circuit_committee_n,
            circuit_committee_h: *circuit_committee_h,
            c1_proofs: selected_proofs,
            no_proof_parties: Vec::new(),
            canonical_party_nodes: std::mem::take(canonical_party_nodes),
        })
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
    /// collections aligned. C1 still waits for the accepted dealer roster.
    pub(crate) fn handle_member_expelled(
        mut state: PublicKeyAggregatorState,
        node: Address,
    ) -> Result<PublicKeyAggregatorState> {
        let PublicKeyAggregatorState::Collecting {
            threshold_n,
            threshold_m,
            keyshares,
            c1_proofs,
            nodes,
            submission_order,
            ..
        } = &mut state
        else {
            return Ok(state);
        };

        // Find the expelled node's index in submission_order and remove from
        // all parallel collections so they stay aligned.
        if let Some(idx) = submission_order.iter().position(|(_, candidate, _)| {
            candidate
                .parse::<Address>()
                .is_ok_and(|candidate| candidate == node)
        }) {
            let (_, _, expelled_keyshare) = submission_order.remove(idx);
            keyshares.remove(&expelled_keyshare);
            c1_proofs.remove(idx);
        }

        let expelled_node = nodes
            .iter()
            .find(|candidate| {
                candidate
                    .parse::<Address>()
                    .is_ok_and(|candidate| candidate == node)
            })
            .cloned();
        if let Some(expelled_node) = expelled_node {
            nodes.remove(&expelled_node);
        }

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

        Ok(state)
    }
}
