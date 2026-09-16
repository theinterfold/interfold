// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure selection of an H-dealer set with complete, matching recipient receipts.

use std::collections::BTreeMap;

use alloy::primitives::keccak256;
use alloy::sol_types::SolValue;
use anyhow::{ensure, Result};
use e3_events::{DkgDealer, E3id, ProofType, SignedProofPayload};
use e3_utils::ArcBytes;

pub(crate) fn dealer_identity(
    e3_id: &E3id,
    party_id: u64,
    pk_share: &ArcBytes,
    c2a: &SignedProofPayload,
    c2b: &SignedProofPayload,
) -> Result<DkgDealer> {
    ensure!(
        c2a.payload.e3_id == *e3_id
            && c2b.payload.e3_id == *e3_id
            && c2a.payload.proof_type == ProofType::C2aSkShareComputation
            && c2b.payload.proof_type == ProofType::C2bESmShareComputation
            && c2a
                .payload
                .proof_type
                .circuit_names()
                .contains(&c2a.payload.proof.circuit)
            && c2b
                .payload
                .proof_type
                .circuit_names()
                .contains(&c2b.payload.proof.circuit),
        "dealer proof pair does not match the E3, C2 proof types, and circuits"
    );
    let contribution_hash: [u8; 32] = keccak256(
        (
            keccak256(&**pk_share),
            c2a.payload.statement_digest()?,
            c2b.payload.statement_digest()?,
        )
            .abi_encode(),
    )
    .into();
    Ok(DkgDealer {
        party_id,
        contribution_hash,
    })
}

/// Find the first H-party set whose members each hold the same version of
/// every selected dealer contribution. Party IDs and dealer versions are
/// checked before this function receives the readiness map.
pub(crate) fn select_ready_roster(
    ready: &BTreeMap<u64, Vec<DkgDealer>>,
    h: usize,
) -> Option<Vec<DkgDealer>> {
    if h == 0 || ready.len() < h {
        return None;
    }

    let ids: Vec<u64> = ready.keys().copied().collect();
    let mut selected = Vec::with_capacity(h);
    select_from(ready, &ids, h, 0, &mut selected)
}

fn select_from(
    ready: &BTreeMap<u64, Vec<DkgDealer>>,
    ids: &[u64],
    h: usize,
    start: usize,
    selected: &mut Vec<DkgDealer>,
) -> Option<Vec<DkgDealer>> {
    if selected.len() == h {
        return Some(selected.clone());
    }
    if selected.len() + ids.len().saturating_sub(start) < h {
        return None;
    }

    for idx in start..ids.len() {
        let candidate_id = ids[idx];
        let candidate_ready = &ready[&candidate_id];
        let own = candidate_ready
            .iter()
            .find(|dealer| dealer.party_id == candidate_id);
        let Some(own) = own else {
            continue;
        };
        if !selected.iter().all(|dealer| {
            candidate_ready.iter().any(|seen| seen == dealer)
                && ready[&dealer.party_id].iter().any(|seen| seen == own)
        }) {
            continue;
        }
        selected.push(own.clone());
        if let Some(roster) = select_from(ready, ids, h, idx + 1, selected) {
            return Some(roster);
        }
        selected.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{CircuitName, Proof, ProofPayload};

    fn dealers(ids: &[u64]) -> Vec<DkgDealer> {
        ids.iter()
            .map(|&party_id| DkgDealer {
                party_id,
                contribution_hash: [party_id as u8; 32],
            })
            .collect()
    }

    fn signed_c2(
        e3_id: &E3id,
        proof_type: ProofType,
        circuit: CircuitName,
        proof_data: &[u8],
        public_signals: &[u8],
    ) -> SignedProofPayload {
        SignedProofPayload {
            payload: ProofPayload {
                e3_id: e3_id.clone(),
                proof_type,
                proof: Proof::new(
                    circuit,
                    ArcBytes::from_bytes(proof_data),
                    ArcBytes::from_bytes(public_signals),
                ),
            },
            signature: ArcBytes::from_bytes(&[]),
        }
    }

    #[test]
    fn dealer_identity_is_stable_across_equivalent_proofs() {
        let e3_id = E3id::new("42", 1);
        let c2a_first = signed_c2(
            &e3_id,
            ProofType::C2aSkShareComputation,
            CircuitName::SkShareComputation,
            &[1],
            &[10],
        );
        let c2a_second = signed_c2(
            &e3_id,
            ProofType::C2aSkShareComputation,
            CircuitName::SkShareComputation,
            &[2],
            &[10],
        );
        let c2b_first = signed_c2(
            &e3_id,
            ProofType::C2bESmShareComputation,
            CircuitName::ESmShareComputation,
            &[3],
            &[20],
        );
        let c2b_second = signed_c2(
            &e3_id,
            ProofType::C2bESmShareComputation,
            CircuitName::ESmShareComputation,
            &[4],
            &[20],
        );
        let pk_share = ArcBytes::from_bytes(&[30]);

        assert_eq!(
            dealer_identity(&e3_id, 0, &pk_share, &c2a_first, &c2b_first).unwrap(),
            dealer_identity(&e3_id, 0, &pk_share, &c2a_second, &c2b_second).unwrap()
        );
    }

    #[test]
    fn dealer_identity_changes_with_public_statement() {
        let e3_id = E3id::new("42", 1);
        let c2a = signed_c2(
            &e3_id,
            ProofType::C2aSkShareComputation,
            CircuitName::SkShareComputation,
            &[1],
            &[10],
        );
        let c2a_changed = signed_c2(
            &e3_id,
            ProofType::C2aSkShareComputation,
            CircuitName::SkShareComputation,
            &[1],
            &[11],
        );
        let c2b = signed_c2(
            &e3_id,
            ProofType::C2bESmShareComputation,
            CircuitName::ESmShareComputation,
            &[2],
            &[20],
        );
        let pk_share = ArcBytes::from_bytes(&[30]);

        assert_ne!(
            dealer_identity(&e3_id, 0, &pk_share, &c2a, &c2b).unwrap(),
            dealer_identity(&e3_id, 0, &pk_share, &c2a_changed, &c2b).unwrap()
        );
    }

    #[test]
    fn skips_an_offline_nonprefix_member() {
        let mut ready = BTreeMap::new();
        for recipient in [0, 1, 3, 4] {
            ready.insert(recipient, dealers(&[0, 1, 3, 4]));
        }
        let roster = select_ready_roster(&ready, 3).unwrap();
        assert_eq!(
            roster
                .iter()
                .map(|dealer| dealer.party_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 3]
        );
    }

    #[test]
    fn small_committee_selects_fourteen_mutually_ready_dealers() {
        let available: Vec<u64> = (0..19).filter(|id| ![2, 7].contains(id)).collect();
        let ready = available
            .iter()
            .map(|&recipient| (recipient, dealers(&available)))
            .collect();
        let roster = select_ready_roster(&ready, 14).unwrap();
        assert_eq!(
            roster
                .iter()
                .map(|dealer| dealer.party_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn selects_h_ready_parties_without_the_primary_proposer() {
        let mut ready = BTreeMap::new();
        for recipient in [1, 2, 3, 4] {
            ready.insert(recipient, dealers(&[1, 2, 3, 4]));
        }
        let roster = select_ready_roster(&ready, 3).unwrap();
        assert_eq!(
            roster
                .iter()
                .map(|dealer| dealer.party_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn excludes_a_dealer_missing_from_one_selected_recipient() {
        let mut ready = BTreeMap::new();
        ready.insert(0, dealers(&[0, 1, 2, 3]));
        ready.insert(1, dealers(&[0, 1, 3]));
        ready.insert(2, dealers(&[0, 1, 2, 3]));
        ready.insert(3, dealers(&[0, 1, 2, 3]));
        let roster = select_ready_roster(&ready, 3).unwrap();
        assert_eq!(
            roster
                .iter()
                .map(|dealer| dealer.party_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 3]
        );
    }

    #[test]
    fn rejects_different_versions_of_the_same_dealer() {
        let mut ready = BTreeMap::new();
        ready.insert(0, dealers(&[0, 1, 2]));
        let mut recipient_one = dealers(&[0, 1, 2]);
        recipient_one[0].contribution_hash[0] ^= 1;
        ready.insert(1, recipient_one);
        ready.insert(2, dealers(&[0, 1, 2]));
        assert!(select_ready_roster(&ready, 3).is_none());
    }

    #[test]
    fn cannot_select_below_h() {
        let ready = BTreeMap::from([(0, dealers(&[0, 1]))]);
        assert!(select_ready_roster(&ready, 2).is_none());
    }
}
