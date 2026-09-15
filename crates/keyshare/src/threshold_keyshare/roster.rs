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
            && c2b.payload.proof_type == ProofType::C2bESmShareComputation,
        "dealer proof pair does not match the E3 and C2 proof types"
    );
    let contribution_hash: [u8; 32] = keccak256(
        (
            keccak256(&**pk_share),
            c2a.payload.digest()?,
            c2b.payload.digest()?,
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

    fn dealers(ids: &[u64]) -> Vec<DkgDealer> {
        ids.iter()
            .map(|&party_id| DkgDealer {
                party_id,
                contribution_hash: [party_id as u8; 32],
            })
            .collect()
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
