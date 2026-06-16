// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure tally logic for collecting threshold (DKG) shares from the committee.
//!
//! No actix/timer/bus dependencies — plain synchronous state plus tracing.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use e3_events::{E3id, PartyId, SignedProofPayload, ThresholdShare};
use tracing::info;

/// Proofs received alongside a threshold share from a sender.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReceivedShareProofs {
    /// Signed C2a proof (sk share computation) from the sender.
    pub signed_c2a_proof: Option<SignedProofPayload>,
    /// Signed C2b proof (e_sm share computation) from the sender.
    pub signed_c2b_proof: Option<SignedProofPayload>,
    /// Signed C3a proofs (sk share encryption per modulus row).
    pub signed_c3a_proofs: Vec<SignedProofPayload>,
    /// Signed C3b proofs (e_sm share encryption per modulus row).
    pub signed_c3b_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectionPhase {
    Collecting,
    Finished,
    TimedOut,
}

/// Result of feeding an input into the share collection.
#[derive(Debug)]
pub(crate) enum ShareCollectOutcome {
    /// Nothing actionable (not collecting, unexpected party, or already-delivered
    /// expelled party scrubbed).
    Ignored,
    /// Input accepted, still waiting on more parties.
    Pending,
    /// All expected shares are present.
    Completed {
        shares: HashMap<PartyId, Arc<ThresholdShare>>,
        proofs: HashMap<PartyId, ReceivedShareProofs>,
    },
}

/// Pure tally for the threshold-share collection phase.
pub(crate) struct ThresholdShareCollection {
    e3_id: E3id,
    todo: HashSet<PartyId>,
    shares: HashMap<PartyId, Arc<ThresholdShare>>,
    share_proofs: HashMap<PartyId, ReceivedShareProofs>,
    phase: CollectionPhase,
}

impl ThresholdShareCollection {
    /// Expect shares from parties `0..total` excluding `own_party_id`
    /// (own share is consumed locally for C4).
    pub fn new(e3_id: E3id, total: u64, own_party_id: u64) -> Self {
        Self {
            e3_id,
            todo: (0..total).filter(|p| *p != own_party_id).collect(),
            shares: HashMap::new(),
            share_proofs: HashMap::new(),
            phase: CollectionPhase::Collecting,
        }
    }

    pub fn is_collecting(&self) -> bool {
        matches!(self.phase, CollectionPhase::Collecting)
    }

    pub fn receive(
        &mut self,
        share: Arc<ThresholdShare>,
        proofs: ReceivedShareProofs,
    ) -> ShareCollectOutcome {
        if !self.is_collecting() {
            info!(e3_id = %self.e3_id, "ThresholdShareCollection is not collecting, ignoring");
            return ShareCollectOutcome::Ignored;
        }

        let pid = share.party_id;
        if self.todo.take(&pid).is_none() {
            info!(
                e3_id = %self.e3_id,
                "Error: {} was not in threshold share collector's ID list",
                pid
            );
            return ShareCollectOutcome::Ignored;
        }

        info!(e3_id = %self.e3_id, "Inserting... waiting on: {}", self.todo.len());
        self.share_proofs.insert(pid, proofs);
        self.shares.insert(pid, share);
        self.finish_if_done()
    }

    pub fn expel(&mut self, party_id: PartyId) -> ShareCollectOutcome {
        if !self.is_collecting() {
            return ShareCollectOutcome::Ignored;
        }

        if !self.todo.remove(&party_id) {
            let had_share = self.shares.remove(&party_id).is_some();
            let had_proofs = self.share_proofs.remove(&party_id).is_some();
            if had_share || had_proofs {
                info!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Expelled party {} already delivered share — removed from collected data",
                    party_id
                );
            } else {
                info!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Expelled party {} was not in share collection todo set and had no collected data",
                    party_id
                );
            }
            return ShareCollectOutcome::Ignored;
        }

        info!(
            e3_id = %self.e3_id,
            party_id,
            remaining = self.todo.len(),
            "Removed expelled party {} from threshold share collection, {} remaining",
            party_id,
            self.todo.len()
        );
        self.finish_if_done()
    }

    pub fn timeout(&mut self) -> Option<Vec<PartyId>> {
        if !self.is_collecting() {
            return None;
        }
        self.phase = CollectionPhase::TimedOut;
        Some(self.todo.iter().copied().collect())
    }

    fn finish_if_done(&mut self) -> ShareCollectOutcome {
        if self.todo.is_empty() {
            info!(e3_id = %self.e3_id, "We have received all threshold shares");
            self.phase = CollectionPhase::Finished;
            ShareCollectOutcome::Completed {
                shares: self.shares.clone(),
                proofs: std::mem::take(&mut self.share_proofs),
            }
        } else {
            ShareCollectOutcome::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proofs() -> ReceivedShareProofs {
        ReceivedShareProofs {
            signed_c2a_proof: None,
            signed_c2b_proof: None,
            signed_c3a_proofs: Vec::new(),
            signed_c3b_proofs: Vec::new(),
        }
    }

    fn share(party_id: u64) -> Arc<ThresholdShare> {
        Arc::new(ThresholdShare {
            party_id,
            pk_share: e3_utils::utility_types::ArcBytes::from_bytes(&[]),
            sk_sss: Default::default(),
            esi_sss: Vec::new(),
        })
    }

    fn collection() -> ThresholdShareCollection {
        // total 3, own party 1 -> expect parties {0, 2}
        ThresholdShareCollection::new(E3id::new("1", 1), 3, 1)
    }

    #[test]
    fn excludes_own_party_from_todo() {
        let mut c = collection();
        // party 0 then party 2 completes (own party 1 excluded)
        assert!(matches!(
            c.receive(share(0), proofs()),
            ShareCollectOutcome::Pending
        ));
        match c.receive(share(2), proofs()) {
            ShareCollectOutcome::Completed { shares, .. } => {
                let mut ids: Vec<_> = shares.keys().copied().collect();
                ids.sort();
                assert_eq!(ids, vec![0, 2]);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn own_party_share_is_unexpected() {
        let mut c = collection();
        assert!(matches!(
            c.receive(share(1), proofs()),
            ShareCollectOutcome::Ignored
        ));
    }

    #[test]
    fn expel_completes_with_remaining() {
        let mut c = collection();
        c.receive(share(0), proofs());
        match c.expel(2) {
            ShareCollectOutcome::Completed { shares, .. } => {
                let ids: Vec<_> = shares.keys().copied().collect();
                assert_eq!(ids, vec![0]);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn expel_after_delivery_scrubs_data() {
        let mut c = collection();
        c.receive(share(0), proofs());
        assert!(matches!(c.expel(0), ShareCollectOutcome::Ignored));
        assert!(c.is_collecting());
        match c.expel(2) {
            ShareCollectOutcome::Completed { shares, proofs } => {
                assert!(shares.is_empty(), "scrubbed share must not remain");
                assert!(proofs.is_empty());
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn timeout_reports_missing() {
        let mut c = collection();
        let mut missing = c.timeout().expect("missing");
        missing.sort();
        assert_eq!(missing, vec![0, 2]);
        assert!(c.timeout().is_none());
    }
}
