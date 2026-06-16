// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure tally logic for collecting `DecryptionKeyShared` events (Exchange #3).
//!
//! No actix/timer/bus dependencies — plain synchronous state plus tracing.
//! Unlike the other collectors the expected set is an arbitrary set of honest
//! party IDs (H minus self), not a contiguous `0..n` range.

use std::collections::{HashMap, HashSet};

use e3_events::{DecryptionKeyShared, E3id};
use tracing::info;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectionPhase {
    Collecting,
    Finished,
    TimedOut,
}

/// Result of feeding an input into the decryption-key-share collection.
#[derive(Debug)]
pub(crate) enum DecryptionShareOutcome {
    /// Nothing actionable (not collecting, unexpected party, or already-delivered
    /// expelled party scrubbed).
    Ignored,
    /// Input accepted, still waiting on more parties.
    Pending,
    /// All expected shares are present.
    Completed(HashMap<u64, DecryptionKeyShared>),
}

/// Pure tally for the decryption-key-shared collection phase.
pub(crate) struct DecryptionKeySharedCollection {
    e3_id: E3id,
    expected: HashSet<u64>,
    shares: HashMap<u64, DecryptionKeyShared>,
    phase: CollectionPhase,
}

impl DecryptionKeySharedCollection {
    /// Expect shares from the arbitrary `expected_parties` set (H minus self).
    pub fn new(e3_id: E3id, expected_parties: HashSet<u64>) -> Self {
        Self {
            e3_id,
            expected: expected_parties,
            shares: HashMap::new(),
            phase: CollectionPhase::Collecting,
        }
    }

    pub fn is_collecting(&self) -> bool {
        matches!(self.phase, CollectionPhase::Collecting)
    }

    pub fn expected_len(&self) -> usize {
        self.expected.len()
    }

    pub fn receive(&mut self, share: DecryptionKeyShared) -> DecryptionShareOutcome {
        if !self.is_collecting() {
            return DecryptionShareOutcome::Ignored;
        }

        let pid = share.party_id;
        if !self.expected.remove(&pid) {
            info!(
                e3_id = %self.e3_id,
                "DecryptionKeySharedCollection: party {} not in expected set, ignoring",
                pid
            );
            return DecryptionShareOutcome::Ignored;
        }

        info!(
            e3_id = %self.e3_id,
            "DecryptionKeySharedCollection: received from party {}, waiting on {}",
            pid,
            self.expected.len()
        );
        self.shares.insert(pid, share);
        self.finish_if_done()
    }

    pub fn expel(&mut self, party_id: u64) -> DecryptionShareOutcome {
        if !self.is_collecting() {
            return DecryptionShareOutcome::Ignored;
        }

        if !self.expected.remove(&party_id) {
            if self.shares.remove(&party_id).is_some() {
                info!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Expelled party {} already delivered decryption key share — removed from collected data",
                    party_id
                );
            } else {
                info!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Expelled party {} was not in expected set and had no collected data",
                    party_id
                );
            }
            return DecryptionShareOutcome::Ignored;
        }

        info!(
            e3_id = %self.e3_id,
            party_id,
            remaining = self.expected.len(),
            "Removed expelled party {} from decryption key shared collection, {} remaining",
            party_id,
            self.expected.len()
        );
        self.finish_if_done()
    }

    pub fn timeout(&mut self) -> Option<Vec<u64>> {
        if !self.is_collecting() {
            return None;
        }
        self.phase = CollectionPhase::TimedOut;
        Some(self.expected.iter().copied().collect())
    }

    fn finish_if_done(&mut self) -> DecryptionShareOutcome {
        if self.expected.is_empty() {
            info!(e3_id = %self.e3_id, "All DecryptionKeyShared events collected");
            self.phase = CollectionPhase::Finished;
            DecryptionShareOutcome::Completed(std::mem::take(&mut self.shares))
        } else {
            DecryptionShareOutcome::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{CircuitName, Proof, ProofPayload, ProofType, SignedProofPayload};
    use e3_utils::utility_types::ArcBytes;

    fn proof() -> SignedProofPayload {
        SignedProofPayload {
            payload: ProofPayload {
                e3_id: E3id::new("1", 1),
                proof_type: ProofType::C4aSkShareDecryption,
                proof: Proof::new(
                    CircuitName::DkgShareDecryption,
                    ArcBytes::from_bytes(&[]),
                    ArcBytes::from_bytes(&[]),
                ),
            },
            signature: ArcBytes::from_bytes(&[]),
        }
    }

    fn share(party_id: u64) -> DecryptionKeyShared {
        DecryptionKeyShared {
            e3_id: E3id::new("1", 1),
            party_id,
            node: String::new(),
            signed_sk_decryption_proof: proof(),
            signed_e_sm_decryption_proofs: Vec::new(),
            external: false,
        }
    }

    fn collection() -> DecryptionKeySharedCollection {
        // arbitrary expected set {2, 5}
        DecryptionKeySharedCollection::new(E3id::new("1", 1), HashSet::from([2, 5]))
    }

    #[test]
    fn collects_arbitrary_expected_set() {
        let mut c = collection();
        assert_eq!(c.expected_len(), 2);
        assert!(matches!(
            c.receive(share(5)),
            DecryptionShareOutcome::Pending
        ));
        match c.receive(share(2)) {
            DecryptionShareOutcome::Completed(shares) => {
                let mut ids: Vec<_> = shares.keys().copied().collect();
                ids.sort();
                assert_eq!(ids, vec![2, 5]);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(!c.is_collecting());
    }

    #[test]
    fn unexpected_party_ignored() {
        let mut c = collection();
        assert!(matches!(
            c.receive(share(9)),
            DecryptionShareOutcome::Ignored
        ));
    }

    #[test]
    fn expel_completes_remaining() {
        let mut c = collection();
        c.receive(share(2));
        match c.expel(5) {
            DecryptionShareOutcome::Completed(shares) => {
                let ids: Vec<_> = shares.keys().copied().collect();
                assert_eq!(ids, vec![2]);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn expel_after_delivery_scrubs() {
        let mut c = collection();
        c.receive(share(2));
        assert!(matches!(c.expel(2), DecryptionShareOutcome::Ignored));
        assert!(c.is_collecting());
        match c.expel(5) {
            DecryptionShareOutcome::Completed(shares) => assert!(shares.is_empty()),
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn timeout_reports_missing() {
        let mut c = collection();
        let mut missing = c.timeout().expect("missing");
        missing.sort();
        assert_eq!(missing, vec![2, 5]);
        assert!(c.timeout().is_none());
    }
}
