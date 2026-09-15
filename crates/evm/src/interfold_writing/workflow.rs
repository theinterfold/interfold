// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure validation for on-chain plaintext-output publication.
//!
//! The actor only performs the chain preflight + transaction once these
//! invariants hold; rejecting a malformed result is safer than a partial
//! on-chain write.

use e3_events::{E3Stage, E3id, Proof};
use e3_utils::utility_types::ArcBytes;
use std::collections::HashMap;
use std::time::Duration;

#[cfg(test)]
use e3_events::CircuitName;

/// Validate a decrypted result before it is written on-chain.
///
/// Returns `Ok(())` when exactly one decrypted output is present and the non-empty proof list
/// matches the output count.
/// Returns a human-readable error message otherwise.
pub(crate) fn validate_plaintext_output(
    e3_id: &E3id,
    decrypted_output: &[ArcBytes],
    decryption_aggregator_proofs: &[Proof],
) -> Result<(), String> {
    if decrypted_output.is_empty() {
        return Err("Decrypted output was empty!".to_string());
    }
    // Reject multi-output results — partial on-chain write is worse than failing.
    if decrypted_output.len() > 1 {
        return Err(format!(
            "E3 {} has {} decrypted outputs but only single-output is supported. \
            Refusing partial on-chain write.",
            e3_id,
            decrypted_output.len()
        ));
    }
    if decryption_aggregator_proofs.is_empty() {
        return Err(format!(
            "E3 {} has no decryption aggregator proof payload",
            e3_id
        ));
    }
    if decrypted_output.len() != decryption_aggregator_proofs.len() {
        return Err(format!(
            "E3 {} decrypted_output len ({}) != decryption_aggregator_proofs len ({})",
            e3_id,
            decrypted_output.len(),
            decryption_aggregator_proofs.len()
        ));
    }
    Ok(())
}

/// Return a deterministic wait for one committee member's deadline attempt.
/// A past deadline still keeps the party-id stagger after restart.
pub(crate) fn failure_watch_delay(
    now_unix_secs: u64,
    deadline_unix_secs: u64,
    party_id: Option<u64>,
    permissionless_grace_secs: u64,
    party_stagger_secs: u64,
) -> Duration {
    let delay = match party_id {
        Some(party_id) => deadline_unix_secs
            .saturating_sub(now_unix_secs)
            .saturating_add(1)
            .saturating_add(party_id.saturating_mul(party_stagger_secs)),
        None => {
            let permissionless_at = if permissionless_grace_secs == 0 {
                deadline_unix_secs.saturating_add(1)
            } else {
                deadline_unix_secs.saturating_add(permissionless_grace_secs)
            };
            permissionless_at.saturating_sub(now_unix_secs)
        }
    };
    Duration::from_secs(delay)
}

/// Return the finalized committee party that can act during the protected grace window.
///
/// A `Requested` E3 has only provisional ticket candidates. The registry does not consider those
/// candidates active committee members, so they must wait for permissionless failure marking.
pub(crate) fn failure_watch_party_id(stage: &E3Stage, party_id: Option<u64>) -> Option<u64> {
    if *stage == E3Stage::Requested {
        None
    } else {
        party_id
    }
}

/// Reject stage-discovery results that a newer lifecycle event has superseded.
#[derive(Debug, Default)]
pub(crate) struct FailureStageDiscoveryGate {
    next_generation: u64,
    active: HashMap<E3id, u64>,
}

impl FailureStageDiscoveryGate {
    pub(crate) fn start(&mut self, e3_id: E3id) -> u64 {
        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        self.active.insert(e3_id, generation);
        generation
    }

    pub(crate) fn invalidate(&mut self, e3_id: &E3id) {
        self.active.remove(e3_id);
    }

    pub(crate) fn complete(&mut self, e3_id: &E3id, generation: u64) -> bool {
        if self.active.get(e3_id) != Some(&generation) {
            return false;
        }
        self.active.remove(e3_id);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e3() -> E3id {
        E3id::new("1", 1)
    }

    fn bytes(n: usize) -> Vec<ArcBytes> {
        (0..n).map(|i| ArcBytes::from_bytes(&[i as u8])).collect()
    }

    fn proof() -> Proof {
        Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[0u8]),
            ArcBytes::from_bytes(&[0u8]),
        )
    }

    #[test]
    fn rejects_empty_output() {
        let err = validate_plaintext_output(&e3(), &[], &[]).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn rejects_multi_output() {
        let err = validate_plaintext_output(&e3(), &bytes(2), &[]).unwrap_err();
        assert!(err.contains("single-output"));
    }

    #[test]
    fn rejects_single_output_without_proof() {
        let err = validate_plaintext_output(&e3(), &bytes(1), &[]).unwrap_err();
        assert!(err.contains("no decryption aggregator proof"));
    }

    #[test]
    fn rejects_proof_count_mismatch() {
        let proofs = vec![proof(), proof()];
        let err = validate_plaintext_output(&e3(), &bytes(1), &proofs).unwrap_err();
        assert!(err.contains("!="));
    }

    #[test]
    fn accepts_matching_single_proof() {
        let proofs = vec![proof()];
        assert!(validate_plaintext_output(&e3(), &bytes(1), &proofs).is_ok());
    }

    #[test]
    fn failure_watch_stagger_survives_restart() {
        assert_eq!(failure_watch_delay(100, 160, Some(0), 90, 15).as_secs(), 61);
        assert_eq!(failure_watch_delay(100, 160, Some(2), 90, 15).as_secs(), 91);
        assert_eq!(failure_watch_delay(200, 160, Some(0), 90, 15).as_secs(), 1);
        assert_eq!(failure_watch_delay(200, 160, Some(2), 90, 15).as_secs(), 31);
    }

    #[test]
    fn requested_stage_failure_without_party_waits_for_permissionless_grace() {
        assert_eq!(failure_watch_delay(100, 160, None, 90, 15).as_secs(), 150);
        assert_eq!(failure_watch_delay(200, 160, None, 90, 15).as_secs(), 50);
        assert_eq!(failure_watch_delay(250, 160, None, 90, 15).as_secs(), 0);
        assert_eq!(failure_watch_delay(160, 160, None, 0, 15).as_secs(), 1);
    }

    #[test]
    fn requested_stage_ignores_provisional_party_id() {
        assert_eq!(failure_watch_party_id(&E3Stage::Requested, Some(2)), None);
        assert_eq!(
            failure_watch_party_id(&E3Stage::CommitteeFinalized, Some(2)),
            Some(2)
        );
    }

    #[test]
    fn stage_discovery_ignores_superseded_results() {
        let e3_id = E3id::new("7", 1);
        let mut gate = FailureStageDiscoveryGate::default();

        let first = gate.start(e3_id.clone());
        let second = gate.start(e3_id.clone());
        assert!(!gate.complete(&e3_id, first));
        assert!(gate.complete(&e3_id, second));

        let invalidated = gate.start(e3_id.clone());
        gate.invalidate(&e3_id);
        assert!(!gate.complete(&e3_id, invalidated));
    }
}
