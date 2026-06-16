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

use e3_events::{E3id, Proof};
use e3_utils::utility_types::ArcBytes;

#[cfg(test)]
use e3_events::CircuitName;

/// Validate a decrypted result before it is written on-chain.
///
/// Returns `Ok(())` when exactly one decrypted output is present and (when
/// proof aggregation is enabled) the proof count matches the output count.
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
    // `decryption_aggregator_proofs` is empty when proof aggregation is disabled.
    // When enabled, its length must match `decrypted_output`.
    if !decryption_aggregator_proofs.is_empty()
        && decrypted_output.len() != decryption_aggregator_proofs.len()
    {
        return Err(format!(
            "E3 {} decrypted_output len ({}) != decryption_aggregator_proofs len ({})",
            e3_id,
            decrypted_output.len(),
            decryption_aggregator_proofs.len()
        ));
    }
    Ok(())
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
    fn accepts_single_output_no_proofs() {
        assert!(validate_plaintext_output(&e3(), &bytes(1), &[]).is_ok());
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
}
