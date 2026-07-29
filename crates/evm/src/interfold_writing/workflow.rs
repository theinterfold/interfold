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

/// The only plaintext shape accepted by the current contract transaction.
/// Callers cannot reach the transaction boundary with an ambiguous vector.
#[derive(Debug)]
pub(crate) struct PlaintextPublication {
    pub(crate) decrypted_output: ArcBytes,
    pub(crate) proof: Proof,
}

/// Validate and narrow a decrypted result before it is written on-chain.
///
/// Returns an owned single-output transaction payload when exactly one
/// decrypted output and one proof are present.
/// Returns a human-readable error message otherwise.
pub(crate) fn validate_plaintext_output(
    e3_id: &E3id,
    decrypted_output: Vec<ArcBytes>,
    decryption_aggregator_proofs: Vec<Proof>,
) -> Result<PlaintextPublication, String> {
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
    let [decrypted_output] = <[ArcBytes; 1]>::try_from(decrypted_output)
        .map_err(|_| format!("E3 {e3_id} plaintext output did not narrow to one value"))?;
    let [proof] = <[Proof; 1]>::try_from(decryption_aggregator_proofs)
        .map_err(|_| format!("E3 {e3_id} proof payload did not narrow to one value"))?;
    Ok(PlaintextPublication {
        decrypted_output,
        proof,
    })
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
        let err = validate_plaintext_output(&e3(), vec![], vec![]).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn rejects_multi_output() {
        let err = validate_plaintext_output(&e3(), bytes(2), vec![]).unwrap_err();
        assert!(err.contains("single-output"));
    }

    #[test]
    fn rejects_single_output_without_proof() {
        let err = validate_plaintext_output(&e3(), bytes(1), vec![]).unwrap_err();
        assert!(err.contains("no decryption aggregator proof"));
    }

    #[test]
    fn rejects_proof_count_mismatch() {
        let proofs = vec![proof(), proof()];
        let err = validate_plaintext_output(&e3(), bytes(1), proofs).unwrap_err();
        assert!(err.contains("!="));
    }

    #[test]
    fn accepts_matching_single_proof() {
        let publication = validate_plaintext_output(&e3(), bytes(1), vec![proof()]).unwrap();
        assert_eq!(publication.decrypted_output.extract_bytes(), [0]);
        assert_eq!(publication.proof.circuit, CircuitName::PkBfv);
    }
}
