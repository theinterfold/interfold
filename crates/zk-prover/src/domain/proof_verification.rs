// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure validation for externally-received encryption keys (C0 proofs).
//!
//! The [`crate::actors::proof_verification::ProofVerificationActor`] is a thin
//! transport shell; this module owns the signature recovery + circuit/proof
//! consistency checks as a pure function. No actix / `BusHandle` concerns.

use alloy::primitives::Address;
use e3_events::{Proof, SignedProofPayload};

/// A validated external key, ready to be queued for ZK verification.
#[derive(Debug)]
pub(crate) struct ValidatedExternalKey {
    pub(crate) signed_payload: SignedProofPayload,
    pub(crate) recovered_signer: Address,
}

/// Validate an externally-received encryption key before dispatching it for ZK
/// verification.
///
/// Returns the cloned signed payload plus the recovered ECDSA signer address on
/// success, or a human-readable rejection reason. Signed proofs are mandatory.
pub(crate) fn validate_external_key(
    party_id: u64,
    key_proof: Option<&Proof>,
    signed_payload: Option<&SignedProofPayload>,
) -> Result<ValidatedExternalKey, String> {
    let Some(proof) = key_proof else {
        return Err(format!(
            "External key from party {party_id} is missing C0 proof - rejecting"
        ));
    };

    let Some(signed) = signed_payload else {
        return Err(format!(
            "Key from party {party_id} has no signed payload - rejecting (signed proofs are required)"
        ));
    };

    let recovered_signer = signed.recover_address().map_err(|err| {
        format!("Invalid signature on key from party {party_id} - rejecting: {err}")
    })?;

    // Validate circuit name matches expected ProofType circuits.
    let expected_circuits = signed.payload.proof_type.circuit_names();
    if !expected_circuits.contains(&signed.payload.proof.circuit) {
        return Err(format!(
            "Circuit name mismatch for key from party {}: expected {:?}, got {:?}",
            party_id, expected_circuits, signed.payload.proof.circuit
        ));
    }

    if *proof != signed.payload.proof {
        return Err(format!(
            "Proof mismatch for key from party {party_id}: key.proof differs from \
             signed_payload.payload.proof — rejecting"
        ));
    }

    Ok(ValidatedExternalKey {
        signed_payload: signed.clone(),
        recovered_signer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use e3_events::{CircuitName, E3id, ProofPayload, ProofType};
    use e3_utils::utility_types::ArcBytes;

    fn signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn proof() -> Proof {
        Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[10, 20, 30]),
            ArcBytes::from_bytes(&[100, 200]),
        )
    }

    fn signed_for(proof: &Proof) -> SignedProofPayload {
        let payload = ProofPayload {
            e3_id: E3id::new("1", 42),
            proof_type: ProofType::C0PkBfv,
            proof: proof.clone(),
        };
        SignedProofPayload::sign(payload, &signer()).expect("signing should succeed")
    }

    #[test]
    fn rejects_missing_proof() {
        let p = proof();
        let signed = signed_for(&p);
        let err = validate_external_key(1, None, Some(&signed)).unwrap_err();
        assert!(err.contains("missing C0 proof"));
    }

    #[test]
    fn rejects_missing_signed_payload() {
        let p = proof();
        let err = validate_external_key(1, Some(&p), None).unwrap_err();
        assert!(err.contains("no signed payload"));
    }

    #[test]
    fn rejects_proof_mismatch() {
        let p = proof();
        let signed = signed_for(&p);
        let other = Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[9, 9, 9]),
            ArcBytes::from_bytes(&[1, 2]),
        );
        let err = validate_external_key(1, Some(&other), Some(&signed)).unwrap_err();
        assert!(err.contains("Proof mismatch"));
    }

    #[test]
    fn accepts_valid_key() {
        let p = proof();
        let signed = signed_for(&p);
        let validated = validate_external_key(1, Some(&p), Some(&signed)).expect("should validate");
        assert_eq!(validated.recovered_signer, signer().address());
    }
}
