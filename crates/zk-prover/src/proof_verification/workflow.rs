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
use e3_events::{E3Stage, E3id, EncryptionKeyReceived, Proof, ProofType, SignedProofPayload};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::compute_dkg_pk_commitment_from_public_key_bytes;

/// A validated external key, ready to be queued for ZK verification.
#[derive(Debug)]
pub(crate) struct ValidatedExternalKey {
    pub(crate) signed_payload: SignedProofPayload,
    pub(crate) recovered_signer: Address,
}

pub(crate) fn dkg_has_ended(stage: &E3Stage) -> bool {
    matches!(stage, E3Stage::KeyPublished | E3Stage::CiphertextReady) || stage.is_terminal()
}

/// Apply the same admission checks to live and recovered C0 inputs.
pub(crate) fn validate_received_key(
    input: &EncryptionKeyReceived,
    expected_signer: &Address,
    preset: BfvPreset,
) -> Result<ValidatedExternalKey, String> {
    let validated = validate_external_key(
        &input.e3_id,
        expected_signer,
        input.key.party_id,
        input.key.proof.as_ref(),
        input.key.signed_payload.as_ref(),
    )?;
    let commitment = compute_dkg_pk_commitment_from_public_key_bytes(&input.key.pk_bfv, preset)
        .map_err(|error| format!("Could not bind C0 proof to advertised BFV key: {error}"))?;
    validate_external_key_commitment(
        input.key.party_id,
        &validated.signed_payload.payload.proof,
        &commitment,
    )?;
    Ok(validated)
}

/// Validate an externally-received encryption key before dispatching it for ZK
/// verification.
///
/// Returns the cloned signed payload plus the recovered ECDSA signer address on
/// success, or a human-readable rejection reason. Signed proofs are mandatory and are
/// bound to the outer E3, canonical committee party, C0 proof type, and advertised key bytes.
pub(crate) fn validate_external_key(
    expected_e3_id: &E3id,
    expected_signer: &Address,
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

    if signed.payload.e3_id != *expected_e3_id {
        return Err(format!(
            "Key from party {party_id} carries a C0 payload for E3 {}, expected {} - rejecting",
            signed.payload.e3_id, expected_e3_id
        ));
    }

    if signed.payload.proof_type != ProofType::C0PkBfv {
        return Err(format!(
            "Key from party {party_id} carries proof type {:?}, expected {:?} - rejecting",
            signed.payload.proof_type,
            ProofType::C0PkBfv
        ));
    }

    let recovered_signer = signed.recover_address().map_err(|err| {
        format!("Invalid signature on key from party {party_id} - rejecting: {err}")
    })?;
    if recovered_signer != *expected_signer {
        return Err(format!(
            "Key from party {party_id} was signed by {recovered_signer}, expected committee member {expected_signer} - rejecting"
        ));
    }

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

/// Bind an already identity-validated C0 proof to the BFV key bytes advertised alongside it.
/// Kept separate so callers can reject unauthenticated payloads before computing the key
/// commitment, which is materially more expensive than signature and metadata checks.
pub(crate) fn validate_external_key_commitment(
    party_id: u64,
    proof: &Proof,
    expected_key_commitment: &[u8; 32],
) -> Result<(), String> {
    let proof_commitment = proof
        .extract_output("pk_commitment")
        .ok_or_else(|| format!("C0 proof from party {party_id} has no pk_commitment output"))?;
    if &proof_commitment[..] != expected_key_commitment.as_slice() {
        return Err(format!(
            "C0 proof commitment does not match advertised BFV key for party {party_id} - rejecting"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use e3_events::{CircuitName, E3id, ProofPayload, ProofType};
    use e3_utils::utility_types::ArcBytes;

    const KEY_COMMITMENT: [u8; 32] = [0x42; 32];

    fn signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn other_signer() -> PrivateKeySigner {
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
            .parse()
            .unwrap()
    }

    fn e3_id() -> E3id {
        E3id::new("1", 42)
    }

    fn proof() -> Proof {
        Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[10, 20, 30]),
            ArcBytes::from_bytes(&KEY_COMMITMENT),
        )
    }

    fn signed_for(
        proof: &Proof,
        e3_id: E3id,
        proof_type: ProofType,
        signer: &PrivateKeySigner,
    ) -> SignedProofPayload {
        let payload = ProofPayload {
            e3_id,
            proof_type,
            proof: proof.clone(),
        };
        SignedProofPayload::sign(payload, signer).expect("signing should succeed")
    }

    fn valid_signed(proof: &Proof) -> SignedProofPayload {
        signed_for(proof, e3_id(), ProofType::C0PkBfv, &signer())
    }

    fn validate(
        proof: Option<&Proof>,
        signed: Option<&SignedProofPayload>,
    ) -> Result<ValidatedExternalKey, String> {
        let validated = validate_external_key(&e3_id(), &signer().address(), 1, proof, signed)?;
        validate_external_key_commitment(
            1,
            proof.expect("validated proof exists"),
            &KEY_COMMITMENT,
        )?;
        Ok(validated)
    }

    #[test]
    fn rejects_missing_proof() {
        let p = proof();
        let signed = valid_signed(&p);
        let err = validate(None, Some(&signed)).unwrap_err();
        assert!(err.contains("missing C0 proof"));
    }

    #[test]
    fn rejects_missing_signed_payload() {
        let p = proof();
        let err = validate(Some(&p), None).unwrap_err();
        assert!(err.contains("no signed payload"));
    }

    #[test]
    fn rejects_payload_for_different_e3() {
        let p = proof();
        let signed = signed_for(&p, E3id::new("2", 42), ProofType::C0PkBfv, &signer());
        let err = validate(Some(&p), Some(&signed)).unwrap_err();
        assert!(err.contains("expected 42:1"));
    }

    #[test]
    fn rejects_non_c0_payload() {
        let p = Proof::new(
            CircuitName::PkGeneration,
            ArcBytes::from_bytes(&[10, 20, 30]),
            ArcBytes::from_bytes(&KEY_COMMITMENT),
        );
        let signed = signed_for(&p, e3_id(), ProofType::C1PkGeneration, &signer());
        let err = validate(Some(&p), Some(&signed)).unwrap_err();
        assert!(err.contains("expected C0PkBfv"));
    }

    #[test]
    fn rejects_signer_that_does_not_own_party_slot() {
        let p = proof();
        let signed = signed_for(&p, e3_id(), ProofType::C0PkBfv, &other_signer());
        let err = validate(Some(&p), Some(&signed)).unwrap_err();
        assert!(err.contains("expected committee member"));
    }

    #[test]
    fn rejects_proof_mismatch() {
        let p = proof();
        let signed = valid_signed(&p);
        let other = Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[9, 9, 9]),
            ArcBytes::from_bytes(&KEY_COMMITMENT),
        );
        let err = validate(Some(&other), Some(&signed)).unwrap_err();
        assert!(err.contains("Proof mismatch"));
    }

    #[test]
    fn rejects_proof_without_pk_commitment_output() {
        let p = Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[10, 20, 30]),
            ArcBytes::default(),
        );
        let signed = valid_signed(&p);
        let err = validate(Some(&p), Some(&signed)).unwrap_err();
        assert!(err.contains("no pk_commitment output"));
    }

    #[test]
    fn rejects_proof_for_different_key_bytes() {
        let p = proof();
        let signed = valid_signed(&p);
        let different_commitment = [0x24; 32];
        validate_external_key(&e3_id(), &signer().address(), 1, Some(&p), Some(&signed)).unwrap();
        let err = validate_external_key_commitment(1, &p, &different_commitment).unwrap_err();
        assert!(err.contains("does not match advertised BFV key"));
    }

    #[test]
    fn accepts_valid_key() {
        let p = proof();
        let signed = valid_signed(&p);
        let validated = validate(Some(&p), Some(&signed)).expect("should validate");
        assert_eq!(validated.recovered_signer, signer().address());
    }
}
