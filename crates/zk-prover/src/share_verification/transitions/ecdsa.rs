// SPDX-License-Identifier: LGPL-3.0-only

//! Signature, signer-slot, circuit, and canonical-shape validation.

use super::*;

impl ShareVerifier {
    /// Keccak256 over `abi_encode((proof.data, proof.public_signals))`.
    pub(in crate::workflow::share_verification) fn proof_data_hash(
        signed: &SignedProofPayload,
    ) -> [u8; 32] {
        let msg = (
            Bytes::copy_from_slice(&signed.payload.proof.data),
            Bytes::copy_from_slice(&signed.payload.proof.public_signals),
        )
            .abi_encode();
        keccak256(&msg).into()
    }

    /// Check that a party supplied the canonical proof-type layout for this protocol phase.
    ///
    /// C2/C3 counts are derived from the threshold parameter preset. Variable C4b and C6 counts
    /// are checked against trusted local state by their producers. This trust-boundary check
    /// prevents a signed proof for another phase (or a duplicated singleton proof) from satisfying
    /// the current phase merely because its self-declared [`ProofType`] maps to a valid circuit.
    pub(in crate::workflow::share_verification) fn has_canonical_proof_shape(
        kind: &VerificationKind,
        signed_proofs: &[SignedProofPayload],
        params_preset: e3_fhe_params::BfvPreset,
    ) -> bool {
        match kind {
            VerificationKind::PkGenerationProofs => {
                signed_proofs.len() == 1
                    && signed_proofs[0].payload.proof_type == ProofType::C1PkGeneration
            }
            VerificationKind::ShareProofs => {
                // Canonical order is C2a, C2b, C3a x L, C3b x L. Each C3 proof encrypts one
                // modulus row of the threshold-parameter Shamir secret, even though encryption
                // itself uses the paired DKG parameters. The dispatch currently carries that DKG
                // preset, so recover its threshold counterpart before deriving L.
                let threshold_preset = params_preset
                    .threshold_counterpart()
                    .unwrap_or(params_preset);
                let num_share_rows = threshold_preset.metadata().num_moduli;
                signed_proofs.len() == 2 + (2 * num_share_rows)
                    && signed_proofs[0].payload.proof_type == ProofType::C2aSkShareComputation
                    && signed_proofs[1].payload.proof_type == ProofType::C2bESmShareComputation
                    && signed_proofs[2..2 + num_share_rows]
                        .iter()
                        .all(|signed| signed.payload.proof_type == ProofType::C3aSkShareEncryption)
                    && signed_proofs[2 + num_share_rows..]
                        .iter()
                        .all(|signed| signed.payload.proof_type == ProofType::C3bESmShareEncryption)
            }
            VerificationKind::DecryptionProofs => {
                // PartyShareDecryptionProofsToVerify has one distinguished C4a slot followed
                // by one or more C4b slots. The producer checks the exact C4b count against
                // `es_poly_sum`; here we bind every signed payload to its structural role because
                // C4a/C4b share a CircuitName.
                signed_proofs.len() >= 2
                    && signed_proofs[0].payload.proof_type == ProofType::C4aSkShareDecryption
                    && signed_proofs[1..]
                        .iter()
                        .all(|signed| signed.payload.proof_type == ProofType::C4bESmShareDecryption)
            }
            VerificationKind::ThresholdDecryptionProofs => {
                !signed_proofs.is_empty()
                    && signed_proofs.iter().all(|signed| {
                        signed.payload.proof_type == ProofType::C6ThresholdShareDecryption
                    })
            }
            VerificationKind::RelinRound1Proofs => {
                // One C8 proof per gadget digit; the exact count (`dnum`)
                // and the digit bindings are checked by the CKKS keyshare
                // machine against the E3's own params.
                !signed_proofs.is_empty()
                    && signed_proofs
                        .iter()
                        .all(|signed| signed.payload.proof_type == ProofType::C8RelinRound1)
            }
        }
    }

    /// Validate ECDSA properties for a set of signed proofs from one party:
    /// 1. e3_id match
    /// 2. Signature recovery (valid ECDSA)
    /// 3. Recovered signer owns the canonical finalized-committee party slot
    /// 4. Signer consistency (all proofs from same address)
    /// 5. Circuit name matches expected ProofType circuits
    pub(in crate::workflow::share_verification) fn ecdsa_validate_signed_proofs(
        sender_party_id: u64,
        signed_proofs: &[SignedProofPayload],
        e3_id_str: &str,
        label: &str,
        expected_signer: Option<Address>,
    ) -> EcdsaPartyResult {
        if signed_proofs.is_empty() {
            info!(
                "{} party {} supplied an empty signed-proof bundle",
                label, sender_party_id
            );
            return EcdsaPartyResult {
                passed: false,
                failed_payload: None,
            };
        }

        let Some(expected_signer) = expected_signer else {
            info!(
                "{} party {} has no canonical finalized-committee slot",
                label, sender_party_id
            );
            return EcdsaPartyResult {
                passed: false,
                // The outer party id is not part of the signed payload. Its absence from the
                // canonical committee is therefore a structural dispatch failure, not
                // self-authenticating evidence that can safely be attributed to the signer.
                failed_payload: None,
            };
        };

        let mut expected_addr: Option<Address> = None;

        for signed in signed_proofs {
            // 1. e3_id match
            if signed.payload.e3_id.to_string() != e3_id_str {
                info!(
                    "{} proof from party {} has wrong e3_id ({} vs {})",
                    label, sender_party_id, signed.payload.e3_id, e3_id_str
                );
                return EcdsaPartyResult {
                    passed: false,
                    failed_payload: Some((signed.clone(), expected_addr)),
                };
            }

            // 2. Signature recovery
            match signed.recover_address() {
                Ok(addr) => {
                    // 3. Canonical party ownership and signer consistency
                    if addr != expected_signer {
                        info!(
                            "{} proof signer {} does not own party {} (expected {})",
                            label, addr, sender_party_id, expected_signer
                        );
                        return EcdsaPartyResult {
                            passed: false,
                            failed_payload: Some((signed.clone(), Some(addr))),
                        };
                    }
                    match &expected_addr {
                        Some(ea) if *ea != addr => {
                            info!(
                                "{} inconsistent signer for party {}",
                                label, sender_party_id
                            );
                            return EcdsaPartyResult {
                                passed: false,
                                failed_payload: Some((signed.clone(), Some(addr))),
                            };
                        }
                        None => expected_addr = Some(addr),
                        _ => {}
                    }
                }
                Err(e) => {
                    info!(
                        "{} signature recovery failed for party {} ({:?}): {}",
                        label, sender_party_id, signed.payload.proof_type, e
                    );
                    return EcdsaPartyResult {
                        passed: false,
                        failed_payload: Some((signed.clone(), expected_addr)),
                    };
                }
            }

            // 4. Circuit name validation
            let expected_circuits = signed.payload.proof_type.circuit_names();
            if !expected_circuits.contains(&signed.payload.proof.circuit) {
                info!(
                    "{} circuit mismatch for party {}: expected {:?}, got {:?}",
                    label, sender_party_id, expected_circuits, signed.payload.proof.circuit
                );
                return EcdsaPartyResult {
                    passed: false,
                    failed_payload: Some((signed.clone(), expected_addr)),
                };
            }
        }

        EcdsaPartyResult {
            passed: true,
            failed_payload: None,
        }
    }
}
