// SPDX-License-Identifier: LGPL-3.0-only

//! Signature, signer-slot, circuit, and canonical-shape validation.

use super::*;
use alloy::primitives::U256;
use e3_committee_hash::{
    hash_lbfv_accepted_party_set, hash_lbfv_proof_session, split_hash_to_field_limbs,
};
use e3_events::{CircuitName, LbfvVerificationContext};
use e3_zk_helpers::{LbfvPkAggregationPublicLayout, RlkAggregationPublicLayout};

impl ShareVerifier {
    fn has_exact_legacy_c1_shape(signed: &SignedProofPayload) -> bool {
        signed.payload.proof_type == ProofType::C1PkGeneration
            && signed.payload.proof.circuit == CircuitName::PkGeneration
            && signed.payload.proof.public_signals.len()
                == e3_zk_helpers::PK_GENERATION_OUTPUTS.len() * e3_zk_helpers::FIELD_BYTE_LEN
    }

    fn has_complete_row_family(
        signed_proofs: &[SignedProofPayload],
        expected_type: ProofType,
        rows: usize,
    ) -> bool {
        if signed_proofs.len() != rows {
            return false;
        }
        signed_proofs.iter().all(|signed| {
            signed.payload.proof_type == expected_type
                && signed.payload.proof.circuit == expected_type.circuit_names()[0]
        })
    }

    fn has_complete_lbfv_bundle(
        signed_proofs: &[SignedProofPayload],
        first: ProofType,
        second: ProofType,
        rows: usize,
    ) -> bool {
        signed_proofs.len() == 2 * rows
            && Self::has_complete_row_family(&signed_proofs[..rows], first, rows)
            && Self::has_complete_row_family(&signed_proofs[rows..], second, rows)
    }

    fn has_complete_lbfv_generation_bundle(
        signed_proofs: &[SignedProofPayload],
        rows: usize,
    ) -> bool {
        signed_proofs.len() == 1 + (2 * rows)
            && Self::has_exact_legacy_c1_shape(&signed_proofs[0])
            && Self::has_complete_row_family(
                &signed_proofs[1..1 + rows],
                ProofType::LbfvPkGeneration,
                rows,
            )
            && Self::has_complete_row_family(
                &signed_proofs[1 + rows..],
                ProofType::RlkGeneration,
                rows,
            )
    }

    fn public_field<'a>(
        signed: &'a SignedProofPayload,
        input: bool,
        name: &str,
    ) -> Option<&'a [u8]> {
        let proof = &signed.payload.proof;
        if input {
            proof
                .circuit
                .input_layout()
                .extract_field(&proof.public_signals, name)
        } else {
            proof
                .circuit
                .output_layout()
                .extract_field(&proof.public_signals, name)
        }
    }

    fn public_u32_equals(signed: &SignedProofPayload, name: &str, expected: u32) -> bool {
        Self::public_field(signed, true, name).is_some_and(|field| {
            field[..28].iter().all(|byte| *byte == 0) && field[28..] == expected.to_be_bytes()
        })
    }

    fn public_field_at(signed: &SignedProofPayload, index: usize) -> &[u8] {
        let start = index * e3_zk_helpers::FIELD_BYTE_LEN;
        &signed.payload.proof.public_signals[start..start + e3_zk_helpers::FIELD_BYTE_LEN]
    }

    fn field_matches_u128(field: &[u8], expected: u128) -> bool {
        field[..16].iter().all(|byte| *byte == 0) && field[16..] == expected.to_be_bytes()
    }

    fn has_authoritative_session(
        signed: &SignedProofPayload,
        expected_hi: u128,
        expected_lo: u128,
    ) -> bool {
        Self::public_field(signed, true, "session_id_hi")
            .is_some_and(|field| Self::field_matches_u128(field, expected_hi))
            && Self::public_field(signed, true, "session_id_lo")
                .is_some_and(|field| Self::field_matches_u128(field, expected_lo))
    }

    fn all_fields_equal(signed_proofs: &[SignedProofPayload], input: bool, name: &str) -> bool {
        let Some(expected) = signed_proofs
            .first()
            .and_then(|signed| Self::public_field(signed, input, name))
        else {
            return false;
        };
        signed_proofs.iter().all(|signed| {
            Self::public_field(signed, input, name).is_some_and(|field| field == expected)
        })
    }

    pub(in crate::workflow::share_verification) fn has_valid_lbfv_statements(
        kind: &VerificationKind,
        signed_proofs: &[SignedProofPayload],
        sender_party_id: u64,
        e3_id: &E3id,
        committee_size: CiphernodesCommitteeSize,
        lbfv_context: Option<&LbfvVerificationContext>,
    ) -> bool {
        if !matches!(
            kind,
            VerificationKind::LbfvGenerationProofs | VerificationKind::LbfvAggregationProofs
        ) {
            return lbfv_context.is_none();
        }
        let Some(LbfvVerificationContext::V2(context)) = lbfv_context else {
            return false;
        };
        let Ok(sender_party_id) = u32::try_from(sender_party_id) else {
            return false;
        };
        let Ok(dispatch_e3_id) = U256::try_from(e3_id.clone()) else {
            return false;
        };
        if context.proof_domain.chain_id != e3_id.chain_id()
            || context.proof_domain.e3_id != dispatch_e3_id
        {
            return false;
        }
        let committee = committee_size.values();
        let committee_h = committee.h;
        let expected_session =
            split_hash_to_field_limbs(hash_lbfv_proof_session(context.proof_domain));
        let expected_fields = |proof_type| match proof_type {
            ProofType::LbfvPkGeneration => Some(7),
            ProofType::RlkGeneration => Some(9),
            ProofType::LbfvPkAggregation => {
                Some(LbfvPkAggregationPublicLayout::new(committee_h).field_count)
            }
            ProofType::RlkAggregation => {
                Some(RlkAggregationPublicLayout::new(committee_h).field_count)
            }
            _ => None,
        };
        let exact_lbfv_public_shape = |proofs: &[SignedProofPayload]| {
            proofs.iter().all(|signed| {
                expected_fields(signed.payload.proof_type).is_some_and(|fields| {
                    signed.payload.proof.public_signals.len()
                        == fields * e3_zk_helpers::FIELD_BYTE_LEN
                })
            })
        };

        match kind {
            VerificationKind::LbfvGenerationProofs => {
                if context.aggregation.is_some() {
                    return false;
                }
                let Some((c1, lbfv_proofs)) = signed_proofs.split_first() else {
                    return false;
                };
                if lbfv_proofs.len() % 2 != 0 {
                    return false;
                }
                let rows = lbfv_proofs.len() / 2;
                if lbfv_proofs.len() != 2 * rows {
                    return false;
                }
                let rlk = &lbfv_proofs[rows..];
                if !Self::has_exact_legacy_c1_shape(c1) || !exact_lbfv_public_shape(lbfv_proofs) {
                    return false;
                }
                let Some(c1_sk_commitment) = Self::public_field(c1, false, "sk_commitment") else {
                    return false;
                };

                lbfv_proofs.iter().all(|signed| {
                    Self::has_authoritative_session(
                        signed,
                        expected_session.hi,
                        expected_session.lo,
                    )
                }) && lbfv_proofs
                    .iter()
                    .all(|signed| Self::public_u32_equals(signed, "party_id", sender_party_id))
                    && lbfv_proofs[..rows].iter().enumerate().all(|(row, signed)| {
                        Self::public_u32_equals(signed, "row_index", row as u32)
                    })
                    && lbfv_proofs[rows..].iter().enumerate().all(|(row, signed)| {
                        Self::public_u32_equals(signed, "row_index", row as u32)
                    })
                    && lbfv_proofs.iter().all(|signed| {
                        Self::public_field(signed, false, "sk_commitment") == Some(c1_sk_commitment)
                    })
                    && Self::all_fields_equal(rlk, false, "r_commitment")
            }
            VerificationKind::LbfvAggregationProofs => {
                let Some(aggregation) = context.aggregation.as_ref() else {
                    return false;
                };
                if signed_proofs.len() % 2 != 0 {
                    return false;
                }
                let rows = signed_proofs.len() / 2;
                let accepted_party_ids = aggregation
                    .accepted_parties
                    .iter()
                    .map(|party| party.party_id)
                    .collect::<Vec<_>>();
                let Ok(accepted_set_hash) =
                    hash_lbfv_accepted_party_set(&accepted_party_ids, committee.n, committee.h)
                else {
                    return false;
                };
                let accepted_set = split_hash_to_field_limbs(accepted_set_hash);
                let pk_layout = LbfvPkAggregationPublicLayout::new(committee_h);
                let rlk_layout = RlkAggregationPublicLayout::new(committee_h);
                if signed_proofs.len() != 2 * rows || !exact_lbfv_public_shape(signed_proofs) {
                    return false;
                }

                let statement_matches = |signed: &SignedProofPayload| {
                    Self::has_authoritative_session(
                        signed,
                        expected_session.hi,
                        expected_session.lo,
                    ) && Self::public_u32_equals(signed, "aggregator_party_id", sender_party_id)
                        && Self::public_field(signed, true, "accepted_party_set_hash_hi")
                            .is_some_and(|field| Self::field_matches_u128(field, accepted_set.hi))
                        && Self::public_field(signed, true, "accepted_party_set_hash_lo")
                            .is_some_and(|field| Self::field_matches_u128(field, accepted_set.lo))
                };
                let pk_matches = signed_proofs[..rows]
                    .iter()
                    .enumerate()
                    .all(|(row, signed)| {
                        statement_matches(signed)
                            && Self::public_u32_equals(signed, "row_index", row as u32)
                            && aggregation.accepted_parties.iter().enumerate().all(
                                |(party_position, party)| {
                                    Self::public_field_at(
                                        signed,
                                        pk_layout.expected_pk_generation_commitments.start
                                            + party_position,
                                    ) == party.pk_generation_commitments[row].as_slice()
                                },
                            )
                    });
                let rlk_matches = signed_proofs[rows..]
                    .iter()
                    .enumerate()
                    .all(|(row, signed)| {
                        statement_matches(signed)
                            && Self::public_u32_equals(signed, "row_index", row as u32)
                            && aggregation.accepted_parties.iter().enumerate().all(
                                |(party_position, party)| {
                                    Self::public_field_at(
                                        signed,
                                        rlk_layout.expected_d0_commitments.start + party_position,
                                    ) == party.rlk_d0_commitments[row].as_slice()
                                        && Self::public_field_at(
                                            signed,
                                            rlk_layout.expected_d2_commitments.start
                                                + party_position,
                                        ) == party.rlk_d2_commitments[row].as_slice()
                                },
                            )
                    });
                pk_matches && rlk_matches
            }
            _ => true,
        }
    }

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
            VerificationKind::LbfvGenerationProofs => e3_fhe_params::lbfv_row_count(params_preset)
                .is_some_and(|rows| Self::has_complete_lbfv_generation_bundle(signed_proofs, rows)),
            VerificationKind::LbfvAggregationProofs => e3_fhe_params::lbfv_row_count(params_preset)
                .is_some_and(|rows| {
                    Self::has_complete_lbfv_bundle(
                        signed_proofs,
                        ProofType::LbfvPkAggregation,
                        ProofType::RlkAggregation,
                        rows,
                    )
                }),
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
