// SPDX-License-Identifier: LGPL-3.0-only

//! Signature, signer-slot, circuit, and canonical-shape validation.

use super::*;
use alloy::primitives::U256;
use e3_committee_hash::{
    hash_lbfv_accepted_party_set, hash_lbfv_proof_session, split_decryption_domain,
};
use e3_events::LbfvVerificationContext;
use e3_zk_witness::threshold::rlk_aggregation::RlkAggregationComponent;
use e3_zk_witness::{LbfvPkAggregationPublicLayout, RlkAggregationPublicLayout};

impl ShareVerifier {
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

    /// `rows` proofs of `first`, then `second_count` proofs of `second`.
    fn has_complete_lbfv_bundle(
        signed_proofs: &[SignedProofPayload],
        first: ProofType,
        second: ProofType,
        rows: usize,
        second_count: usize,
    ) -> bool {
        signed_proofs.len() == rows + second_count
            && Self::has_complete_row_family(&signed_proofs[..rows], first, rows)
            && Self::has_complete_row_family(&signed_proofs[rows..], second, second_count)
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

    fn public_field_at(signed: &SignedProofPayload, index: usize) -> &[u8] {
        let start = index * e3_zk_witness::FIELD_BYTE_LEN;
        &signed.payload.proof.public_signals[start..start + e3_zk_witness::FIELD_BYTE_LEN]
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

    /// Check the authoritative l-BFV context of a dispatch against the dispatch itself.
    ///
    /// Nothing here depends on what a peer sent, so an `Err` is a fault of the local dispatch: the
    /// caller abstains and blames no peer.
    pub(crate) fn validate_lbfv_dispatch(
        kind: &VerificationKind,
        e3_id: &E3id,
        params_profile: e3_fhe_params::BfvProfile,
        committee_size: CiphernodesCommitteeSize,
        lbfv_context: Option<&LbfvVerificationContext>,
    ) -> Result<(), String> {
        if !kind.is_lbfv() {
            return match lbfv_context {
                None => Ok(()),
                Some(_) => Err("a non-l-BFV dispatch carries an l-BFV context".to_string()),
            };
        }
        let Some(LbfvVerificationContext::V2(context)) = lbfv_context else {
            return Err("an l-BFV dispatch carries no l-BFV context".to_string());
        };
        let rows = e3_fhe_params::lbfv_row_count(params_profile.threshold_preset())
            .ok_or_else(|| "the dispatch profile has no l-BFV rows".to_string())?;
        let dispatch_e3_id = U256::try_from(e3_id.clone())
            .map_err(|_| "the dispatch E3 ID does not fit a U256".to_string())?;
        if context.proof_domain.chain_id != e3_id.chain_id()
            || context.proof_domain.e3_id != dispatch_e3_id
        {
            return Err("the l-BFV proof domain is for another E3".to_string());
        }
        match (kind, context.aggregation.as_ref()) {
            (VerificationKind::LbfvGenerationProofs, None) => Ok(()),
            (VerificationKind::LbfvGenerationProofs, Some(_)) => {
                Err("a generation dispatch carries an aggregation context".to_string())
            }
            (_, None) => Err("an aggregation dispatch carries no aggregation context".to_string()),
            (_, Some(aggregation)) => {
                let committee = committee_size.values();
                let accepted_party_ids = aggregation
                    .accepted_parties
                    .iter()
                    .map(|party| party.party_id)
                    .collect::<Vec<_>>();
                hash_lbfv_accepted_party_set(&accepted_party_ids, committee.n, committee.h)?;
                if aggregation.accepted_parties.iter().all(|party| {
                    [
                        &party.pk_generation_commitments,
                        &party.rlk_d0_commitments,
                        &party.rlk_d2_commitments,
                    ]
                    .iter()
                    .all(|commitments| commitments.len() == rows)
                }) {
                    Ok(())
                } else {
                    Err(format!(
                        "an accepted party does not carry {rows} commitments per family"
                    ))
                }
            }
        }
    }

    /// Check one party's l-BFV public statements against the context that
    /// [`Self::validate_lbfv_dispatch`] accepted. Everything compared here comes from the peer.
    pub(in crate::workflow::share_verification) fn has_valid_lbfv_statements(
        kind: &VerificationKind,
        signed_proofs: &[SignedProofPayload],
        sender_party_id: u64,
        committee_size: CiphernodesCommitteeSize,
        lbfv_context: Option<&LbfvVerificationContext>,
    ) -> bool {
        if !kind.is_lbfv() {
            return true;
        }
        let Some(LbfvVerificationContext::V2(context)) = lbfv_context else {
            return false;
        };
        let Ok(sender_party_id) = u32::try_from(sender_party_id) else {
            return false;
        };
        let committee = committee_size.values();
        let committee_h = committee.h;
        let expected_session =
            split_decryption_domain(hash_lbfv_proof_session(context.proof_domain));
        let expected_fields = |proof_type| match proof_type {
            ProofType::LbfvPkGeneration => Some(6),
            ProofType::RlkGeneration => Some(8),
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
                        == fields * e3_zk_witness::FIELD_BYTE_LEN
                })
            })
        };

        match kind {
            VerificationKind::LbfvGenerationProofs => {
                let lbfv_proofs = signed_proofs;
                if lbfv_proofs.is_empty() || lbfv_proofs.len() % 2 != 0 {
                    return false;
                }
                let rows = lbfv_proofs.len() / 2;
                let rlk = &lbfv_proofs[rows..];
                if !exact_lbfv_public_shape(lbfv_proofs) {
                    return false;
                }

                // Every PK and RLK row of the party commits one `sk`. C2a's secret root must
                // equal that commitment; the `lbfv_generation_sk` links check it.
                lbfv_proofs.iter().all(|signed| {
                    let proof = &signed.payload.proof;
                    proof.has_session(expected_session.hi, expected_session.lo)
                        && proof.input_u32("party_id") == Some(sender_party_id)
                }) && [&lbfv_proofs[..rows], rlk]
                    .into_iter()
                    .flat_map(|family| family.iter().enumerate())
                    .all(|(row, signed)| {
                        signed.payload.proof.input_u32("row_index") == Some(row as u32)
                    })
                    && Self::all_fields_equal(lbfv_proofs, false, "sk_commitment")
                    && Self::all_fields_equal(rlk, false, "r_commitment")
            }
            VerificationKind::LbfvAggregationProofs => {
                let Some(aggregation) = context.aggregation.as_ref() else {
                    return false;
                };
                // One PK proof and two RLK component proofs per row.
                let families = 1 + RlkAggregationComponent::ALL.len();
                if signed_proofs.is_empty() || signed_proofs.len() % families != 0 {
                    return false;
                }
                let rows = signed_proofs.len() / families;
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
                let accepted_set = split_decryption_domain(accepted_set_hash);
                let pk_layout = LbfvPkAggregationPublicLayout::new(committee_h);
                let rlk_layout = RlkAggregationPublicLayout::new(committee_h);
                if !exact_lbfv_public_shape(signed_proofs) {
                    return false;
                }

                let statement_matches = |signed: &SignedProofPayload| {
                    let proof = &signed.payload.proof;
                    proof.has_session(expected_session.hi, expected_session.lo)
                        && proof.input_u32("aggregator_party_id") == Some(sender_party_id)
                        && proof.input_u128("accepted_party_set_hash_hi") == Some(accepted_set.hi)
                        && proof.input_u128("accepted_party_set_hash_lo") == Some(accepted_set.lo)
                };
                let pk_matches = signed_proofs[..rows]
                    .iter()
                    .enumerate()
                    .all(|(row, signed)| {
                        statement_matches(signed)
                            && signed.payload.proof.input_u32("row_index") == Some(row as u32)
                            && aggregation.accepted_parties.iter().enumerate().all(
                                |(party_position, party)| {
                                    party.pk_generation_commitments.get(row).is_some_and(
                                        |commitment| {
                                            Self::public_field_at(
                                                signed,
                                                pk_layout.expected_pk_generation_commitments.start
                                                    + party_position,
                                            ) == commitment.as_slice()
                                        },
                                    )
                                },
                            )
                    });
                let rlk_matches = RlkAggregationComponent::ALL
                    .into_iter()
                    .zip(signed_proofs[rows..].chunks(rows))
                    .all(|(component, family)| {
                        family.iter().enumerate().all(|(row, signed)| {
                            statement_matches(signed)
                                && signed.payload.proof.input_u32("row_index") == Some(row as u32)
                                && signed.payload.proof.input_u32("component")
                                    == Some(component.index())
                                && aggregation.accepted_parties.iter().enumerate().all(
                                    |(party_position, party)| {
                                        let expected = match component {
                                            RlkAggregationComponent::D0 => {
                                                &party.rlk_d0_commitments
                                            }
                                            RlkAggregationComponent::D2 => {
                                                &party.rlk_d2_commitments
                                            }
                                        };
                                        expected.get(row).is_some_and(|commitment| {
                                            Self::public_field_at(
                                                signed,
                                                rlk_layout.expected_commitments.start
                                                    + party_position,
                                            ) == commitment.as_slice()
                                        })
                                    },
                                )
                        })
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
    /// C2/C3 counts are derived from the profile's threshold parameters. Variable C4b and C6 counts
    /// are checked against trusted local state by their producers. This trust-boundary check
    /// prevents a signed proof for another phase (or a duplicated singleton proof) from satisfying
    /// the current phase merely because its self-declared [`ProofType`] maps to a valid circuit.
    pub(in crate::workflow::share_verification) fn has_canonical_proof_shape(
        kind: &VerificationKind,
        signed_proofs: &[SignedProofPayload],
        params_profile: e3_fhe_params::BfvProfile,
    ) -> bool {
        if params_profile.protocol() == e3_fhe_params::BfvDecryptionProtocol::Synchronized {
            return match kind {
                VerificationKind::PkGenerationProofs => {
                    signed_proofs.len() == 1
                        && signed_proofs[0].payload.proof_type == ProofType::C1PkGeneration
                }
                VerificationKind::ShareProofs => {
                    let rows = params_profile.threshold_preset().metadata().num_moduli;
                    signed_proofs.len() == 1 + rows
                        && signed_proofs[0].payload.proof_type == ProofType::C2aSkShareComputation
                        && signed_proofs[1..].iter().all(|proof| {
                            proof.payload.proof_type == ProofType::C3aSkShareEncryption
                        })
                }
                VerificationKind::DecryptionProofs => {
                    signed_proofs.len() == 1
                        && signed_proofs[0].payload.proof_type == ProofType::C4aSkShareDecryption
                }
                // Synchronized C6 is a separate statement, not the existing SS proof.
                VerificationKind::ThresholdDecryptionProofs => false,
                // l-BFV proofs exist only on the secret-shared path.
                VerificationKind::LbfvGenerationProofs
                | VerificationKind::LbfvAggregationProofs => false,
            };
        }
        let params_preset = params_profile.threshold_preset();
        // Every proof must come from its type's circuit on this E3's protocol path; a circuit of
        // the other path never satisfies the phase.
        let on_path = signed_proofs.iter().all(|signed| {
            signed
                .payload
                .proof_type
                .circuit_names_for(params_preset)
                .contains(&signed.payload.proof.circuit)
        });
        if !on_path {
            return false;
        }
        match kind {
            // The l-BFV path proves no C1.
            VerificationKind::PkGenerationProofs => {
                !e3_fhe_params::is_lbfv_path(params_preset)
                    && signed_proofs.len() == 1
                    && signed_proofs[0].payload.proof_type == ProofType::C1PkGeneration
            }
            VerificationKind::ShareProofs => {
                // Canonical order is C2a, C2b, C3a x L, C3b x L. Each C3 proof encrypts one
                // modulus row of the threshold-parameter Shamir secret, even though encryption
                // itself uses the profile's paired DKG parameters.
                let num_share_rows = params_profile.threshold_preset().metadata().num_moduli;
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
                .is_some_and(|rows| {
                    Self::has_complete_lbfv_bundle(
                        signed_proofs,
                        ProofType::LbfvPkGeneration,
                        ProofType::RlkGeneration,
                        rows,
                        rows,
                    )
                }),
            // Canonical order is the PK rows, then the RLK `d0` rows, then the RLK `d2` rows.
            VerificationKind::LbfvAggregationProofs => e3_fhe_params::lbfv_row_count(params_preset)
                .is_some_and(|rows| {
                    Self::has_complete_lbfv_bundle(
                        signed_proofs,
                        ProofType::LbfvPkAggregation,
                        ProofType::RlkAggregation,
                        rows,
                        RlkAggregationComponent::ALL.len() * rows,
                    )
                }),
        }
    }

    /// Validate ECDSA properties for a set of signed proofs from one party:
    /// 1. e3_id match
    /// 2. Signature recovery (valid ECDSA)
    /// 3. Recovered signer owns the canonical finalized-committee party slot
    /// 4. Signer consistency (all proofs from same address)
    /// 5. Circuit name matches the circuits of `params_preset`'s path for the ProofType
    pub(in crate::workflow::share_verification) fn ecdsa_validate_signed_proofs(
        sender_party_id: u64,
        signed_proofs: &[SignedProofPayload],
        e3_id_str: &str,
        label: &str,
        expected_signer: Option<Address>,
        params_preset: e3_fhe_params::BfvPreset,
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
                    failed_payload: None,
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
                            failed_payload: None,
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
                                failed_payload: None,
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
                        failed_payload: None,
                    };
                }
            }

            // 4. Circuit name validation
            let expected_circuits = signed.payload.proof_type.circuit_names_for(params_preset);
            if !expected_circuits.contains(&signed.payload.proof.circuit) {
                info!(
                    "{} circuit mismatch for party {}: expected {:?}, got {:?}",
                    label, sender_party_id, expected_circuits, signed.payload.proof.circuit
                );
                return EcdsaPartyResult {
                    passed: false,
                    failed_payload: None,
                };
            }
        }

        EcdsaPartyResult {
            passed: true,
            failed_payload: None,
        }
    }
}
