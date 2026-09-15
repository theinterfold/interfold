// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure commitment validation for validated l-BFV share transport documents.

use anyhow::{ensure, Result};
use e3_events::{
    LbfvAcceptedPartyCommitments, LbfvPublicKeyShareDocumentV1,
    LbfvRelinearizationKeyShareDocumentV1, ProofIdentity, ProofType, SignedProofPayload,
};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::validate_lbfv_serialized_share_commitments;

/// Recompute all PK, RLK d0, and RLK d2 row commitments from two V1 documents.
///
/// The caller must first validate both transport documents. This function does not validate
/// signatures, verify proofs, or access the DHT.
pub fn validate_lbfv_key_share_document_commitments(
    preset: BfvPreset,
    public_key: &LbfvPublicKeyShareDocumentV1,
    rlk: &LbfvRelinearizationKeyShareDocumentV1,
) -> Result<LbfvAcceptedPartyCommitments> {
    ensure!(
        public_key.context == rlk.context,
        "l-BFV PK and RLK document contexts do not match"
    );
    let public_key_row_signals =
        ordered_row_signals(&public_key.signed_row_proofs, ProofType::LbfvPkGeneration)?;
    let rlk_row_signals = ordered_row_signals(&rlk.signed_row_proofs, ProofType::RlkGeneration)?;
    let commitments = validate_lbfv_serialized_share_commitments(
        preset,
        &public_key.share,
        &rlk.share,
        &public_key_row_signals,
        &rlk_row_signals,
    )?;

    Ok(LbfvAcceptedPartyCommitments {
        party_id: public_key.context.party_id,
        pk_generation_commitments: commitments.pk_generation_commitments,
        rlk_d0_commitments: commitments.rlk_d0_commitments,
        rlk_d2_commitments: commitments.rlk_d2_commitments,
    })
}

fn ordered_row_signals(
    proofs: &[SignedProofPayload; ProofType::LBFV_ROW_INSTANCES as usize],
    proof_type: ProofType,
) -> Result<Vec<&[u8]>> {
    proofs
        .iter()
        .enumerate()
        .map(|(row, signed)| {
            ensure!(
                signed.payload.proof_type == proof_type,
                "l-BFV row proof has the wrong proof type"
            );
            ensure!(
                proof_type.identity(&signed.payload.proof)?
                    == (ProofIdentity {
                        proof_type,
                        instance: row as u32,
                    }),
                "l-BFV row proof is not in its canonical position"
            );
            Ok(signed.payload.proof.public_signals.as_ref())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{E3id, Proof, ProofPayload};
    use e3_utils::ArcBytes;
    use e3_zk_helpers::FIELD_BYTE_LEN;

    fn row_proofs(
        proof_type: ProofType,
    ) -> [SignedProofPayload; ProofType::LBFV_ROW_INSTANCES as usize] {
        std::array::from_fn(|row| {
            let circuit = proof_type.circuit_names()[0];
            let input_layout = circuit.input_layout();
            let field_count = input_layout.field_count().unwrap()
                + circuit.output_layout().field_count().unwrap();
            let mut public_signals = vec![0u8; field_count * FIELD_BYTE_LEN];
            let row_index = input_layout.field_index("row_index").unwrap();
            public_signals[row_index * FIELD_BYTE_LEN + 28..(row_index + 1) * FIELD_BYTE_LEN]
                .copy_from_slice(&(row as u32).to_be_bytes());

            SignedProofPayload {
                payload: ProofPayload {
                    e3_id: E3id::new("1", 1),
                    proof_type,
                    proof: Proof::new(
                        circuit,
                        ArcBytes::from_bytes(&[1]),
                        ArcBytes::from_bytes(&public_signals),
                    ),
                },
                signature: ArcBytes::from_bytes(&[]),
            }
        })
    }

    #[test]
    fn ordered_rows_require_the_expected_family_and_position() {
        let mut proofs = row_proofs(ProofType::LbfvPkGeneration);
        assert_eq!(
            ordered_row_signals(&proofs, ProofType::LbfvPkGeneration)
                .unwrap()
                .len(),
            ProofType::LBFV_ROW_INSTANCES as usize
        );

        proofs[0].payload.proof_type = ProofType::RlkGeneration;
        assert!(ordered_row_signals(&proofs, ProofType::LbfvPkGeneration).is_err());

        let mut proofs = row_proofs(ProofType::LbfvPkGeneration);
        proofs.swap(0, 1);
        assert!(ordered_row_signals(&proofs, ProofType::LbfvPkGeneration).is_err());
    }
}
