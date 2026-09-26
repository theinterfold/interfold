// SPDX-License-Identifier: LGPL-3.0-only

//! Cryptographic commitment and DKG-fold attestation checks.

use super::*;
use e3_events::DkgFoldAttestationContext;

/// Circuit honest-party count `H` for the committee `(threshold_m, threshold_n)`.
pub(crate) fn committee_h_for(threshold_m: usize, threshold_n: usize) -> Result<usize> {
    Ok(
        CiphernodesCommitteeSize::from_threshold(threshold_m, threshold_n)
            .with_context(|| {
                format!("unknown committee for threshold_m={threshold_m} threshold_n={threshold_n}")
            })?
            .values()
            .h,
    )
}

/// Public-signal key for the aggregated PK commitment in `CircuitName::PkAggregation` (C5).
/// Must stay in lock-step with the Noir circuit's output ABI declaration.
const C5_PK_COMMITMENT_FIELD: &str = "commitment";

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_dkg_fold_attestation(
    e3_id: &E3id,
    party_id: u64,
    proof: &Proof,
    attestation: &SignedDkgFoldAttestation,
    expected_context: DkgFoldAttestationContext,
    expected_node: &str,
    committee_n: usize,
    committee_h: usize,
    n_moduli: usize,
) -> Result<()> {
    ensure!(
        attestation.payload.e3_id == *e3_id,
        "attestation e3_id mismatch"
    );
    ensure!(
        attestation.payload.party_id == party_id,
        "attestation party_id mismatch"
    );
    ensure!(
        attestation.payload.registry == expected_context.registry,
        "attestation registry mismatch"
    );
    ensure!(
        attestation.payload.verifying_contract == expected_context.verifying_contract,
        "attestation verifying contract mismatch"
    );
    let expected: Address = expected_node
        .parse()
        .with_context(|| format!("invalid committee node address {expected_node}"))?;
    ensure!(
        attestation.verify_signer(&expected)?,
        "fold attestation signer does not match committee node for party {party_id}"
    );
    let (extracted_party, commits) =
        extract_node_fold_agg_commits(proof, committee_n, committee_h, n_moduli)
            .map_err(|e| anyhow!("{e}"))?;
    ensure!(extracted_party == party_id, "NodeFold party_id mismatch");
    ensure!(
        commits == attestation.payload.agg_commits,
        "NodeFold commits do not match signed attestation"
    );
    Ok(())
}

/// Extract the hash-based aggregated PK commitment from the signed C5 proof.
/// This is the last public signal of `CircuitName::PkAggregation`.
pub(crate) fn extract_pk_commitment(c5_proof: &Proof) -> Result<[u8; 32]> {
    let layout = CircuitName::PkAggregation.output_layout();
    let bytes = layout
        .extract_field(&c5_proof.public_signals, C5_PK_COMMITMENT_FIELD)
        .ok_or_else(|| anyhow::anyhow!("C5 proof is missing `commitment` public signal"))?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "C5 `commitment` public signal must be 32 bytes"
        ));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Extract the versioned key-envelope commitment from a V2 DKG proof.
pub(crate) fn extract_lbfv_key_envelope_commitment(
    proof: &Proof,
    committee_h: usize,
    lbfv_row_count: usize,
) -> Result<[u8; 32]> {
    ensure!(
        proof.circuit == CircuitName::DkgAggregatorV2,
        "key-envelope commitment requires a DkgAggregatorV2 proof"
    );
    let layout = e3_zk_helpers::DkgAggregatorV2PublicLayout::new(committee_h, lbfv_row_count);
    let expected_len = layout
        .field_count
        .checked_mul(e3_zk_helpers::FIELD_BYTE_LEN)
        .ok_or_else(|| anyhow!("V2 public-signal length overflow"))?;
    ensure!(
        proof.public_signals.len() == expected_len,
        "DkgAggregatorV2 proof has {} public-signal bytes, expected {expected_len}",
        proof.public_signals.len()
    );
    let bytes = layout
        .extract_key_envelope_commitment(&proof.public_signals)
        .ok_or_else(|| anyhow!("V2 proof is missing the key-envelope commitment"))?;
    Ok(bytes
        .try_into()
        .expect("the V2 commitment slice has a fixed length"))
}

/// Outcome of cross-checking each honest party's keyshare against its signed C1
/// `pk_commitment` public signal.
pub(crate) struct C1CommitmentAudit {
    /// Parties whose keyshare does not recompute to their signed C1 commitment, paired
    /// with the proof for `SignedProofFailed` reporting.
    pub mismatched: Vec<(u64, SignedProofPayload)>,
    /// Parties that carried no C1 proof at all (defensive — normally already dishonest).
    pub missing_proof: Vec<u64>,
}

/// Recompute each honest party's `pk_commitment` from its keyshare bytes and compare it
/// against the `pk_commitment` public signal in the party's signed C1 proof. Pure: the
/// actor publishes `SignedProofFailed` for `mismatched` and folds both result sets into
/// `dishonest_parties`.
pub(crate) fn check_c1_keyshare_commitments(
    entries: &[(u64, String, ArcBytes, Option<SignedProofPayload>)],
    fhe: &Fhe,
) -> C1CommitmentAudit {
    let mut mismatched = Vec::new();
    let mut missing_proof = Vec::new();
    for (party_id, _node, ks, c1) in entries {
        let Some(signed_proof) = c1.as_ref() else {
            warn!(
                "Party {} has no C1 proof but was not marked dishonest",
                party_id
            );
            missing_proof.push(*party_id);
            continue;
        };
        let ok = match e3_zk_helpers::compute_pk_commitment_from_keyshare_bytes(
            ks,
            &fhe.params,
            &fhe.crp,
        ) {
            Ok(computed) => signed_proof
                .payload
                .proof
                .extract_output("pk_commitment")
                .is_some_and(|extracted| extracted[..] == computed[..]),
            Err(e) => {
                warn!(
                    "Failed to compute pk_commitment for party {}: {}",
                    party_id, e
                );
                false
            }
        };
        if !ok {
            mismatched.push((*party_id, signed_proof.clone()));
        }
    }
    C1CommitmentAudit {
        mismatched,
        missing_proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use e3_events::{DkgFoldAggCommits, DkgFoldAttestationPayload};

    fn signed_attestation() -> (SignedDkgFoldAttestation, PrivateKeySigner) {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("test signer");
        let payload = DkgFoldAttestationPayload {
            e3_id: E3id::new("7", 1),
            registry: Address::repeat_byte(0x11),
            verifying_contract: Address::repeat_byte(0x22),
            party_id: 3,
            agg_commits: DkgFoldAggCommits {
                sk_agg_commit: [1; 32],
                esm_agg_commit: [2; 32],
            },
        };
        (
            SignedDkgFoldAttestation::sign(payload, &signer).expect("sign attestation"),
            signer,
        )
    }

    fn verify_with_context(expected_context: DkgFoldAttestationContext) -> Result<()> {
        let (attestation, signer) = signed_attestation();
        verify_dkg_fold_attestation(
            &attestation.payload.e3_id,
            attestation.payload.party_id,
            &Proof::new(
                CircuitName::NodeFold,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&[2]),
            ),
            &attestation,
            expected_context,
            &signer.address().to_string(),
            3,
            3,
            1,
        )
    }

    #[test]
    fn rejects_attestation_for_another_registry() {
        let err = verify_with_context(DkgFoldAttestationContext {
            registry: Address::repeat_byte(0x33),
            verifying_contract: Address::repeat_byte(0x22),
        })
        .expect_err("registry mismatch must fail");
        assert!(err.to_string().contains("registry mismatch"));
    }

    #[test]
    fn rejects_attestation_for_another_verifier() {
        let err = verify_with_context(DkgFoldAttestationContext {
            registry: Address::repeat_byte(0x11),
            verifying_contract: Address::repeat_byte(0x44),
        })
        .expect_err("verifier mismatch must fail");
        assert!(err.to_string().contains("verifying contract mismatch"));
    }

    #[test]
    fn extracts_minimum_v2_key_envelope_commitment_from_layout() {
        let mut public_signals = vec![0u8; 64 * 32];
        let expected = [0xabu8; 32];
        public_signals[29 * 32..30 * 32].copy_from_slice(&expected);
        let proof = Proof::new(
            CircuitName::DkgAggregatorV2,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&public_signals),
        );

        assert_eq!(
            extract_lbfv_key_envelope_commitment(&proof, 2, 5).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_v2_proof_with_another_public_signal_shape() {
        let proof = Proof::new(
            CircuitName::DkgAggregatorV2,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&vec![0u8; 63 * 32]),
        );

        let err = extract_lbfv_key_envelope_commitment(&proof, 2, 5)
            .expect_err("an incompatible public-signal shape must fail");
        assert!(err.to_string().contains("expected 2048"));
    }
}
