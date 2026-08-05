// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::E3id;

fn arc(bytes: &[u8]) -> ArcBytes {
    ArcBytes::from_bytes(bytes)
}

fn base_state(state: KeyshareState) -> ThresholdKeyshareState {
    ThresholdKeyshareState::new(
        E3id::new("42", 1),
        0,
        state,
        1,
        3,
        arc(b"params"),
        "0xabc".to_string(),
    )
}

#[test]
fn new_initialises_defaults_and_records_dkg_start() {
    let s = base_state(KeyshareState::Init);
    assert_eq!(s.variant_name(), "Init");
    assert!(s.aggregated_pk.is_none());
    assert!(s.expelled_parties.is_empty());
    assert!(s.honest_parties.is_none());
    assert!(s.dkg_started_at_unix_secs.is_some());
    assert_eq!(s.get_threshold_m(), 1);
    assert_eq!(s.get_threshold_n(), 3);
    assert_eq!(s.get_party_id(), 0);
    assert_eq!(s.get_address(), "0xabc");
}

#[test]
fn same_branch_transition_is_always_valid() {
    // Re-entering the same phase variant must be accepted (idempotent mutations).
    let a = KeyshareState::AggregatingDecryptionKey(adk());
    let b = KeyshareState::AggregatingDecryptionKey(adk());
    assert!(a.next(b).is_ok());
}

#[test]
fn full_happy_path_transitions_in_order() {
    let order = [
        KeyshareState::Init,
        KeyshareState::CollectingEncryptionKeys(cek()),
        KeyshareState::GeneratingThresholdShare(gts()),
        KeyshareState::AggregatingDecryptionKey(adk()),
        KeyshareState::ReadyForDecryption(rfd()),
        KeyshareState::Decrypting(decrypting()),
        KeyshareState::GeneratingDecryptionProof(gdp()),
        KeyshareState::Completed,
    ];
    for pair in order.windows(2) {
        assert!(
            pair[0].next(pair[1].clone()).is_ok(),
            "expected {} -> {} to be valid",
            pair[0].variant_name(),
            pair[1].variant_name()
        );
    }
}

#[test]
fn skipping_a_phase_is_rejected() {
    let init = KeyshareState::Init;
    // Init must go to CollectingEncryptionKeys, not straight to aggregation.
    assert!(init
        .next(KeyshareState::AggregatingDecryptionKey(adk()))
        .is_err());
}

#[test]
fn backwards_transition_is_rejected() {
    let completed = KeyshareState::Completed;
    assert!(completed.next(KeyshareState::Init).is_err());
}

#[test]
fn failure_is_terminal_and_reachable_from_active_dkg() {
    let failed = KeyshareState::Failed {
        failed_at_stage: E3Stage::CommitteeFinalized,
        reason: FailureReason::DKGTimeout,
    };

    assert!(KeyshareState::CollectingEncryptionKeys(cek())
        .next(failed.clone())
        .is_ok());
    assert!(failed.next(failed.clone()).is_ok());
    assert!(failed
        .next(KeyshareState::Failed {
            failed_at_stage: E3Stage::CiphertextReady,
            reason: FailureReason::DecryptionTimeout,
        })
        .is_err());
    assert!(failed.next(KeyshareState::Init).is_err());
    assert!(KeyshareState::Completed
        .next(KeyshareState::Failed {
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGTimeout,
        })
        .is_err());
}

#[test]
fn new_state_preserves_metadata_and_advances_phase() {
    let s = base_state(KeyshareState::Init);
    let next = s
        .clone()
        .new_state(KeyshareState::CollectingEncryptionKeys(cek()))
        .expect("valid transition");
    assert_eq!(next.variant_name(), "CollectingEncryptionKeys");
    assert_eq!(next.e3_id, s.e3_id);
    assert_eq!(next.party_id, s.party_id);
    assert_eq!(next.threshold_m, s.threshold_m);
    assert_eq!(next.threshold_n, s.threshold_n);
}

#[test]
fn new_state_rejects_illegal_transition() {
    let s = base_state(KeyshareState::Init);
    assert!(s.new_state(KeyshareState::Completed).is_err());
}

// ---- builders for phase data (minimal, transition logic ignores contents) ----

fn sens() -> SensitiveBytes {
    SensitiveBytes::from_encrypted(&[])
}

fn cek() -> CollectingEncryptionKeysData {
    CollectingEncryptionKeysData {
        sk_bfv: sens(),
        pk_bfv: arc(b"pk"),
        ciphernode_selected: CiphernodeSelected::default(),
    }
}

fn gts() -> GeneratingThresholdShareData {
    GeneratingThresholdShareData {
        pk_share: None,
        sk_sss: None,
        esi_sss: None,
        e_sm_raw: None,
        sk_bfv: sens(),
        pk_bfv: arc(b"pk"),
        collected_encryption_keys: Vec::new(),
        ciphernode_selected: None,
        proof_request_data: None,
    }
}

fn adk() -> AggregatingDecryptionKey {
    AggregatingDecryptionKey {
        pk_share: arc(b"pk"),
        sk_bfv: sens(),
        own_sk_share_raw: sens(),
        own_esi_shares_raw: Vec::new(),
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    }
}

fn rfd() -> ReadyForDecryption {
    ReadyForDecryption {
        pk_share: arc(b"pk"),
        sk_poly_sum: sens(),
        es_poly_sum: Vec::new(),
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    }
}

fn decrypting() -> Decrypting {
    Decrypting {
        pk_share: arc(b"pk"),
        sk_poly_sum: sens(),
        es_poly_sum: Vec::new(),
        ciphertext_output: Vec::new(),
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    }
}

fn gdp() -> GeneratingDecryptionProof {
    GeneratingDecryptionProof {
        pk_share: arc(b"pk"),
        decryption_share: Vec::new(),
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    }
}
