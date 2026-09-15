// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::{CorrelationId, FieldValue, PartyProofData, VerificationKind};

/// A minimal same-party commitment link: extracts the first 32 bytes of the
/// source public signals and requires them to equal the first 32 bytes of
/// the target public signals.
struct TestLink {
    scope: LinkScope,
    source: ProofType,
    target: ProofType,
}

impl CommitmentLink for TestLink {
    fn name(&self) -> &'static str {
        "test_link"
    }
    fn source_proof_type(&self) -> ProofType {
        self.source
    }
    fn target_proof_type(&self) -> ProofType {
        self.target
    }
    fn scope(&self) -> LinkScope {
        self.scope
    }
    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        if public_signals.len() < 32 {
            return Vec::new();
        }
        let mut v = [0u8; 32];
        v.copy_from_slice(&public_signals[..32]);
        vec![v]
    }
    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        if target_public_signals.len() < 32 {
            return false;
        }
        source_values
            .iter()
            .any(|v| v[..] == target_public_signals[..32])
    }
}

fn e3() -> E3id {
    E3id::new("7", 31337)
}

fn addr(byte: u8) -> Address {
    Address::from([byte; 20])
}

fn signals(byte: u8) -> ArcBytes {
    ArcBytes::from_bytes(&[byte; 32])
}

fn identity(proof_type: ProofType) -> ProofIdentity {
    ProofIdentity {
        proof_type,
        instance: 0,
    }
}

fn passed(
    e3_id: E3id,
    party_id: u64,
    address: Address,
    proof_type: ProofType,
    data_hash: [u8; 32],
    public_signals: ArcBytes,
) -> ProofVerificationPassed {
    ProofVerificationPassed {
        e3_id,
        party_id,
        address,
        proof_type,
        data_hash,
        public_signals,
        proof_data: ArcBytes::from_bytes(&[0xAA, 0xBB]),
    }
}

fn same_party_link() -> Box<dyn CommitmentLink> {
    Box::new(TestLink {
        scope: LinkScope::SameParty,
        source: ProofType::C1PkGeneration,
        target: ProofType::C2aSkShareComputation,
    })
}

#[test]
fn consistent_same_party_proofs_emit_no_violation() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let a = addr(1);

    // Target first (C2) so the source check has something to compare to.
    let v = svc.on_proof_verified(passed(
        e3(),
        1,
        a,
        ProofType::C2aSkShareComputation,
        [0x11; 32],
        signals(0x42),
    ));
    assert!(v.is_empty());

    // Source (C1) with matching signals — consistent.
    let v = svc.on_proof_verified(passed(
        e3(),
        1,
        a,
        ProofType::C1PkGeneration,
        [0x22; 32],
        signals(0x42),
    ));
    assert!(v.is_empty(), "matching commitments must not violate");
}

#[test]
fn mismatched_same_party_proofs_emit_violation() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let a = addr(2);

    svc.on_proof_verified(passed(
        e3(),
        3,
        a,
        ProofType::C2aSkShareComputation,
        [0x11; 32],
        signals(0x01),
    ));

    let v = svc.on_proof_verified(passed(
        e3(),
        3,
        a,
        ProofType::C1PkGeneration,
        [0x22; 32],
        signals(0x99),
    ));

    assert_eq!(
        v.len(),
        1,
        "mismatched commitments must produce a violation"
    );
    let viol = &v[0];
    assert_eq!(viol.accused_party_id, 3);
    assert_eq!(viol.accused_address, a);
    assert_eq!(viol.proof_type, ProofType::C1PkGeneration);
    assert_eq!(viol.data_hash, [0x22; 32]);
    assert!(
        !viol.evidence.is_empty(),
        "evidence preimage must be present"
    );
}

#[test]
fn zero_data_hash_mismatch_is_skipped() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let a = addr(3);

    svc.on_proof_verified(passed(
        e3(),
        4,
        a,
        ProofType::C2aSkShareComputation,
        [0x11; 32],
        signals(0x01),
    ));

    // Source carries an unresolved (zero) data_hash — must be skipped.
    let v = svc.on_proof_verified(passed(
        e3(),
        4,
        a,
        ProofType::C1PkGeneration,
        [0u8; 32],
        signals(0x99),
    ));

    assert!(v.is_empty(), "zero-data_hash mismatch must be skipped");
}

#[test]
fn foreign_e3_id_is_ignored() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let other = E3id::new("999", 31337);
    let a = addr(4);

    let v = svc.on_proof_verified(passed(
        other.clone(),
        1,
        a,
        ProofType::C1PkGeneration,
        [0x22; 32],
        signals(0x99),
    ));
    assert!(v.is_empty(), "proofs for a foreign E3 must be ignored");

    let req = CommitmentConsistencyCheckRequested {
        e3_id: other,
        kind: VerificationKind::ShareProofs,
        correlation_id: CorrelationId::new(),
        party_proofs: vec![],
    };
    assert!(
        svc.on_check_requested(req).is_none(),
        "pre-ZK requests for a foreign E3 must return None"
    );
}

#[test]
fn pre_zk_check_flags_and_evicts_inconsistent_party() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let honest = addr(5);
    let faulty = addr(6);

    let req = CommitmentConsistencyCheckRequested {
        e3_id: e3(),
        kind: VerificationKind::ShareProofs,
        correlation_id: CorrelationId::new(),
        party_proofs: vec![
            PartyProofData {
                party_id: 1,
                address: honest,
                proofs: vec![
                    (
                        identity(ProofType::C1PkGeneration),
                        signals(0x42),
                        [0xa1; 32],
                        ArcBytes::from_bytes(&[0x01]),
                    ),
                    (
                        identity(ProofType::C2aSkShareComputation),
                        signals(0x42),
                        [0xa2; 32],
                        ArcBytes::from_bytes(&[0x02]),
                    ),
                ],
            },
            PartyProofData {
                party_id: 2,
                address: faulty,
                proofs: vec![
                    (
                        identity(ProofType::C1PkGeneration),
                        signals(0x11),
                        [0xb1; 32],
                        ArcBytes::from_bytes(&[0x03]),
                    ),
                    (
                        identity(ProofType::C2aSkShareComputation),
                        signals(0x99),
                        [0xb2; 32],
                        ArcBytes::from_bytes(&[0x04]),
                    ),
                ],
            },
        ],
    };

    let outcome = svc.on_check_requested(req).expect("same e3");
    assert!(
        outcome.complete.inconsistent_parties.contains(&2),
        "faulty party must be flagged"
    );
    assert!(
        !outcome.complete.inconsistent_parties.contains(&1),
        "honest party must not be flagged"
    );
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].accused_party_id, 2);

    // The faulty party's cache entries are evicted, so a later post-ZK
    // event for the honest party does not re-report the faulty one.
    let v = svc.on_proof_verified(passed(
        e3(),
        1,
        honest,
        ProofType::C1PkGeneration,
        [0xa1; 32],
        signals(0x42),
    ));
    assert!(v.is_empty(), "evicted faulty party must not resurface");
}

#[test]
fn c2_sender_at_or_above_h_skips_c4_cross_check() {
    let link = Box::new(TestLink {
        scope: LinkScope::SourceMustExistInTargets,
        source: ProofType::C2aSkShareComputation,
        target: ProofType::C4aSkShareDecryption,
    });
    let mut svc = CommitmentConsistency::new(e3(), vec![link], 2);

    // Party 2 (>= H) C2 cannot appear in C4 rows; must not be faulted.
    svc.on_proof_verified(passed(
        e3(),
        2,
        addr(0x22),
        ProofType::C2aSkShareComputation,
        [0xc2; 32],
        signals(0x22),
    ));
    let violations = svc.on_proof_verified(passed(
        e3(),
        1,
        addr(0x11),
        ProofType::C4aSkShareDecryption,
        [0xc4; 32],
        signals(0x11),
    ));
    assert!(
        violations.is_empty(),
        "party_id >= H must be outside C4 expected_commitments roster"
    );
}
