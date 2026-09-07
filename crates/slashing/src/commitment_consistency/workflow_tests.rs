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

/// A link that scans **every** 32-byte field of the target's public signals,
/// mirroring how `C1ToC5PkCommitmentLink::check_signals` searches all `H` input
/// slots of the C5 aggregate rather than only the first one.
struct ChunkScanLink {
    scope: LinkScope,
    source: ProofType,
    target: ProofType,
}

impl CommitmentLink for ChunkScanLink {
    fn name(&self) -> &'static str {
        "chunk_scan_link"
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
        target_public_signals
            .chunks_exact(32)
            .any(|chunk| source_values.iter().any(|v| v[..] == *chunk))
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
                        ProofType::C1PkGeneration,
                        signals(0x42),
                        [0xa1; 32],
                        ArcBytes::from_bytes(&[0x01]),
                    ),
                    (
                        ProofType::C2aSkShareComputation,
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
                        ProofType::C1PkGeneration,
                        signals(0x11),
                        [0xb1; 32],
                        ArcBytes::from_bytes(&[0x03]),
                    ),
                    (
                        ProofType::C2aSkShareComputation,
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

#[test]
fn surplus_c1_sender_is_not_faulted_when_c5_witnesses_only_h_parties() {
    // Micro committee: N=9, H=5. All nine parties produce a C1 proof, but the
    // aggregator caps the canonical honest subset to the five lowest party IDs,
    // so C5 can only ever witness parties 0..=4. Faulting the surplus parties
    // would accuse four honest operators on every successful DKG round.
    const COMMITTEE_H: usize = 5;
    const COMMITTEE_N: u64 = 9;

    let link = Box::new(ChunkScanLink {
        scope: LinkScope::CrossParty,
        source: ProofType::C1PkGeneration,
        target: ProofType::C5PkAggregation,
    });
    let mut svc = CommitmentConsistency::new(e3(), vec![link], COMMITTEE_H);

    // Every committee member publishes a C1 proof with its own commitment.
    for party_id in 0..COMMITTEE_N {
        let violations = svc.on_proof_verified(passed(
            e3(),
            party_id,
            addr(party_id as u8 + 1),
            ProofType::C1PkGeneration,
            [party_id as u8 + 0xC0; 32],
            signals(party_id as u8),
        ));
        assert!(
            violations.is_empty(),
            "no C5 target is cached yet, so no party can be faulted"
        );
    }

    // C5 lands, witnessing only the lowest H party IDs. The aggregator proves
    // one commitment per honest slot; the surplus parties are absent by design.
    let mut c5_signals = Vec::new();
    for party_id in 0..COMMITTEE_H as u64 {
        c5_signals.extend_from_slice(&[party_id as u8; 32]);
    }

    let violations = svc.on_proof_verified(passed(
        e3(),
        0,
        addr(0xAA),
        ProofType::C5PkAggregation,
        [0xC5; 32],
        ArcBytes::from_bytes(&c5_signals),
    ));

    assert!(
        violations.is_empty(),
        "surplus honest C1 senders (party_id >= H) must not be accused when C5 \
         only witnesses the H lowest parties; got {} violation(s) for parties {:?}",
        violations.len(),
        violations
            .iter()
            .map(|v| v.accused_party_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn c1_sender_below_h_is_still_faulted_when_absent_from_c5() {
    // The cap must not become a blanket exemption: a party inside the honest
    // roster that C5 does not attest to is still a real inconsistency.
    const COMMITTEE_H: usize = 5;

    let link = Box::new(ChunkScanLink {
        scope: LinkScope::CrossParty,
        source: ProofType::C1PkGeneration,
        target: ProofType::C5PkAggregation,
    });
    let mut svc = CommitmentConsistency::new(e3(), vec![link], COMMITTEE_H);

    // Party 1 is inside the roster but publishes a commitment C5 never proves.
    svc.on_proof_verified(passed(
        e3(),
        1,
        addr(0x11),
        ProofType::C1PkGeneration,
        [0xC1; 32],
        signals(0xEE),
    ));

    let mut c5_signals = Vec::new();
    for party_id in 0..COMMITTEE_H as u64 {
        c5_signals.extend_from_slice(&[party_id as u8; 32]);
    }

    let violations = svc.on_proof_verified(passed(
        e3(),
        0,
        addr(0xAA),
        ProofType::C5PkAggregation,
        [0xC5; 32],
        ArcBytes::from_bytes(&c5_signals),
    ));

    assert_eq!(
        violations.len(),
        1,
        "a party inside the H roster whose commitment C5 does not carry is a real violation"
    );
    assert_eq!(violations[0].accused_party_id, 1);
}

/// Round 13, cn3: replay after a restart starts at the aggregate snapshot cursor, so the
/// pre-crash `ProofVerificationPassed` events never reach a freshly built checker. The node's
/// own C0 is the one it can never re-learn live (peers' keys are re-fetched and re-verified,
/// its own is not). A cache rebuilt from the durable snapshot must judge exactly as the
/// original would have — a peer C3 that encrypts to this node passes, one that encrypts to
/// an unknown key is still faulted.
#[test]
fn restored_cache_keeps_the_own_c0_target_across_a_restart() {
    let c3_to_c0 = || -> Box<dyn CommitmentLink> {
        Box::new(TestLink {
            scope: LinkScope::SourceMustExistInTargets,
            source: ProofType::C3aSkShareEncryption,
            target: ProofType::C0PkBfv,
        })
    };
    let own = addr(1);
    let peer = addr(2);
    let own_pk = signals(0x11);

    // Pre-crash: own C0 is cached from the local publish path.
    let mut before = CommitmentConsistency::new(e3(), vec![c3_to_c0()], 2);
    assert!(before
        .on_proof_verified(passed(
            e3(),
            1,
            own,
            ProofType::C0PkBfv,
            [0xC0; 32],
            own_pk.clone(),
        ))
        .is_empty());
    let snapshot = before.snapshot();

    // Post-restart: a fresh checker restored from the snapshot.
    let mut after = CommitmentConsistency::new(e3(), vec![c3_to_c0()], 2);
    assert_eq!(after.cached_proof_count(), 0);
    after.restore(snapshot);
    assert_eq!(after.cached_proof_count(), 1);

    // A peer C3 encrypting to our pk must pass — this is the exact link that faulted both
    // peers in Round 13 because the own C0 target was missing.
    let ok = after.on_proof_verified(passed(
        e3(),
        2,
        peer,
        ProofType::C3aSkShareEncryption,
        [0xC3; 32],
        own_pk,
    ));
    assert!(
        ok.is_empty(),
        "C3 to our own pk must match the restored C0 target"
    );

    // And a C3 to a pk nobody published is still a real violation.
    let bad = after.on_proof_verified(passed(
        e3(),
        2,
        peer,
        ProofType::C3aSkShareEncryption,
        [0xC4; 32],
        signals(0x99),
    ));
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].accused_party_id, 2);
}

/// A restored-then-empty snapshot is not the same as "no cache": an empty snapshot restores
/// to an empty cache and the SourceMustExistInTargets skip-when-no-targets rule still applies.
#[test]
fn snapshot_roundtrip_is_lossless() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    for (party, byte) in [(0u64, 0x10u8), (1, 0x20), (2, 0x30)] {
        svc.on_proof_verified(passed(
            e3(),
            party,
            addr(party as u8 + 5),
            ProofType::C1PkGeneration,
            [byte; 32],
            signals(byte),
        ));
        svc.on_proof_verified(passed(
            e3(),
            party,
            addr(party as u8 + 5),
            ProofType::C2aSkShareComputation,
            [byte + 1; 32],
            signals(byte),
        ));
    }
    assert_eq!(svc.cached_proof_count(), 6);
    let snap = svc.snapshot();
    let bytes = bincode::serialize(&snap).expect("serialize");
    let back: CommitmentConsistencySnapshot = bincode::deserialize(&bytes).expect("deserialize");
    let mut restored = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    restored.restore(back);
    assert_eq!(restored.cached_proof_count(), 6);
    assert_eq!(restored.snapshot().entries.len(), snap.entries.len());
}
