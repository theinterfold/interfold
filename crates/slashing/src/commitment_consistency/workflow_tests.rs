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

struct SelectedRowLink;

impl CommitmentLink for SelectedRowLink {
    fn name(&self) -> &'static str {
        "selected_row"
    }
    fn source_proof_type(&self) -> ProofType {
        ProofType::C2aSkShareComputation
    }
    fn target_proof_type(&self) -> ProofType {
        ProofType::C4aSkShareDecryption
    }
    fn scope(&self) -> LinkScope {
        LinkScope::SourceMustExistInTargets
    }
    fn extract_source_values(&self, _: &[u8]) -> Vec<FieldValue> {
        vec![[1; 32]]
    }
    fn check_consistency(
        &self,
        _: &[FieldValue],
        target_public_signals: &[u8],
        source_row: u64,
        _: u64,
    ) -> bool {
        target_public_signals.first().copied() == Some(source_row as u8)
    }
}

#[test]
fn c2_c4_uses_selected_row_not_full_committee_id() {
    let mut svc = CommitmentConsistency::new(e3(), vec![Box::new(SelectedRowLink)], 2);
    let c2_party_two = passed(
        e3(),
        2,
        addr(0x22),
        ProofType::C2aSkShareComputation,
        [0xc2; 32],
        signals(0x22),
    );
    assert!(svc.on_proof_verified(c2_party_two).is_empty());
    assert!(svc
        .on_proof_verified(passed(
            e3(),
            1,
            addr(0x11),
            ProofType::C4aSkShareDecryption,
            [0xc4; 32],
            signals(1),
        ))
        .is_empty());
    assert!(svc
        .on_roster_selected(CommitmentRosterSelected {
            e3_id: e3(),
            party_ids: vec![1, 2],
        })
        .is_empty());
    assert!(svc
        .on_proof_verified(passed(
            e3(),
            2,
            addr(0x22),
            ProofType::C4aSkShareDecryption,
            [0xd4; 32],
            signals(1),
        ))
        .is_empty());
    assert!(svc
        .on_proof_verified(passed(
            e3(),
            0,
            addr(0x00),
            ProofType::C2aSkShareComputation,
            [0xd2; 32],
            signals(0),
        ))
        .is_empty());
}

#[test]
fn c2_c4_reports_a_selected_row_mismatch() {
    let mut svc = CommitmentConsistency::new(e3(), vec![Box::new(SelectedRowLink)], 2);
    svc.on_proof_verified(passed(
        e3(),
        2,
        addr(0x22),
        ProofType::C4aSkShareDecryption,
        [0xc4; 32],
        signals(1),
    ));
    svc.on_proof_verified(passed(
        e3(),
        1,
        addr(0x11),
        ProofType::C2aSkShareComputation,
        [0xc2; 32],
        signals(0),
    ));
    assert!(svc
        .on_roster_selected(CommitmentRosterSelected {
            e3_id: e3(),
            party_ids: vec![1, 2],
        })
        .is_empty());
    let violations = svc.on_proof_verified(passed(
        e3(),
        1,
        addr(0x11),
        ProofType::C4aSkShareDecryption,
        [0xd4; 32],
        signals(1),
    ));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].accused_party_id, 1);
}

#[test]
fn missing_c0_cannot_accuse_a_c3_sender() {
    let link = Box::new(TestLink {
        scope: LinkScope::SourceMustExistInTargets,
        source: ProofType::C3aSkShareEncryption,
        target: ProofType::C0PkBfv,
    });
    let mut svc = CommitmentConsistency::new(e3(), vec![link], 2);
    svc.on_proof_verified(passed(
        e3(),
        0,
        addr(0x00),
        ProofType::C0PkBfv,
        [0xc0; 32],
        signals(0x11),
    ));
    let violations = svc.on_proof_verified(passed(
        e3(),
        1,
        addr(0x11),
        ProofType::C3aSkShareEncryption,
        [0xc3; 32],
        signals(0x22),
    ));
    assert!(violations.is_empty());
}

#[test]
fn snapshot_roundtrip_preserves_proofs_and_selected_roster() {
    let mut before = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    assert!(before
        .on_roster_selected(CommitmentRosterSelected {
            e3_id: e3(),
            party_ids: vec![1, 2],
        })
        .is_empty());
    assert!(before
        .on_proof_verified(passed(
            e3(),
            1,
            addr(1),
            ProofType::C1PkGeneration,
            [0x10; 32],
            signals(0x42),
        ))
        .is_empty());

    let encoded = bincode::serialize(&before.snapshot()).expect("serialize snapshot");
    let snapshot: CommitmentConsistencySnapshot =
        bincode::deserialize(&encoded).expect("deserialize snapshot");
    let mut after = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    after.restore(snapshot).expect("restore snapshot");

    assert_eq!(after.cached_proof_count(), 1);
    assert_eq!(after.accepted_roster(), Some(&[1, 2][..]));
    assert!(after
        .on_proof_verified(passed(
            e3(),
            1,
            addr(1),
            ProofType::C2aSkShareComputation,
            [0x20; 32],
            signals(0x42),
        ))
        .is_empty());
}

#[test]
fn snapshot_rejects_an_unsupported_version() {
    let before = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let mut snapshot = before.snapshot();
    snapshot.version = COMMITMENT_CONSISTENCY_SNAPSHOT_VERSION + 1;
    let mut after = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    let error = after
        .restore(snapshot)
        .expect_err("unknown snapshot version must fail closed");
    assert!(error
        .to_string()
        .contains("unsupported commitment-consistency snapshot version"));
}

#[test]
fn snapshot_is_emitted_only_after_state_changes() {
    let mut svc = CommitmentConsistency::new(e3(), vec![same_party_link()], 2);
    assert!(svc.take_snapshot_if_changed().is_none());

    let proof = passed(
        e3(),
        1,
        addr(1),
        ProofType::C1PkGeneration,
        [0x10; 32],
        signals(0x42),
    );
    assert!(svc.on_proof_verified(proof.clone()).is_empty());
    assert!(svc.take_snapshot_if_changed().is_some());
    assert!(svc.take_snapshot_if_changed().is_none());

    assert!(svc.on_proof_verified(proof).is_empty());
    assert!(
        svc.take_snapshot_if_changed().is_none(),
        "a replayed proof must not rewrite the complete cache"
    );
}

#[actix::test]
async fn actor_persists_state_and_restores_it_after_restart() -> anyhow::Result<()> {
    use crate::actors::commitment_consistency_checker::CommitmentConsistencyChecker;
    use crate::repo::CommitmentConsistencyRepositoryFactory;
    use actix::{Actor, Context, Handler};
    use e3_data::{DataStore, InMemStore, RepositoriesFactory};
    use e3_events::{
        hlc_factory::HlcFactory, EventBus, EventBusConfig, EventConstructorWithTimestamp,
        EventSource, InterfoldEvent, Sequencer, StoreEventRequested, TypedEvent, Unsequenced,
    };

    struct StoreSink;

    impl Actor for StoreSink {
        type Context = Context<Self>;
    }

    impl Handler<StoreEventRequested> for StoreSink {
        type Result = ();

        fn handle(&mut self, _: StoreEventRequested, _: &mut Self::Context) {}
    }

    let event_bus = EventBus::new(EventBusConfig { deduplicate: true }).start();
    let sequencer = Sequencer::new(&event_bus, StoreSink.start().recipient()).start();
    let bus = e3_events::BusHandle::new(event_bus, sequencer, HlcFactory::new())
        .enable("commitment-consistency-persistence-test");
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repo = store.repositories().commitment_consistency(&e3());
    let checker = CommitmentConsistencyChecker::new(&bus, e3(), vec![same_party_link()], 2)
        .with_snapshot(repo.clone(), None)?
        .start();

    let proof = passed(
        e3(),
        1,
        addr(1),
        ProofType::C1PkGeneration,
        [0x10; 32],
        signals(0x42),
    );
    let proof_context = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        proof.clone().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1)
    .get_ctx()
    .clone();
    checker.send(TypedEvent::new(proof, proof_context)).await?;

    let roster = CommitmentRosterSelected {
        e3_id: e3(),
        party_ids: vec![1, 2],
    };
    let roster_context = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        roster.clone().into(),
        None,
        2,
        None,
        EventSource::Local,
    )
    .into_sequenced(2)
    .get_ctx()
    .clone();
    checker
        .send(TypedEvent::new(roster, roster_context))
        .await?;

    let restored = actix::clock::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(snapshot) = repo.read().await? {
                if snapshot.entries.len() == 1 && snapshot.roster.as_deref() == Some(&[1, 2]) {
                    break Ok::<_, anyhow::Error>(snapshot);
                }
            }
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await??;

    let restarted = CommitmentConsistencyChecker::new(&bus, e3(), vec![same_party_link()], 2)
        .with_snapshot(repo.clone(), Some(restored))?;
    assert_eq!(restarted.cached_proof_count(), 1);
    assert_eq!(restarted.accepted_roster(), Some(&[1, 2][..]));

    let restarted = restarted.start();
    let complete = e3_events::E3RequestComplete { e3_id: e3() };
    let complete_context = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        complete.clone().into(),
        None,
        3,
        None,
        EventSource::Local,
    )
    .into_sequenced(3)
    .get_ctx()
    .clone();
    restarted
        .send(TypedEvent::new(complete, complete_context))
        .await?;
    actix::clock::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if repo.read().await?.is_none() {
                break Ok::<_, anyhow::Error>(());
            }
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}
