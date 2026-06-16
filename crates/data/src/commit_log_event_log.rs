// SPDX-License-Identifier: LGPL-2.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Context;
use anyhow::Result;
use commitlog::message::MessageSet;
use commitlog::{CommitLog, LogOptions, ReadLimit};
use e3_events::{EventLog, InterfoldEvent, Unsequenced};
use std::path::PathBuf;
use tracing::error;

/// Maximum message size for both reads and writes (32 MB).
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

pub struct CommitLogEventLog {
    log: CommitLog,
}

impl CommitLogEventLog {
    pub fn new(path: &PathBuf) -> Result<Self> {
        let mut opts = LogOptions::new(path);
        // TODO: derive this from config - currently set high to be permissive
        opts.message_max_bytes(MAX_MESSAGE_BYTES);
        let log = CommitLog::new(opts)?;
        Ok(Self { log })
    }

    fn append_bytes(&mut self, bytes: &[u8]) -> Result<u64> {
        let offset = self
            .log
            .append_msg(bytes)
            .context("Failed to append to event log")?;
        // Return 1-indexed sequence number
        Ok(offset + 1)
    }
}

impl EventLog for CommitLogEventLog {
    fn append(&mut self, event: &InterfoldEvent<Unsequenced>) -> Result<u64> {
        let bytes = bincode::serialize(event)?;
        self.append_bytes(&bytes)
    }

    #[allow(clippy::while_let_loop)]
    fn read_from(&self, from: u64) -> Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>> {
        // Convert 1-indexed sequence to 0-indexed offset
        let mut current_offset = from.saturating_sub(1);
        let mut events = Vec::new();
        // Sequence number of the first message that failed to deserialize, if any.
        // A deserialize failure is only tolerable when it is the *tail* of the log
        // (a torn write from a crash mid-append). If a corrupt entry is followed by
        // a valid one it is mid-log corruption and replaying past it would silently
        // diverge actor state, so we halt loudly instead of skipping.
        let mut corrupt_at: Option<u64> = None;

        loop {
            let message_buf = match self
                .log
                .read(current_offset, ReadLimit::max_bytes(MAX_MESSAGE_BYTES))
            {
                Ok(msgs) => msgs,
                Err(_) => break,
            };

            let mut count = 0;
            for msg in message_buf.iter() {
                let seq = msg.offset() + 1;
                match bincode::deserialize::<InterfoldEvent<Unsequenced>>(msg.payload()) {
                    Ok(event) => {
                        if let Some(bad_seq) = corrupt_at {
                            // We already saw a corrupt entry and now found a valid one
                            // after it: the corruption is NOT at the tail.
                            panic!(
                                "Non-tail corruption in event log: entry at seq {bad_seq} failed \
                                 to deserialize but is followed by a valid entry at seq {seq}. \
                                 Replaying past it would silently drop an event. Halting; operator \
                                 recovery required."
                            );
                        }
                        // Convert 0-indexed offset back to 1-indexed sequence number
                        events.push((seq, event));
                    }
                    Err(_) => {
                        // Defer the decision: tolerate only if nothing valid follows.
                        error!("Error deserializing event in read_from at seq {seq}");
                        if corrupt_at.is_none() {
                            corrupt_at = Some(seq);
                        }
                    }
                }
                current_offset = msg.offset() + 1; // Next offset to read from
                count += 1;
            }

            // No more messages to read
            if count == 0 {
                break;
            }
        }

        Box::new(events.into_iter())
    }

    fn head(&self) -> u64 {
        // `last_offset` is 0-indexed; convert to a 1-indexed sequence number.
        self.log.last_offset().map(|o| o + 1).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{EventConstructorWithTimestamp, EventSource, InterfoldEventData, TestEvent};
    use tempfile::tempdir;

    // ── Event size reporting ─────────────────────────────────────────────────
    //
    // Run with `cargo test -p e3-data report_event_sizes -- --nocapture` to see
    // the full size table. Sizes are for minimal (empty-bytes) instances, so
    // they represent structural overhead only; real events with proof/key
    // payloads will be larger.

    #[allow(clippy::too_many_lines)]
    #[test]
    fn report_event_sizes() {
        use alloy_primitives::{Address, Bytes};
        use e3_events::{
            AccusationOutcome, AccusationQuorumReached, AccusationVote, AggregatorChanged,
            CiphernodeAdded, CiphernodeRemoved, CiphernodeSelected, CiphertextOutputPublished,
            CircuitName, CommitteeFinalizeRequested, CommitteeFinalized, CommitteePublished,
            CommitteeRequested, DecryptionKeyShared, DecryptionshareCreated, E3Failed,
            E3RequestComplete, E3Requested, E3Stage, E3id, FailureReason, KeyshareCreated,
            PlaintextAggregated, PlaintextOutputPublished, Proof, ProofPayload, ProofType,
            PublicKeyAggregated, Seed, SignedProofPayload, TicketGenerated, TicketId,
            TicketSubmitted,
        };
        use e3_utils::ArcBytes;

        let e3_id = E3id::new("1", 1);
        let empty = ArcBytes::from_bytes(&[]);
        let node = "0x0000000000000000000000000000000000000001".to_string();

        let empty_proof = Proof::new(CircuitName::PkBfv, empty.clone(), empty.clone());
        let empty_signed_proof = SignedProofPayload {
            payload: ProofPayload {
                e3_id: e3_id.clone(),
                proof_type: ProofType::C1PkGeneration,
                proof: empty_proof.clone(),
            },
            signature: ArcBytes::from_bytes(&[0u8; 65]),
        };

        let events: Vec<(&str, InterfoldEventData)> = vec![
            // Registration / sortition
            (
                "CiphernodeAdded",
                CiphernodeAdded {
                    address: node.clone(),
                    index: 0,
                    num_nodes: 1,
                    chain_id: 1,
                }
                .into(),
            ),
            (
                "CiphernodeRemoved",
                CiphernodeRemoved {
                    address: node.clone(),
                    index: 0,
                    num_nodes: 0,
                    chain_id: 1,
                }
                .into(),
            ),
            // Committee formation
            (
                "CommitteeRequested",
                CommitteeRequested {
                    e3_id: e3_id.clone(),
                    seed: Seed([0u8; 32]),
                    threshold: [2, 3],
                    request_block: 0,
                    committee_deadline: 0,
                    chain_id: 1,
                }
                .into(),
            ),
            ("CiphernodeSelected", CiphernodeSelected::default().into()),
            (
                "TicketGenerated",
                TicketGenerated {
                    e3_id: e3_id.clone(),
                    ticket_id: TicketId::Score(0),
                    node: node.clone(),
                    party_index: Some(0),
                }
                .into(),
            ),
            (
                "TicketSubmitted",
                TicketSubmitted {
                    e3_id: e3_id.clone(),
                    node: node.clone(),
                    ticket_id: 0,
                    score: "0".into(),
                    chain_id: 1,
                }
                .into(),
            ),
            (
                "CommitteeFinalized",
                CommitteeFinalized {
                    e3_id: e3_id.clone(),
                    committee: vec![node.clone()],
                    scores: vec!["0".into()],
                    chain_id: 1,
                }
                .into(),
            ),
            // E3 lifecycle
            ("E3Requested", E3Requested::default().into()),
            (
                "CommitteeFinalizeRequested",
                CommitteeFinalizeRequested {
                    e3_id: e3_id.clone(),
                }
                .into(),
            ),
            // DKG
            (
                "KeyshareCreated",
                KeyshareCreated {
                    pubkey: empty.clone(),
                    e3_id: e3_id.clone(),
                    node: node.clone(),
                    party_id: 0,
                    signed_pk_generation_proof: None,
                }
                .into(),
            ),
            (
                "KeyshareCreated (with proof)",
                KeyshareCreated {
                    pubkey: empty.clone(),
                    e3_id: e3_id.clone(),
                    node: node.clone(),
                    party_id: 0,
                    signed_pk_generation_proof: Some(empty_signed_proof.clone()),
                }
                .into(),
            ),
            (
                "PublicKeyAggregated",
                PublicKeyAggregated {
                    pubkey: empty.clone(),
                    e3_id: e3_id.clone(),
                    nodes: Default::default(),
                    committee_addresses: vec![Address::ZERO],
                    honest_committee_addresses: vec![Address::ZERO],
                    pk_commitment: [0u8; 32],
                    dkg_aggregator_proof: None,
                    dkg_attestation_bundle: None,
                }
                .into(),
            ),
            (
                "CommitteePublished",
                CommitteePublished {
                    e3_id: e3_id.clone(),
                    nodes: vec![node.clone()],
                    public_key: empty.clone(),
                    proof: empty.clone(),
                }
                .into(),
            ),
            // Computation / decryption
            (
                "CiphertextOutputPublished",
                CiphertextOutputPublished {
                    e3_id: e3_id.clone(),
                    ciphertext_output: vec![empty.clone()],
                }
                .into(),
            ),
            (
                "DecryptionKeyShared",
                DecryptionKeyShared {
                    e3_id: e3_id.clone(),
                    party_id: 0,
                    node: node.clone(),
                    signed_sk_decryption_proof: empty_signed_proof.clone(),
                    signed_e_sm_decryption_proofs: vec![],
                    external: false,
                }
                .into(),
            ),
            (
                "DecryptionshareCreated",
                DecryptionshareCreated {
                    party_id: 0,
                    decryption_share: vec![empty.clone()],
                    e3_id: e3_id.clone(),
                    node: node.clone(),
                    signed_decryption_proofs: vec![],
                }
                .into(),
            ),
            (
                "PlaintextAggregated",
                PlaintextAggregated {
                    e3_id: e3_id.clone(),
                    decrypted_output: vec![empty.clone()],
                    decryption_aggregator_proofs: vec![],
                }
                .into(),
            ),
            (
                "PlaintextOutputPublished",
                PlaintextOutputPublished {
                    e3_id: e3_id.clone(),
                    plaintext_output: empty.clone(),
                    proof: empty.clone(),
                }
                .into(),
            ),
            // Aggregator
            (
                "AggregatorChanged",
                AggregatorChanged {
                    e3_id: e3_id.clone(),
                    is_aggregator: true,
                }
                .into(),
            ),
            // Accusation / slashing
            (
                "AccusationVote",
                AccusationVote {
                    e3_id: e3_id.clone(),
                    accusation_id: [0u8; 32],
                    voter: Address::ZERO,
                    data_hash: [0u8; 32],
                    deadline: 0,
                    signature: empty.clone(),
                }
                .into(),
            ),
            (
                "AccusationQuorumReached",
                AccusationQuorumReached {
                    e3_id: e3_id.clone(),
                    accuser: Address::ZERO,
                    accused: Address::ZERO,
                    proof_type: ProofType::C1PkGeneration,
                    votes_for: vec![],
                    outcome: AccusationOutcome::AccusedFaulted,
                    evidence: Bytes::new(),
                }
                .into(),
            ),
            // Completion / failure
            (
                "E3RequestComplete",
                E3RequestComplete {
                    e3_id: e3_id.clone(),
                }
                .into(),
            ),
            (
                "E3Failed",
                E3Failed {
                    e3_id: e3_id.clone(),
                    failed_at_stage: E3Stage::None,
                    reason: FailureReason::None,
                }
                .into(),
            ),
        ];

        let mut rows: Vec<(&str, usize)> = events
            .iter()
            .map(|(name, data)| {
                let event = event_from(data.clone());
                let bytes = bincode::serialize(&event).expect("serialize");
                (*name, bytes.len())
            })
            .collect();

        rows.sort_by(|a, b| b.1.cmp(&a.1));

        println!("\n{:<50} {:>10}", "Event variant", "Bytes");
        println!("{}", "-".repeat(62));
        for (name, size) in &rows {
            println!("{:<50} {:>10}", name, size);
        }
    }

    fn event_from(data: impl Into<InterfoldEventData>) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            None,
            123,
            None,
            EventSource::Local,
        )
    }

    #[test]
    fn test_append_and_read() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();

        let event1 = event_from(TestEvent::new("one", 1));
        let event2 = event_from(TestEvent::new("two", 2));

        let offset1 = log.append(&event1).unwrap();
        let offset2 = log.append(&event2).unwrap();

        assert_eq!(offset1, 1); // 1-indexed
        assert_eq!(offset2, 2);

        // Read back from the beginning
        let events: Vec<_> = log.read_from(1).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 1);
        assert_eq!(events[1].0, 2);
    }

    #[test]
    fn test_read_from_offset() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();

        let event1 = event_from(TestEvent::new("one", 1));
        let event2 = event_from(TestEvent::new("two", 2));
        let event3 = event_from(TestEvent::new("three", 3));

        log.append(&event1).unwrap();
        log.append(&event2).unwrap();
        log.append(&event3).unwrap();

        // Read from offset 2 (should get events 2 and 3)
        let events: Vec<_> = log.read_from(2).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 2);
        assert_eq!(events[1].0, 3);
    }

    #[test]
    fn test_read_from_corruption_at_end_causes_infinite_loop() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();

        for i in 0..100 {
            let e = event_from(TestEvent::new("myevent", i));
            log.append(&e).unwrap();
        }
        // Corrupt the last message
        log.append_bytes(b"I am a bad event!").unwrap();

        // Ensure if last message is corrupt we don't end up in an infinite loop
        let _: Vec<_> = log.read_from(1).collect();
    }

    #[test]
    #[should_panic(expected = "Non-tail corruption")]
    fn test_read_from_non_tail_corruption_halts() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();

        for i in 0..10 {
            let e = event_from(TestEvent::new("before", i));
            log.append(&e).unwrap();
        }
        // Corrupt entry in the MIDDLE of the log...
        log.append_bytes(b"I am a bad event!").unwrap();
        // ...followed by a valid entry, making the corruption non-tail.
        for i in 0..10 {
            let e = event_from(TestEvent::new("after", i));
            log.append(&e).unwrap();
        }

        let _: Vec<_> = log.read_from(1).collect();
    }

    #[test]
    fn test_head_reports_last_sequence() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();
        assert_eq!(log.head(), 0);
        log.append(&event_from(TestEvent::new("one", 1))).unwrap();
        log.append(&event_from(TestEvent::new("two", 2))).unwrap();
        assert_eq!(log.head(), 2);
    }

    #[test]
    fn test_read_empty_log() {
        let dir = tempdir().unwrap();
        let log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();

        let events: Vec<_> = log.read_from(1).collect();
        assert!(events.is_empty());
    }

    #[test]
    fn test_read_past_end() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(&dir.path().to_path_buf()).unwrap();

        let event = event_from(TestEvent::new("one", 1));
        log.append(&event).unwrap();

        // Read from offset beyond what exists
        let events: Vec<_> = log.read_from(100).collect();
        assert!(events.is_empty());
    }
}
