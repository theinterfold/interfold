// SPDX-License-Identifier: LGPL-2.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, Context, Result};
use commitlog::message::{MessageBuf, MessageSet};
use commitlog::{CommitLog, LogOptions, ReadLimit};
use e3_events::{EventLog, InterfoldEvent, Unsequenced};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tracing::warn;

/// Maximum message size for both reads and writes (32 MB).
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const COMMITLOG_HEADER_BYTES: usize = 20;
const COMMITLOG_INDEX_ENTRY_BYTES: usize = 8;
const COMMITLOG_SEGMENT_MAGIC: [u8; 2] = [0xff, 0xff];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventLogOpenMode {
    /// Repair only a provably uncommitted physical tail before opening.
    RecoverTail,
    /// Detect a recoverable tail without changing any on-disk bytes.
    ValidateOnly,
}

#[derive(Debug)]
struct TailRecoveryPlan {
    segment_path: PathBuf,
    indexed_end: u64,
    physical_end: u64,
    next_offset: u64,
    recovered_payloads: Vec<Vec<u8>>,
}

#[derive(Debug)]
enum PhysicalFrame {
    Complete {
        offset: u64,
        payload: Vec<u8>,
        end: u64,
    },
    Incomplete(String),
}

pub struct CommitLogEventLog {
    log: CommitLog,
    path: PathBuf,
}

impl CommitLogEventLog {
    pub fn new(path: &Path) -> Result<Self> {
        Self::open(path, EventLogOpenMode::RecoverTail)
    }

    pub fn open(path: &Path, mode: EventLogOpenMode) -> Result<Self> {
        let recovery = inspect_active_tail(path)?;
        if let Some(plan) = recovery.as_ref() {
            match mode {
                EventLogOpenMode::RecoverTail => apply_tail_recovery(plan)?,
                EventLogOpenMode::ValidateOnly => {
                    let complete = plan.recovered_payloads.len();
                    let tail_bytes = plan.physical_end.saturating_sub(plan.indexed_end);
                    anyhow::bail!(
                        "recoverable uncommitted event-log tail detected in {}: {complete} complete \
                         unindexed record(s), {tail_bytes} physical tail byte(s); rerun with \
                         `interfold node validate --repair` while the node is stopped",
                        plan.segment_path.display()
                    );
                }
            }
        }

        let mut opts = LogOptions::new(path);
        // TODO: derive this from config - currently set high to be permissive
        opts.message_max_bytes(MAX_MESSAGE_BYTES);
        let mut log = CommitLog::new(opts)?;

        if let Some(plan) = recovery {
            for (index, payload) in plan.recovered_payloads.iter().enumerate() {
                let expected_offset = plan.next_offset + index as u64;
                let actual_offset = log
                    .append_msg(payload)
                    .context("failed to restore a complete unindexed event-log tail record")?;
                if actual_offset != expected_offset {
                    anyhow::bail!(
                        "event-log tail recovery offset mismatch: expected {expected_offset}, got \
                         {actual_offset}"
                    );
                }
            }
            log.flush()
                .context("failed to flush repaired event-log tail")?;
            sync_commitlog_path(path)
                .context("failed to sync repaired event-log tail to stable storage")?;
        }

        let opened = Self {
            log,
            path: path.to_path_buf(),
        };
        opened
            .read_from_checked(1)
            .context("event log integrity check failed during open")?;
        Ok(opened)
    }

    fn append_bytes(&mut self, bytes: &[u8]) -> Result<u64> {
        let offset = self
            .log
            .append_msg(bytes)
            .context("Failed to append to event log")?;
        // Return 1-indexed sequence number
        Ok(offset + 1)
    }

    /// Read and decode every event starting at `from`, failing on the first
    /// unreadable commit-log segment or invalid event payload.
    ///
    /// A commit-log record with a valid frame/CRC but an invalid bincode payload
    /// is not safe to treat as an ignorable torn tail. Its sequence number has
    /// already been committed, so skipping it would make replayed state diverge
    /// from the state that existed before the crash and a later append would turn
    /// the same record into mid-log corruption. The [`EventLog`] adapter carries
    /// this error to startup and query callers instead of panicking an actor.
    pub fn read_from_checked(&self, from: u64) -> Result<Vec<(u64, InterfoldEvent<Unsequenced>)>> {
        self.read_from_checked_with_limit(from, None)
    }

    fn read_from_checked_with_limit(
        &self,
        from: u64,
        limit: Option<usize>,
    ) -> Result<Vec<(u64, InterfoldEvent<Unsequenced>)>> {
        // Convert 1-indexed sequence to 0-indexed offset.
        let mut current_offset = from.saturating_sub(1);
        let mut events = Vec::with_capacity(limit.unwrap_or_default().min(1024));

        if limit == Some(0) {
            return Ok(events);
        }

        loop {
            let message_buf = self
                .log
                .read(current_offset, ReadLimit::max_bytes(MAX_MESSAGE_BYTES))
                .map_err(|error| {
                    anyhow!(
                        "commit log read failed at sequence {}: {error:?}",
                        current_offset + 1
                    )
                })?;

            let mut count = 0;
            for msg in message_buf.iter() {
                let seq = msg.offset() + 1;
                if usize::from(msg.metadata_size()) > msg.size() as usize {
                    anyhow::bail!(
                        "commit log event at sequence {seq} has invalid frame metadata length; \
                         log is corrupt"
                    );
                }
                let event = InterfoldEvent::<Unsequenced>::from_bytes(msg.payload()).with_context(
                    || {
                        format!(
                            "commit log event at sequence {seq} failed to decode; log is corrupt"
                        )
                    },
                )?;
                events.push((seq, event));
                current_offset = msg.offset() + 1;
                count += 1;

                if limit.is_some_and(|limit| events.len() >= limit) {
                    break;
                }
            }

            if count == 0 || limit.is_some_and(|limit| events.len() >= limit) {
                break;
            }
        }

        Ok(events)
    }
}

fn inspect_active_tail(path: &Path) -> Result<Option<TailRecoveryPlan>> {
    if !path.exists() {
        return Ok(None);
    }

    let mut segments = BTreeSet::new();
    let mut indexes = BTreeSet::new();
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to list event-log directory {}", path.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_path = entry.path();
        let Some(stem) = file_path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if stem.len() != 20 || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let base_offset = stem.parse::<u64>().with_context(|| {
            format!(
                "invalid commit-log segment base offset in {}",
                file_path.display()
            )
        })?;
        match file_path
            .extension()
            .and_then(|extension| extension.to_str())
        {
            Some("log") => {
                segments.insert(base_offset);
            }
            Some("index") => {
                indexes.insert(base_offset);
            }
            _ => {}
        }
    }

    if segments != indexes {
        anyhow::bail!(
            "commit-log segment/index set mismatch in {} (segments: {segments:?}, indexes: \
             {indexes:?})",
            path.display()
        );
    }
    let Some(base_offset) = segments.last().copied() else {
        return Ok(None);
    };

    let segment_path = path.join(format!("{base_offset:020}.log"));
    let index_path = path.join(format!("{base_offset:020}.index"));
    let mut index_bytes = Vec::new();
    File::open(&index_path)
        .with_context(|| format!("failed to open commit-log index {}", index_path.display()))?
        .read_to_end(&mut index_bytes)?;
    if index_bytes.len() % COMMITLOG_INDEX_ENTRY_BYTES != 0 {
        anyhow::bail!(
            "commit-log index {} has invalid length {}",
            index_path.display(),
            index_bytes.len()
        );
    }

    let mut index_entries = Vec::new();
    let mut reached_empty = false;
    for entry in index_bytes.chunks_exact(COMMITLOG_INDEX_ENTRY_BYTES) {
        let relative_offset = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        let file_position = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        if relative_offset == 0 && file_position == 0 {
            reached_empty = true;
            continue;
        }
        if reached_empty {
            anyhow::bail!(
                "commit-log index {} contains a non-empty entry after its first empty slot",
                index_path.display()
            );
        }
        let expected_relative = u32::try_from(index_entries.len())
            .context("commit-log index contains more than u32::MAX entries")?;
        if relative_offset != expected_relative {
            anyhow::bail!(
                "commit-log index {} is non-contiguous at entry {}: expected relative offset {}, \
                 got {}",
                index_path.display(),
                index_entries.len(),
                expected_relative,
                relative_offset
            );
        }
        index_entries.push(u64::from(file_position));
    }

    let mut segment = File::open(&segment_path).with_context(|| {
        format!(
            "failed to open commit-log segment {}",
            segment_path.display()
        )
    })?;
    let physical_end = segment.metadata()?.len();
    let mut magic = [0u8; 2];
    segment.read_exact(&mut magic).with_context(|| {
        format!(
            "commit-log segment {} is missing its header",
            segment_path.display()
        )
    })?;
    if magic != COMMITLOG_SEGMENT_MAGIC {
        anyhow::bail!(
            "commit-log segment {} has invalid version magic",
            segment_path.display()
        );
    }

    let mut indexed_end = COMMITLOG_SEGMENT_MAGIC.len() as u64;
    for (index, position) in index_entries.iter().copied().enumerate() {
        if position != indexed_end {
            anyhow::bail!(
                "commit-log index {} points entry {} at byte {}, expected byte {}",
                index_path.display(),
                index,
                position,
                indexed_end
            );
        }
        let expected_offset = base_offset + index as u64;
        let expected_sequence = expected_offset + 1;
        let PhysicalFrame::Complete {
            offset,
            payload,
            end,
        } = read_physical_frame(&mut segment, position, physical_end)?
        else {
            anyhow::bail!(
                "committed event-log record at offset {expected_offset} is truncated or has an \
                 invalid CRC"
            );
        };
        if offset != expected_offset {
            anyhow::bail!(
                "committed event-log record offset mismatch: expected {expected_offset}, got \
                 {offset}"
            );
        }
        InterfoldEvent::<Unsequenced>::from_bytes(&payload).with_context(|| {
            format!("committed event-log record at sequence {expected_sequence} failed to decode")
        })?;
        indexed_end = end;
    }

    let next_offset = base_offset + index_entries.len() as u64;
    let mut position = indexed_end;
    let mut recovered_payloads = Vec::new();
    while position < physical_end {
        match read_physical_frame(&mut segment, position, physical_end)? {
            PhysicalFrame::Complete {
                offset,
                payload,
                end,
            } => {
                let expected_offset = next_offset + recovered_payloads.len() as u64;
                if offset != expected_offset {
                    anyhow::bail!(
                        "unindexed event-log record offset mismatch at byte {position}: expected \
                         {expected_offset}, got {offset}"
                    );
                }
                InterfoldEvent::<Unsequenced>::from_bytes(&payload).with_context(|| {
                    format!(
                        "CRC-valid unindexed event-log record at offset {offset} failed to decode; \
                         refusing to discard a potentially committed event"
                    )
                })?;
                recovered_payloads.push(payload);
                position = end;
            }
            PhysicalFrame::Incomplete(reason) => {
                warn!(
                    segment = %segment_path.display(),
                    byte = position,
                    %reason,
                    "Detected an uncommitted torn event-log tail"
                );
                break;
            }
        }
    }

    if position == physical_end && recovered_payloads.is_empty() {
        return Ok(None);
    }

    Ok(Some(TailRecoveryPlan {
        segment_path,
        indexed_end,
        physical_end,
        next_offset,
        recovered_payloads,
    }))
}

fn read_physical_frame(file: &mut File, position: u64, physical_end: u64) -> Result<PhysicalFrame> {
    let header_end = position.saturating_add(COMMITLOG_HEADER_BYTES as u64);
    if header_end > physical_end {
        return Ok(PhysicalFrame::Incomplete(format!(
            "only {} of {COMMITLOG_HEADER_BYTES} header bytes were written",
            physical_end.saturating_sub(position)
        )));
    }

    file.seek(SeekFrom::Start(position))?;
    let mut header = [0u8; COMMITLOG_HEADER_BYTES];
    file.read_exact(&mut header)?;
    let offset = u64::from_le_bytes(header[0..8].try_into().unwrap());
    let body_size = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
    let metadata_size = u16::from_le_bytes(header[18..20].try_into().unwrap()) as usize;
    if body_size > MAX_MESSAGE_BYTES || metadata_size > body_size {
        return Ok(PhysicalFrame::Incomplete(format!(
            "invalid frame sizes (body {body_size}, metadata {metadata_size})"
        )));
    }
    let frame_size = COMMITLOG_HEADER_BYTES
        .checked_add(body_size)
        .context("commit-log frame size overflow")?;
    let end = position
        .checked_add(frame_size as u64)
        .context("commit-log frame position overflow")?;
    if end > physical_end {
        return Ok(PhysicalFrame::Incomplete(format!(
            "frame declares {frame_size} bytes but only {} remain",
            physical_end.saturating_sub(position)
        )));
    }

    let mut frame = vec![0u8; frame_size];
    frame[..COMMITLOG_HEADER_BYTES].copy_from_slice(&header);
    file.read_exact(&mut frame[COMMITLOG_HEADER_BYTES..])?;
    let message_buf = match MessageBuf::from_bytes(frame) {
        Ok(message_buf) => message_buf,
        Err(error) => {
            return Ok(PhysicalFrame::Incomplete(format!(
                "frame CRC/length validation failed: {error:?}"
            )))
        }
    };
    let message = message_buf
        .iter()
        .next()
        .context("commit-log frame contained no message")?;
    Ok(PhysicalFrame::Complete {
        offset,
        payload: message.payload().to_vec(),
        end,
    })
}

fn apply_tail_recovery(plan: &TailRecoveryPlan) -> Result<()> {
    let mut segment = OpenOptions::new()
        .write(true)
        .open(&plan.segment_path)
        .with_context(|| {
            format!(
                "failed to open recoverable event-log tail {}",
                plan.segment_path.display()
            )
        })?;
    segment.set_len(plan.indexed_end).with_context(|| {
        format!(
            "failed to truncate uncommitted event-log tail in {}",
            plan.segment_path.display()
        )
    })?;
    segment.flush()?;
    segment.sync_all()?;
    warn!(
        segment = %plan.segment_path.display(),
        removed_bytes = plan.physical_end.saturating_sub(plan.indexed_end),
        recovered_records = plan.recovered_payloads.len(),
        "Recovered uncommitted event-log tail"
    );
    Ok(())
}

/// Sync every commitlog data/index file and the containing directory.
///
/// `commitlog 0.2.0`'s `CommitLog::flush` flushes Rust buffers and the index
/// mmap but does not call `File::sync_all`. The event pipeline treats a
/// successful [`EventLog::flush`] as its durability acknowledgement, so the
/// wrapper must provide the stronger stable-media boundary itself.
fn sync_commitlog_path(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to list event-log directory {}", path.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_path = entry.path();
        let is_commitlog_file = matches!(
            file_path
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("log" | "index")
        );
        if !is_commitlog_file {
            continue;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .with_context(|| format!("failed to open {} for stable sync", file_path.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync {}", file_path.display()))?;
    }

    File::open(path)
        .with_context(|| format!("failed to open event-log directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync event-log directory {}", path.display()))?;
    Ok(())
}

impl EventLog for CommitLogEventLog {
    fn append(&mut self, event: &InterfoldEvent<Unsequenced>) -> Result<u64> {
        let bytes = bincode::serialize(event)?;
        self.append_bytes(&bytes)
    }

    fn flush(&mut self) -> Result<()> {
        self.log.flush().context("Failed to flush event log")?;
        sync_commitlog_path(&self.path).context("Failed to sync event log to stable storage")?;
        Ok(())
    }

    fn read_from(
        &self,
        from: u64,
    ) -> Result<Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>>> {
        Ok(Box::new(self.read_from_checked(from)?.into_iter()))
    }

    fn read_from_bounded(
        &self,
        from: u64,
        limit: usize,
    ) -> Result<Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>>> {
        Ok(Box::new(
            self.read_from_checked_with_limit(from, Some(limit))?
                .into_iter(),
        ))
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
    use std::io::{Seek, SeekFrom, Write};
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
                    ciphertext_commitment: [0u8; 32],
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
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();

        let event1 = event_from(TestEvent::new("one", 1));
        let event2 = event_from(TestEvent::new("two", 2));

        let offset1 = log.append(&event1).unwrap();
        let offset2 = log.append(&event2).unwrap();

        assert_eq!(offset1, 1); // 1-indexed
        assert_eq!(offset2, 2);

        // Read back from the beginning
        let events: Vec<_> = log.read_from(1).unwrap().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 1);
        assert_eq!(events[1].0, 2);
    }

    #[test]
    fn test_read_from_offset() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();

        let event1 = event_from(TestEvent::new("one", 1));
        let event2 = event_from(TestEvent::new("two", 2));
        let event3 = event_from(TestEvent::new("three", 3));

        log.append(&event1).unwrap();
        log.append(&event2).unwrap();
        log.append(&event3).unwrap();

        // Read from offset 2 (should get events 2 and 3)
        let events: Vec<_> = log.read_from(2).unwrap().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 2);
        assert_eq!(events[1].0, 3);
    }

    #[test]
    fn bounded_read_decodes_only_requested_window() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();
        for value in 1..=5 {
            log.append(&event_from(TestEvent::new("event", value)))
                .unwrap();
        }

        let events: Vec<_> = log.read_from_bounded(2, 2).unwrap().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 2);
        assert_eq!(events[1].0, 3);
    }

    #[test]
    fn read_from_checked_reports_tail_corruption() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();

        for i in 0..100 {
            let e = event_from(TestEvent::new("myevent", i));
            log.append(&e).unwrap();
        }
        // Corrupt the last message
        log.append_bytes(b"I am a bad event!").unwrap();

        let error = log.read_from_checked(1).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("sequence 101"), "{message}");
        assert!(message.contains("failed to decode"), "{message}");
    }

    #[test]
    fn startup_truncates_a_torn_unindexed_tail_and_remains_appendable() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let segment_path = path.join("00000000000000000000.log");
        let mut log = CommitLogEventLog::new(&path).unwrap();
        log.append(&event_from(TestEvent::new("before-crash", 1)))
            .unwrap();
        log.flush().unwrap();
        drop(log);

        let indexed_len = fs::metadata(&segment_path).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .unwrap()
            .write_all(b"partial-frame")
            .unwrap();

        let error = CommitLogEventLog::open(&path, EventLogOpenMode::ValidateOnly)
            .err()
            .unwrap();
        assert!(
            format!("{error:#}").contains("recoverable uncommitted event-log tail"),
            "{error:#}"
        );
        assert_eq!(
            fs::metadata(&segment_path).unwrap().len(),
            indexed_len + b"partial-frame".len() as u64,
            "detection-only validation must not mutate the segment"
        );

        let mut recovered = CommitLogEventLog::new(&path).unwrap();
        assert_eq!(fs::metadata(&segment_path).unwrap().len(), indexed_len);
        assert_eq!(recovered.read_from(1).unwrap().count(), 1);
        recovered
            .append(&event_from(TestEvent::new("after-recovery", 2)))
            .unwrap();
        assert_eq!(recovered.head(), 2);
        assert_eq!(recovered.read_from(1).unwrap().count(), 2);
    }

    #[test]
    fn startup_reindexes_complete_crc_valid_tail_records() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let index_path = path.join("00000000000000000000.index");
        let mut log = CommitLogEventLog::new(&path).unwrap();
        log.append(&event_from(TestEvent::new("indexed", 1)))
            .unwrap();
        log.append(&event_from(TestEvent::new("index-lost", 2)))
            .unwrap();
        log.flush().unwrap();
        drop(log);

        let mut index = OpenOptions::new().write(true).open(&index_path).unwrap();
        index.seek(SeekFrom::Start(8)).unwrap();
        index.write_all(&[0u8; 8]).unwrap();
        index.sync_all().unwrap();
        drop(index);

        let error = CommitLogEventLog::open(&path, EventLogOpenMode::ValidateOnly)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("1 complete unindexed record"));

        let recovered = CommitLogEventLog::new(&path).unwrap();
        let events: Vec<_> = recovered.read_from(1).unwrap().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 1);
        assert_eq!(events[1].0, 2);
        assert_eq!(recovered.head(), 2);
    }

    #[test]
    fn startup_refuses_crc_corruption_in_an_indexed_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let segment_path = path.join("00000000000000000000.log");
        let mut log = CommitLogEventLog::new(&path).unwrap();
        log.append(&event_from(TestEvent::new("committed", 1)))
            .unwrap();
        log.flush().unwrap();
        drop(log);

        let mut segment = OpenOptions::new().write(true).open(&segment_path).unwrap();
        segment
            .seek(SeekFrom::Start(
                (COMMITLOG_SEGMENT_MAGIC.len() + COMMITLOG_HEADER_BYTES) as u64,
            ))
            .unwrap();
        segment.write_all(&[0xff]).unwrap();
        segment.sync_all().unwrap();

        let error = CommitLogEventLog::new(&path).err().unwrap();
        let message = format!("{error:#}");
        assert!(message.contains("committed event-log record"), "{message}");
        assert!(message.contains("invalid CRC"), "{message}");
    }

    #[test]
    fn event_log_adapter_returns_tail_corruption() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();

        log.append(&event_from(TestEvent::new("valid", 1))).unwrap();
        log.append_bytes(b"I am a bad event!").unwrap();

        let error = log.read_from(1).err().unwrap();
        assert!(format!("{error:#}").contains("sequence 2"));
    }

    #[test]
    fn test_read_from_non_tail_corruption_returns_error() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();

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

        let error = log.read_from(1).err().unwrap();
        assert!(format!("{error:#}").contains("failed to decode"));
    }

    #[test]
    fn test_head_reports_last_sequence() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();
        assert_eq!(log.head(), 0);
        log.append(&event_from(TestEvent::new("one", 1))).unwrap();
        log.append(&event_from(TestEvent::new("two", 2))).unwrap();
        assert_eq!(log.head(), 2);
    }

    #[test]
    fn test_read_empty_log() {
        let dir = tempdir().unwrap();
        let log = CommitLogEventLog::new(dir.path()).unwrap();

        let events: Vec<_> = log.read_from(1).unwrap().collect();
        assert!(events.is_empty());
    }

    #[test]
    fn test_read_past_end() {
        let dir = tempdir().unwrap();
        let mut log = CommitLogEventLog::new(dir.path()).unwrap();

        let event = event_from(TestEvent::new("one", 1));
        log.append(&event).unwrap();

        // Read from offset beyond what exists
        let events: Vec<_> = log.read_from(100).unwrap().collect();
        assert!(events.is_empty());
    }
}
