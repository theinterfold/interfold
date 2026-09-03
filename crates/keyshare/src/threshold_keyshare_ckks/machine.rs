// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure state machine for the CKKS threshold-keyshare actor: events in,
//! commands out, no actix/bus/persistence — the functional core the thin
//! actor shell drives (same separation as the BFV `state.rs`/`actor.rs`).
//!
//! Lifecycle (CKKS twin of the BFV phases, minus the BFV-only C4 round):
//!
//! ```text
//! Init
//!   -- CiphernodeSelected --> CollectingEncryptionKeys   (ephemeral BFV keys)
//!   -- all keys collected --> GeneratingThresholdShare   (deal + broadcast)
//!   -- all ThresholdShares --> ReadyForDecryption        (joint pk known)
//!   -- CiphertextOutputPublished --> Decrypting          (share published)
//!   -- plaintext aggregated --> Completed
//! ```
//!
//! Commands tell the shell what to DO (broadcast an event, publish a
//! decryption share, persist); the machine never does I/O itself.

use anyhow::{anyhow, bail, Result};
use e3_events::ThresholdShare;
use e3_fhe::{CkksFhe, CkksKeyshareMaterial};
use e3_fhe_params::ckks_presets::RelinCeremonyPlan;
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::encrypted_dkg::{build_encrypted_threshold_share, finalize_from_threshold_shares};
use super::workflow::{build_decryption_share, ReadyForDecryption};

/// Fixed chunk size for relin-ceremony share transport (8 MiB). A single
/// per-(round, level) share scales with the parameter set (~180 MiB at
/// N=32768, L=20) while the wire caps documents at `MAX_GOSSIP_BYTES` =
/// 10 MiB and `MAX_DHT_DOCUMENT_BYTES` = 25 MiB — so the send path splits
/// every share into fixed-size chunks that always fit, and the receive
/// path reassembles + keccak-verifies before ingestion. 8 MiB leaves
/// headroom for the event + document envelope under the 10 MiB gossip cap.
/// Demo-shaped shares (N=512, 2 limbs) are far below this: exactly 1 chunk.
pub const CKKS_RELIN_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// The `level` slot a HYBRID ceremony share travels in. The hybrid
/// protocol has no level (ONE share per round yields ONE key for every
/// level), so it reuses the per-(round, level) chunk transport with this
/// sentinel — it fits the wire event's `u32` level field unchanged, and a
/// hybrid machine rejects real levels while a per-level machine rejects
/// the sentinel, so mixed-mode chunks fail at the envelope check instead
/// of at key decode.
pub const HYBRID_RELIN_LEVEL: usize = u32::MAX as usize;

/// Upper bound on the serialized size of one per-(round, level) relin
/// share for `params`, used to reject a `chunk_count` no honest party
/// could need. A per-level share carries `2 · L_level` NTT polynomials
/// of `L_level` limbs each (`L_level` = moduli remaining at `level`); a
/// hybrid share (`level == HYBRID_RELIN_LEVEL`) carries `2 · dnum`
/// polynomials of `L + k` limbs. Every limb serializes as ≤ 8 bytes per
/// coefficient; the constant factor covers the protobuf/length-prefix
/// envelope.
pub fn max_relin_share_bytes(params: &fhe::ckks::CkksParameters, level: usize) -> usize {
    let raw = if level == HYBRID_RELIN_LEVEL {
        let limbs = params.moduli().len() + params.special_moduli().len();
        2 * params.dnum().max(1) * limbs * params.degree() * 8
    } else {
        let limbs = params.moduli().len().saturating_sub(level).max(1);
        // 2 (h0 + h1) · limbs (decomposition index) · limbs (RNS rows) ·
        // degree · 8 bytes.
        2 * limbs * limbs * params.degree() * 8
    };
    // Plus a generous 25% envelope allowance.
    raw + raw / 4 + 64
}

/// Largest `chunk_count` a party may advertise for one relin share at
/// `level` under `params` with the given chunk budget. Anything above is
/// rejected before a buffer is allocated (an attacker cannot make a
/// receiver reserve unbounded chunk slots).
pub fn max_relin_chunk_count(
    params: &fhe::ckks::CkksParameters,
    level: usize,
    chunk_bytes: usize,
) -> u32 {
    let chunk_bytes = chunk_bytes.max(1);
    let count = max_relin_share_bytes(params, level)
        .div_ceil(chunk_bytes)
        .max(1);
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// One fixed-size chunk of a per-(round, level) relin-ceremony share.
/// `payload_keccak` is keccak256 of the COMPLETE reassembled payload —
/// the receiver's integrity check and dedupe key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelinShareChunk {
    /// Multiplication level the share is for.
    pub level: usize,
    /// 0-based index of this chunk within the per-(round, level) payload.
    pub chunk_index: u32,
    /// Total number of chunks the payload was split into (≥ 1).
    pub chunk_count: u32,
    /// keccak256 of the complete reassembled payload.
    pub payload_keccak: [u8; 32],
    /// This chunk's bytes.
    pub bytes: ArcBytes,
}

/// Native C8 bindings of one party's signed digit-proof bundle against its
/// reassembled hybrid round-1 share (all public data; the Honk proofs
/// themselves are verified by the ShareVerificationActor):
/// - `signed_proofs[j]` is a `C8RelinRound1` proof on the digit circuit
///   whose public `digit` input equals `j` (every digit exactly once);
/// - `s_commitment` is identical across digits AND equals the party's
///   C1-CKKS sk commitment (`anchor`, from its `KeyshareCreated` proof) —
///   the ceremony secret IS the DKG secret;
/// - `u_commitment` is identical across digits (one ephemeral `u`);
/// - `share_commitment` (output) equals the commitment recomputed from
///   the reassembled share's digit-`j` rows, exactly as the witness
///   builder defines it (`digit_share_commitments_from_bytes`).
pub fn check_relin_round_1_bindings(
    fhe: &CkksFhe,
    party_id: u64,
    signed_proofs: &[e3_events::SignedProofPayload],
    share: &ArcBytes,
    anchor: Option<&[u8; 32]>,
) -> Result<()> {
    use e3_events::{CircuitName, ProofType};
    use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks_digit::digit_share_commitments_from_bytes;
    use e3_zk_helpers::threshold::user_data_encryption_ckks::CkksPreset;

    let Some(anchor) = anchor else {
        bail!("party {party_id}: no C1-CKKS sk commitment recorded — its KeyshareCreated proof was never observed");
    };
    let preset = CkksPreset {
        params: fhe.params.clone(),
        input_bound: 1.0,
    };
    let expected = digit_share_commitments_from_bytes(&preset, share)
        .map_err(|e| anyhow!("party {party_id}: reassembled R1 share does not decode: {e}"))?;
    if signed_proofs.len() != expected.len() {
        bail!(
            "party {party_id}: {} digit proofs for dnum = {}",
            signed_proofs.len(),
            expected.len()
        );
    }
    let in_layout = CircuitName::RelinRound1HybridCkksDigit.input_layout();
    let out_layout = CircuitName::RelinRound1HybridCkksDigit.output_layout();
    let mut u_commitment: Option<[u8; 32]> = None;
    for (j, signed) in signed_proofs.iter().enumerate() {
        if signed.payload.proof_type != ProofType::C8RelinRound1
            || signed.payload.proof.circuit != CircuitName::RelinRound1HybridCkksDigit
        {
            bail!("party {party_id}: bundle entry {j} is not a C8 digit proof");
        }
        let signals = &signed.payload.proof.public_signals;
        let field = |name: &str, from_inputs: bool| -> Result<[u8; 32]> {
            let bytes = if from_inputs {
                in_layout.extract_field(signals, name)
            } else {
                out_layout.extract_field(signals, name)
            }
            .ok_or_else(|| anyhow!("party {party_id}: digit {j} proof lacks `{name}`"))?;
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        };
        let s_c = field("s_commitment", true)?;
        let u_c = field("u_commitment", true)?;
        let digit = field("digit", true)?;
        let share_c = field("share_commitment", false)?;
        let mut digit_expected = [0u8; 32];
        digit_expected[24..].copy_from_slice(&(j as u64).to_be_bytes());
        if digit != digit_expected {
            bail!("party {party_id}: bundle entry {j} proves a different digit");
        }
        if s_c != *anchor {
            bail!("party {party_id}: digit {j} s_commitment differs from the party's C1-CKKS sk commitment");
        }
        match u_commitment {
            None => u_commitment = Some(u_c),
            Some(prev) if prev != u_c => {
                bail!("party {party_id}: digit {j} u_commitment differs across digits")
            }
            _ => {}
        }
        if share_c != expected[j] {
            bail!(
                "party {party_id}: digit {j} share_commitment does not match the reassembled share"
            );
        }
    }
    Ok(())
}

/// Split one serialized per-(round, level) share into fixed-size chunks.
/// Always emits at least one chunk; every chunk carries the keccak of the
/// whole payload so the receiver can verify reassembly.
pub fn chunk_relin_payload(
    level: usize,
    payload: &[u8],
    chunk_bytes: usize,
) -> Vec<RelinShareChunk> {
    let chunk_bytes = chunk_bytes.max(1);
    let payload_keccak: [u8; 32] = alloy::primitives::keccak256(payload).0;
    let count = payload.len().div_ceil(chunk_bytes).max(1);
    (0..count)
        .map(|i| {
            let start = i * chunk_bytes;
            let end = (start + chunk_bytes).min(payload.len());
            RelinShareChunk {
                level,
                chunk_index: i as u32,
                chunk_count: count as u32,
                payload_keccak,
                bytes: ArcBytes::from_bytes(&payload[start..end]),
            }
        })
        .collect()
}

/// In-flight reassembly buffer for one (party, level)'s chunked share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelinChunkBuffer {
    chunk_count: u32,
    payload_keccak: [u8; 32],
    chunks: BTreeMap<u32, ArcBytes>,
}

/// Bounds a [`RelinChunkCollector`] enforces on every ingested chunk,
/// derived from the E3's own parameters (never from the sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelinChunkBounds {
    /// SEND-side chunk budget: this party splits its own shares at this
    /// size. Received chunks are bounded by the wire cap
    /// [`CKKS_RELIN_CHUNK_BYTES`] instead, so a peer with a different
    /// (smaller, test) budget still interoperates.
    pub chunk_bytes: usize,
    /// Largest acceptable `chunk_count`, per level
    /// ([`max_relin_chunk_count`]); `None` = unbounded (tests only).
    pub max_chunk_count: Option<u32>,
    /// Maximum number of PARTIAL (in-flight) buffers one party may hold
    /// open at once across levels. A party legitimately streams one level
    /// at a time per round, so a small bound suffices; exceeding it is an
    /// attributable protocol violation.
    pub max_partial_per_party: usize,
}

impl RelinChunkBounds {
    /// Bounds for `params` under `chunk_bytes`: the chunk-count cap is
    /// computed at the DEEPEST-share level (level 0 has the most limbs and
    /// therefore the largest legitimate share), or at the hybrid share
    /// size when the params carry special primes.
    pub fn for_params(params: &fhe::ckks::CkksParameters, chunk_bytes: usize) -> Self {
        let level = if params.hybrid_enabled() {
            HYBRID_RELIN_LEVEL
        } else {
            0
        };
        Self {
            chunk_bytes,
            max_chunk_count: Some(max_relin_chunk_count(params, level, chunk_bytes)),
            max_partial_per_party: DEFAULT_MAX_PARTIAL_PER_PARTY,
        }
    }

    /// Unbounded counts (machine-level tests that inject tiny chunk
    /// budgets without a parameter set).
    pub fn unbounded(chunk_bytes: usize) -> Self {
        Self {
            chunk_bytes,
            max_chunk_count: None,
            max_partial_per_party: DEFAULT_MAX_PARTIAL_PER_PARTY,
        }
    }
}

/// Default cap on concurrent partial buffers per party. Chunks of one
/// party arrive from the DHT in any order across levels, so several
/// levels can legitimately be in flight; 8 covers observed live fan-out
/// while bounding memory at `8 · max_chunk_count · chunk_bytes` per party.
pub const DEFAULT_MAX_PARTIAL_PER_PARTY: usize = 8;

/// Per-round chunk collection: buffers chunks per (level, party), and on
/// a complete, keccak-verified set moves the reassembled payload into
/// `complete`. Duplicate chunks are idempotent; conflicting metadata or a
/// failed integrity check bails ATTRIBUTABLY (the sender is known).
///
/// Memory is bounded per party by [`RelinChunkBounds`]: at most
/// `max_partial_per_party` in-flight buffers, each at most
/// `max_chunk_count` chunks of at most `chunk_bytes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelinChunkCollector {
    /// level -> party -> in-flight buffer.
    pending: BTreeMap<usize, BTreeMap<u64, RelinChunkBuffer>>,
    /// level -> party -> (payload keccak, reassembled share bytes).
    complete: BTreeMap<usize, BTreeMap<u64, ([u8; 32], ArcBytes)>>,
}

impl RelinChunkCollector {
    /// Feed one chunk from `party_id`. Returns `Ok(true)` when this chunk
    /// completed a new payload, `Ok(false)` for partial progress or
    /// idempotent re-delivery. Bails on integrity or bound violations,
    /// naming the party.
    fn ingest(
        &mut self,
        party_id: u64,
        chunk: &RelinShareChunk,
        bounds: &RelinChunkBounds,
    ) -> Result<bool> {
        if chunk.chunk_count == 0 || chunk.chunk_index >= chunk.chunk_count {
            bail!(
                "party {party_id} sent invalid relin chunk {}/{} for level {}",
                chunk.chunk_index,
                chunk.chunk_count,
                chunk.level
            );
        }
        if let Some(max) = bounds.max_chunk_count {
            if chunk.chunk_count > max {
                bail!(
                    "party {party_id} advertised {} relin chunks for level {} but no share at \
                     these parameters needs more than {max}",
                    chunk.chunk_count,
                    chunk.level
                );
            }
        }
        if chunk.bytes.size() > CKKS_RELIN_CHUNK_BYTES {
            bail!(
                "party {party_id} sent a {}-byte relin chunk for level {} over the {}-byte wire cap",
                chunk.bytes.size(),
                chunk.level,
                CKKS_RELIN_CHUNK_BYTES
            );
        }
        // Already reassembled: same payload is an idempotent re-delivery;
        // a DIFFERENT payload from the same party is equivocation.
        if let Some((keccak, _)) = self
            .complete
            .get(&chunk.level)
            .and_then(|m| m.get(&party_id))
        {
            if *keccak == chunk.payload_keccak {
                return Ok(false);
            }
            bail!(
                "party {party_id} equivocated: second relin payload for level {} \
                 after a complete one",
                chunk.level
            );
        }
        let level_pending = self.pending.entry(chunk.level).or_default();
        if !level_pending.contains_key(&party_id) {
            let open = self
                .pending
                .values()
                .filter(|m| m.contains_key(&party_id))
                .count();
            if open >= bounds.max_partial_per_party {
                bail!(
                    "party {party_id} has {open} relin shares in flight (limit {}); refusing to \
                     open level {}",
                    bounds.max_partial_per_party,
                    chunk.level
                );
            }
        }
        let buffer = self
            .pending
            .entry(chunk.level)
            .or_default()
            .entry(party_id)
            .or_insert_with(|| RelinChunkBuffer {
                chunk_count: chunk.chunk_count,
                payload_keccak: chunk.payload_keccak,
                chunks: BTreeMap::new(),
            });
        if buffer.chunk_count != chunk.chunk_count || buffer.payload_keccak != chunk.payload_keccak
        {
            bail!(
                "party {party_id} sent inconsistent relin chunk metadata for level {} \
                 (count {} vs {}, or differing payload keccak)",
                chunk.level,
                chunk.chunk_count,
                buffer.chunk_count,
            );
        }
        match buffer.chunks.get(&chunk.chunk_index) {
            Some(existing) if existing == &chunk.bytes => return Ok(false), // duplicate
            Some(_) => bail!(
                "party {party_id} sent conflicting bytes for relin chunk {} of level {}",
                chunk.chunk_index,
                chunk.level
            ),
            None => {
                buffer.chunks.insert(chunk.chunk_index, chunk.bytes.clone());
            }
        }
        if buffer.chunks.len() < buffer.chunk_count as usize {
            return Ok(false);
        }
        // All chunks in: reassemble (BTreeMap iterates in index order) and
        // verify the payload against the advertised keccak.
        let payload: Vec<u8> = buffer
            .chunks
            .values()
            .flat_map(|b| b.iter().copied())
            .collect();
        let actual: [u8; 32] = alloy::primitives::keccak256(&payload).0;
        if actual != buffer.payload_keccak {
            // Drop the poisoned buffer so an honest retransmission can
            // still land, and attribute the failure.
            let keccak = buffer.payload_keccak;
            self.pending
                .get_mut(&chunk.level)
                .map(|m| m.remove(&party_id));
            bail!(
                "party {party_id} relin payload for level {} failed integrity: \
                 keccak {actual:02x?} != advertised {keccak:02x?}",
                chunk.level
            );
        }
        self.pending
            .get_mut(&chunk.level)
            .map(|m| m.remove(&party_id));
        self.complete
            .entry(chunk.level)
            .or_default()
            .insert(party_id, (actual, ArcBytes::from_bytes(&payload)));
        Ok(true)
    }

    /// True when every (level, party) payload has been reassembled.
    fn is_complete(&self, levels: &[usize], n_parties: usize) -> bool {
        levels
            .iter()
            .all(|l| self.complete.get(l).is_some_and(|m| m.len() == n_parties))
    }

    /// Number of reassembled payloads across all levels.
    fn complete_count(&self) -> usize {
        self.complete.values().map(BTreeMap::len).sum()
    }

    /// Reassembled payloads for one level, in party order.
    fn payloads_for_level(&self, level: usize) -> Vec<Vec<u8>> {
        self.complete
            .get(&level)
            .map(|m| m.values().map(|(_, b)| b.to_vec()).collect())
            .unwrap_or_default()
    }
}

/// Phase of the CKKS keyshare lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CkksPhase {
    /// Waiting for the committee's ephemeral BFV encryption keys.
    CollectingEncryptionKeys {
        /// party_id -> serialized ephemeral BFV pk, in committee order.
        collected: BTreeMap<u64, ArcBytes>,
    },
    /// Own material generated and broadcast; collecting everyone's shares.
    CollectingThresholdShares {
        /// Own DKG contribution (SENSITIVE fields inside; the shell
        /// persists this encrypted at rest).
        material: CkksKeyshareMaterial,
        /// Collected broadcasts, dealer party_id -> share.
        collected: BTreeMap<u64, Arc<ThresholdShare>>,
        /// Committee ephemeral pks (needed to finalize).
        encryption_keys: BTreeMap<u64, ArcBytes>,
    },
    /// DKG done; running the relinearization-key ceremony (round 1):
    /// waiting for every party's R1 share for every required level
    /// (chunks buffer in the machine-level `r1_chunks` collector, which
    /// also accepts EARLY deliveries while the DKG is still running —
    /// the network does not order peers' DKG completion against our own).
    RelinRound1 {
        /// Finalized DKG state (moves to ReadyForDecryption at the end).
        ready: Box<ReadyForDecryption>,
        /// Own secret contribution coefficients (SENSITIVE — needed for
        /// both ceremony rounds, zeroized when the ceremony completes).
        sk_coeffs: Vec<i64>,
        /// Per-party ephemeral seed for the ceremony (SENSITIVE).
        u_seed: [u8; 32],
        /// Levels needing keys (from the E3 program requirements).
        levels: Vec<usize>,
        /// Whether our own R1 chunks have been computed + emitted. R1
        /// generation for all levels is EXPENSIVE (seconds in a debug
        /// build) and the resulting documents are multi-MB × levels; doing
        /// either during DKG finalization blocks the node's event loop
        /// (peers drop on missed keepalives — observed live: a node lost
        /// its entire swarm and its KeyshareCreated put found no peers)
        /// and floods the DHT alongside the small KeyshareCreated
        /// documents. Both the compute and the publication happen in
        /// `on_public_key_aggregated`, AFTER pk consensus is confirmed.
        /// Pure ordering, deterministic on every node.
        r1_published: bool,
    },
    /// Relin ceremony round 2: every party's R1 share is in, collecting R2
    /// shares (in the machine-level `r2_chunks` collector). The per-level
    /// R1 aggregations live in the machine-level `r1_aggregated` cache
    /// (NOT here: they are bulky and recoverable from the R1 chunks).
    RelinRound2 {
        ready: Box<ReadyForDecryption>,
        sk_coeffs: Vec<i64>,
        u_seed: [u8; 32],
        levels: Vec<usize>,
    },
    /// DKG done: joint pk known, aggregated share polys held.
    ReadyForDecryption(ReadyForDecryption),
    /// Decryption share published for a ciphertext output. The hash pins
    /// the ONE ciphertext this committee's smudging share has flooded:
    /// the dealt e_sm is single-use, so a different ciphertext must be
    /// refused (reuse cancels the flooding across openings — the
    /// Li–Micciancio IND-CPA-D channel).
    Decrypting {
        ready: ReadyForDecryption,
        /// keccak256 of the served ciphertext bytes.
        served_ct_hash: [u8; 32],
    },
    /// Plaintext aggregated; lifecycle over.
    Completed,
}

/// What the shell must do after feeding an event in.
#[derive(Debug)]
pub enum CkksCommand {
    /// Broadcast this party's ephemeral encryption key.
    PublishEncryptionKey { pk_bfv: ArcBytes },
    /// Broadcast this party's ThresholdShare (encrypted dealt rows).
    PublishThresholdShare { share: Box<ThresholdShare> },
    /// DKG converged: announce THIS PARTY's pk share (KeyshareCreated).
    /// BFV-style publication: the aggregator sums the N shares and
    /// publishes the joint pk — giving it a real, provable aggregation
    /// step (C5-CKKS later) instead of a byte-equality consensus check.
    /// The machine still aggregates locally (ReadyForDecryption carries
    /// the joint pk) because decryption-share proofs (C6) bind to it.
    /// `c1_witness` carries the secrets the C1-CKKS pk-share proof needs
    /// (`pk_share = -a*sk + e`, plus the smudging contribution committed
    /// as `e_sm_commitment`); the shell routes it through the proof
    /// request path so `KeyshareCreated` leaves the node WITH a signed
    /// proof (the aggregator's rogue-key gate rejects a missing one).
    PublishKeyshareCreated {
        pk_share: ArcBytes,
        c1_witness: CkksC1Witness,
    },
    /// Publish this party's decryption share for the E3 output.
    /// Carries the ciphertext so the C6 proof request can bind to it.
    PublishDecryptionShare {
        share: ArcBytes,
        ciphertext: ArcBytes,
    },
    /// Broadcast this party's relin-ceremony round-1 share chunks
    /// (fixed-size transport pieces; one event per chunk on the wire).
    /// `c8_witness` is `Some` for a HYBRID ceremony: the whole-share
    /// witness the per-digit C8 proofs need (the shell routes it to the
    /// proof request path, which publishes `RelinCeremonyProofSigned`).
    /// Per-level ceremonies carry `None` (verify-by-determinism).
    PublishRelinRound1 {
        chunks: Vec<RelinShareChunk>,
        c8_witness: Option<CkksC8Witness>,
    },
    /// Broadcast this party's relin-ceremony round-2 share chunks.
    PublishRelinRound2 { chunks: Vec<RelinShareChunk> },
    /// Ceremony complete: the aggregated joint relin keys, one per level
    /// (every honest party computes identical bytes; the shell hands them
    /// to the evaluator/aggregator). A hybrid ceremony yields exactly one
    /// entry at [`HYBRID_RELIN_LEVEL`].
    RelinKeysReady { keys: Vec<(usize, ArcBytes)> },
    /// C8 gate: every party's hybrid round-1 share is reassembled AND its
    /// signed per-digit proof bundle passed the native bindings; the
    /// shell must now dispatch the bundles for Honk verification
    /// (`ShareVerificationDispatched { kind: RelinRound1Proofs }`) and feed
    /// the outcome back through
    /// [`CkksKeyshareMachine::on_relin_round_1_proofs_verified`].
    VerifyRelinRound1Proofs {
        bundles: Vec<(u64, Vec<e3_events::SignedProofPayload>)>,
    },
    /// The ceremony cannot complete: a party's round-1 contribution was
    /// rejected by the C8 gate (attributable). The shell fails the E3.
    RelinCeremonyFailed { party_id: u64, reason: String },
}

/// How the machine gates round-1 aggregation on C8-CKKS proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RelinProofGate {
    /// No proofs expected (per-level plans: verify-by-determinism; the
    /// explicit proof-free off-switch; no ceremony).
    #[default]
    Off,
    /// Hybrid plan under a proven posture: a party's R1 contribution is
    /// aggregated ONLY after its `dnum` digit proofs verified and bound
    /// to the reassembled share.
    Required,
}

/// Per-party C8 bundle state under [`RelinProofGate::Required`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelinProofState {
    /// party -> signed digit proofs (as received; bindings checked once the
    /// party's share is reassembled).
    pub bundles: BTreeMap<u64, Vec<e3_events::SignedProofPayload>>,
    /// Parties whose bundle passed the native bindings against their
    /// reassembled share.
    pub bound: std::collections::BTreeSet<u64>,
    /// Whether the Honk verification round was dispatched.
    pub dispatched: bool,
    /// Whether every party's proofs verified (round complete, no
    /// dishonest party).
    pub verified: bool,
}

/// The C8-CKKS (hybrid round-1) proof witness (SENSITIVE, transient).
#[derive(Clone)]
pub struct CkksC8Witness {
    /// The published share bytes (public statement).
    pub share: Vec<u8>,
    /// This party's secret-key contribution coefficients.
    pub sk_coeffs: Vec<i64>,
    /// Ephemeral `u` coefficients.
    pub u_coeffs: Vec<i64>,
    /// h0-leg errors, one per digit.
    pub e0_coeffs: Vec<Vec<i64>>,
    /// h1-leg errors, one per digit.
    pub e1_coeffs: Vec<Vec<i64>>,
}

impl std::fmt::Debug for CkksC8Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksC8Witness")
            .field("share_len", &self.share.len())
            .field("sk_coeffs", &"<redacted>")
            .field("u_coeffs", &"<redacted>")
            .finish()
    }
}

/// The C1-CKKS proof witness (SENSITIVE, never persisted — commands are
/// transient). `Debug` redacts every field.
#[derive(Clone)]
pub struct CkksC1Witness {
    /// This party's secret-key contribution coefficients.
    pub sk_coeffs: Vec<i64>,
    /// The pk-share key-generation error `e` coefficients.
    pub e_coeffs: Vec<i64>,
    /// This party's smudging contribution coefficients.
    pub e_sm_coeffs: Vec<i64>,
}

impl std::fmt::Debug for CkksC1Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksC1Witness")
            .field("sk_coeffs", &"<redacted>")
            .field("e_coeffs", &"<redacted>")
            .field("e_sm_coeffs", &"<redacted>")
            .finish()
    }
}

/// The machine: committee shape + own identity + current phase.
///
/// PARTY-ID BASE: `party_id` and every party id the machine accepts are
/// the 1-based Shamir x-coordinates (`party_id_machine`); the actor shell
/// converts from the 0-based on-chain committee slot (`party_id_chain`)
/// at its boundary. A 0 is rejected everywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CkksKeyshareMachine {
    /// This party's 1-based Shamir id.
    pub party_id: u64,
    /// Committee size `N`.
    pub n_parties: usize,
    /// Reconstruction threshold `T` (`T + 1` shares decrypt).
    pub threshold: usize,
    /// Ceremony slots: the levels the E3's program needs per-level relin
    /// keys for (empty = no ceremony, e.g. the masked-difference
    /// auction), or the single [`HYBRID_RELIN_LEVEL`] slot for a hybrid
    /// ceremony. Sorted, deduped at construction. Derive the plan with
    /// [`Self::relin_plan`].
    pub relin_levels: Vec<usize>,
    /// Public CRP seed for the relin ceremony (from the E3 seed; all
    /// parties must agree).
    pub relin_crp_seed: [u8; 32],
    /// Chunk-transport bounds for ceremony shares: budget per chunk plus
    /// the per-party caps the collectors enforce. Defaults to the
    /// production budget with unbounded counts; the shell installs
    /// parameter-derived bounds ([`RelinChunkBounds::for_params`]).
    #[serde(default = "default_relin_bounds")]
    pub relin_bounds: RelinChunkBounds,
    /// Whether pk consensus has been confirmed (PublicKeyAggregated /
    /// CommitteePublished observed). Persisted: the confirmation can
    /// arrive before this node's own DKG completes, and a restart must
    /// not wait for a signal the chain already delivered.
    #[serde(default)]
    pub pk_confirmed: bool,
    /// Round-1 ceremony chunk buffers. Machine-level (not phase-level)
    /// because the real network delivers peers' R1 chunks BEFORE this
    /// node's own DKG finalizes — early chunks must buffer, not error.
    ///
    /// `skip`: NEVER persisted. The shell snapshots the machine after
    /// EVERY event, and these buffers hold up to the whole ceremony
    /// payload (~100 MB at ladder params) — serializing them per incoming
    /// chunk wrote ~11 GB/node/run and filled the disk (surfacing as
    /// 'Snapshot batch flush failed: No space left on device'). A restart
    /// mid-ceremony replays the chunks the shell logged per chunk in its
    /// durable `CeremonyChunkLog` (see the shell's recovery branch), so
    /// buffered chunks are recoverable state, not snapshot state.
    #[serde(skip)]
    pub r1_chunks: RelinChunkCollector,
    /// Round-2 ceremony chunk buffers (same early-delivery reasoning:
    /// a peer can reach round 2 while we are still finishing round 1).
    /// `skip`: same rationale as `r1_chunks`.
    #[serde(skip)]
    pub r2_chunks: RelinChunkCollector,
    /// level -> aggregated round-1 bytes (input to the final aggregation).
    /// `skip`: same size class as a full R1 share set (~50 MB at ladder
    /// params); persisting it per event re-created the disk-fill failure
    /// that `r1_chunks` skipping fixed. After a restart in `RelinRound2`
    /// it is empty and [`Self::try_advance_relin`] rebuilds it from the
    /// replayed R1 chunks (which the shell's chunk log keeps until the
    /// ceremony completes).
    #[serde(skip)]
    pub r1_aggregated: BTreeMap<usize, ArcBytes>,
    /// C8 gate mode (set by the shell from the E3's proof posture; the
    /// default `Off` keeps pre-C8 snapshots and per-level plans working).
    #[serde(default)]
    pub relin_proof_gate: RelinProofGate,
    /// C8 bundles + verification progress (small: a few KB per party).
    #[serde(default)]
    pub relin_proofs: RelinProofState,
    /// The C8 sk-commitment anchor: each party's C1-CKKS sk commitment
    /// (public output of the signed proof its `KeyshareCreated` carried),
    /// machine party id -> 32-byte field. The shell records them from the
    /// `KeyshareCreated` events it observes (`on_c1_sk_commitment`); at
    /// gate time a party without an anchor, or whose digit proofs name a
    /// different `s_commitment`, is rejected attributably.
    #[serde(default)]
    pub c1_sk_commitments: BTreeMap<u64, [u8; 32]>,
    /// Current lifecycle phase.
    pub phase: CkksPhase,
}

fn default_relin_bounds() -> RelinChunkBounds {
    RelinChunkBounds::unbounded(CKKS_RELIN_CHUNK_BYTES)
}

/// A ceremony progress fact the machine reports SYNCHRONOUSLY, at the
/// moment it happens, to the observer the shell passes in. The machine
/// owns no clock (pure workflow rule); the shell timestamps these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkksProgress {
    /// Own round-1 share for `level` generated (`bytes` serialized).
    RelinRound1LevelGenerated { level: usize, bytes: usize },
    /// Every party's round-1 share for `level` reassembled and aggregated.
    RelinRound1LevelComplete { level: usize },
    /// Own round-2 share for `level` generated (`bytes` serialized).
    RelinRound2LevelGenerated { level: usize, bytes: usize },
    /// Every party's round-2 share for `level` reassembled; joint key
    /// for `level` aggregated.
    RelinRound2LevelComplete { level: usize },
}

/// Receiver of [`CkksProgress`] facts. The shell implements this with a
/// clock; tests and callers that do not care pass `&mut ()`.
pub trait CkksObserver {
    /// Called by the machine when a progress fact occurs.
    fn on_progress(&mut self, progress: CkksProgress);
}

impl CkksObserver for () {
    fn on_progress(&mut self, _: CkksProgress) {}
}

impl<F: FnMut(CkksProgress)> CkksObserver for F {
    fn on_progress(&mut self, progress: CkksProgress) {
        self(progress)
    }
}

impl CkksKeyshareMachine {
    /// Entry point on `CiphernodeSelected` (params already decoded as CKKS
    /// by `SchemeParams`). The shell registers its own ephemeral key too.
    pub fn new(party_id: u64, n_parties: usize, threshold: usize) -> Self {
        Self::with_relin_levels(party_id, n_parties, threshold, vec![], [0u8; 32])
    }

    /// Entry point from a param set's [`RelinCeremonyPlan`]: per-level
    /// plans key each listed level; the hybrid plan runs ONE two-round
    /// ceremony (one slot, [`HYBRID_RELIN_LEVEL`]) whose single key
    /// serves every level.
    pub fn with_relin_plan(
        party_id: u64,
        n_parties: usize,
        threshold: usize,
        plan: &RelinCeremonyPlan,
        relin_crp_seed: [u8; 32],
    ) -> Self {
        let levels = match plan {
            RelinCeremonyPlan::None => vec![],
            RelinCeremonyPlan::Hybrid => vec![HYBRID_RELIN_LEVEL],
            RelinCeremonyPlan::PerLevel(levels) => levels.clone(),
        };
        Self::with_relin_levels(party_id, n_parties, threshold, levels, relin_crp_seed)
    }

    /// The ceremony plan this machine runs (inverse of
    /// [`Self::with_relin_plan`]).
    pub fn relin_plan(&self) -> RelinCeremonyPlan {
        if self.relin_levels.is_empty() {
            RelinCeremonyPlan::None
        } else if self.relin_levels == [HYBRID_RELIN_LEVEL] {
            RelinCeremonyPlan::Hybrid
        } else {
            RelinCeremonyPlan::PerLevel(self.relin_levels.clone())
        }
    }

    /// True when this machine runs the hybrid (single-key) ceremony.
    pub fn relin_is_hybrid(&self) -> bool {
        self.relin_levels == [HYBRID_RELIN_LEVEL]
    }

    /// Install the C8 gate mode (shell: `Required` iff the plan is hybrid
    /// AND the E3's ceremony posture is `Proven`). Idempotent.
    pub fn with_relin_proof_gate(mut self, gate: RelinProofGate) -> Self {
        if gate == RelinProofGate::Required && !self.relin_is_hybrid() {
            // Per-level plans have no digit proofs; the gate is meaningless.
            self.relin_proof_gate = RelinProofGate::Off;
        } else {
            self.relin_proof_gate = gate;
        }
        self
    }

    /// Record a party's C1-CKKS sk commitment (the C8 `s_commitment`
    /// anchor) from the signed proof its `KeyshareCreated` carried.
    /// Idempotent for the same value; a DIFFERENT value for a known party
    /// is equivocation and bails.
    pub fn on_c1_sk_commitment(&mut self, party_id: u64, c1_anchor: [u8; 32]) -> Result<()> {
        if party_id == 0 || party_id > self.n_parties as u64 {
            bail!("C1 sk commitment from party id {party_id} out of range");
        }
        match self.c1_sk_commitments.get(&party_id) {
            Some(prev) if *prev != c1_anchor => bail!(
                "party {party_id} published two different C1-CKKS sk commitments (equivocation)"
            ),
            Some(_) => Ok(()),
            None => {
                self.c1_sk_commitments.insert(party_id, c1_anchor);
                Ok(())
            }
        }
    }

    /// Feed one party's signed C8 digit-proof bundle
    /// (`RelinCeremonyProofSigned`). Under [`RelinProofGate::Off`] the
    /// bundle is ignored. Stored, bound against the party's reassembled
    /// share when both are in, and once EVERY party is bound the
    /// [`CkksCommand::VerifyRelinRound1Proofs`] dispatch is emitted.
    /// Idempotent for an identical re-delivery; a different bundle from
    /// the same party bails (equivocation).
    pub fn on_relin_round_1_proofs(
        &mut self,
        party_id: u64,
        round: u8,
        level: usize,
        signed_proofs: Vec<e3_events::SignedProofPayload>,
        fhe: &CkksFhe,
    ) -> Result<Vec<CkksCommand>> {
        if self.relin_proof_gate == RelinProofGate::Off {
            return Ok(vec![]);
        }
        if party_id == 0 || party_id > self.n_parties as u64 {
            bail!(
                "relin proof bundle from party id {party_id} out of range 1..={}",
                self.n_parties
            );
        }
        if round != 1 {
            bail!("party {party_id} sent relin proofs for round {round}; only round 1 is proven");
        }
        if level != HYBRID_RELIN_LEVEL {
            bail!("party {party_id} sent relin proofs for level {level}; hybrid ceremonies use the sentinel");
        }
        let dnum = fhe.params.dnum();
        if signed_proofs.len() != dnum {
            bail!(
                "party {party_id} sent {} C8 digit proofs; this E3 has dnum = {dnum}",
                signed_proofs.len()
            );
        }
        match self.relin_proofs.bundles.get(&party_id) {
            Some(existing) if *existing == signed_proofs => return Ok(vec![]),
            Some(_) => bail!("party {party_id} sent two different C8 proof bundles (equivocation)"),
            None => {
                self.relin_proofs.bundles.insert(party_id, signed_proofs);
            }
        }
        self.try_bind_relin_proofs(fhe)
    }

    /// Outcome of the Honk verification round the shell dispatched:
    /// `dishonest` parties failed. Empty -> the gate opens and the
    /// ceremony advances (buffered shares permitting). Non-empty -> the
    /// ceremony fails attributably (a CKKS joint key needs every dealer).
    pub fn on_relin_round_1_proofs_verified(
        &mut self,
        dishonest: &std::collections::BTreeSet<u64>,
        fhe: &CkksFhe,
        observer: &mut impl CkksObserver,
    ) -> Result<Vec<CkksCommand>> {
        if self.relin_proof_gate == RelinProofGate::Off || self.relin_proofs.verified {
            return Ok(vec![]);
        }
        if let Some(&party_id) = dishonest.iter().next() {
            return Ok(vec![CkksCommand::RelinCeremonyFailed {
                party_id,
                reason: format!(
                    "C8-CKKS digit proofs failed Honk verification for {} part(y/ies) {:?}",
                    dishonest.len(),
                    dishonest
                ),
            }]);
        }
        self.relin_proofs.verified = true;
        self.try_advance_relin(fhe, observer)
    }

    /// True when the C8 gate still holds round-1 aggregation back.
    fn relin_proof_gate_closed(&self) -> bool {
        self.relin_proof_gate == RelinProofGate::Required && !self.relin_proofs.verified
    }

    /// Bind every stored bundle whose share is reassembled; when all N
    /// parties are bound, emit the verification dispatch (once).
    fn try_bind_relin_proofs(&mut self, fhe: &CkksFhe) -> Result<Vec<CkksCommand>> {
        if self.relin_proof_gate == RelinProofGate::Off || self.relin_proofs.dispatched {
            return Ok(vec![]);
        }
        let complete = self.r1_chunks.complete.get(&HYBRID_RELIN_LEVEL);
        let unbound: Vec<u64> = self
            .relin_proofs
            .bundles
            .keys()
            .copied()
            .filter(|p| !self.relin_proofs.bound.contains(p))
            .collect();
        for party_id in unbound {
            let Some((_, share)) = complete.and_then(|m| m.get(&party_id)) else {
                continue; // share not reassembled yet; bind later
            };
            let bundle = &self.relin_proofs.bundles[&party_id];
            if let Err(reason) = check_relin_round_1_bindings(
                fhe,
                party_id,
                bundle,
                share,
                self.c1_sk_commitments.get(&party_id),
            ) {
                return Ok(vec![CkksCommand::RelinCeremonyFailed {
                    party_id,
                    reason: reason.to_string(),
                }]);
            }
            self.relin_proofs.bound.insert(party_id);
        }
        if self.relin_proofs.bound.len() < self.n_parties {
            return Ok(vec![]);
        }
        self.relin_proofs.dispatched = true;
        let bundles = self
            .relin_proofs
            .bundles
            .iter()
            .map(|(p, b)| (*p, b.clone()))
            .collect();
        Ok(vec![CkksCommand::VerifyRelinRound1Proofs { bundles }])
    }

    /// Entry point for E3s whose program multiplies: `relin_levels` lists
    /// every level a relinearization occurs at; the DKG is followed by a
    /// two-round multiparty ceremony producing one joint key per level.
    /// (Tests and per-level plans; [`Self::with_relin_plan`] is the
    /// param-set entry point.)
    pub fn with_relin_levels(
        party_id: u64,
        n_parties: usize,
        threshold: usize,
        mut relin_levels: Vec<usize>,
        relin_crp_seed: [u8; 32],
    ) -> Self {
        relin_levels.sort_unstable();
        relin_levels.dedup();
        Self {
            party_id,
            n_parties,
            threshold,
            relin_levels,
            relin_crp_seed,
            relin_bounds: default_relin_bounds(),
            pk_confirmed: false,
            r1_chunks: RelinChunkCollector::default(),
            r2_chunks: RelinChunkCollector::default(),
            r1_aggregated: BTreeMap::new(),
            relin_proof_gate: RelinProofGate::Off,
            relin_proofs: RelinProofState::default(),
            c1_sk_commitments: BTreeMap::new(),
            phase: CkksPhase::CollectingEncryptionKeys {
                collected: BTreeMap::new(),
            },
        }
    }

    /// Override the ceremony-share transport chunk budget (tests force
    /// multi-chunk paths with a tiny budget; production uses the default).
    /// Keeps the chunk-count cap as it was.
    pub fn with_relin_chunk_bytes(mut self, chunk_bytes: usize) -> Self {
        self.relin_bounds.chunk_bytes = chunk_bytes.max(1);
        self
    }

    /// Install the complete chunk-transport bounds (the shell derives them
    /// from the E3's parameters).
    pub fn with_relin_bounds(mut self, bounds: RelinChunkBounds) -> Self {
        self.relin_bounds = bounds;
        self.relin_bounds.chunk_bytes = self.relin_bounds.chunk_bytes.max(1);
        self
    }

    /// Number of reassembled ceremony payloads currently held per round
    /// `(round 1, round 2)` — recovery diagnostics.
    pub fn relin_complete_counts(&self) -> (usize, usize) {
        (
            self.r1_chunks.complete_count(),
            self.r2_chunks.complete_count(),
        )
    }

    /// Feed one committee member's ephemeral encryption key (own included).
    /// When all `n_parties` are in, generates material and emits the
    /// ThresholdShare broadcast.
    #[allow(clippy::too_many_arguments)]
    pub fn on_encryption_key<R: RngCore + CryptoRng>(
        &mut self,
        party_id: u64,
        pk_bfv: ArcBytes,
        fhe: &CkksFhe,
        share_enc_params: &Arc<BfvParameters>,
        ckks_moduli: &[u64],
        smudging_bits: usize,
        rng: &mut R,
    ) -> Result<Vec<CkksCommand>> {
        let CkksPhase::CollectingEncryptionKeys { collected } = &mut self.phase else {
            bail!("encryption key in phase {:?}", self.phase_name());
        };
        if party_id == 0 || party_id > self.n_parties as u64 {
            bail!("party id {party_id} out of range 1..={}", self.n_parties);
        }
        if collected.insert(party_id, pk_bfv).is_some() {
            // Idempotent re-delivery; nothing new to do.
            return Ok(vec![]);
        }
        if collected.len() < self.n_parties {
            return Ok(vec![]);
        }

        // All keys in: deal + broadcast.
        let keys = collected.clone();
        let recipient_pks: Vec<PublicKey> = keys
            .values()
            .map(|bytes| {
                fhe_traits::DeserializeParametrized::from_bytes(bytes, share_enc_params)
                    .map_err(|e| anyhow!("bad encryption key: {e:?}"))
            })
            .collect::<Result<_>>()?;
        let material = fhe.generate_keyshare(smudging_bits)?;
        let share = build_encrypted_threshold_share(
            &material,
            self.party_id,
            &recipient_pks,
            share_enc_params,
            ckks_moduli,
            rng,
        )?;
        self.phase = CkksPhase::CollectingThresholdShares {
            material,
            collected: BTreeMap::new(),
            encryption_keys: keys,
        };
        Ok(vec![CkksCommand::PublishThresholdShare {
            share: Box::new(share),
        }])
    }

    /// Feed one member's ThresholdShare broadcast (own included). When all
    /// are in, finalizes the DKG and announces the joint pk.
    pub fn on_threshold_share(
        &mut self,
        share: Arc<ThresholdShare>,
        fhe: &CkksFhe,
        sk_bfv: &SecretKey,
        share_enc_params: &Arc<BfvParameters>,
    ) -> Result<Vec<CkksCommand>> {
        let CkksPhase::CollectingThresholdShares {
            material,
            collected,
            ..
        } = &mut self.phase
        else {
            bail!("threshold share in phase {:?}", self.phase_name());
        };
        let pid = share.party_id;
        if pid == 0 || pid > self.n_parties as u64 {
            bail!("dealer id {pid} out of range 1..={}", self.n_parties);
        }
        if collected.insert(pid, share).is_some() {
            return Ok(vec![]);
        }
        if collected.len() < self.n_parties {
            return Ok(vec![]);
        }

        let shares: Vec<Arc<ThresholdShare>> = collected.values().cloned().collect();
        let sk_coeffs = material.sk_coeffs.clone();
        let c1_witness = CkksC1Witness {
            sk_coeffs: material.sk_coeffs.clone(),
            e_coeffs: material.e_coeffs.clone(),
            e_sm_coeffs: material.es_coeffs.clone(),
        };
        let ready = finalize_from_threshold_shares(
            fhe,
            self.party_id,
            material,
            &shares,
            sk_bfv,
            share_enc_params,
        )?;
        let pk_share = ArcBytes::from_bytes(&material.pk_share);

        if self.relin_levels.is_empty() {
            self.phase = CkksPhase::ReadyForDecryption(ready);
            return Ok(vec![CkksCommand::PublishKeyshareCreated {
                pk_share,
                c1_witness,
            }]);
        }

        // Relin ceremony round 1: derive a fresh SECRET per-ceremony seed
        // for the ephemeral u (must be identical across rounds 1 and 2 —
        // the machine may be persisted/restored between them, so only the
        // seed is held, never the generator). R1 shares themselves are
        // NOT computed here — generation is expensive and its output
        // bulky; both wait for `on_public_key_aggregated` so DKG
        // finalization stays fast and the wire stays clear for
        // KeyshareCreated (see `r1_published`).
        let u_seed = fhe.random_seed()?;
        let levels = self.relin_levels.clone();
        self.phase = CkksPhase::RelinRound1 {
            ready: Box::new(ready),
            sk_coeffs,
            u_seed,
            levels,
            r1_published: false,
        };
        Ok(vec![CkksCommand::PublishKeyshareCreated {
            pk_share,
            c1_witness,
        }])
    }

    /// Feed the pk-consensus confirmation (`PublicKeyAggregated` or the
    /// chain-observed `CommitteePublished`): the (bulky) relin-ceremony
    /// round-1 shares may now be generated and published without
    /// competing with DKG traffic. Idempotent — generation happens once;
    /// later confirmations emit nothing. Arriving BEFORE this node's DKG
    /// completes, the confirmation is remembered and the release happens
    /// on DKG completion instead ([`Self::on_threshold_share`]).
    pub fn on_public_key_aggregated(
        &mut self,
        fhe: &CkksFhe,
        observer: &mut impl CkksObserver,
    ) -> Result<Vec<CkksCommand>> {
        self.pk_confirmed = true;
        self.release_relin_round_1(fhe, observer)
    }

    /// True when the ceremony is waiting for this node to generate and
    /// publish its round-1 shares (pk confirmed, DKG done, not yet
    /// released).
    pub fn relin_round_1_pending(&self) -> bool {
        self.pk_confirmed
            && matches!(
                self.phase,
                CkksPhase::RelinRound1 {
                    r1_published: false,
                    ..
                }
            )
    }

    fn release_relin_round_1(
        &mut self,
        fhe: &CkksFhe,
        observer: &mut impl CkksObserver,
    ) -> Result<Vec<CkksCommand>> {
        let chunk_bytes = self.relin_bounds.chunk_bytes;
        let crp_seed = self.relin_crp_seed;
        let CkksPhase::RelinRound1 {
            sk_coeffs,
            u_seed,
            levels,
            r1_published,
            ..
        } = &mut self.phase
        else {
            return Ok(vec![]);
        };
        if *r1_published {
            return Ok(vec![]);
        }
        let mut own = Vec::new();
        let mut c8_witness = None;
        for &level in levels.iter() {
            let share = if level == HYBRID_RELIN_LEVEL {
                let w = fhe.hybrid_relin_round_1_extended(sk_coeffs, crp_seed, *u_seed)?;
                c8_witness = Some(CkksC8Witness {
                    share: w.share.clone(),
                    sk_coeffs: sk_coeffs.clone(),
                    u_coeffs: w.u_coeffs,
                    e0_coeffs: w.e0_coeffs,
                    e1_coeffs: w.e1_coeffs,
                });
                w.share
            } else {
                fhe.relin_round_1(sk_coeffs, crp_seed, *u_seed, level)?
            };
            observer.on_progress(CkksProgress::RelinRound1LevelGenerated {
                level,
                bytes: share.len(),
            });
            own.extend(chunk_relin_payload(level, &share, chunk_bytes));
        }
        *r1_published = true;
        let mut cmds = vec![CkksCommand::PublishRelinRound1 {
            chunks: own,
            c8_witness,
        }];
        // Peers may already have delivered enough buffered chunks for the
        // ceremony to advance the moment our own share is out.
        cmds.extend(self.try_advance_relin(fhe, observer)?);
        Ok(cmds)
    }

    /// Feed one CHUNK of a party's relin round-1 broadcast (own included).
    /// Chunks buffer per (party, level) in the machine-level collector —
    /// including EARLY deliveries while our own DKG is still running (the
    /// network does not order peers' DKG completion against ours). A
    /// complete keccak-verified set reassembles into that party's share;
    /// when all parties' shares for all levels are in (and we are in the
    /// ceremony), round 1 aggregates and our round-2 chunks are emitted.
    pub fn on_relin_round_1(
        &mut self,
        party_id: u64,
        chunk: &RelinShareChunk,
        fhe: &CkksFhe,
        observer: &mut impl CkksObserver,
    ) -> Result<Vec<CkksCommand>> {
        self.check_relin_chunk_envelope(party_id, chunk, 1)?;
        let bounds = self.relin_bounds;
        match &self.phase {
            // Early delivery (peer ahead of us) or in-ceremony: buffer.
            CkksPhase::CollectingEncryptionKeys { .. }
            | CkksPhase::CollectingThresholdShares { .. } => {
                self.r1_chunks.ingest(party_id, chunk, &bounds)?;
                Ok(vec![])
            }
            CkksPhase::RelinRound1 { .. } => {
                if !self.r1_chunks.ingest(party_id, chunk, &bounds)? {
                    return Ok(vec![]);
                }
                self.try_advance_relin(fhe, observer)
            }
            // Round 2 after a restart: the R1 aggregation cache is empty
            // (never persisted) and must be rebuilt from replayed R1 chunks
            // before the final aggregation can run. With a full cache this
            // is a late re-delivery and is dropped.
            CkksPhase::RelinRound2 { levels, .. } => {
                if levels.iter().all(|l| self.r1_aggregated.contains_key(l)) {
                    return Ok(vec![]);
                }
                if !self.r1_chunks.ingest(party_id, chunk, &bounds)? {
                    return Ok(vec![]);
                }
                self.try_advance_relin(fhe, observer)
            }
            // Ceremony over: late re-delivery, ignore.
            CkksPhase::ReadyForDecryption(_)
            | CkksPhase::Decrypting { .. }
            | CkksPhase::Completed => Ok(vec![]),
        }
    }

    /// Feed one CHUNK of a party's relin round-2 broadcast (own included).
    /// Early deliveries buffer (a peer can reach round 2 while we finish
    /// round 1); when all parties' reassembled shares are in, aggregates
    /// the joint keys, zeroizes ceremony secrets, and completes the DKG
    /// (ReadyForDecryption).
    pub fn on_relin_round_2(
        &mut self,
        party_id: u64,
        chunk: &RelinShareChunk,
        fhe: &CkksFhe,
        observer: &mut impl CkksObserver,
    ) -> Result<Vec<CkksCommand>> {
        self.check_relin_chunk_envelope(party_id, chunk, 2)?;
        let bounds = self.relin_bounds;
        match &self.phase {
            CkksPhase::CollectingEncryptionKeys { .. }
            | CkksPhase::CollectingThresholdShares { .. }
            | CkksPhase::RelinRound1 { .. } => {
                self.r2_chunks.ingest(party_id, chunk, &bounds)?;
                Ok(vec![])
            }
            CkksPhase::RelinRound2 { .. } => {
                if !self.r2_chunks.ingest(party_id, chunk, &bounds)? {
                    return Ok(vec![]);
                }
                self.try_advance_relin(fhe, observer)
            }
            // Ceremony over: late re-delivery, ignore.
            CkksPhase::ReadyForDecryption(_)
            | CkksPhase::Decrypting { .. }
            | CkksPhase::Completed => Ok(vec![]),
        }
    }

    /// Trust-boundary checks common to both rounds: sender party id in
    /// range, level one the E3 actually relinearizes at, and a ceremony
    /// configured at all.
    fn check_relin_chunk_envelope(
        &self,
        party_id: u64,
        chunk: &RelinShareChunk,
        round: u8,
    ) -> Result<()> {
        let n_parties = self.n_parties;
        if party_id == 0 || party_id > n_parties as u64 {
            bail!(
                "relin round-{round} chunk from party id {party_id} out of range 1..={n_parties}"
            );
        }
        if self.relin_levels.is_empty() {
            bail!("party {party_id} sent a relin round-{round} chunk but this E3 runs no ceremony");
        }
        if !self.relin_levels.contains(&chunk.level) {
            bail!(
                "party {party_id} sent a relin round-{round} chunk for level {} which is not a \
                 ceremony level of this E3 ({:?})",
                chunk.level,
                self.relin_levels
            );
        }
        Ok(())
    }

    /// Advance the ceremony as far as buffered chunks allow: RelinRound1
    /// -> RelinRound2 when every party's R1 share is reassembled, then
    /// RelinRound2 -> ReadyForDecryption when every R2 share is in (both
    /// can fire in one call when peers ran ahead of us).
    fn try_advance_relin(
        &mut self,
        fhe: &CkksFhe,
        observer: &mut impl CkksObserver,
    ) -> Result<Vec<CkksCommand>> {
        let mut cmds = Vec::new();
        let n_parties = self.n_parties;
        let chunk_bytes = self.relin_bounds.chunk_bytes;
        let crp_seed = self.relin_crp_seed;

        // C8 gate: every party's digit proofs must be bound to its
        // reassembled share AND Honk-verified before any R1 share is
        // aggregated. Binding (native, cheap) may become possible right
        // now — the last share just landed — so try it, then hold.
        let gate_closed = self.relin_proof_gate_closed();
        if matches!(self.phase, CkksPhase::RelinRound1 { .. }) && gate_closed {
            cmds.extend(self.try_bind_relin_proofs(fhe)?);
            return Ok(cmds);
        }

        if let CkksPhase::RelinRound1 {
            ready,
            sk_coeffs,
            u_seed,
            levels,
            r1_published,
        } = &mut self.phase
        {
            // Never advance past R1 while our own chunks are unpublished:
            // peers cannot have our share yet, and completing locally
            // would emit R2 before R1 ever hit the wire.
            if !*r1_published {
                return Ok(cmds);
            }
            if !self.r1_chunks.is_complete(levels, n_parties) {
                return Ok(cmds);
            }
            // Aggregate R1 per level (party order is deterministic), cache
            // the aggregations for the final step, and emit our R2 share.
            let mut r1_aggregated = BTreeMap::new();
            let mut own_r2 = Vec::new();
            for &level in levels.iter() {
                let per_level = self.r1_chunks.payloads_for_level(level);
                let agg = if level == HYBRID_RELIN_LEVEL {
                    fhe.hybrid_relin_aggregate_round_1(&per_level)?
                } else {
                    fhe.relin_aggregate_round_1(&per_level)?
                };
                observer.on_progress(CkksProgress::RelinRound1LevelComplete { level });
                let r2 = if level == HYBRID_RELIN_LEVEL {
                    fhe.hybrid_relin_round_2(sk_coeffs, crp_seed, *u_seed, &agg)?
                } else {
                    fhe.relin_round_2(sk_coeffs, crp_seed, *u_seed, level, &agg)?
                };
                observer.on_progress(CkksProgress::RelinRound2LevelGenerated {
                    level,
                    bytes: r2.len(),
                });
                r1_aggregated.insert(level, ArcBytes::from_bytes(&agg));
                own_r2.extend(chunk_relin_payload(level, &r2, chunk_bytes));
            }
            self.phase = CkksPhase::RelinRound2 {
                ready: ready.clone(),
                sk_coeffs: std::mem::take(sk_coeffs),
                u_seed: *u_seed,
                levels: levels.clone(),
            };
            self.r1_aggregated = r1_aggregated;
            // R1 buffers are no longer needed; free the memory.
            self.r1_chunks = RelinChunkCollector::default();
            cmds.push(CkksCommand::PublishRelinRound2 { chunks: own_r2 });
        }

        if let CkksPhase::RelinRound2 {
            ready,
            sk_coeffs,
            u_seed,
            levels,
        } = &mut self.phase
        {
            if !self.r2_chunks.is_complete(levels, n_parties) {
                return Ok(cmds);
            }
            if gate_closed {
                // Cannot happen (R2 is entered after the gate opened) unless
                // the snapshot predates the gate; refuse to aggregate.
                bail!("relin round 2 reached with the C8 gate still closed");
            }
            // Restart mid-round-2: rebuild any missing R1 aggregation from
            // the replayed R1 chunks; wait if they are not all back yet.
            for &level in levels.iter() {
                if self.r1_aggregated.contains_key(&level) {
                    continue;
                }
                if !self.r1_chunks.is_complete(&[level], n_parties) {
                    return Ok(cmds);
                }
                let per_level = self.r1_chunks.payloads_for_level(level);
                let agg = if level == HYBRID_RELIN_LEVEL {
                    fhe.hybrid_relin_aggregate_round_1(&per_level)?
                } else {
                    fhe.relin_aggregate_round_1(&per_level)?
                };
                self.r1_aggregated.insert(level, ArcBytes::from_bytes(&agg));
            }
            let mut keys = Vec::with_capacity(levels.len());
            for &level in levels.iter() {
                let per_level = self.r2_chunks.payloads_for_level(level);
                let agg = self
                    .r1_aggregated
                    .get(&level)
                    .ok_or_else(|| anyhow!("missing round-1 aggregation for level {level}"))?;
                let key = if level == HYBRID_RELIN_LEVEL {
                    fhe.hybrid_relin_aggregate_round_2(&per_level, agg)?
                } else {
                    fhe.relin_aggregate_round_2(&per_level, agg)?
                };
                observer.on_progress(CkksProgress::RelinRound2LevelComplete { level });
                keys.push((level, ArcBytes::from_bytes(&key)));
            }

            // Ceremony over: zeroize secrets, free buffers, complete the DKG.
            use zeroize::Zeroize;
            sk_coeffs.zeroize();
            u_seed.zeroize();
            let ready = std::mem::replace(
                ready,
                Box::new(ReadyForDecryption {
                    party_id: 0,
                    public_key: ArcBytes::from_bytes(&[]),
                    sk_poly_sum: ArcBytes::from_bytes(&[]),
                    es_poly_sum: ArcBytes::from_bytes(&[]),
                }),
            );
            self.phase = CkksPhase::ReadyForDecryption(*ready);
            self.r1_chunks = RelinChunkCollector::default();
            self.r2_chunks = RelinChunkCollector::default();
            self.r1_aggregated = BTreeMap::new();
            cmds.push(CkksCommand::RelinKeysReady { keys });
        }
        Ok(cmds)
    }

    /// Feed the E3's evaluated ciphertext output: publish our decryption
    /// share and move to Decrypting.
    pub fn on_ciphertext_output(
        &mut self,
        ciphertext_output: &[u8],
        fhe: &CkksFhe,
    ) -> Result<Vec<CkksCommand>> {
        let ct_hash: [u8; 32] = alloy::primitives::keccak256(ciphertext_output).0;
        let ready = match &self.phase {
            CkksPhase::ReadyForDecryption(r) => r.clone(),
            CkksPhase::Decrypting {
                ready,
                served_ct_hash,
            } => {
                // SINGLE-USE smudging share: re-serving the SAME ciphertext
                // is deterministic and safe (event replay); a DIFFERENT one
                // would reuse e_sm and cancel the flooding across openings.
                if *served_ct_hash != ct_hash {
                    bail!(
                        "refusing second decryption with the same smudging share: \
                         e_sm is single-use per ciphertext (IND-CPA-D)"
                    );
                }
                ready.clone()
            }
            _ => bail!("ciphertext output in phase {:?}", self.phase_name()),
        };
        let share = build_decryption_share(fhe, &ready, ciphertext_output)?;
        self.phase = CkksPhase::Decrypting {
            ready,
            served_ct_hash: ct_hash,
        };
        Ok(vec![CkksCommand::PublishDecryptionShare {
            share: ArcBytes::from_bytes(&share),
            ciphertext: ArcBytes::from_bytes(ciphertext_output),
        }])
    }

    /// Read-only view of the current phase (shell-side C6 proof requests
    /// need the aggregated share polynomials in ReadyForDecryption).
    pub fn phase(&self) -> &CkksPhase {
        &self.phase
    }

    /// Plaintext aggregated (aggregator observed): lifecycle done.
    pub fn on_plaintext_aggregated(&mut self) -> Result<()> {
        match &self.phase {
            CkksPhase::Decrypting { .. } => {
                self.phase = CkksPhase::Completed;
                Ok(())
            }
            _ => bail!("plaintext aggregated in phase {:?}", self.phase_name()),
        }
    }

    /// The joint public key, once the DKG has converged.
    pub fn joint_public_key(&self) -> Option<&ArcBytes> {
        match &self.phase {
            CkksPhase::ReadyForDecryption(r) => Some(&r.public_key),
            CkksPhase::Decrypting { ready, .. } => Some(&ready.public_key),
            _ => None,
        }
    }

    fn phase_name(&self) -> &'static str {
        match self.phase {
            CkksPhase::CollectingEncryptionKeys { .. } => "CollectingEncryptionKeys",
            CkksPhase::CollectingThresholdShares { .. } => "CollectingThresholdShares",
            CkksPhase::RelinRound1 { .. } => "RelinRound1",
            CkksPhase::RelinRound2 { .. } => "RelinRound2",
            CkksPhase::ReadyForDecryption(_) => "ReadyForDecryption",
            CkksPhase::Decrypting { .. } => "Decrypting",
            CkksPhase::Completed => "Completed",
        }
    }
}
