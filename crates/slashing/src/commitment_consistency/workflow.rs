// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Plain, synchronous domain service for cross-circuit commitment consistency.
//!
//! This module contains **all** the consistency-checking business logic that
//! used to live inside the `CommitmentConsistencyChecker` actix actor:
//!
//! - caching verified proof outputs keyed by `(Address, ProofType)`
//! - evaluating registered [`CommitmentLink`]s across the three [`LinkScope`]s
//! - building the evidence preimage for [`CommitmentConsistencyViolation`]s
//!
//! Following the same pattern as [`crate::workflow::accusation_voting`], the
//! [`CommitmentConsistency`] service owns the protocol state and exposes plain
//! methods that mutate that state and **return decisions/data** (violations to
//! emit, the pre-ZK completion message). The service itself performs **no**
//! I/O: it never touches the event bus or the actix context. The thin actor in
//! [`crate::actors::commitment_consistency_checker`] drives it and publishes
//! whatever it returns.

use alloy::primitives::Address;
use alloy::sol_types::SolValue;
use e3_events::{
    CommitmentConsistencyCheckComplete, CommitmentConsistencyCheckRequested,
    CommitmentConsistencyViolation, CommitmentLink, E3id, LinkScope, ProofType,
    ProofVerificationPassed,
};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use tracing::warn;

/// Cached data from a verified proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VerifiedProofData {
    party_id: u64,
    address: Address,
    public_signals: ArcBytes,
    data_hash: [u8; 32],
    /// Raw `proof.data` bytes. Together with `public_signals` they form the
    /// preimage `abi.encode(proof.data, public_signals)` of `data_hash` —
    /// forwarded to slashing so the on-chain contract can verify the dataHash
    /// bound in voter signatures.
    proof_data: ArcBytes,
}

/// Durable image of the verified-proof cache.
///
/// EventStore replay on restart starts at the aggregate snapshot cursor, not at the start of
/// the log, so a freshly created checker never sees the `ProofVerificationPassed` events that
/// were delivered before the crash. The one it can never recover live is this node's **own**
/// C0: peers' keys are re-fetched and re-verified, but a node does not verify its own key, so
/// the only copy was the pre-crash event. Without it every peer C3 that encrypts *to this node*
/// fails the C3→C0 link on the next pre-ZK gate, both peers are flagged inconsistent, and the
/// E3 fails with "too few honest parties" (Round 13, cn3).
///
/// The cache is therefore persisted after every mutation and restored on hydrate. The map is
/// flattened to a `Vec` because the key is a tuple.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CommitmentConsistencySnapshot {
    entries: Vec<(Address, ProofType, Vec<VerifiedProofData>)>,
}

/// Describes a source entry whose commitments are inconsistent with a target.
struct Mismatch {
    party_id: u64,
    address: Address,
    proof_type: ProofType,
    data_hash: [u8; 32],
    /// Same preimage as `VerifiedProofData.proof_data` paired with
    /// `public_signals`. Carried from cache into the emitted violation so
    /// downstream slashing can bind voter signatures to evidence bytes.
    proof_data: ArcBytes,
    public_signals: ArcBytes,
}

/// Result of the pre-ZK gating check ([`CommitmentConsistency::on_check_requested`]).
pub(crate) struct PreZkOutcome {
    /// Violations the actor must publish for the accusation pipeline.
    pub(crate) violations: Vec<CommitmentConsistencyViolation>,
    /// Response to `ShareVerificationActor` listing inconsistent parties.
    pub(crate) complete: CommitmentConsistencyCheckComplete,
}

/// Plain, synchronous core that enforces cross-circuit commitment consistency
/// for a single E3. Owns the verified-proof cache and the registered links.
pub(crate) struct CommitmentConsistency {
    e3_id: E3id,
    links: Vec<Box<dyn CommitmentLink>>,
    /// Canonical honest-party count H. C4 `expected_commitments` only bind the lowest H
    /// senders; C2 proofs from `party_id >= H` are outside the circuit roster.
    committee_h: usize,
    /// Verified proof outputs: `(address, proof_type) → data`.
    /// Multiple proofs per key are supported (e.g. N-1 C3a proofs per sender).
    verified: HashMap<(Address, ProofType), Vec<VerifiedProofData>>,
}

impl CommitmentConsistency {
    pub(crate) fn new(
        e3_id: E3id,
        links: Vec<Box<dyn CommitmentLink>>,
        committee_h: usize,
    ) -> Self {
        Self {
            e3_id,
            links,
            committee_h,
            verified: HashMap::new(),
        }
    }

    /// Export the verified-proof cache for persistence.
    pub(crate) fn snapshot(&self) -> CommitmentConsistencySnapshot {
        CommitmentConsistencySnapshot {
            entries: self
                .verified
                .iter()
                .map(|((address, proof_type), entries)| (*address, *proof_type, entries.clone()))
                .collect(),
        }
    }

    /// Restore a cache exported by [`Self::snapshot`]. Replaces the current cache.
    pub(crate) fn restore(&mut self, snapshot: CommitmentConsistencySnapshot) {
        self.verified = snapshot
            .entries
            .into_iter()
            .map(|(address, proof_type, entries)| ((address, proof_type), entries))
            .collect();
    }

    /// Number of cached verified proofs (all parties, all types).
    pub(crate) fn cached_proof_count(&self) -> usize {
        self.verified.values().map(Vec::len).sum()
    }

    /// Number of registered links (for actor startup logging).
    pub(crate) fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Insert a proof into the cache, deduplicating by `data_hash` to avoid
    /// double-counting when the same proof arrives via both the pre-ZK batch
    /// and the post-ZK `ProofVerificationPassed` path.
    fn insert_verified(
        &mut self,
        address: Address,
        proof_type: ProofType,
        data: VerifiedProofData,
    ) {
        let entries = self.verified.entry((address, proof_type)).or_default();
        if !entries.iter().any(|e| e.data_hash == data.data_hash) {
            entries.push(data);
        }
    }

    /// Find all source entries whose commitments are inconsistent with cached
    /// targets for a given link.
    fn find_mismatches(&self, link: &dyn CommitmentLink) -> Vec<Mismatch> {
        let src_type = link.source_proof_type();
        let tgt_type = link.target_proof_type();

        match link.scope() {
            // Same address: each source entry must be consistent with each
            // target entry from the same address.
            LinkScope::SameParty => {
                let mut mismatches = Vec::new();
                for ((addr, pt), srcs) in &self.verified {
                    if *pt != src_type {
                        continue;
                    }
                    let Some(tgts) = self.verified.get(&(*addr, tgt_type)) else {
                        continue;
                    };
                    for src in srcs {
                        let vals = link.extract_source_values(&src.public_signals);
                        for tgt in tgts {
                            if !link.check_consistency(
                                &vals,
                                &tgt.public_signals,
                                src.party_id,
                                tgt.party_id,
                            ) {
                                mismatches.push(Mismatch {
                                    party_id: src.party_id,
                                    address: *addr,
                                    proof_type: src_type,
                                    data_hash: src.data_hash,
                                    proof_data: src.proof_data.clone(),
                                    public_signals: src.public_signals.clone(),
                                });
                                break; // one mismatch per source entry is enough
                            }
                        }
                    }
                }
                mismatches
            }

            // Cross-party: each source's extracted value must appear in at
            // least one target's public signals. Fault the source if no match.
            // If no targets are cached yet, skip — the check will run again
            // when a target arrives.
            LinkScope::CrossParty => {
                let all_targets: Vec<&VerifiedProofData> = self
                    .verified
                    .iter()
                    .filter(|((_, pt), _)| *pt == tgt_type)
                    .flat_map(|(_, entries)| entries)
                    .collect();

                if all_targets.is_empty() {
                    return Vec::new();
                }

                let mut mismatches = Vec::new();
                for ((_, pt), srcs) in &self.verified {
                    if *pt != src_type {
                        continue;
                    }
                    for src in srcs {
                        if self.skip_capped_roster_source(src_type, src.party_id) {
                            continue;
                        }
                        let vals = link.extract_source_values(&src.public_signals);
                        if vals.is_empty() {
                            continue;
                        }
                        // Source must match AT LEAST ONE target.
                        let found = all_targets.iter().any(|tgt| {
                            link.check_consistency(
                                &vals,
                                &tgt.public_signals,
                                src.party_id,
                                tgt.party_id,
                            )
                        });
                        if !found {
                            mismatches.push(Mismatch {
                                party_id: src.party_id,
                                address: src.address,
                                proof_type: src_type,
                                data_hash: src.data_hash,
                                proof_data: src.proof_data.clone(),
                                public_signals: src.public_signals.clone(),
                            });
                        }
                    }
                }
                mismatches
            }

            // Each source claims a value that must exist among any target's
            // outputs. Fault the source (e.g. C3) when no target (e.g. C0)
            // matches. If no targets are cached yet, skip — the check will
            // run when a target arrives via post-ZK ProofVerificationPassed.
            LinkScope::SourceMustExistInTargets => {
                let all_targets: Vec<&VerifiedProofData> = self
                    .verified
                    .iter()
                    .filter(|((_, pt), _)| *pt == tgt_type)
                    .flat_map(|(_, entries)| entries)
                    .collect();

                if all_targets.is_empty() {
                    return Vec::new();
                }

                let mut mismatches = Vec::new();
                for ((_, pt), srcs) in &self.verified {
                    if *pt != src_type {
                        continue;
                    }
                    for src in srcs {
                        if self.skip_capped_roster_source(src_type, src.party_id) {
                            continue;
                        }
                        let vals = link.extract_source_values(&src.public_signals);
                        if vals.is_empty() {
                            continue;
                        }
                        let found = all_targets.iter().any(|tgt| {
                            link.check_consistency(
                                &vals,
                                &tgt.public_signals,
                                src.party_id,
                                tgt.party_id,
                            )
                        });
                        if !found {
                            mismatches.push(Mismatch {
                                party_id: src.party_id,
                                address: src.address,
                                proof_type: src_type,
                                data_hash: src.data_hash,
                                proof_data: src.proof_data.clone(),
                                public_signals: src.public_signals.clone(),
                            });
                        }
                    }
                }
                mismatches
            }
        }
    }

    /// Circuits that only witness the lowest `H` senders cannot attest to a surplus
    /// party's proof, so a source above that cap must not be faulted.
    ///
    /// Two independent circuit families cap their roster at `H`:
    ///
    /// - **C4** binds `expected_commitments` for the lowest `H` C2a/C2b senders.
    /// - **C5** witnesses the canonical honest subset chosen by
    ///   `select_honest_set`, which keeps the `H` lowest party IDs and leaves the
    ///   remaining `N - H` parties in the full committee (see
    ///   `e3_aggregator::public_key_aggregation`). Every one of the `N` parties
    ///   produces a C1 proof, so on any committee with `N > H` the surplus C1
    ///   sources have no C5 target and would otherwise be reported as violations
    ///   on a completely successful DKG round.
    ///
    /// C6 needs no such exemption: only the `H` honest-subset members submit
    /// decryption shares and every canonical committee has `H == T + 1`, which is
    /// exactly the C7 witness width.
    fn skip_capped_roster_source(&self, proof_type: ProofType, party_id: u64) -> bool {
        matches!(
            proof_type,
            ProofType::C2aSkShareComputation
                | ProofType::C2bESmShareComputation
                | ProofType::C1PkGeneration
        ) && party_id as usize >= self.committee_h
    }

    /// Build the [`CommitmentConsistencyViolation`] for a mismatch, computing
    /// the evidence preimage `abi.encode(proof.data, public_signals)`.
    ///
    /// The on-chain `SlashingManager.proposeSlash` recomputes
    /// `keccak256(evidence)` and requires it to equal each voter's signed
    /// `dataHash`. Without these bytes, slashing via the consistency-violation
    /// path would be gated by the evidence binding (safe but unable to slash).
    fn build_violation(&self, m: &Mismatch) -> CommitmentConsistencyViolation {
        let evidence = alloy::primitives::Bytes::from(
            (
                alloy::primitives::Bytes::copy_from_slice(&m.proof_data),
                alloy::primitives::Bytes::copy_from_slice(&m.public_signals),
            )
                .abi_encode(),
        );
        CommitmentConsistencyViolation {
            e3_id: self.e3_id.clone(),
            accused_party_id: m.party_id,
            accused_address: m.address,
            proof_type: m.proof_type,
            data_hash: m.data_hash,
            evidence,
        }
    }

    /// Post-ZK: cache a newly verified proof and evaluate the links relevant to
    /// its proof type, returning any [`CommitmentConsistencyViolation`]s to emit.
    pub(crate) fn on_proof_verified(
        &mut self,
        data: ProofVerificationPassed,
    ) -> Vec<CommitmentConsistencyViolation> {
        if data.e3_id != self.e3_id {
            return Vec::new();
        }

        let proof_type = data.proof_type;
        let address = data.address;

        self.insert_verified(
            address,
            proof_type,
            VerifiedProofData {
                party_id: data.party_id,
                address,
                public_signals: data.public_signals,
                data_hash: data.data_hash,
                proof_data: data.proof_data,
            },
        );

        self.check_links(proof_type)
    }

    /// Evaluate links relevant to a newly arrived proof type and collect
    /// violations on mismatch.
    fn check_links(&self, new_proof_type: ProofType) -> Vec<CommitmentConsistencyViolation> {
        let mut violations = Vec::new();
        for link in &self.links {
            if new_proof_type != link.source_proof_type()
                && new_proof_type != link.target_proof_type()
            {
                continue;
            }
            for m in self.find_mismatches(link.as_ref()) {
                // Defense-in-depth: skip entries with unresolved data_hash
                // (should not happen now that pre-ZK caching uses real hashes,
                // but guards against future regressions).
                if m.data_hash == [0u8; 32] {
                    warn!(
                        e3_id = %self.e3_id,
                        "[{}] Skipping mismatch with zero data_hash for party {} ({}) {:?}",
                        link.name(),
                        m.party_id,
                        m.address,
                        m.proof_type,
                    );
                    continue;
                }
                warn!(
                    "[{}] Commitment mismatch for E3 {} — party {} ({}) {:?}",
                    link.name(),
                    self.e3_id,
                    m.party_id,
                    m.address,
                    m.proof_type,
                );
                violations.push(self.build_violation(&m));
            }
        }
        violations
    }

    /// Pre-ZK gating: cache all party proofs, evaluate every link, and return
    /// the inconsistent parties (to exclude from ZK) plus the violations to
    /// emit. Returns `None` for a foreign `e3_id`.
    pub(crate) fn on_check_requested(
        &mut self,
        data: CommitmentConsistencyCheckRequested,
    ) -> Option<PreZkOutcome> {
        if data.e3_id != self.e3_id {
            return None;
        }

        let mut inconsistent_parties = BTreeSet::new();
        let mut violations = Vec::new();

        // Cache each party's proof data for link evaluation.
        for party in &data.party_proofs {
            for (proof_type, public_signals, data_hash, proof_data) in &party.proofs {
                self.insert_verified(
                    party.address,
                    *proof_type,
                    VerifiedProofData {
                        party_id: party.party_id,
                        address: party.address,
                        public_signals: public_signals.clone(),
                        data_hash: *data_hash,
                        proof_data: proof_data.clone(),
                    },
                );
            }
        }

        // Evaluate every link and collect inconsistent parties.
        // Also build violations so AccusationManager can initiate the quorum
        // protocol — parties excluded pre-ZK would otherwise never trigger a
        // post-ZK violation.
        for link in &self.links {
            for m in self.find_mismatches(link.as_ref()) {
                warn!(
                    "[{}] Pre-ZK commitment mismatch for E3 {} — party {} ({})",
                    link.name(),
                    self.e3_id,
                    m.party_id,
                    m.address,
                );
                inconsistent_parties.insert(m.party_id);
                violations.push(self.build_violation(&m));
            }
        }

        // Remove cached entries for inconsistent parties so they don't
        // participate in future post-ZK `find_mismatches` evaluations.
        if !inconsistent_parties.is_empty() {
            self.verified.retain(|_, entries| {
                entries.retain(|v| !inconsistent_parties.contains(&v.party_id));
                !entries.is_empty()
            });
        }

        Some(PreZkOutcome {
            violations,
            complete: CommitmentConsistencyCheckComplete {
                e3_id: data.e3_id,
                kind: data.kind,
                correlation_id: data.correlation_id,
                inconsistent_parties,
            },
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
