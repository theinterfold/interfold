// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous domain logic for C1/C2/C3/C4/C6 share-proof verification.
//!
//! The [`crate::actors::share_verification::ShareVerificationActor`] is a thin
//! transport shell: it owns the event bus and performs all publish/persist I/O.
//! This module owns the business logic — ECDSA validation, proof-commitment
//! hashing, consistency filtering, and ZK-result tallying — as pure functions on
//! the stateless [`ShareVerifier`] service, plus the per-E3 pending-state types.
//! It has NO actix / `BusHandle` / `Addr` concerns (tracing is allowed).

use std::collections::{BTreeSet, HashMap, HashSet};

use alloy::primitives::{keccak256, Address, Bytes};
use alloy::sol_types::SolValue;
use e3_events::{
    E3id, EventContext, PartyProofData, PartyProofsToVerify, PartyShareDecryptionProofsToVerify,
    PartyVerificationResult, ProofType, Sequenced, SignedProofPayload, VerificationKind,
};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{info, warn};

/// Trait for party types whose signed proofs can be ECDSA-validated and ZK-verified.
pub(crate) trait VerifiableParty: Clone {
    fn party_id(&self) -> u64;
    fn signed_proofs(&self) -> Vec<SignedProofPayload>;
}

impl VerifiableParty for PartyProofsToVerify {
    fn party_id(&self) -> u64 {
        self.sender_party_id
    }
    fn signed_proofs(&self) -> Vec<SignedProofPayload> {
        self.signed_proofs.clone()
    }
}

impl VerifiableParty for PartyShareDecryptionProofsToVerify {
    fn party_id(&self) -> u64 {
        self.sender_party_id
    }
    fn signed_proofs(&self) -> Vec<SignedProofPayload> {
        std::iter::once(self.signed_sk_decryption_proof.clone())
            .chain(self.signed_e_sm_decryption_proofs.iter().cloned())
            .collect()
    }
}

/// ECDSA validation result for a single party.
pub(crate) struct EcdsaPartyResult {
    pub(crate) passed: bool,
    /// The pair (signed_payload, recovered_address) of the first failing proof, if any.
    pub(crate) failed_payload: Option<(SignedProofPayload, Option<Address>)>,
}

/// A single ECDSA failure to be attributed (emitted) by the actor.
pub(crate) struct EcdsaFailure {
    pub(crate) party_id: u64,
    pub(crate) signed: SignedProofPayload,
    pub(crate) recovered: Option<Address>,
}

/// Outcome of validating + preparing a batch of party proofs for the
/// consistency-check + ZK phases. Pure data; the actor performs the I/O.
pub(crate) struct EcdsaValidationOutcome<P> {
    pub(crate) ecdsa_dishonest: HashSet<u64>,
    /// Failures to emit, in party iteration order.
    pub(crate) failures: Vec<EcdsaFailure>,
    pub(crate) ecdsa_passed_parties: Vec<P>,
    pub(crate) party_addresses: HashMap<u64, Address>,
    pub(crate) party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>>,
    pub(crate) party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    pub(crate) party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Assembled per-party data for the consistency-check request.
    pub(crate) consistency_party_data: Vec<PartyProofData>,
}

/// Pending verification state — stored while ZK verification is in flight.
pub(crate) struct PendingVerification {
    pub(crate) e3_id: E3id,
    pub(crate) kind: VerificationKind,
    pub(crate) ec: EventContext<Sequenced>,
    /// Parties that failed ECDSA (dishonest before ZK runs).
    pub(crate) ecdsa_dishonest: HashSet<u64>,
    /// Pre-dishonest parties from the dispatch (missing/incomplete proofs).
    pub(crate) pre_dishonest: BTreeSet<u64>,
    /// Party IDs dispatched for ZK verification (for cross-checking results).
    pub(crate) dispatched_party_ids: HashSet<u64>,
    /// Recovered address for each party (from ECDSA step).
    pub(crate) party_addresses: HashMap<u64, Address>,
    /// Cached (proof_type, data_hash) per party — for emitting ProofVerificationPassed.
    pub(crate) party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>>,
    /// Cached (proof_type, public_signals) per party — for commitment consistency checking.
    pub(crate) party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Parallel to `party_public_signals` — raw `proof.data` per (party, proof_type).
    pub(crate) party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// BFV preset for circuit artifact resolution.
    #[allow(dead_code)]
    pub(crate) params_preset: e3_fhe_params::BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    #[allow(dead_code)]
    pub(crate) committee_size: CiphernodesCommitteeSize,
}

/// Pending consistency check — stored between ECDSA pass and ZK dispatch.
pub(crate) struct PendingConsistencyCheck {
    pub(crate) e3_id: E3id,
    pub(crate) kind: VerificationKind,
    pub(crate) ec: EventContext<Sequenced>,
    /// Parties that failed ECDSA (dishonest before consistency runs).
    pub(crate) ecdsa_dishonest: HashSet<u64>,
    /// Pre-dishonest parties from the dispatch (missing/incomplete proofs).
    pub(crate) pre_dishonest: BTreeSet<u64>,
    /// Recovered address per ECDSA-passed party.
    pub(crate) party_addresses: HashMap<u64, Address>,
    /// (proof_type, data_hash) per party — for ProofVerificationPassed after ZK.
    pub(crate) party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>>,
    /// (proof_type, public_signals) per party — for consistency & ZK.
    pub(crate) party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Parallel to `party_public_signals` — raw `proof.data` per (party, proof_type).
    pub(crate) party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>>,
    /// Original ECDSA-passed share proofs for ZK dispatch.
    pub(crate) ecdsa_passed_share_proofs: Vec<PartyProofsToVerify>,
    /// Original ECDSA-passed decryption proofs for ZK dispatch.
    pub(crate) ecdsa_passed_decryption_proofs: Vec<PartyShareDecryptionProofsToVerify>,
    /// BFV preset for circuit artifact resolution.
    pub(crate) params_preset: e3_fhe_params::BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    pub(crate) committee_size: CiphernodesCommitteeSize,
}

/// Filter out inconsistent parties and collect dispatched party IDs.
/// Returns `None` if all parties were filtered out (nothing to verify).
pub(crate) fn filter_consistent<P>(
    proofs: Vec<P>,
    inconsistent: &BTreeSet<u64>,
    party_id_of: impl Fn(&P) -> u64,
) -> Option<(Vec<P>, HashSet<u64>)> {
    let passed: Vec<P> = proofs
        .into_iter()
        .filter(|p| !inconsistent.contains(&party_id_of(p)))
        .collect();
    if passed.is_empty() {
        return None;
    }
    let ids = passed.iter().map(party_id_of).collect();
    Some((passed, ids))
}

/// Per-party emission decision produced when tallying ZK verification results.
pub(crate) enum ZkPartyEmission {
    /// Party failed ZK — attribute fault using the signed payload.
    Failed {
        party_id: u64,
        signed: SignedProofPayload,
    },
    /// Party passed ZK — emit `ProofVerificationPassed` for each cached proof.
    Passed { party_id: u64 },
}

/// Outcome of tallying ZK verification results: the accumulated dishonest set
/// and the ordered emission decisions.
pub(crate) struct ZkTallyOutcome {
    pub(crate) dishonest: BTreeSet<u64>,
    pub(crate) emissions: Vec<ZkPartyEmission>,
}

/// Human-readable label for a verification kind (used in log lines).
pub(crate) fn label_for(kind: &VerificationKind) -> &'static str {
    match kind {
        VerificationKind::ShareProofs => "C2/C3",
        VerificationKind::ThresholdDecryptionProofs => "C6",
        VerificationKind::PkGenerationProofs => "C1",
        VerificationKind::DecryptionProofs => "C4",
    }
}

/// Stateless service holding all pure share-verification business logic.
pub(crate) struct ShareVerifier;

impl ShareVerifier {
    /// Keccak256 over `abi_encode((proof.data, proof.public_signals))`.
    fn proof_data_hash(signed: &SignedProofPayload) -> [u8; 32] {
        let msg = (
            Bytes::copy_from_slice(&signed.payload.proof.data),
            Bytes::copy_from_slice(&signed.payload.proof.public_signals),
        )
            .abi_encode();
        keccak256(&msg).into()
    }

    /// Validate ECDSA properties for a set of signed proofs from one party:
    /// 1. e3_id match
    /// 2. Signature recovery (valid ECDSA)
    /// 3. Signer consistency (all proofs from same address)
    /// 4. Circuit name matches expected ProofType circuits
    pub(crate) fn ecdsa_validate_signed_proofs(
        sender_party_id: u64,
        signed_proofs: &[SignedProofPayload],
        e3_id_str: &str,
        label: &str,
    ) -> EcdsaPartyResult {
        let mut expected_addr: Option<Address> = None;

        for signed in signed_proofs {
            // 1. e3_id match
            if signed.payload.e3_id.to_string() != e3_id_str {
                info!(
                    "{} proof from party {} has wrong e3_id ({} vs {})",
                    label, sender_party_id, signed.payload.e3_id, e3_id_str
                );
                return EcdsaPartyResult {
                    passed: false,
                    failed_payload: Some((signed.clone(), expected_addr)),
                };
            }

            // 2. Signature recovery
            match signed.recover_address() {
                Ok(addr) => {
                    // 3. Signer consistency
                    match &expected_addr {
                        Some(ea) if *ea != addr => {
                            info!(
                                "{} inconsistent signer for party {}",
                                label, sender_party_id
                            );
                            return EcdsaPartyResult {
                                passed: false,
                                failed_payload: Some((signed.clone(), Some(addr))),
                            };
                        }
                        None => expected_addr = Some(addr),
                        _ => {}
                    }
                }
                Err(e) => {
                    info!(
                        "{} signature recovery failed for party {} ({:?}): {}",
                        label, sender_party_id, signed.payload.proof_type, e
                    );
                    return EcdsaPartyResult {
                        passed: false,
                        failed_payload: Some((signed.clone(), expected_addr)),
                    };
                }
            }

            // 4. Circuit name validation
            let expected_circuits = signed.payload.proof_type.circuit_names();
            if !expected_circuits.contains(&signed.payload.proof.circuit) {
                info!(
                    "{} circuit mismatch for party {}: expected {:?}, got {:?}",
                    label, sender_party_id, expected_circuits, signed.payload.proof.circuit
                );
                return EcdsaPartyResult {
                    passed: false,
                    failed_payload: Some((signed.clone(), expected_addr)),
                };
            }
        }

        EcdsaPartyResult {
            passed: true,
            failed_payload: None,
        }
    }

    /// Run ECDSA validation across all parties and prepare the cached proof
    /// hashes/signals/data plus the consistency-check request payload for the
    /// parties that passed. Pure: no event publishing.
    pub(crate) fn validate_and_prepare<P: VerifiableParty>(
        party_proofs: &[P],
        e3_id_str: &str,
        label: &str,
    ) -> EcdsaValidationOutcome<P> {
        let mut ecdsa_dishonest = HashSet::new();
        let mut failures = Vec::new();
        let mut ecdsa_passed_parties = Vec::new();
        let mut party_addresses: HashMap<u64, Address> = HashMap::new();

        for party in party_proofs {
            let proofs = party.signed_proofs();
            let result =
                Self::ecdsa_validate_signed_proofs(party.party_id(), &proofs, e3_id_str, label);
            if result.passed {
                ecdsa_passed_parties.push(party.clone());
            } else {
                ecdsa_dishonest.insert(party.party_id());
                if let Some((signed, addr)) = result.failed_payload {
                    failures.push(EcdsaFailure {
                        party_id: party.party_id(),
                        signed,
                        recovered: addr,
                    });
                }
            }
        }

        // Store recovered addresses for passed parties.
        for party in party_proofs {
            if !ecdsa_dishonest.contains(&party.party_id()) {
                let proofs = party.signed_proofs();
                if let Some(first_signed) = proofs.first() {
                    if let Ok(addr) = first_signed.recover_address() {
                        party_addresses.insert(party.party_id(), addr);
                    }
                }
            }
        }

        // Compute proof hashes and public signals for ECDSA-passed parties.
        let mut party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>> = HashMap::new();
        let mut party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>> = HashMap::new();
        let mut party_raw_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>> = HashMap::new();
        for party in &ecdsa_passed_parties {
            let hashes: Vec<(ProofType, [u8; 32])> = party
                .signed_proofs()
                .iter()
                .map(|signed| (signed.payload.proof_type, Self::proof_data_hash(signed)))
                .collect();
            let signals: Vec<(ProofType, ArcBytes)> = party
                .signed_proofs()
                .iter()
                .map(|signed| {
                    (
                        signed.payload.proof_type,
                        signed.payload.proof.public_signals.clone(),
                    )
                })
                .collect();
            let datas: Vec<(ProofType, ArcBytes)> = party
                .signed_proofs()
                .iter()
                .map(|signed| (signed.payload.proof_type, signed.payload.proof.data.clone()))
                .collect();
            party_proof_hashes.insert(party.party_id(), hashes);
            party_public_signals.insert(party.party_id(), signals);
            party_raw_proof_data.insert(party.party_id(), datas);
        }

        // Assemble consistency-check request payload.
        let consistency_party_data: Vec<PartyProofData> = ecdsa_passed_parties
            .iter()
            .map(|party| {
                let signals = party_public_signals
                    .get(&party.party_id())
                    .cloned()
                    .unwrap_or_default();
                let hashes = party_proof_hashes
                    .get(&party.party_id())
                    .cloned()
                    .unwrap_or_default();
                let raw_datas = party_raw_proof_data
                    .get(&party.party_id())
                    .cloned()
                    .unwrap_or_default();
                let proofs = signals
                    .into_iter()
                    .zip(hashes)
                    .zip(raw_datas)
                    .map(|(((pt, ps), (_, dh)), (_, pd))| (pt, ps, dh, pd))
                    .collect();
                PartyProofData {
                    party_id: party.party_id(),
                    address: party_addresses
                        .get(&party.party_id())
                        .copied()
                        .unwrap_or_default(),
                    proofs,
                }
            })
            .collect();

        EcdsaValidationOutcome {
            ecdsa_dishonest,
            failures,
            ecdsa_passed_parties,
            party_addresses,
            party_proof_hashes,
            party_public_signals,
            party_proof_data: party_raw_proof_data,
            consistency_party_data,
        }
    }

    /// Tally ZK verification results against the dispatched set: accumulate the
    /// dishonest party set (including parties missing from the response) and
    /// produce ordered per-party emission decisions. Pure: no event publishing.
    pub(crate) fn tally_zk_results(
        pre_dishonest: BTreeSet<u64>,
        ecdsa_dishonest: &HashSet<u64>,
        dispatched_party_ids: &HashSet<u64>,
        zk_results: &[PartyVerificationResult],
    ) -> ZkTallyOutcome {
        let mut dishonest: BTreeSet<u64> = pre_dishonest;
        dishonest.extend(ecdsa_dishonest);

        // Cross-check: every dispatched party must appear in results.
        let returned_party_ids: HashSet<u64> =
            zk_results.iter().map(|r| r.sender_party_id).collect();
        for &dispatched_pid in dispatched_party_ids {
            if !returned_party_ids.contains(&dispatched_pid) {
                warn!(
                    "Party {} was dispatched for ZK verification but missing from results — treating as dishonest",
                    dispatched_pid
                );
                dishonest.insert(dispatched_pid);
            }
        }

        let mut emissions = Vec::new();
        for result in zk_results {
            // Ignore results for parties we never dispatched (defense-in-depth).
            if !dispatched_party_ids.contains(&result.sender_party_id) {
                warn!(
                    "ZK result for party {} was not dispatched — ignoring",
                    result.sender_party_id
                );
                continue;
            }
            if !result.all_verified {
                dishonest.insert(result.sender_party_id);
                if let Some(ref signed) = result.failed_signed_payload {
                    emissions.push(ZkPartyEmission::Failed {
                        party_id: result.sender_party_id,
                        signed: signed.clone(),
                    });
                }
            } else {
                emissions.push(ZkPartyEmission::Passed {
                    party_id: result.sender_party_id,
                });
            }
        }

        ZkTallyOutcome {
            dishonest,
            emissions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use e3_events::{Proof, ProofPayload, ProofType};

    fn signer() -> PrivateKeySigner {
        PrivateKeySigner::random()
    }

    /// Build a signed C1 (PkGeneration) proof for `party_id` under `e3_id`,
    /// optionally with a deliberately wrong circuit name.
    fn signed_pk(s: &PrivateKeySigner, e3_id: &E3id, wrong_circuit: bool) -> SignedProofPayload {
        use e3_events::CircuitName;
        let proof_type = ProofType::C1PkGeneration;
        let circuit = if wrong_circuit {
            CircuitName::PkBfv
        } else {
            proof_type.circuit_names()[0]
        };
        let proof = Proof::new(
            circuit,
            ArcBytes::from_bytes(&[1, 2, 3]),
            ArcBytes::from_bytes(&[4, 5, 6]),
        );
        let payload = ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof,
        };
        SignedProofPayload::sign(payload, s).expect("sign")
    }

    fn e3() -> E3id {
        E3id::new("1", 1)
    }

    #[test]
    fn ecdsa_passes_for_well_formed_proof() {
        let s = signer();
        let e3 = e3();
        let p = signed_pk(&s, &e3, false);
        let res = ShareVerifier::ecdsa_validate_signed_proofs(7, &[p], &e3.to_string(), "C1");
        assert!(res.passed);
        assert!(res.failed_payload.is_none());
    }

    #[test]
    fn ecdsa_fails_on_wrong_e3_id() {
        let s = signer();
        let p = signed_pk(&s, &e3(), false);
        let res = ShareVerifier::ecdsa_validate_signed_proofs(7, &[p], "999/0", "C1");
        assert!(!res.passed);
        assert!(res.failed_payload.is_some());
    }

    #[test]
    fn ecdsa_fails_on_circuit_mismatch() {
        let s = signer();
        let e3 = e3();
        let p = signed_pk(&s, &e3, true);
        let res = ShareVerifier::ecdsa_validate_signed_proofs(7, &[p], &e3.to_string(), "C1");
        assert!(!res.passed);
    }

    #[test]
    fn ecdsa_fails_on_inconsistent_signer() {
        let s1 = signer();
        let s2 = signer();
        let e3 = e3();
        let p1 = signed_pk(&s1, &e3, false);
        let p2 = signed_pk(&s2, &e3, false);
        let res = ShareVerifier::ecdsa_validate_signed_proofs(7, &[p1, p2], &e3.to_string(), "C1");
        assert!(!res.passed);
    }

    #[test]
    fn filter_consistent_drops_inconsistent_and_returns_ids() {
        let proofs = vec![1u64, 2, 3];
        let inconsistent: BTreeSet<u64> = [2].into_iter().collect();
        let (passed, ids) = filter_consistent(proofs, &inconsistent, |p| *p).expect("some");
        assert_eq!(passed, vec![1, 3]);
        assert!(ids.contains(&1) && ids.contains(&3) && !ids.contains(&2));
    }

    #[test]
    fn filter_consistent_returns_none_when_all_filtered() {
        let proofs = vec![1u64, 2];
        let inconsistent: BTreeSet<u64> = [1, 2].into_iter().collect();
        assert!(filter_consistent(proofs, &inconsistent, |p| *p).is_none());
    }

    #[test]
    fn tally_marks_missing_dispatched_party_dishonest() {
        let dispatched: HashSet<u64> = [1, 2].into_iter().collect();
        let ecdsa: HashSet<u64> = HashSet::new();
        // No ZK results at all → both dispatched parties are missing → dishonest.
        let out = ShareVerifier::tally_zk_results(BTreeSet::new(), &ecdsa, &dispatched, &[]);
        assert!(out.dishonest.contains(&1));
        assert!(out.dishonest.contains(&2));
        assert!(out.emissions.is_empty());
    }
}
