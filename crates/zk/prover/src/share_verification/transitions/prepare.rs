// SPDX-License-Identifier: LGPL-3.0-only

//! Replay-safe batch normalization and consistency payload preparation.

use super::*;

impl ShareVerifier {
    /// Run ECDSA validation across all parties and prepare the cached proof
    /// hashes/signals/data plus the consistency-check request payload for the
    /// parties that passed. Pure: no event publishing.
    pub(crate) fn validate_and_prepare<P: VerifiableParty>(
        party_proofs: &[P],
        e3_id_str: &str,
        kind: &VerificationKind,
        label: &str,
        committee: Option<&[Address]>,
        params_preset: e3_fhe_params::BfvPreset,
        committee_size: CiphernodesCommitteeSize,
    ) -> EcdsaValidationOutcome<P> {
        let mut ecdsa_dishonest = HashSet::new();
        let mut failures = Vec::new();
        let mut ecdsa_passed_parties = Vec::new();
        let mut party_addresses: HashMap<u64, Address> = HashMap::new();

        // A finalized committee is a one-to-one party-slot map. The on-chain sortition path
        // guarantees unique operators, but replayed/test-produced events also cross this
        // boundary. Refuse an ambiguous map rather than allowing one signer to own two slots.
        let expected_committee_n = committee_size.values().n;
        let committee = committee.filter(|members| {
            let unique_members: HashSet<Address> = members.iter().copied().collect();
            let is_unique = unique_members.len() == members.len();
            let has_expected_size = members.len() == expected_committee_n;
            if !is_unique {
                warn!(
                    "{} finalized committee contains duplicate addresses; rejecting proof batch",
                    label
                );
            }
            if !has_expected_size {
                warn!(
                    "{} finalized committee has {} members, expected {}; rejecting proof batch",
                    label,
                    members.len(),
                    expected_committee_n
                );
            }
            is_unique && has_expected_size
        });

        // Collapse byte-identical replayed bundles idempotently. Two different bundles for the
        // same outer party id are ambiguous and are both excluded, so a canonical party can
        // contribute at most one verification result and one set of passed-proof emissions.
        let mut unique_parties: Vec<&P> = Vec::new();
        let mut party_positions: HashMap<u64, usize> = HashMap::new();
        let mut conflicting_party_ids = HashSet::new();
        for party in party_proofs {
            match party_positions.get(&party.party_id()).copied() {
                Some(position) if unique_parties[position] == party => {
                    warn!(
                        "{} duplicate replay for party {} ignored",
                        label,
                        party.party_id()
                    );
                }
                Some(_) => {
                    warn!(
                        "{} conflicting proof bundles for party {}; rejecting that party",
                        label,
                        party.party_id()
                    );
                    conflicting_party_ids.insert(party.party_id());
                }
                None => {
                    party_positions.insert(party.party_id(), unique_parties.len());
                    unique_parties.push(party);
                }
            }
        }

        for party in unique_parties {
            if conflicting_party_ids.contains(&party.party_id()) {
                ecdsa_dishonest.insert(party.party_id());
                continue;
            }

            let proofs = party.signed_proofs();
            if !Self::has_canonical_proof_shape(kind, &proofs, params_preset) {
                info!(
                    "{} party {} supplied a non-canonical proof-type multiplicity/order",
                    label,
                    party.party_id()
                );
                // The verification kind and outer bundle are not signed. Exclude the party,
                // but do not manufacture slash evidence from an otherwise valid signed proof.
                ecdsa_dishonest.insert(party.party_id());
                continue;
            }

            let expected_signer = usize::try_from(party.party_id())
                .ok()
                .and_then(|party_id| committee.and_then(|members| members.get(party_id)))
                .copied();
            let result = Self::ecdsa_validate_signed_proofs(
                party.party_id(),
                &proofs,
                e3_id_str,
                label,
                expected_signer,
            );
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
        for party in &ecdsa_passed_parties {
            let proofs = party.signed_proofs();
            if let Some(first_signed) = proofs.first() {
                if let Ok(addr) = first_signed.recover_address() {
                    party_addresses.insert(party.party_id(), addr);
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
}
