// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable metadata and pure transitions for remote l-BFV contribution collection.

use std::collections::BTreeMap;

use alloy::primitives::{keccak256, Address, B256, U256};
use anyhow::{anyhow, ensure, Result};
use e3_committee_hash::{
    hash_lbfv_accepted_party_set, hash_lbfv_proof_session, validate_and_hash_finalized_committee,
    LbfvProofDomainContext,
};
use e3_events::{
    E3id, LbfvAcceptedPartyCommitments, LbfvKeyShareDocumentFetchFailed,
    LbfvKeyShareDocumentFetchFailureClass, LbfvKeyShareDocumentFetchRequested,
    LbfvKeyShareDocumentFetchRequestedV1, LbfvKeyShareDocumentReceived, LbfvKeyShareDocumentRole,
    LbfvKeyShareManifest, SignedLbfvKeyShareManifest,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use serde::{Deserialize, Serialize};

pub const LBFV_CONTRIBUTION_COLLECTION_SCHEMA_VERSION: u32 = 1;

/// The collection phase for one E3 proof session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LbfvContributionVerificationStateV1 {
    Collecting,
    Ready {
        party_ids: Vec<u32>,
    },
    Dispatched {
        party_ids: Vec<u32>,
    },
    Sealed {
        candidate_party_ids: Vec<u32>,
        accepted_parties: Vec<LbfvAcceptedPartyCommitments>,
    },
    Failed {
        reason: String,
    },
}

/// The bounded collection status for one committee party.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LbfvPartyContributionStatusV1 {
    AwaitingManifest,
    FetchingDocuments,
    Ready,
    Equivocated,
    InvalidData,
    DocumentsDurable,
    Excluded,
}

/// Durable restart state for one manifest-authorized document fetch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbfvContributionFetchStateV1 {
    pub expected_content_hash: B256,
    pub next_attempt: u32,
    pub retry_at: Option<u64>,
    pub artifact_durable: bool,
    pub permanent_invalid_data: bool,
}

impl LbfvContributionFetchStateV1 {
    fn new(expected_content_hash: B256) -> Self {
        Self {
            expected_content_hash,
            next_attempt: 1,
            retry_at: None,
            artifact_durable: false,
            permanent_invalid_data: false,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.expected_content_hash != B256::ZERO,
            "persisted l-BFV fetch hash is zero"
        );
        ensure!(
            self.next_attempt > 0,
            "persisted l-BFV fetch attempt is zero"
        );
        if self.artifact_durable || self.permanent_invalid_data {
            ensure!(
                self.retry_at.is_none(),
                "completed l-BFV fetch retains a retry time"
            );
        }
        Ok(())
    }

    fn is_due(&self, unix_time: u64) -> bool {
        !self.artifact_durable
            && !self.permanent_invalid_data
            && self.retry_at.is_none_or(|retry_at| retry_at <= unix_time)
    }
}

/// Compact metadata for one party. Document bytes live in content-addressed repositories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbfvPartyContributionStateV1 {
    pub manifest: Option<SignedLbfvKeyShareManifest>,
    pub conflicting_manifest: Option<SignedLbfvKeyShareManifest>,
    pub excluded: bool,
    pub public_key_fetch: Option<LbfvContributionFetchStateV1>,
    pub relinearization_key_fetch: Option<LbfvContributionFetchStateV1>,
    pub status: LbfvPartyContributionStatusV1,
    pub validated_commitments: Option<LbfvAcceptedPartyCommitments>,
}

impl Default for LbfvPartyContributionStateV1 {
    fn default() -> Self {
        Self {
            manifest: None,
            conflicting_manifest: None,
            excluded: false,
            public_key_fetch: None,
            relinearization_key_fetch: None,
            validated_commitments: None,
            status: LbfvPartyContributionStatusV1::AwaitingManifest,
        }
    }
}

/// Version 1 collection sidecar for one l-BFV proof session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbfvContributionCollectionStateV1 {
    pub schema_version: u32,
    pub e3_id: E3id,
    pub proof_domain: LbfvProofDomainContext,
    pub proof_session_id: B256,
    pub committee: Vec<Address>,
    pub committee_h: u32,
    pub parties: BTreeMap<u32, LbfvPartyContributionStateV1>,
    pub verification: LbfvContributionVerificationStateV1,
}

/// Result of manifest admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LbfvManifestAdmission {
    Accepted,
    Duplicate,
    EquivocationRecorded,
    EquivocationAlreadyRecorded,
    Terminal,
}

/// Result of durable document admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LbfvDocumentAdmission {
    Recorded,
    Duplicate,
    Terminal,
}

/// Result of validating one party's complete durable bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LbfvBundleAdmission {
    Ready,
    Duplicate,
    Invalid,
    NotReady,
    Terminal,
}

impl LbfvContributionCollectionStateV1 {
    pub fn new(
        e3_id: E3id,
        proof_domain: LbfvProofDomainContext,
        committee: Vec<Address>,
        committee_h: usize,
    ) -> Result<Self> {
        let committee_h = u32::try_from(committee_h)
            .map_err(|_| anyhow!("l-BFV committee H does not fit the collection schema"))?;
        let parties = (0..committee.len())
            .map(|party_id| {
                u32::try_from(party_id)
                    .map(|party_id| (party_id, LbfvPartyContributionStateV1::default()))
                    .map_err(|_| anyhow!("l-BFV party ID does not fit the collection schema"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let state = Self {
            schema_version: LBFV_CONTRIBUTION_COLLECTION_SCHEMA_VERSION,
            e3_id,
            proof_domain,
            proof_session_id: hash_lbfv_proof_session(proof_domain),
            committee,
            committee_h,
            parties,
            verification: LbfvContributionVerificationStateV1::Collecting,
        };
        state.validate_loaded()?;
        Ok(state)
    }

    pub fn validate_loaded(&self) -> Result<()> {
        ensure!(
            self.schema_version == LBFV_CONTRIBUTION_COLLECTION_SCHEMA_VERSION,
            "unsupported l-BFV contribution collection schema version {}",
            self.schema_version
        );
        self.validate_context()?;
        CiphernodesCommitteeSize::from_n_h(self.committee.len(), self.committee_h as usize)?;
        ensure!(
            validate_and_hash_finalized_committee(&self.committee, self.committee.len())
                .map_err(anyhow::Error::msg)?
                == self.proof_domain.finalized_committee_hash,
            "persisted l-BFV collection committee does not match the proof domain"
        );
        ensure!(
            self.parties.len() == self.committee.len()
                && self
                    .parties
                    .keys()
                    .copied()
                    .eq(0..self.committee.len() as u32),
            "persisted l-BFV collection does not contain the canonical party slots"
        );

        for (party_id, party) in &self.parties {
            if let Some(manifest) = &party.manifest {
                self.validate_signed_manifest(*party_id, manifest)?;
                let (public_key_hash, relinearization_key_hash) =
                    manifest_hashes(&manifest.payload);
                ensure!(
                    party.public_key_fetch.as_ref().is_some_and(|fetch| {
                        fetch.expected_content_hash == public_key_hash && fetch.validate().is_ok()
                    }) && party
                        .relinearization_key_fetch
                        .as_ref()
                        .is_some_and(|fetch| {
                            fetch.expected_content_hash == relinearization_key_hash
                                && fetch.validate().is_ok()
                        }),
                    "persisted l-BFV fetch slots do not match the first manifest"
                );
            } else {
                ensure!(
                    party.conflicting_manifest.is_none()
                        && party.public_key_fetch.is_none()
                        && party.relinearization_key_fetch.is_none(),
                    "persisted l-BFV party has fetch metadata without a manifest"
                );
            }
            if let Some(conflict) = &party.conflicting_manifest {
                self.validate_signed_manifest(*party_id, conflict)?;
                ensure!(
                    party
                        .manifest
                        .as_ref()
                        .is_some_and(|first| first.payload != conflict.payload),
                    "persisted l-BFV manifest conflict does not differ from the first payload"
                );
            }
            if let Some(commitments) = &party.validated_commitments {
                ensure!(
                    commitments.party_id == *party_id,
                    "persisted l-BFV commitments do not match their party slot"
                );
                ensure!(
                    party
                        .public_key_fetch
                        .as_ref()
                        .is_some_and(|fetch| fetch.artifact_durable)
                        && party
                            .relinearization_key_fetch
                            .as_ref()
                            .is_some_and(|fetch| fetch.artifact_durable),
                    "persisted l-BFV commitments do not have two durable documents"
                );
            }
            ensure!(
                party.status == expected_party_status(party),
                "persisted l-BFV party status does not match its metadata"
            );
        }

        match &self.verification {
            LbfvContributionVerificationStateV1::Collecting => {}
            LbfvContributionVerificationStateV1::Ready { party_ids }
            | LbfvContributionVerificationStateV1::Dispatched { party_ids } => {
                self.validate_persisted_candidate_parties(party_ids)?;
            }
            LbfvContributionVerificationStateV1::Sealed {
                candidate_party_ids,
                accepted_parties,
            } => {
                self.validate_sealed_parties(candidate_party_ids, accepted_parties)?;
            }
            LbfvContributionVerificationStateV1::Failed { reason } => {
                ensure!(
                    !reason.trim().is_empty(),
                    "persisted l-BFV collection failure reason is empty"
                );
            }
        }
        Ok(())
    }

    /// Iterate over all canonical party slots in ascending party-ID order.
    pub fn party_states(
        &self,
    ) -> impl ExactSizeIterator<Item = (u32, &LbfvPartyContributionStateV1)> {
        self.parties
            .iter()
            .map(|(party_id, state)| (*party_id, state))
    }

    pub fn admit_manifest(
        &mut self,
        signed: &SignedLbfvKeyShareManifest,
    ) -> Result<LbfvManifestAdmission> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(LbfvManifestAdmission::Terminal);
        }
        let party_id = signed.payload.context().party_id;
        self.validate_signed_manifest(party_id, signed)?;
        let party = self
            .parties
            .get_mut(&party_id)
            .ok_or_else(|| anyhow!("l-BFV manifest party ID is outside the committee"))?;
        if party.excluded {
            return Ok(LbfvManifestAdmission::Terminal);
        }
        let Some(first) = &party.manifest else {
            let (public_key_hash, relinearization_key_hash) = manifest_hashes(&signed.payload);
            party.manifest = Some(signed.clone());
            party.public_key_fetch = Some(LbfvContributionFetchStateV1::new(public_key_hash));
            party.relinearization_key_fetch =
                Some(LbfvContributionFetchStateV1::new(relinearization_key_hash));
            party.status = expected_party_status(party);
            return Ok(LbfvManifestAdmission::Accepted);
        };
        if first.payload == signed.payload {
            return Ok(LbfvManifestAdmission::Duplicate);
        }
        if party.conflicting_manifest.is_some() {
            return Ok(LbfvManifestAdmission::EquivocationAlreadyRecorded);
        }

        party.conflicting_manifest = Some(signed.clone());
        party.status = LbfvPartyContributionStatusV1::Equivocated;
        self.invalidate_selected_party(party_id);
        Ok(LbfvManifestAdmission::EquivocationRecorded)
    }

    /// Return due fetches in ascending party order, then PK-before-RLK role order.
    pub fn due_fetch_requests(
        &self,
        unix_time: u64,
    ) -> Result<Vec<LbfvKeyShareDocumentFetchRequested>> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(Vec::new());
        }
        let mut requests = Vec::new();
        for (party_id, party) in self.party_states() {
            if !party_is_eligible(party) {
                continue;
            }
            for role in [
                LbfvKeyShareDocumentRole::PublicKey,
                LbfvKeyShareDocumentRole::RelinearizationKey,
            ] {
                let fetch = fetch_state(party, role)?;
                if fetch.is_due(unix_time) {
                    requests.push(LbfvKeyShareDocumentFetchRequested::V1(
                        LbfvKeyShareDocumentFetchRequestedV1 {
                            e3_id: self.e3_id.clone(),
                            proof_session_id: self.proof_session_id,
                            party_id,
                            role,
                            content_hash: fetch.expected_content_hash,
                            attempt: fetch.next_attempt,
                        },
                    ));
                }
            }
        }
        Ok(requests)
    }

    /// Return the earliest persisted retry deadline for an eligible incomplete fetch.
    pub fn next_retry_at(&self) -> Result<Option<u64>> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(None);
        }
        Ok(self
            .parties
            .values()
            .filter(|party| party_is_eligible(party))
            .flat_map(|party| {
                [
                    party.public_key_fetch.as_ref(),
                    party.relinearization_key_fetch.as_ref(),
                ]
            })
            .flatten()
            .filter(|fetch| !fetch.artifact_durable && !fetch.permanent_invalid_data)
            .filter_map(|fetch| fetch.retry_at)
            .min())
    }

    pub fn record_fetch_failure(
        &mut self,
        failed: &LbfvKeyShareDocumentFetchFailed,
    ) -> Result<bool> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(false);
        }
        let failed = failed.failure();
        ensure!(
            failed.e3_id == self.e3_id && failed.proof_session_id == self.proof_session_id,
            "l-BFV fetch failure does not match the collection context"
        );
        let party = self
            .parties
            .get_mut(&failed.party_id)
            .ok_or_else(|| anyhow!("l-BFV fetch failure party ID is outside the committee"))?;
        if party.excluded {
            return Ok(false);
        }
        ensure!(
            party.manifest.is_some(),
            "l-BFV fetch failure has no durable manifest"
        );
        let fetch = fetch_state_mut(party, failed.role)?;
        ensure!(
            failed.content_hash == fetch.expected_content_hash,
            "l-BFV fetch failure hash does not match its manifest slot"
        );
        if fetch.artifact_durable {
            return Ok(false);
        }
        if is_duplicate_failure(fetch, failed) {
            return Ok(false);
        }
        ensure!(
            failed.attempt == fetch.next_attempt,
            "stale or future l-BFV fetch failure attempt {} does not match next attempt {}",
            failed.attempt,
            fetch.next_attempt
        );
        let next_attempt = failed
            .attempt
            .checked_add(1)
            .ok_or_else(|| anyhow!("l-BFV fetch attempt overflow"))?;
        match failed.failure_class {
            LbfvKeyShareDocumentFetchFailureClass::Unavailable => {
                ensure!(
                    failed.retry_at.is_some(),
                    "unavailable l-BFV fetch failure has no retry time"
                );
                fetch.next_attempt = next_attempt;
                fetch.retry_at = failed.retry_at;
            }
            LbfvKeyShareDocumentFetchFailureClass::InvalidData => {
                ensure!(
                    failed.retry_at.is_none(),
                    "invalid l-BFV fetch failure cannot have a retry time"
                );
                fetch.next_attempt = next_attempt;
                fetch.retry_at = None;
                fetch.permanent_invalid_data = true;
            }
        }
        party.status = expected_party_status(party);
        if party.status == LbfvPartyContributionStatusV1::InvalidData {
            self.invalidate_selected_party(failed.party_id);
        }
        Ok(true)
    }

    pub fn mark_ready(&mut self, party_ids: Vec<u32>) -> Result<bool> {
        self.validate_loaded()?;
        match &self.verification {
            LbfvContributionVerificationStateV1::Collecting => {
                self.validate_new_candidate_parties(&party_ids)?;
                self.verification = LbfvContributionVerificationStateV1::Ready { party_ids };
                Ok(true)
            }
            LbfvContributionVerificationStateV1::Ready {
                party_ids: existing,
            } if existing == &party_ids => Ok(false),
            LbfvContributionVerificationStateV1::Ready { .. } => Err(anyhow!(
                "l-BFV verification is ready for a different party set"
            )),
            _ => Err(anyhow!(
                "l-BFV verification can become ready only while collecting"
            )),
        }
    }

    pub fn mark_verification_dispatched(&mut self) -> Result<bool> {
        self.validate_loaded()?;
        match &self.verification {
            LbfvContributionVerificationStateV1::Ready { party_ids } => {
                self.verification = LbfvContributionVerificationStateV1::Dispatched {
                    party_ids: party_ids.clone(),
                };
                Ok(true)
            }
            LbfvContributionVerificationStateV1::Dispatched { .. } => Ok(false),
            _ => Err(anyhow!(
                "l-BFV verification can be dispatched only from ready state"
            )),
        }
    }

    pub fn seal(&mut self, accepted_parties: Vec<LbfvAcceptedPartyCommitments>) -> Result<bool> {
        self.validate_loaded()?;
        match &self.verification {
            LbfvContributionVerificationStateV1::Dispatched { party_ids } => {
                self.validate_sealed_parties(party_ids, &accepted_parties)?;
                self.verification = LbfvContributionVerificationStateV1::Sealed {
                    candidate_party_ids: party_ids.clone(),
                    accepted_parties,
                };
                Ok(true)
            }
            LbfvContributionVerificationStateV1::Sealed {
                accepted_parties: existing,
                ..
            } if existing == &accepted_parties => Ok(false),
            LbfvContributionVerificationStateV1::Sealed { .. } => {
                Err(anyhow!("sealed l-BFV accepted party set is immutable"))
            }
            _ => Err(anyhow!(
                "l-BFV verification can be sealed only after dispatch"
            )),
        }
    }

    pub fn fail(&mut self, reason: impl Into<String>) -> Result<bool> {
        self.validate_loaded()?;
        let reason = reason.into();
        ensure!(
            !reason.trim().is_empty(),
            "l-BFV collection failure reason is empty"
        );
        match &self.verification {
            LbfvContributionVerificationStateV1::Sealed { .. } => {
                Err(anyhow!("sealed l-BFV collection cannot fail"))
            }
            LbfvContributionVerificationStateV1::Failed { reason: existing } => {
                ensure!(
                    existing == &reason,
                    "l-BFV collection already failed for a different reason"
                );
                Ok(false)
            }
            _ => {
                self.verification = LbfvContributionVerificationStateV1::Failed { reason };
                Ok(true)
            }
        }
    }

    pub fn accepted_parties(&self) -> Option<&[LbfvAcceptedPartyCommitments]> {
        match &self.verification {
            LbfvContributionVerificationStateV1::Sealed {
                accepted_parties, ..
            } => Some(accepted_parties),
            _ => None,
        }
    }

    /// Derive the stable identity of the currently dispatched candidate set.
    pub fn dispatched_verification_id(&self) -> Result<B256> {
        self.validate_loaded()?;
        let LbfvContributionVerificationStateV1::Dispatched { party_ids } = &self.verification
        else {
            return Err(anyhow!("l-BFV verification has not been dispatched"));
        };
        let mut preimage = Vec::with_capacity(48 + party_ids.len() * 4);
        preimage.extend_from_slice(b"interfold-lbfv-generation-verification-v1");
        preimage.extend_from_slice(self.proof_session_id.as_slice());
        preimage.extend_from_slice(&(party_ids.len() as u32).to_be_bytes());
        for party_id in party_ids {
            preimage.extend_from_slice(&party_id.to_be_bytes());
        }
        Ok(keccak256(preimage))
    }

    pub(crate) fn validate_document_admission(
        &self,
        received: &LbfvKeyShareDocumentReceived,
    ) -> Result<bool> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(false);
        }
        ensure!(
            received.document.content_hash()? == received.content_hash,
            "l-BFV document content hash does not match its bytes"
        );
        let signer = received.document.validate()?;
        let context = received.document.context();
        self.validate_transport_context(context)?;
        let party = self
            .parties
            .get(&context.party_id)
            .ok_or_else(|| anyhow!("l-BFV document party ID is outside the committee"))?;
        let manifest = party
            .manifest
            .as_ref()
            .ok_or_else(|| anyhow!("l-BFV document has no durable signed manifest"))?;
        ensure!(
            party_is_eligible(party),
            "l-BFV document belongs to an ineligible party"
        );
        ensure!(
            self.committee.get(context.party_id as usize) == Some(&signer)
                && manifest.recover_address()? == signer,
            "l-BFV document signer does not match its signed manifest"
        );
        let fetch = fetch_state(party, received.document.role())?;
        ensure!(
            received.content_hash == fetch.expected_content_hash,
            "l-BFV document hash does not match its manifest slot"
        );
        Ok(true)
    }

    /// Mark a validated document durable after its content-addressed artifact write completes.
    pub fn mark_document_durable(
        &mut self,
        received: &LbfvKeyShareDocumentReceived,
    ) -> Result<LbfvDocumentAdmission> {
        if !self.validate_document_admission(received)? {
            return Ok(LbfvDocumentAdmission::Terminal);
        }
        let party_id = received.document.context().party_id;
        let party = self
            .parties
            .get_mut(&party_id)
            .expect("validated canonical l-BFV party slot");
        let fetch = fetch_state_mut(party, received.document.role())?;
        if fetch.artifact_durable {
            return Ok(LbfvDocumentAdmission::Duplicate);
        }
        fetch.artifact_durable = true;
        fetch.retry_at = None;
        party.status = expected_party_status(party);
        Ok(LbfvDocumentAdmission::Recorded)
    }

    /// Mark a complete, commitment-checked document bundle eligible for verification.
    pub fn mark_party_validated(
        &mut self,
        commitments: LbfvAcceptedPartyCommitments,
    ) -> Result<bool> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(false);
        }
        let party = self
            .parties
            .get_mut(&commitments.party_id)
            .ok_or_else(|| anyhow!("l-BFV validated party ID is outside the committee"))?;
        if let Some(existing) = &party.validated_commitments {
            ensure!(
                existing == &commitments,
                "validated l-BFV commitments changed for one party"
            );
            return Ok(false);
        }
        ensure!(
            party.status == LbfvPartyContributionStatusV1::DocumentsDurable,
            "l-BFV party can become ready only after both documents are durable"
        );
        party.validated_commitments = Some(commitments);
        party.status = expected_party_status(party);
        Ok(true)
    }

    /// Permanently exclude a party whose manifest-authorized bundle is invalid.
    pub fn mark_party_invalid(&mut self, party_id: u32) -> Result<bool> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(false);
        }
        let party = self
            .parties
            .get_mut(&party_id)
            .ok_or_else(|| anyhow!("invalid l-BFV party ID is outside the committee"))?;
        if party.excluded {
            return Ok(false);
        }
        if party.status == LbfvPartyContributionStatusV1::InvalidData {
            return Ok(false);
        }
        ensure!(
            party.manifest.is_some(),
            "cannot invalidate an l-BFV party without a manifest"
        );
        for fetch in [
            party.public_key_fetch.as_mut(),
            party.relinearization_key_fetch.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            fetch.retry_at = None;
            fetch.permanent_invalid_data = true;
        }
        party.validated_commitments = None;
        party.status = expected_party_status(party);
        self.invalidate_selected_party(party_id);
        Ok(true)
    }

    /// Exclude one canonical committee party before the accepted set is sealed.
    pub fn mark_party_excluded(&mut self, party_id: u32) -> Result<bool> {
        self.validate_loaded()?;
        if self.is_terminal() {
            return Ok(false);
        }
        let party = self
            .parties
            .get_mut(&party_id)
            .ok_or_else(|| anyhow!("excluded l-BFV party ID is outside the committee"))?;
        if party.excluded {
            return Ok(false);
        }
        party.excluded = true;
        party.status = expected_party_status(party);
        self.invalidate_selected_party(party_id);
        Ok(true)
    }

    pub fn ready_party_ids(&self, submitted_party_ids: &[u32]) -> Result<Vec<u32>> {
        self.validate_loaded()?;
        let mut party_ids = submitted_party_ids
            .iter()
            .copied()
            .filter(|party_id| {
                self.parties
                    .get(party_id)
                    .is_some_and(|party| party.status == LbfvPartyContributionStatusV1::Ready)
            })
            .collect::<Vec<_>>();
        party_ids.sort_unstable();
        party_ids.dedup();
        Ok(party_ids)
    }

    /// Return the canonical ready set after this collector has a verification quorum.
    pub fn ready_quorum_party_ids(&self, submitted_party_ids: &[u32]) -> Result<Option<Vec<u32>>> {
        let mut party_ids = self.ready_party_ids(submitted_party_ids)?;
        if party_ids.len() < self.committee_h as usize {
            return Ok(None);
        }
        party_ids.truncate(self.committee_h as usize);
        Ok(Some(party_ids))
    }

    pub fn ineligible_party_ids(&self, submitted_party_ids: &[u32]) -> Result<Vec<u32>> {
        self.validate_loaded()?;
        Ok(submitted_party_ids
            .iter()
            .copied()
            .filter(|party_id| {
                self.parties.get(party_id).is_some_and(|party| {
                    matches!(
                        party.status,
                        LbfvPartyContributionStatusV1::Equivocated
                            | LbfvPartyContributionStatusV1::InvalidData
                            | LbfvPartyContributionStatusV1::Excluded
                    )
                })
            })
            .collect())
    }

    pub fn all_submitted_parties_settled(&self, submitted_party_ids: &[u32]) -> Result<bool> {
        self.validate_loaded()?;
        Ok(submitted_party_ids.iter().all(|party_id| {
            self.parties.get(party_id).is_some_and(|party| {
                matches!(
                    party.status,
                    LbfvPartyContributionStatusV1::Ready
                        | LbfvPartyContributionStatusV1::Equivocated
                        | LbfvPartyContributionStatusV1::InvalidData
                        | LbfvPartyContributionStatusV1::Excluded
                )
            })
        }))
    }

    pub fn validated_commitments(&self, party_id: u32) -> Result<&LbfvAcceptedPartyCommitments> {
        self.parties
            .get(&party_id)
            .and_then(|party| party.validated_commitments.as_ref())
            .ok_or_else(|| anyhow!("l-BFV party does not have validated commitments"))
    }

    fn validate_context(&self) -> Result<()> {
        ensure!(
            self.e3_id.chain_id() == self.proof_domain.chain_id,
            "l-BFV collection chain does not match the proof domain"
        );
        let e3_id: U256 = self
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("l-BFV collection E3 ID cannot be converted to U256"))?;
        ensure!(
            e3_id == self.proof_domain.e3_id,
            "l-BFV collection E3 ID does not match the proof domain"
        );
        ensure!(
            self.proof_session_id == hash_lbfv_proof_session(self.proof_domain),
            "l-BFV collection proof session does not match the proof domain"
        );
        Ok(())
    }

    fn validate_transport_context(
        &self,
        context: &e3_events::LbfvKeyShareDocumentContextV1,
    ) -> Result<()> {
        context.validate()?;
        ensure!(
            context.e3_id == self.e3_id
                && context.proof_domain == self.proof_domain
                && context.proof_session_id == self.proof_session_id,
            "l-BFV contribution context does not match the collection"
        );
        ensure!(
            (context.party_id as usize) < self.committee.len(),
            "l-BFV contribution party ID is outside the committee"
        );
        Ok(())
    }

    fn validate_signed_manifest(
        &self,
        party_id: u32,
        manifest: &SignedLbfvKeyShareManifest,
    ) -> Result<()> {
        ensure!(
            manifest.payload.context().party_id == party_id,
            "l-BFV manifest party ID does not match its collection slot"
        );
        self.validate_transport_context(manifest.payload.context())?;
        let (public_key_hash, relinearization_key_hash) = manifest_hashes(&manifest.payload);
        ensure!(
            public_key_hash != B256::ZERO && relinearization_key_hash != B256::ZERO,
            "l-BFV manifest contains a zero document hash"
        );
        ensure!(
            public_key_hash != relinearization_key_hash,
            "l-BFV manifest uses one hash for both document roles"
        );
        manifest.verify_committee_signer(&self.committee)
    }

    fn validate_persisted_candidate_parties(&self, party_ids: &[u32]) -> Result<()> {
        ensure!(
            (self.committee_h as usize..=self.committee.len()).contains(&party_ids.len()),
            "persisted l-BFV candidate set does not contain H through N parties"
        );
        ensure!(
            party_ids.windows(2).all(|pair| pair[0] < pair[1]),
            "l-BFV candidate party IDs are not unique and strictly ascending"
        );
        for party_id in party_ids {
            ensure!(
                self.parties
                    .get(party_id)
                    .is_some_and(|party| party.status == LbfvPartyContributionStatusV1::Ready),
                "l-BFV candidate party does not have a complete contribution"
            );
        }
        Ok(())
    }

    fn validate_new_candidate_parties(&self, party_ids: &[u32]) -> Result<()> {
        self.validate_persisted_candidate_parties(party_ids)?;
        ensure!(
            party_ids.len() == self.committee_h as usize,
            "new l-BFV candidate set does not contain exactly H parties"
        );
        Ok(())
    }

    fn validate_sealed_parties(
        &self,
        candidate_party_ids: &[u32],
        accepted_parties: &[LbfvAcceptedPartyCommitments],
    ) -> Result<()> {
        self.validate_persisted_candidate_parties(candidate_party_ids)?;
        let accepted_party_ids = accepted_parties
            .iter()
            .map(|party| party.party_id)
            .collect::<Vec<_>>();
        hash_lbfv_accepted_party_set(
            &accepted_party_ids,
            self.committee.len(),
            self.committee_h as usize,
        )
        .map_err(anyhow::Error::msg)?;
        for accepted in accepted_parties {
            ensure!(
                candidate_party_ids
                    .binary_search(&accepted.party_id)
                    .is_ok(),
                "l-BFV accepted party was not in the dispatched candidate set"
            );
            ensure!(
                self.parties.get(&accepted.party_id).is_some_and(|party| {
                    party.status == LbfvPartyContributionStatusV1::Ready
                        && party.validated_commitments.as_ref() == Some(accepted)
                }),
                "l-BFV accepted party commitments do not match its validated contribution"
            );
        }
        Ok(())
    }

    fn invalidate_selected_party(&mut self, party_id: u32) {
        if self
            .verification_party_ids()
            .is_some_and(|ids| ids.contains(&party_id))
        {
            self.verification = LbfvContributionVerificationStateV1::Collecting;
        }
    }

    fn verification_party_ids(&self) -> Option<&[u32]> {
        match &self.verification {
            LbfvContributionVerificationStateV1::Ready { party_ids }
            | LbfvContributionVerificationStateV1::Dispatched { party_ids } => Some(party_ids),
            _ => None,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.verification,
            LbfvContributionVerificationStateV1::Sealed { .. }
                | LbfvContributionVerificationStateV1::Failed { .. }
        )
    }
}

pub(crate) fn manifest_hashes(manifest: &LbfvKeyShareManifest) -> (B256, B256) {
    match manifest {
        LbfvKeyShareManifest::V1(manifest) => (
            manifest.public_key_document_hash,
            manifest.relinearization_key_document_hash,
        ),
    }
}

fn fetch_state(
    party: &LbfvPartyContributionStateV1,
    role: LbfvKeyShareDocumentRole,
) -> Result<&LbfvContributionFetchStateV1> {
    match role {
        LbfvKeyShareDocumentRole::PublicKey => party.public_key_fetch.as_ref(),
        LbfvKeyShareDocumentRole::RelinearizationKey => party.relinearization_key_fetch.as_ref(),
    }
    .ok_or_else(|| anyhow!("l-BFV document role has no manifest-authorized fetch slot"))
}

fn fetch_state_mut(
    party: &mut LbfvPartyContributionStateV1,
    role: LbfvKeyShareDocumentRole,
) -> Result<&mut LbfvContributionFetchStateV1> {
    match role {
        LbfvKeyShareDocumentRole::PublicKey => party.public_key_fetch.as_mut(),
        LbfvKeyShareDocumentRole::RelinearizationKey => party.relinearization_key_fetch.as_mut(),
    }
    .ok_or_else(|| anyhow!("l-BFV document role has no manifest-authorized fetch slot"))
}

fn party_is_eligible(party: &LbfvPartyContributionStateV1) -> bool {
    !party.excluded
        && party.manifest.is_some()
        && party.conflicting_manifest.is_none()
        && party
            .public_key_fetch
            .as_ref()
            .is_some_and(|fetch| !fetch.permanent_invalid_data)
        && party
            .relinearization_key_fetch
            .as_ref()
            .is_some_and(|fetch| !fetch.permanent_invalid_data)
}

fn expected_party_status(party: &LbfvPartyContributionStateV1) -> LbfvPartyContributionStatusV1 {
    if party.excluded {
        return LbfvPartyContributionStatusV1::Excluded;
    }
    if party.conflicting_manifest.is_some() {
        return LbfvPartyContributionStatusV1::Equivocated;
    }
    let (Some(public_key), Some(relinearization_key)) = (
        party.public_key_fetch.as_ref(),
        party.relinearization_key_fetch.as_ref(),
    ) else {
        return LbfvPartyContributionStatusV1::AwaitingManifest;
    };
    if public_key.permanent_invalid_data || relinearization_key.permanent_invalid_data {
        LbfvPartyContributionStatusV1::InvalidData
    } else if party.validated_commitments.is_some() {
        LbfvPartyContributionStatusV1::Ready
    } else if public_key.artifact_durable && relinearization_key.artifact_durable {
        LbfvPartyContributionStatusV1::DocumentsDurable
    } else {
        LbfvPartyContributionStatusV1::FetchingDocuments
    }
}

fn is_duplicate_failure(
    fetch: &LbfvContributionFetchStateV1,
    failed: &e3_events::LbfvKeyShareDocumentFetchFailedV1,
) -> bool {
    if failed.attempt.checked_add(1) != Some(fetch.next_attempt) {
        return false;
    }
    match failed.failure_class {
        LbfvKeyShareDocumentFetchFailureClass::Unavailable => {
            failed.retry_at.is_some()
                && !fetch.permanent_invalid_data
                && fetch.retry_at == failed.retry_at
        }
        LbfvKeyShareDocumentFetchFailureClass::InvalidData => {
            fetch.permanent_invalid_data && failed.retry_at.is_none()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy::{
        primitives::keccak256,
        signers::{local::PrivateKeySigner, Signer},
    };
    use e3_committee_hash::{hash_committee_addresses, split_hash_to_field_limbs};
    use e3_events::{
        LbfvKeyShareDocument, LbfvKeyShareDocumentContextV1, LbfvKeyShareDocumentFetchFailedV1,
        LbfvKeyShareManifestV1, LbfvPublicKeyShareDocumentV1,
        LbfvRelinearizationKeyShareDocumentV1, Proof, ProofPayload, ProofType, SignedProofPayload,
    };
    use e3_utils::ArcBytes;
    use e3_zk_helpers::FIELD_BYTE_LEN;

    pub(crate) struct Fixture {
        pub state: LbfvContributionCollectionStateV1,
        pub signers: Vec<PrivateKeySigner>,
    }

    pub(crate) fn fixture() -> Fixture {
        let mut signers = [1_u8, 2, 3]
            .map(|byte| PrivateKeySigner::from_bytes(&B256::repeat_byte(byte)).unwrap());
        signers.sort_by_key(|signer| signer.address());
        let committee = signers.iter().map(Signer::address).collect::<Vec<_>>();
        let e3_id = E3id::new("7", 1);
        let proof_domain = LbfvProofDomainContext {
            protocol_version: 4,
            chain_id: e3_id.chain_id(),
            interfold_address: Address::repeat_byte(0x11),
            e3_id: U256::from(7),
            crypto_config_id: B256::repeat_byte(0x22),
            finalized_committee_hash: hash_committee_addresses(&committee),
            lbfv_constants_version: 1,
            ciphertext_level: 0,
            key_level: 0,
        };
        Fixture {
            state: LbfvContributionCollectionStateV1::new(e3_id, proof_domain, committee, 2)
                .unwrap(),
            signers: signers.into(),
        }
    }

    fn context(
        state: &LbfvContributionCollectionStateV1,
        party_id: u32,
    ) -> LbfvKeyShareDocumentContextV1 {
        LbfvKeyShareDocumentContextV1 {
            e3_id: state.e3_id.clone(),
            proof_domain: state.proof_domain,
            proof_session_id: state.proof_session_id,
            party_id,
        }
    }

    fn proof(
        context: &LbfvKeyShareDocumentContextV1,
        proof_type: ProofType,
        row: u32,
        signer: &PrivateKeySigner,
    ) -> SignedProofPayload {
        let circuit = proof_type.circuit_names()[0];
        let input = circuit.input_layout();
        let field_count =
            input.field_count().unwrap() + circuit.output_layout().field_count().unwrap();
        let mut public_signals = vec![0; field_count * FIELD_BYTE_LEN];
        if proof_type.is_multirow() {
            let session = split_hash_to_field_limbs(context.proof_session_id);
            let index = input.field_index("session_id_hi").unwrap();
            public_signals[index * 32 + 16..index * 32 + 32]
                .copy_from_slice(&session.hi.to_be_bytes());
            let index = input.field_index("session_id_lo").unwrap();
            public_signals[index * 32 + 16..index * 32 + 32]
                .copy_from_slice(&session.lo.to_be_bytes());
            let index = input.field_index("party_id").unwrap();
            public_signals[index * 32 + 28..index * 32 + 32]
                .copy_from_slice(&context.party_id.to_be_bytes());
            let index = input.field_index("row_index").unwrap();
            public_signals[index * 32 + 28..index * 32 + 32].copy_from_slice(&row.to_be_bytes());
        }
        SignedProofPayload::sign(
            ProofPayload {
                e3_id: context.e3_id.clone(),
                proof_type,
                proof: Proof::new(
                    circuit,
                    ArcBytes::from_bytes(&[row as u8]),
                    ArcBytes::from_bytes(&public_signals),
                ),
            },
            signer,
        )
        .unwrap()
    }

    pub(crate) fn bundle(
        fixture: &Fixture,
        party_id: u32,
    ) -> (
        LbfvKeyShareDocumentReceived,
        LbfvKeyShareDocumentReceived,
        SignedLbfvKeyShareManifest,
    ) {
        let context = context(&fixture.state, party_id);
        let signer = &fixture.signers[party_id as usize];
        let public_key = LbfvKeyShareDocument::PublicKeyV1(LbfvPublicKeyShareDocumentV1 {
            context: context.clone(),
            share: ArcBytes::from_bytes(format!("public-key-{party_id}").as_bytes()),
            signed_c1_proof: proof(&context, ProofType::C1PkGeneration, 0, signer),
            signed_row_proofs: std::array::from_fn(|row| {
                proof(&context, ProofType::LbfvPkGeneration, row as u32, signer)
            }),
        });
        let relinearization_key =
            LbfvKeyShareDocument::RelinearizationKeyV1(LbfvRelinearizationKeyShareDocumentV1 {
                context: context.clone(),
                share: ArcBytes::from_bytes(format!("relinearization-key-{party_id}").as_bytes()),
                signed_row_proofs: std::array::from_fn(|row| {
                    proof(&context, ProofType::RlkGeneration, row as u32, signer)
                }),
            });
        let manifest = SignedLbfvKeyShareManifest::sign(
            LbfvKeyShareManifest::V1(LbfvKeyShareManifestV1 {
                context,
                public_key_document_hash: public_key.content_hash().unwrap(),
                relinearization_key_document_hash: relinearization_key.content_hash().unwrap(),
            }),
            signer,
        )
        .unwrap();
        (
            LbfvKeyShareDocumentReceived {
                content_hash: public_key.content_hash().unwrap(),
                document: public_key,
            },
            LbfvKeyShareDocumentReceived {
                content_hash: relinearization_key.content_hash().unwrap(),
                document: relinearization_key,
            },
            manifest,
        )
    }

    pub(crate) fn complete_party(
        state: &mut LbfvContributionCollectionStateV1,
        fixture: &Fixture,
        party_id: u32,
    ) {
        let (public_key, relinearization_key, manifest) = bundle(fixture, party_id);
        state.admit_manifest(&manifest).unwrap();
        state.mark_document_durable(&public_key).unwrap();
        state.mark_document_durable(&relinearization_key).unwrap();
        state
            .mark_party_validated(accepted_commitments(party_id))
            .unwrap();
    }

    pub(crate) fn accepted_commitments(party_id: u32) -> LbfvAcceptedPartyCommitments {
        let commitment =
            |domain: u8, row: usize| B256::repeat_byte(domain + (party_id as u8 * 16) + row as u8);
        LbfvAcceptedPartyCommitments {
            party_id,
            pk_generation_commitments: std::array::from_fn(|row| commitment(1, row)),
            rlk_d0_commitments: std::array::from_fn(|row| commitment(6, row)),
            rlk_d2_commitments: std::array::from_fn(|row| commitment(11, row)),
        }
    }

    fn accepted_parties(party_ids: &[u32]) -> Vec<LbfvAcceptedPartyCommitments> {
        party_ids
            .iter()
            .copied()
            .map(accepted_commitments)
            .collect()
    }

    pub(crate) fn failure(
        state: &LbfvContributionCollectionStateV1,
        party_id: u32,
        role: LbfvKeyShareDocumentRole,
        attempt: u32,
        failure_class: LbfvKeyShareDocumentFetchFailureClass,
        retry_at: Option<u64>,
    ) -> LbfvKeyShareDocumentFetchFailed {
        let party = &state.parties[&party_id];
        LbfvKeyShareDocumentFetchFailed::V1(LbfvKeyShareDocumentFetchFailedV1 {
            e3_id: state.e3_id.clone(),
            proof_session_id: state.proof_session_id,
            party_id,
            role,
            content_hash: fetch_state(party, role).unwrap().expected_content_hash,
            attempt,
            failure_class,
            retry_at,
        })
    }

    #[test]
    fn signed_manifest_hydration_preserves_first_and_one_conflict() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (_, _, manifest) = bundle(&fixture, 0);
        assert_eq!(
            state.admit_manifest(&manifest).unwrap(),
            LbfvManifestAdmission::Accepted
        );

        let mut alternate_signature = manifest.clone();
        let mut signature = alternate_signature.signature.to_vec();
        signature[64] = match signature[64] {
            0 | 1 => signature[64] + 27,
            27 | 28 => signature[64] - 27,
            value => panic!("unexpected recovery byte {value}"),
        };
        alternate_signature.signature = ArcBytes::from_bytes(&signature);
        assert_eq!(
            state.admit_manifest(&alternate_signature).unwrap(),
            LbfvManifestAdmission::Duplicate
        );
        assert_eq!(state.parties[&0].manifest.as_ref(), Some(&manifest));

        let mut conflict_payload = manifest.payload.clone();
        let LbfvKeyShareManifest::V1(conflict) = &mut conflict_payload;
        conflict.public_key_document_hash = B256::repeat_byte(0x99);
        let conflict =
            SignedLbfvKeyShareManifest::sign(conflict_payload, &fixture.signers[0]).unwrap();
        assert_eq!(
            state.admit_manifest(&conflict).unwrap(),
            LbfvManifestAdmission::EquivocationRecorded
        );
        let mut third_payload = manifest.payload.clone();
        let LbfvKeyShareManifest::V1(third) = &mut third_payload;
        third.public_key_document_hash = B256::repeat_byte(0x88);
        let third = SignedLbfvKeyShareManifest::sign(third_payload, &fixture.signers[0]).unwrap();
        assert_eq!(
            state.admit_manifest(&third).unwrap(),
            LbfvManifestAdmission::EquivocationAlreadyRecorded
        );
        assert_eq!(
            state.parties[&0].conflicting_manifest.as_ref(),
            Some(&conflict)
        );

        let encoded = bincode::serialize(&state).unwrap();
        let restored: LbfvContributionCollectionStateV1 = bincode::deserialize(&encoded).unwrap();
        restored.validate_loaded().unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn unavailable_fetch_retries_recovers_and_rejects_stale_results() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (public_key, _, manifest) = bundle(&fixture, 0);
        state.admit_manifest(&manifest).unwrap();

        let due = state.due_fetch_requests(10).unwrap();
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].request().role, LbfvKeyShareDocumentRole::PublicKey);
        assert_eq!(
            due[1].request().role,
            LbfvKeyShareDocumentRole::RelinearizationKey
        );
        assert!(due.iter().all(|request| request.request().attempt == 1));

        let unavailable = failure(
            &state,
            0,
            LbfvKeyShareDocumentRole::PublicKey,
            1,
            LbfvKeyShareDocumentFetchFailureClass::Unavailable,
            Some(100),
        );
        assert!(state.record_fetch_failure(&unavailable).unwrap());
        assert!(!state.record_fetch_failure(&unavailable).unwrap());
        assert_eq!(state.due_fetch_requests(99).unwrap().len(), 1);
        let due = state.due_fetch_requests(100).unwrap();
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].request().attempt, 2);

        let stale = failure(
            &state,
            0,
            LbfvKeyShareDocumentRole::PublicKey,
            1,
            LbfvKeyShareDocumentFetchFailureClass::Unavailable,
            Some(101),
        );
        assert!(state.record_fetch_failure(&stale).is_err());

        assert_eq!(
            state.mark_document_durable(&public_key).unwrap(),
            LbfvDocumentAdmission::Recorded
        );
        let public_key_fetch = state.parties[&0].public_key_fetch.as_ref().unwrap();
        assert!(public_key_fetch.artifact_durable);
        assert_eq!(public_key_fetch.retry_at, None);
        assert_eq!(state.due_fetch_requests(u64::MAX).unwrap().len(), 1);
    }

    #[test]
    fn invalid_data_permanently_excludes_the_party() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (_, _, manifest) = bundle(&fixture, 0);
        state.admit_manifest(&manifest).unwrap();
        let invalid = failure(
            &state,
            0,
            LbfvKeyShareDocumentRole::RelinearizationKey,
            1,
            LbfvKeyShareDocumentFetchFailureClass::InvalidData,
            None,
        );
        assert!(state.record_fetch_failure(&invalid).unwrap());
        assert!(!state.record_fetch_failure(&invalid).unwrap());
        assert_eq!(
            state.parties[&0].status,
            LbfvPartyContributionStatusV1::InvalidData
        );
        assert!(state.due_fetch_requests(u64::MAX).unwrap().is_empty());
        assert!(state.mark_ready(vec![0, 1]).is_err());
    }

    #[test]
    fn ready_parties_are_canonical_for_shuffled_submission_order() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }

        assert_eq!(state.ready_party_ids(&[2, 0, 1, 2]).unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn ready_quorum_does_not_wait_for_an_unavailable_party() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        complete_party(&mut state, &fixture, 0);
        complete_party(&mut state, &fixture, 2);

        assert!(!state.all_submitted_parties_settled(&[2, 1, 0]).unwrap());
        assert_eq!(
            state.ready_quorum_party_ids(&[2, 1, 0]).unwrap(),
            Some(vec![0, 2])
        );
    }

    #[test]
    fn ready_quorum_keeps_exactly_the_first_h_ascending_parties() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }

        assert_eq!(
            state.ready_quorum_party_ids(&[2, 1, 0]).unwrap(),
            Some(vec![0, 1])
        );
    }

    #[test]
    fn persisted_candidate_set_does_not_change_after_a_late_arrival() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        complete_party(&mut state, &fixture, 0);
        complete_party(&mut state, &fixture, 2);
        state.mark_ready(vec![0, 2]).unwrap();

        complete_party(&mut state, &fixture, 1);

        assert!(matches!(
            state.verification,
            LbfvContributionVerificationStateV1::Ready { ref party_ids }
                if party_ids == &[0, 2]
        ));
    }

    #[test]
    fn exclusion_invalidates_an_unsealed_dispatch_and_survives_hydration() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }
        state.mark_ready(vec![0, 1]).unwrap();
        state.mark_verification_dispatched().unwrap();
        let first_verification_id = state.dispatched_verification_id().unwrap();

        assert!(state.mark_party_excluded(1).unwrap());
        assert!(!state.mark_party_excluded(1).unwrap());
        assert_eq!(
            state.parties[&1].status,
            LbfvPartyContributionStatusV1::Excluded
        );
        assert!(matches!(
            state.verification,
            LbfvContributionVerificationStateV1::Collecting
        ));
        assert_eq!(state.ready_party_ids(&[2, 1, 0]).unwrap(), vec![0, 2]);
        assert_eq!(state.ineligible_party_ids(&[2, 1, 0]).unwrap(), vec![1]);
        assert!(state.all_submitted_parties_settled(&[2, 1, 0]).unwrap());
        state.mark_ready(vec![0, 2]).unwrap();
        state.mark_verification_dispatched().unwrap();
        assert_ne!(
            state.dispatched_verification_id().unwrap(),
            first_verification_id
        );

        let encoded = bincode::serialize(&state).unwrap();
        let restored: LbfvContributionCollectionStateV1 = bincode::deserialize(&encoded).unwrap();
        restored.validate_loaded().unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn failed_candidate_selects_the_next_ready_quorum() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }
        state.mark_ready(vec![0, 1]).unwrap();
        state.mark_verification_dispatched().unwrap();
        let first_verification_id = state.dispatched_verification_id().unwrap();

        assert!(state.mark_party_invalid(1).unwrap());
        assert_eq!(
            state.ready_quorum_party_ids(&[0, 1, 2]).unwrap(),
            Some(vec![0, 2])
        );
        state.mark_ready(vec![0, 2]).unwrap();
        state.mark_verification_dispatched().unwrap();
        assert_ne!(
            state.dispatched_verification_id().unwrap(),
            first_verification_id
        );

        let encoded = bincode::serialize(&state).unwrap();
        let restored: LbfvContributionCollectionStateV1 = bincode::deserialize(&encoded).unwrap();
        restored.validate_loaded().unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn exclusion_before_manifest_prevents_document_fetches() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (_, _, manifest) = bundle(&fixture, 1);

        assert!(state.mark_party_excluded(1).unwrap());
        assert_eq!(
            state.admit_manifest(&manifest).unwrap(),
            LbfvManifestAdmission::Terminal
        );
        assert!(state.due_fetch_requests(u64::MAX).unwrap().is_empty());
        state.validate_loaded().unwrap();
    }

    #[test]
    fn verification_seals_exact_h_commitments_immutably() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }
        assert!(state.mark_ready(vec![0, 2]).unwrap());
        assert!(state.mark_verification_dispatched().unwrap());
        assert!(state.seal(accepted_parties(&[0, 1, 2])).is_err());
        assert!(state.seal(accepted_parties(&[2, 0])).is_err());
        assert!(state.seal(accepted_parties(&[0])).is_err());

        let mut mismatched = accepted_parties(&[0, 2]);
        mismatched[0].pk_generation_commitments[0] = B256::repeat_byte(0xff);
        assert!(state.seal(mismatched).is_err());

        let accepted = accepted_parties(&[0, 2]);
        assert!(state.seal(accepted.clone()).unwrap());
        assert!(!state.seal(accepted.clone()).unwrap());
        let mut changed = accepted.clone();
        changed[0].pk_generation_commitments[0] = B256::repeat_byte(0xff);
        assert!(state.seal(changed).is_err());
        assert_eq!(state.accepted_parties(), Some(accepted.as_slice()));

        assert!(matches!(
            &state.verification,
            LbfvContributionVerificationStateV1::Sealed {
                candidate_party_ids,
                accepted_parties,
            } if candidate_party_ids == &[0, 2] && accepted_parties == &accepted
        ));

        let sealed = state.clone();
        let (_, _, manifest) = bundle(&fixture, 2);
        assert_eq!(
            state.admit_manifest(&manifest).unwrap(),
            LbfvManifestAdmission::Terminal
        );
        assert_eq!(state, sealed);
    }

    #[test]
    fn sealing_rejects_a_ready_party_that_was_not_dispatched() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }
        state.mark_ready(vec![0, 1]).unwrap();
        state.mark_verification_dispatched().unwrap();

        assert!(state.seal(accepted_parties(&[0, 2])).is_err());
        assert!(matches!(
            state.verification,
            LbfvContributionVerificationStateV1::Dispatched { .. }
        ));
    }

    #[test]
    fn candidate_validation_rejects_small_or_noncanonical_sets() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        for party_id in 0..3 {
            complete_party(&mut state, &fixture, party_id);
        }

        assert!(state.mark_ready(vec![0]).is_err());
        assert!(state.mark_ready(vec![1, 0]).is_err());
        assert!(state.mark_ready(vec![0, 0]).is_err());
        assert!(state.mark_ready(vec![0, 3]).is_err());
        assert!(state.mark_ready(vec![0, 1, 2]).is_err());
    }

    #[test]
    fn failure_is_terminal_and_idempotent() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        assert!(state.fail(" ").is_err());
        assert!(state.fail("verification failed").unwrap());
        assert!(!state.fail("verification failed").unwrap());
        assert!(state.fail("different failure").is_err());

        let terminal = state.clone();
        let (_, _, manifest) = bundle(&fixture, 0);
        assert_eq!(
            state.admit_manifest(&manifest).unwrap(),
            LbfvManifestAdmission::Terminal
        );
        assert_eq!(state, terminal);
        state.validate_loaded().unwrap();
    }

    #[test]
    fn v1_schema_fixture_has_stable_hash() {
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (public_key, relinearization_key, manifest) = bundle(&fixture, 0);
        state.admit_manifest(&manifest).unwrap();
        let unavailable = failure(
            &state,
            0,
            LbfvKeyShareDocumentRole::PublicKey,
            1,
            LbfvKeyShareDocumentFetchFailureClass::Unavailable,
            Some(100),
        );
        state.record_fetch_failure(&unavailable).unwrap();
        state.mark_document_durable(&public_key).unwrap();
        state.mark_document_durable(&relinearization_key).unwrap();
        state.mark_party_validated(accepted_commitments(0)).unwrap();
        complete_party(&mut state, &fixture, 1);
        complete_party(&mut state, &fixture, 2);
        state.verification = LbfvContributionVerificationStateV1::Ready {
            party_ids: vec![0, 1, 2],
        };
        state.validate_loaded().unwrap();
        state.verification = LbfvContributionVerificationStateV1::Dispatched {
            party_ids: vec![0, 1, 2],
        };
        state.validate_loaded().unwrap();
        state.verification = LbfvContributionVerificationStateV1::Sealed {
            candidate_party_ids: vec![0, 1, 2],
            accepted_parties: accepted_parties(&[0, 2]),
        };
        state.validate_loaded().unwrap();

        let encoded = bincode::serialize(&state).unwrap();
        assert_eq!(
            keccak256(&encoded),
            "0xc7df1c415092cc5cf636dd47d4917c0df100b14ef5ed405116d63bba77f349b5"
                .parse::<B256>()
                .unwrap()
        );
        assert!(!encoded
            .windows(b"public-key-0".len())
            .any(|window| window == b"public-key-0"));
        assert!(!encoded
            .windows(b"relinearization-key-0".len())
            .any(|window| window == b"relinearization-key-0"));
        let restored: LbfvContributionCollectionStateV1 = bincode::deserialize(&encoded).unwrap();
        restored.validate_loaded().unwrap();
        assert_eq!(restored, state);
        assert_eq!(
            restored
                .party_states()
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }
}
