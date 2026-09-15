// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable state and pure transitions for local l-BFV key-share generation.

use std::collections::BTreeMap;

use alloy::{
    primitives::{keccak256, Address, U256},
    sol_types::SolValue,
};
use anyhow::{anyhow, ensure, Context, Result};
use e3_committee_hash::{
    hash_lbfv_proof_session, validate_and_hash_finalized_committee, LbfvProofDomainContext,
};
use e3_events::{
    CiphernodeSelected, LbfvKeyShareDocument, LbfvKeyShareDocumentContextV1, LbfvKeyShareManifest,
    LbfvKeyShareManifestV1, LbfvPkGenerationProofRequest, LbfvPkGenerationProofResponse,
    LbfvPublicKeyShareDocumentV1, LbfvRelinearizationKeyShareDocumentV1, ProofIdentity, ProofType,
    RlkGenerationProofRequest, RlkGenerationProofResponse, SignedLbfvKeyShareManifest,
    SignedProofPayload, ZkRequest,
};
use e3_fhe_params::{BfvPreset, LBFV_CONSTANTS_VERSION};
use e3_trbfv::{
    gen_lbfv_key_shares::{GenLbfvKeySharesRequest, GenLbfvKeySharesResponse},
    lbfv_operation::LbfvOperationId,
};

pub const LBFV_GENERATION_SCHEMA_VERSION: u32 = 1;
const CIRCUIT_VERSION_LABEL: &[u8] = b"interfold-bfv-v2";
const LBFV_ROW_COUNT: usize = ProofType::LBFV_ROW_INSTANCES as usize;

/// Version 1 snapshot for one party's local l-BFV generation workflow.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LbfvGenerationStateV1 {
    pub schema_version: u32,
    pub context: LbfvKeyShareDocumentContextV1,
    pub committee: Vec<Address>,
    pub generation_request: Option<GenLbfvKeySharesRequest>,
    pub generation_response: Option<GenLbfvKeySharesResponse>,
    pub signed_c1_proof: Option<SignedProofPayload>,
    pub signed_pk_row_proofs: BTreeMap<u32, SignedProofPayload>,
    pub signed_rlk_row_proofs: BTreeMap<u32, SignedProofPayload>,
    pub public_key_document: Option<LbfvKeyShareDocument>,
    pub relinearization_key_document: Option<LbfvKeyShareDocument>,
    pub signed_manifest: Option<SignedLbfvKeyShareManifest>,
    pub failure: Option<String>,
}

impl LbfvGenerationStateV1 {
    pub fn from_selection(
        selection: &CiphernodeSelected,
        interfold_address: Address,
        signer: Address,
        protocol_version: u32,
    ) -> Result<Self> {
        ensure!(
            selection.params_preset == BfvPreset::SecureThreshold16384,
            "l-BFV generation state requires SecureThreshold16384"
        );
        let committee = selection
            .committee
            .iter()
            .map(|address| {
                address
                    .parse::<Address>()
                    .with_context(|| format!("invalid finalized committee address {address}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let committee_size = e3_zk_helpers::CiphernodesCommitteeSize::from_threshold(
            selection.threshold_m,
            selection.threshold_n,
        )?;
        ensure!(
            committee_size == e3_zk_helpers::CiphernodesCommitteeSize::Minimum,
            "l-BFV generation supports only the minimum committee size for SecureThreshold16384"
        );
        let finalized_committee_hash =
            validate_and_hash_finalized_committee(&committee, selection.threshold_n)
                .map_err(anyhow::Error::msg)?;
        let party_id = u32::try_from(selection.party_id)
            .context("l-BFV party ID does not fit the transport schema")?;
        ensure!(
            committee.get(party_id as usize) == Some(&signer),
            "l-BFV signer does not match the selected party slot"
        );
        let e3_id: U256 = selection
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("l-BFV E3 ID cannot be converted to U256"))?;
        let crypto_config_id = keccak256(
            (
                keccak256(b"fhe.rs:BFV"),
                keccak256(&*selection.params),
                keccak256(CIRCUIT_VERSION_LABEL),
            )
                .abi_encode(),
        );
        let proof_domain = LbfvProofDomainContext {
            protocol_version,
            chain_id: selection.e3_id.chain_id(),
            interfold_address,
            e3_id,
            crypto_config_id,
            finalized_committee_hash,
            lbfv_constants_version: LBFV_CONSTANTS_VERSION,
            ciphertext_level: 0,
            key_level: 0,
        };
        let context = LbfvKeyShareDocumentContextV1 {
            e3_id: selection.e3_id.clone(),
            proof_domain,
            proof_session_id: hash_lbfv_proof_session(proof_domain),
            party_id,
        };
        context.validate()?;

        Ok(Self {
            schema_version: LBFV_GENERATION_SCHEMA_VERSION,
            context,
            committee,
            generation_request: None,
            generation_response: None,
            signed_c1_proof: None,
            signed_pk_row_proofs: BTreeMap::new(),
            signed_rlk_row_proofs: BTreeMap::new(),
            public_key_document: None,
            relinearization_key_document: None,
            signed_manifest: None,
            failure: None,
        })
    }

    pub fn validate_loaded(&self) -> Result<()> {
        ensure!(
            self.schema_version == LBFV_GENERATION_SCHEMA_VERSION,
            "unsupported l-BFV generation schema version {}",
            self.schema_version
        );
        self.context.validate()?;
        self.committee_size()?;
        ensure!(
            validate_and_hash_finalized_committee(&self.committee, self.committee.len())
                .map_err(anyhow::Error::msg)?
                == self.context.proof_domain.finalized_committee_hash,
            "persisted l-BFV committee does not match the proof domain"
        );
        ensure!(
            self.committee.get(self.context.party_id as usize).is_some(),
            "persisted l-BFV party ID is outside the committee"
        );
        if let Some(request) = &self.generation_request {
            request.validate_operation_id()?;
            ensure!(
                request.session_id == self.context.proof_session_id.0
                    && request.party_id == self.context.party_id,
                "persisted l-BFV generation request does not match its context"
            );
        }
        if self.is_ready() {
            self.signed_manifest.as_ref().unwrap().validate_documents(
                self.public_key_document.as_ref().unwrap(),
                self.relinearization_key_document.as_ref().unwrap(),
            )?;
            self.signed_manifest
                .as_ref()
                .unwrap()
                .verify_committee_signer(&self.committee)?;
        }
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.public_key_document.is_some()
            && self.relinearization_key_document.is_some()
            && self.signed_manifest.is_some()
            && self.failure.is_none()
    }

    pub fn expected_signer(&self) -> Result<Address> {
        self.committee
            .get(self.context.party_id as usize)
            .copied()
            .ok_or_else(|| anyhow!("l-BFV party ID is outside the committee"))
    }

    pub fn record_generation_request(&mut self, request: GenLbfvKeySharesRequest) -> Result<bool> {
        request.validate_operation_id()?;
        ensure!(
            request.session_id == self.context.proof_session_id.0
                && request.party_id == self.context.party_id,
            "l-BFV generation request does not match its durable context"
        );
        if let Some(existing) = &self.generation_request {
            ensure!(
                existing == &request,
                "conflicting l-BFV generation request for one proof session"
            );
            return Ok(false);
        }
        ensure!(!self.is_ready(), "l-BFV generation is already complete");
        self.generation_request = Some(request);
        Ok(true)
    }

    pub fn record_generation_response(
        &mut self,
        response: GenLbfvKeySharesResponse,
    ) -> Result<bool> {
        if self.is_ready() || self.failure.is_some() {
            return Ok(false);
        }
        let request = self
            .generation_request
            .as_ref()
            .ok_or_else(|| anyhow!("l-BFV generation response has no durable request"))?;
        ensure!(
            response.operation_id == request.operation_id,
            "l-BFV generation response operation ID does not match its request"
        );
        ensure!(
            !response.public_key_share_bytes.is_empty() && !response.rlk_share_bytes.is_empty(),
            "l-BFV generation response contains an empty share"
        );
        LbfvPkGenerationProofRequest::from_lbfv_key_shares(
            request,
            &response,
            self.context.proof_domain,
            0,
            self.committee_size()?,
        )?;
        RlkGenerationProofRequest::from_lbfv_key_shares(
            request,
            &response,
            self.context.proof_domain,
            0,
            self.committee_size()?,
        )?;
        if let Some(existing) = &self.generation_response {
            ensure!(
                existing == &response,
                "conflicting l-BFV generation response for one operation"
            );
            return Ok(false);
        }
        self.generation_response = Some(response);
        Ok(true)
    }

    pub fn record_c1_proof(&mut self, signed: SignedProofPayload) -> Result<bool> {
        if self.is_ready() || self.failure.is_some() {
            return Ok(false);
        }
        self.validate_signed_proof(&signed, ProofType::C1PkGeneration, 0)?;
        if let Some(existing) = &self.signed_c1_proof {
            ensure!(
                existing.payload == signed.payload,
                "conflicting C1 proof for one l-BFV generation session"
            );
            return Ok(false);
        }
        self.signed_c1_proof = Some(signed);
        Ok(true)
    }

    pub fn record_pk_row_proof(
        &mut self,
        response: &LbfvPkGenerationProofResponse,
        signed: SignedProofPayload,
    ) -> Result<bool> {
        if self.is_ready() || self.failure.is_some() {
            return Ok(false);
        }
        let expected = self.pk_request(response.row_index)?;
        ensure!(
            response.operation_id == expected.operation_id,
            "l-BFV public-key proof response operation ID does not match its request"
        );
        ensure!(
            signed.payload.proof == response.proof,
            "signed l-BFV public-key proof does not match its compute response"
        );
        self.validate_signed_proof(&signed, ProofType::LbfvPkGeneration, response.row_index)?;
        insert_first(
            &mut self.signed_pk_row_proofs,
            response.row_index,
            signed,
            "public-key",
        )
    }

    pub fn record_rlk_row_proof(
        &mut self,
        response: &RlkGenerationProofResponse,
        signed: SignedProofPayload,
    ) -> Result<bool> {
        if self.is_ready() || self.failure.is_some() {
            return Ok(false);
        }
        let expected = self.rlk_request(response.row_index)?;
        ensure!(
            response.operation_id == expected.operation_id,
            "RLK proof response operation ID does not match its request"
        );
        ensure!(
            signed.payload.proof == response.proof,
            "signed RLK proof does not match its compute response"
        );
        self.validate_signed_proof(&signed, ProofType::RlkGeneration, response.row_index)?;
        insert_first(
            &mut self.signed_rlk_row_proofs,
            response.row_index,
            signed,
            "relinearization-key",
        )
    }

    pub fn pending_proof_identities(&self) -> Vec<ProofIdentity> {
        if self.generation_response.is_none() || self.is_ready() || self.failure.is_some() {
            return Vec::new();
        }
        let mut identities = Vec::with_capacity(2 * LBFV_ROW_COUNT);
        for row in 0..LBFV_ROW_COUNT as u32 {
            if !self.signed_pk_row_proofs.contains_key(&row) {
                identities.push(ProofIdentity {
                    proof_type: ProofType::LbfvPkGeneration,
                    instance: row,
                });
            }
            if !self.signed_rlk_row_proofs.contains_key(&row) {
                identities.push(ProofIdentity {
                    proof_type: ProofType::RlkGeneration,
                    instance: row,
                });
            }
        }
        identities
    }

    pub fn awaits_operation(&self, operation_id: LbfvOperationId) -> Result<bool> {
        if self.is_ready() || self.failure.is_some() {
            return Ok(false);
        }
        if self.generation_response.is_none()
            && self
                .generation_request
                .as_ref()
                .is_some_and(|request| request.operation_id == operation_id)
        {
            return Ok(true);
        }
        for identity in self.pending_proof_identities() {
            if self.proof_request(identity)?.lbfv_operation_id() == Some(operation_id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn proof_request(&self, identity: ProofIdentity) -> Result<ZkRequest> {
        match identity.proof_type {
            ProofType::LbfvPkGeneration => Ok(ZkRequest::LbfvPkGeneration(
                self.pk_request(identity.instance)?,
            )),
            ProofType::RlkGeneration => Ok(ZkRequest::RlkGeneration(
                self.rlk_request(identity.instance)?,
            )),
            _ => Err(anyhow!("unsupported l-BFV generation proof identity")),
        }
    }

    pub fn build_documents(&self) -> Result<Option<(LbfvKeyShareDocument, LbfvKeyShareDocument)>> {
        let (Some(response), Some(c1)) = (&self.generation_response, &self.signed_c1_proof) else {
            return Ok(None);
        };
        if self.signed_pk_row_proofs.len() != LBFV_ROW_COUNT
            || self.signed_rlk_row_proofs.len() != LBFV_ROW_COUNT
        {
            return Ok(None);
        }
        let pk_rows = rows_from_map(&self.signed_pk_row_proofs)?;
        let rlk_rows = rows_from_map(&self.signed_rlk_row_proofs)?;
        let public_key = LbfvKeyShareDocument::PublicKeyV1(LbfvPublicKeyShareDocumentV1 {
            context: self.context.clone(),
            share: response.public_key_share_bytes.clone(),
            signed_c1_proof: c1.clone(),
            signed_row_proofs: pk_rows,
        });
        let relinearization_key =
            LbfvKeyShareDocument::RelinearizationKeyV1(LbfvRelinearizationKeyShareDocumentV1 {
                context: self.context.clone(),
                share: response.rlk_share_bytes.clone(),
                signed_row_proofs: rlk_rows,
            });
        public_key.validate()?;
        relinearization_key.validate()?;
        Ok(Some((public_key, relinearization_key)))
    }

    pub fn manifest_for_documents(
        &self,
        public_key: &LbfvKeyShareDocument,
        relinearization_key: &LbfvKeyShareDocument,
    ) -> Result<LbfvKeyShareManifest> {
        Ok(LbfvKeyShareManifest::V1(LbfvKeyShareManifestV1 {
            context: self.context.clone(),
            public_key_document_hash: public_key.content_hash()?,
            relinearization_key_document_hash: relinearization_key.content_hash()?,
        }))
    }

    pub fn record_bundle(
        &mut self,
        public_key: LbfvKeyShareDocument,
        relinearization_key: LbfvKeyShareDocument,
        signed_manifest: SignedLbfvKeyShareManifest,
    ) -> Result<bool> {
        signed_manifest.validate_documents(&public_key, &relinearization_key)?;
        signed_manifest.verify_committee_signer(&self.committee)?;
        if self.is_ready() {
            ensure!(
                self.public_key_document.as_ref() == Some(&public_key)
                    && self.relinearization_key_document.as_ref() == Some(&relinearization_key)
                    && self.signed_manifest.as_ref() == Some(&signed_manifest),
                "conflicting completed l-BFV generation bundle"
            );
            return Ok(false);
        }
        self.public_key_document = Some(public_key);
        self.relinearization_key_document = Some(relinearization_key);
        self.signed_manifest = Some(signed_manifest);
        self.generation_request = None;
        self.generation_response = None;
        Ok(true)
    }

    pub fn record_failure(&mut self, reason: &str) {
        if self.failure.is_none() {
            self.failure = Some(reason.to_owned());
        }
        self.generation_request = None;
        self.generation_response = None;
    }

    fn pk_request(&self, row: u32) -> Result<LbfvPkGenerationProofRequest> {
        LbfvPkGenerationProofRequest::from_lbfv_key_shares(
            self.generation_request
                .as_ref()
                .ok_or_else(|| anyhow!("missing durable l-BFV generation request"))?,
            self.generation_response
                .as_ref()
                .ok_or_else(|| anyhow!("missing durable l-BFV generation response"))?,
            self.context.proof_domain,
            row,
            self.committee_size()?,
        )
    }

    fn rlk_request(&self, row: u32) -> Result<RlkGenerationProofRequest> {
        RlkGenerationProofRequest::from_lbfv_key_shares(
            self.generation_request
                .as_ref()
                .ok_or_else(|| anyhow!("missing durable l-BFV generation request"))?,
            self.generation_response
                .as_ref()
                .ok_or_else(|| anyhow!("missing durable l-BFV generation response"))?,
            self.context.proof_domain,
            row,
            self.committee_size()?,
        )
    }

    fn validate_signed_proof(
        &self,
        signed: &SignedProofPayload,
        proof_type: ProofType,
        instance: u32,
    ) -> Result<()> {
        let signer = self.context.validate_signed_proof(
            signed,
            ProofIdentity {
                proof_type,
                instance,
            },
        )?;
        let expected_signer = self.expected_signer()?;
        ensure!(
            signer == expected_signer,
            "signed l-BFV proof signer does not match the party slot"
        );
        Ok(())
    }

    fn committee_size(&self) -> Result<e3_zk_helpers::CiphernodesCommitteeSize> {
        e3_zk_helpers::CiphernodesCommitteeSize::from_threshold(
            self.committee.len().saturating_sub(1) / 2,
            self.committee.len(),
        )
    }
}

fn insert_first(
    proofs: &mut BTreeMap<u32, SignedProofPayload>,
    row: u32,
    signed: SignedProofPayload,
    share_kind: &str,
) -> Result<bool> {
    match proofs.entry(row) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(signed);
            Ok(true)
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            ensure!(
                entry.get().payload == signed.payload,
                "conflicting l-BFV {share_kind} proof for row {row}"
            );
            Ok(false)
        }
    }
}

fn rows_from_map(
    proofs: &BTreeMap<u32, SignedProofPayload>,
) -> Result<[SignedProofPayload; LBFV_ROW_COUNT]> {
    (0..LBFV_ROW_COUNT as u32)
        .map(|row| {
            proofs
                .get(&row)
                .cloned()
                .ok_or_else(|| anyhow!("missing l-BFV row proof {row}"))
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow!("l-BFV row proof count does not match the transport schema"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{primitives::B256, signers::local::PrivateKeySigner};
    use e3_committee_hash::split_hash_to_field_limbs;
    use e3_crypto::SensitiveBytes;
    use e3_events::{CircuitName, E3id, Proof, ProofPayload, Seed};
    use e3_trbfv::gen_lbfv_key_shares::EncryptedRlkWitness;
    use e3_utils::ArcBytes;
    use e3_zk_helpers::FIELD_BYTE_LEN;

    fn signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn state() -> LbfvGenerationStateV1 {
        let signer = signer();
        LbfvGenerationStateV1::from_selection(
            &CiphernodeSelected {
                e3_id: E3id::new("7", 31_337),
                threshold_m: 1,
                threshold_n: 3,
                seed: Seed([0; 32]),
                error_size: ArcBytes::from_bytes(&[1]),
                params_preset: BfvPreset::SecureThreshold16384,
                params: ArcBytes::from_bytes(b"secure-16384-params"),
                party_id: 1,
                committee: vec![
                    Address::ZERO.to_string(),
                    signer.address().to_string(),
                    Address::repeat_byte(0xff).to_string(),
                ],
            },
            Address::repeat_byte(0x11),
            signer.address(),
            4,
        )
        .unwrap()
    }

    #[test]
    fn rejects_non_minimum_secure_committee() {
        let signer = signer();
        let selection = CiphernodeSelected {
            e3_id: E3id::new("7", 31_337),
            threshold_m: 4,
            threshold_n: 9,
            seed: Seed([0; 32]),
            error_size: ArcBytes::from_bytes(&[1]),
            params_preset: BfvPreset::SecureThreshold16384,
            params: ArcBytes::from_bytes(b"secure-16384-params"),
            party_id: 1,
            committee: vec![
                Address::ZERO.to_string(),
                signer.address().to_string(),
                Address::repeat_byte(0xff).to_string(),
            ],
        };

        assert!(LbfvGenerationStateV1::from_selection(
            &selection,
            Address::repeat_byte(0x11),
            signer.address(),
            4,
        )
        .is_err());
    }

    fn generation_request(state: &LbfvGenerationStateV1) -> GenLbfvKeySharesRequest {
        let mut request = GenLbfvKeySharesRequest {
            operation_id: LbfvOperationId([0; 32]),
            session_id: state.context.proof_session_id.0,
            party_id: state.context.party_id,
            secret_key_bytes: SensitiveBytes::from_encrypted(&[1]),
            generation_seed: SensitiveBytes::from_encrypted(&[2]),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        };
        request.operation_id = request.expected_operation_id();
        request
    }

    fn generation_response(request: &GenLbfvKeySharesRequest) -> GenLbfvKeySharesResponse {
        GenLbfvKeySharesResponse {
            operation_id: request.operation_id,
            public_key_share_bytes: ArcBytes::from_bytes(b"public-key-share"),
            rlk_share_bytes: ArcBytes::from_bytes(b"relinearization-key-share"),
            witness: EncryptedRlkWitness {
                r_bytes: SensitiveBytes::from_encrypted(&[3]),
                errors_d0_bytes: (0..LBFV_ROW_COUNT)
                    .map(|row| SensitiveBytes::from_encrypted(&[row as u8]))
                    .collect(),
                errors_d2_bytes: (0..LBFV_ROW_COUNT)
                    .map(|row| SensitiveBytes::from_encrypted(&[row as u8 + 5]))
                    .collect(),
            },
        }
    }

    fn proof(state: &LbfvGenerationStateV1, circuit: CircuitName, row: u32) -> Proof {
        let input = circuit.input_layout();
        let field_count =
            input.field_count().unwrap() + circuit.output_layout().field_count().unwrap();
        let mut signals = vec![0u8; field_count * FIELD_BYTE_LEN];
        if let Some(index) = input.field_index("session_id_hi") {
            let session = split_hash_to_field_limbs(state.context.proof_session_id);
            signals[index * 32 + 16..index * 32 + 32].copy_from_slice(&session.hi.to_be_bytes());
            let index = input.field_index("session_id_lo").unwrap();
            signals[index * 32 + 16..index * 32 + 32].copy_from_slice(&session.lo.to_be_bytes());
            let index = input.field_index("party_id").unwrap();
            signals[index * 32 + 28..index * 32 + 32]
                .copy_from_slice(&state.context.party_id.to_be_bytes());
            let index = input.field_index("row_index").unwrap();
            signals[index * 32 + 28..index * 32 + 32].copy_from_slice(&row.to_be_bytes());
        }
        Proof::new(
            circuit,
            ArcBytes::from_bytes(&[0xaa]),
            ArcBytes::from_bytes(&signals),
        )
    }

    fn signed_proof(
        state: &LbfvGenerationStateV1,
        proof_type: ProofType,
        proof: Proof,
    ) -> SignedProofPayload {
        SignedProofPayload::sign(
            ProofPayload {
                e3_id: state.context.e3_id.clone(),
                proof_type,
                proof,
            },
            &signer(),
        )
        .unwrap()
    }

    #[test]
    fn generation_state_redrives_missing_rows_and_finalizes_one_bundle() {
        let mut state = state();
        let request = generation_request(&state);
        let response = generation_response(&request);
        assert!(state.record_generation_request(request).unwrap());
        assert!(state.record_generation_response(response.clone()).unwrap());
        assert_eq!(state.pending_proof_identities().len(), 10);

        let c1 = proof(&state, CircuitName::PkGeneration, 0);
        let signed_c1 = signed_proof(&state, ProofType::C1PkGeneration, c1);
        state.record_c1_proof(signed_c1.clone()).unwrap();
        let mut late_pk_row = None;
        let mut late_rlk_row = None;
        for row in 0..LBFV_ROW_COUNT as u32 {
            let ZkRequest::LbfvPkGeneration(request) = state
                .proof_request(ProofIdentity {
                    proof_type: ProofType::LbfvPkGeneration,
                    instance: row,
                })
                .unwrap()
            else {
                unreachable!();
            };
            let response = LbfvPkGenerationProofResponse {
                operation_id: request.operation_id,
                proof: proof(&state, CircuitName::LbfvPkGeneration, row),
                row_index: row,
            };
            let signed = signed_proof(&state, ProofType::LbfvPkGeneration, response.proof.clone());
            if row == 0 {
                late_pk_row = Some((response.clone(), signed.clone()));
            }
            state.record_pk_row_proof(&response, signed).unwrap();

            let ZkRequest::RlkGeneration(request) = state
                .proof_request(ProofIdentity {
                    proof_type: ProofType::RlkGeneration,
                    instance: row,
                })
                .unwrap()
            else {
                unreachable!();
            };
            let response = RlkGenerationProofResponse {
                operation_id: request.operation_id,
                proof: proof(&state, CircuitName::RlkGeneration, row),
                row_index: row,
            };
            let signed = signed_proof(&state, ProofType::RlkGeneration, response.proof.clone());
            if row == 0 {
                late_rlk_row = Some((response.clone(), signed.clone()));
            }
            state.record_rlk_row_proof(&response, signed).unwrap();
        }
        assert!(state.pending_proof_identities().is_empty());

        let (public_key, relinearization_key) = state.build_documents().unwrap().unwrap();
        let manifest = SignedLbfvKeyShareManifest::sign(
            state
                .manifest_for_documents(&public_key, &relinearization_key)
                .unwrap(),
            &signer(),
        )
        .unwrap();
        assert!(state
            .record_bundle(public_key, relinearization_key, manifest)
            .unwrap());
        assert!(state.is_ready());
        assert!(state.generation_request.is_none());
        assert!(state.generation_response.is_none());
        assert!(!state.record_generation_response(response).unwrap());
        assert!(!state.record_c1_proof(signed_c1).unwrap());
        let (response, signed) = late_pk_row.unwrap();
        assert!(!state.record_pk_row_proof(&response, signed).unwrap());
        let (response, signed) = late_rlk_row.unwrap();
        assert!(!state.record_rlk_row_proof(&response, signed).unwrap());

        let encoded = bincode::serialize(&state).unwrap();
        assert_eq!(
            keccak256(&encoded),
            "0x4c112cdce6ba06dddc846db18d92eebd11695a379b614982c7541bec6172a8d4"
                .parse::<B256>()
                .unwrap()
        );
        let restored: LbfvGenerationStateV1 = bincode::deserialize(&encoded).unwrap();
        restored.validate_loaded().unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn generation_state_rejects_a_conflicting_response() {
        let mut state = state();
        let request = generation_request(&state);
        let response = generation_response(&request);
        state.record_generation_request(request).unwrap();
        state.record_generation_response(response.clone()).unwrap();
        let mut conflicting = response;
        conflicting.public_key_share_bytes = ArcBytes::from_bytes(b"different-share");
        assert!(state.record_generation_response(conflicting).is_err());
    }

    #[test]
    fn generation_state_accepts_errors_only_for_pending_operations() {
        let mut state = state();
        let request = generation_request(&state);
        assert!(state.record_generation_request(request.clone()).unwrap());
        assert!(state.awaits_operation(request.operation_id).unwrap());

        assert!(state
            .record_generation_response(generation_response(&request))
            .unwrap());
        assert!(!state.awaits_operation(request.operation_id).unwrap());

        let identity = ProofIdentity {
            proof_type: ProofType::LbfvPkGeneration,
            instance: 0,
        };
        let ZkRequest::LbfvPkGeneration(row_request) = state.proof_request(identity).unwrap()
        else {
            unreachable!();
        };
        assert!(state.awaits_operation(row_request.operation_id).unwrap());

        let response = LbfvPkGenerationProofResponse {
            operation_id: row_request.operation_id,
            proof: proof(&state, CircuitName::LbfvPkGeneration, 0),
            row_index: 0,
        };
        state
            .record_pk_row_proof(
                &response,
                signed_proof(&state, ProofType::LbfvPkGeneration, response.proof.clone()),
            )
            .unwrap();
        assert!(!state.awaits_operation(row_request.operation_id).unwrap());
    }

    #[test]
    fn generation_state_rejects_conflicting_signed_proofs() {
        let mut state = state();
        let request = generation_request(&state);
        state.record_generation_request(request.clone()).unwrap();
        state
            .record_generation_response(generation_response(&request))
            .unwrap();

        let c1_proof = proof(&state, CircuitName::PkGeneration, 0);
        let c1 = signed_proof(&state, ProofType::C1PkGeneration, c1_proof.clone());
        state.record_c1_proof(c1.clone()).unwrap();
        let conflicting_c1 = signed_proof(
            &state,
            ProofType::C1PkGeneration,
            Proof::new(
                CircuitName::PkGeneration,
                ArcBytes::from_bytes(&[0xbb]),
                c1_proof.public_signals,
            ),
        );
        assert!(state.record_c1_proof(conflicting_c1).is_err());

        let identity = ProofIdentity {
            proof_type: ProofType::LbfvPkGeneration,
            instance: 0,
        };
        let ZkRequest::LbfvPkGeneration(row_request) = state.proof_request(identity).unwrap()
        else {
            unreachable!();
        };
        let response = LbfvPkGenerationProofResponse {
            operation_id: row_request.operation_id,
            proof: proof(&state, CircuitName::LbfvPkGeneration, 0),
            row_index: 0,
        };
        state
            .record_pk_row_proof(
                &response,
                signed_proof(&state, ProofType::LbfvPkGeneration, response.proof.clone()),
            )
            .unwrap();
        let conflicting_response = LbfvPkGenerationProofResponse {
            proof: Proof::new(
                CircuitName::LbfvPkGeneration,
                ArcBytes::from_bytes(&[0xbb]),
                response.proof.public_signals.clone(),
            ),
            ..response
        };
        assert!(state
            .record_pk_row_proof(
                &conflicting_response,
                signed_proof(
                    &state,
                    ProofType::LbfvPkGeneration,
                    conflicting_response.proof.clone(),
                ),
            )
            .is_err());
    }

    #[test]
    fn terminal_failure_discards_generation_secrets_and_witnesses() {
        let mut state = state();
        let request = generation_request(&state);
        let response = generation_response(&request);
        state.record_generation_request(request).unwrap();
        state.record_generation_response(response).unwrap();

        state.record_failure("generation failed");

        assert_eq!(state.failure.as_deref(), Some("generation failed"));
        assert!(state.generation_request.is_none());
        assert!(state.generation_response.is_none());
        assert!(state.pending_proof_identities().is_empty());
    }
}
