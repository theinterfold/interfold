// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Versioned transport types for l-BFV public-key and relinearization-key shares.

use crate::{E3id, ProofIdentity, ProofType, SignedProofPayload};
use actix::Message;
use alloy::{
    primitives::{keccak256, Address, Signature, B256, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol_types::SolValue,
};
use anyhow::{anyhow, ensure, Context, Result};
use derivative::Derivative;
use e3_committee_hash::{
    hash_committee_addresses, hash_lbfv_proof_session, split_hash_to_field_limbs,
    LbfvProofDomainContext,
};
use e3_fhe_params::{is_supported_lbfv_row_count, lbfv_row_count, BfvPreset};
use e3_utils::ArcBytes;
use e3_zk_helpers::FIELD_BYTE_LEN;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LBFV_ROW_COUNT: usize = ProofType::LBFV_ROW_INSTANCES as usize;

/// Public context shared by one party's l-BFV transport documents and manifest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvKeyShareDocumentContextV1 {
    pub e3_id: E3id,
    pub proof_domain: LbfvProofDomainContext,
    pub proof_session_id: B256,
    pub party_id: u32,
}

impl LbfvKeyShareDocumentContextV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.e3_id.chain_id() == self.proof_domain.chain_id,
            "l-BFV transport chain does not match the proof domain"
        );
        let e3_id: U256 = self
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("l-BFV transport E3 ID cannot be converted to U256"))?;
        ensure!(
            e3_id == self.proof_domain.e3_id,
            "l-BFV transport E3 ID does not match the proof domain"
        );
        ensure!(
            self.proof_session_id == hash_lbfv_proof_session(self.proof_domain),
            "l-BFV transport proof session does not match the proof domain"
        );
        Ok(())
    }

    /// Validate one signed proof against this document context and position.
    pub fn validate_signed_proof(
        &self,
        signed: &SignedProofPayload,
        expected_identity: ProofIdentity,
        lbfv_row_count: Option<usize>,
    ) -> Result<Address> {
        validate_proof(signed, self, expected_identity, lbfv_row_count)
    }
}

/// Version 1 public-key share document.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct LbfvPublicKeyShareDocumentV1 {
    pub context: LbfvKeyShareDocumentContextV1,
    #[derivative(Debug = "ignore")]
    pub share: ArcBytes,
    #[derivative(Debug = "ignore")]
    pub signed_c1_proof: SignedProofPayload,
    #[derivative(Debug = "ignore")]
    pub signed_row_proofs: [SignedProofPayload; LBFV_ROW_COUNT],
}

/// Version 1 relinearization-key share document.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct LbfvRelinearizationKeyShareDocumentV1 {
    pub context: LbfvKeyShareDocumentContextV1,
    #[derivative(Debug = "ignore")]
    pub share: ArcBytes,
    #[derivative(Debug = "ignore")]
    pub signed_row_proofs: [SignedProofPayload; LBFV_ROW_COUNT],
}

/// Dynamic public-key share document.
///
/// The row count is the number of CRT moduli in the selected preset. The V1
/// document remains available so nodes can read existing five-row records.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct LbfvPublicKeyShareDocumentV2 {
    pub context: LbfvKeyShareDocumentContextV1,
    #[derivative(Debug = "ignore")]
    pub share: ArcBytes,
    #[derivative(Debug = "ignore")]
    pub signed_c1_proof: SignedProofPayload,
    pub signed_row_proofs: Vec<SignedProofPayload>,
}

/// Dynamic relinearization-key share document.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct LbfvRelinearizationKeyShareDocumentV2 {
    pub context: LbfvKeyShareDocumentContextV1,
    #[derivative(Debug = "ignore")]
    pub share: ArcBytes,
    pub signed_row_proofs: Vec<SignedProofPayload>,
}

/// Content stored in one l-BFV DHT record.
///
/// Bincode encodes variants by order. Append new versions and do not reorder existing variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvKeyShareDocument {
    PublicKeyV1(LbfvPublicKeyShareDocumentV1),
    RelinearizationKeyV1(LbfvRelinearizationKeyShareDocumentV1),
    PublicKeyV2(LbfvPublicKeyShareDocumentV2),
    RelinearizationKeyV2(LbfvRelinearizationKeyShareDocumentV2),
}

impl LbfvKeyShareDocument {
    pub fn context(&self) -> &LbfvKeyShareDocumentContextV1 {
        match self {
            Self::PublicKeyV1(document) => &document.context,
            Self::RelinearizationKeyV1(document) => &document.context,
            Self::PublicKeyV2(document) => &document.context,
            Self::RelinearizationKeyV2(document) => &document.context,
        }
    }

    pub fn e3_id(&self) -> &E3id {
        &self.context().e3_id
    }

    pub fn role(&self) -> LbfvKeyShareDocumentRole {
        match self {
            Self::PublicKeyV1(_) => LbfvKeyShareDocumentRole::PublicKey,
            Self::RelinearizationKeyV1(_) => LbfvKeyShareDocumentRole::RelinearizationKey,
            Self::PublicKeyV2(_) => LbfvKeyShareDocumentRole::PublicKey,
            Self::RelinearizationKeyV2(_) => LbfvKeyShareDocumentRole::RelinearizationKey,
        }
    }

    /// Return the number of row proofs carried by the document.
    #[must_use]
    pub fn row_count(&self) -> usize {
        match self {
            Self::PublicKeyV1(document) => document.signed_row_proofs.len(),
            Self::RelinearizationKeyV1(document) => document.signed_row_proofs.len(),
            Self::PublicKeyV2(document) => document.signed_row_proofs.len(),
            Self::RelinearizationKeyV2(document) => document.signed_row_proofs.len(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("could not serialize l-BFV key-share document")
    }

    pub fn content_hash(&self) -> Result<B256> {
        Ok(lbfv_document_hash(&self.to_bytes()?))
    }

    /// Validate document context, proof order, proof signatures, and signer consistency.
    pub fn validate(&self) -> Result<Address> {
        self.validate_with_row_count(None)
    }

    /// Validate a document against the exact row count for one BFV preset.
    pub fn validate_for_preset(&self, preset: BfvPreset) -> Result<Address> {
        let row_count = lbfv_row_count(preset)
            .ok_or_else(|| anyhow!("preset {} does not support l-BFV", preset.name()))?;
        self.validate_with_row_count(Some(row_count))
    }

    fn validate_with_row_count(&self, expected_row_count: Option<usize>) -> Result<Address> {
        self.context().validate()?;
        match self {
            Self::PublicKeyV1(document) => document.validate(expected_row_count),
            Self::RelinearizationKeyV1(document) => document.validate(expected_row_count),
            Self::PublicKeyV2(document) => document.validate(expected_row_count),
            Self::RelinearizationKeyV2(document) => document.validate(expected_row_count),
        }
    }
}

impl LbfvPublicKeyShareDocumentV1 {
    fn validate(&self, expected_row_count: Option<usize>) -> Result<Address> {
        ensure!(!self.share.is_empty(), "l-BFV public-key share is empty");
        let signer = self.context.validate_signed_proof(
            &self.signed_c1_proof,
            ProofIdentity {
                proof_type: ProofType::C1PkGeneration,
                instance: 0,
            },
            None,
        )?;
        validate_rows(
            &self.signed_row_proofs,
            &self.context,
            ProofType::LbfvPkGeneration,
            signer,
            expected_row_count,
        )?;
        Ok(signer)
    }
}

impl LbfvRelinearizationKeyShareDocumentV1 {
    fn validate(&self, expected_row_count: Option<usize>) -> Result<Address> {
        ensure!(
            !self.share.is_empty(),
            "l-BFV relinearization-key share is empty"
        );
        let signer = self.signed_row_proofs[0].recover_address()?;
        validate_rows(
            &self.signed_row_proofs,
            &self.context,
            ProofType::RlkGeneration,
            signer,
            expected_row_count,
        )?;
        Ok(signer)
    }
}

impl LbfvPublicKeyShareDocumentV2 {
    fn validate(&self, expected_row_count: Option<usize>) -> Result<Address> {
        ensure!(!self.share.is_empty(), "l-BFV public-key share is empty");
        let signer = self.context.validate_signed_proof(
            &self.signed_c1_proof,
            ProofIdentity {
                proof_type: ProofType::C1PkGeneration,
                instance: 0,
            },
            None,
        )?;
        validate_rows_slice(
            &self.signed_row_proofs,
            &self.context,
            ProofType::LbfvPkGeneration,
            signer,
            expected_row_count,
        )?;
        Ok(signer)
    }
}

impl LbfvRelinearizationKeyShareDocumentV2 {
    fn validate(&self, expected_row_count: Option<usize>) -> Result<Address> {
        ensure!(
            !self.share.is_empty(),
            "l-BFV relinearization-key share is empty"
        );
        let signer = self
            .signed_row_proofs
            .first()
            .ok_or_else(|| anyhow!("l-BFV relinearization-key proof bundle is empty"))?
            .recover_address()?;
        validate_rows_slice(
            &self.signed_row_proofs,
            &self.context,
            ProofType::RlkGeneration,
            signer,
            expected_row_count,
        )?;
        Ok(signer)
    }
}

fn validate_rows(
    proofs: &[SignedProofPayload; LBFV_ROW_COUNT],
    context: &LbfvKeyShareDocumentContextV1,
    proof_type: ProofType,
    expected_signer: Address,
    expected_row_count: Option<usize>,
) -> Result<()> {
    validate_rows_slice(
        proofs,
        context,
        proof_type,
        expected_signer,
        expected_row_count,
    )
}

fn validate_rows_slice(
    proofs: &[SignedProofPayload],
    context: &LbfvKeyShareDocumentContextV1,
    proof_type: ProofType,
    expected_signer: Address,
    expected_row_count: Option<usize>,
) -> Result<()> {
    ensure!(!proofs.is_empty(), "l-BFV proof bundle is empty");
    if let Some(expected) = expected_row_count {
        ensure!(
            proofs.len() == expected,
            "l-BFV proof bundle has {} rows; expected {expected}",
            proofs.len()
        );
    } else {
        ensure!(
            is_supported_lbfv_row_count(proofs.len()),
            "l-BFV proof bundle has unsupported row count {}",
            proofs.len()
        );
    }
    let row_count = expected_row_count.unwrap_or(proofs.len());
    for (row, proof) in proofs.iter().enumerate() {
        let signer = context.validate_signed_proof(
            proof,
            ProofIdentity {
                proof_type,
                instance: row as u32,
            },
            Some(row_count),
        )?;
        ensure!(
            signer == expected_signer,
            "l-BFV proof bundle contains signatures from different parties"
        );
    }
    Ok(())
}

fn validate_proof(
    signed: &SignedProofPayload,
    context: &LbfvKeyShareDocumentContextV1,
    expected_identity: ProofIdentity,
    lbfv_row_count: Option<usize>,
) -> Result<Address> {
    ensure!(
        signed.payload.e3_id == context.e3_id,
        "l-BFV proof E3 ID does not match its document"
    );
    ensure!(
        signed.payload.proof_type == expected_identity.proof_type,
        "l-BFV proof type does not match its document position"
    );
    ensure!(
        signed
            .payload
            .proof_type
            .identity(&signed.payload.proof, lbfv_row_count)?
            == expected_identity,
        "l-BFV proof row does not match its document position"
    );
    let proof = &signed.payload.proof;
    let public_field_count = proof
        .circuit
        .input_layout()
        .field_count()
        .and_then(|inputs| {
            proof
                .circuit
                .output_layout()
                .field_count()
                .map(|outputs| inputs + outputs)
        })
        .ok_or_else(|| anyhow!("l-BFV transport proof does not have a fixed public shape"))?;
    ensure!(
        proof.public_signals.len() == public_field_count * FIELD_BYTE_LEN,
        "l-BFV transport proof does not have the expected public shape"
    );

    if expected_identity.proof_type.is_multirow() {
        let session = split_hash_to_field_limbs(context.proof_session_id);
        ensure!(
            public_u128_matches(signed, "session_id_hi", session.hi)
                && public_u128_matches(signed, "session_id_lo", session.lo),
            "l-BFV proof session does not match its document"
        );
        ensure!(
            public_u32_matches(signed, "party_id", context.party_id),
            "l-BFV proof party ID does not match its document"
        );
    }
    signed.recover_address()
}

fn public_u32_matches(signed: &SignedProofPayload, name: &str, expected: u32) -> bool {
    signed
        .payload
        .proof
        .circuit
        .input_layout()
        .extract_field(&signed.payload.proof.public_signals, name)
        .is_some_and(|field| {
            field[..28].iter().all(|byte| *byte == 0) && field[28..] == expected.to_be_bytes()
        })
}

fn public_u128_matches(signed: &SignedProofPayload, name: &str, expected: u128) -> bool {
    signed
        .payload
        .proof
        .circuit
        .input_layout()
        .extract_field(&signed.payload.proof.public_signals, name)
        .is_some_and(|field| {
            field[..16].iter().all(|byte| *byte == 0) && field[16..] == expected.to_be_bytes()
        })
}

/// Compute the SHA-256 content hash used as the DHT record key.
pub fn lbfv_document_hash(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

/// The contribution carried by one l-BFV DHT document.
///
/// Bincode encodes variants by order. Append new roles and do not reorder existing variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvKeyShareDocumentRole {
    PublicKey,
    RelinearizationKey,
}

/// Version 1 manifest that binds one party's two l-BFV DHT records.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvKeyShareManifestV1 {
    pub context: LbfvKeyShareDocumentContextV1,
    pub public_key_document_hash: B256,
    pub relinearization_key_document_hash: B256,
}

impl LbfvKeyShareManifestV1 {
    fn typehash() -> B256 {
        keccak256(
            "LbfvKeyShareManifestV1(uint256 protocolVersion,uint256 chainId,address interfold,uint256 e3Id,bytes32 cryptoConfigId,bytes32 finalizedCommitteeHash,uint256 lbfvConstantsVersion,uint256 ciphertextLevel,uint256 keyLevel,bytes32 proofSessionId,uint256 partyId,bytes32 publicKeyDocumentHash,bytes32 relinearizationKeyDocumentHash)",
        )
    }

    fn digest(&self) -> Result<B256> {
        self.context.validate()?;
        ensure!(
            self.public_key_document_hash != B256::ZERO,
            "l-BFV public-key document hash is zero"
        );
        ensure!(
            self.relinearization_key_document_hash != B256::ZERO,
            "l-BFV relinearization-key document hash is zero"
        );
        let domain = self.context.proof_domain;
        Ok(keccak256(
            (
                Self::typehash(),
                U256::from(domain.protocol_version),
                U256::from(domain.chain_id),
                domain.interfold_address,
                domain.e3_id,
                domain.crypto_config_id,
                domain.finalized_committee_hash,
                U256::from(domain.lbfv_constants_version),
                U256::from(domain.ciphertext_level),
                U256::from(domain.key_level),
                self.context.proof_session_id,
                U256::from(self.context.party_id),
                self.public_key_document_hash,
                self.relinearization_key_document_hash,
            )
                .abi_encode(),
        ))
    }
}

/// Versioned manifest payload.
///
/// Bincode encodes variants by order. Append new versions and do not reorder existing variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvKeyShareManifest {
    V1(LbfvKeyShareManifestV1),
}

impl LbfvKeyShareManifest {
    pub fn context(&self) -> &LbfvKeyShareDocumentContextV1 {
        match self {
            Self::V1(manifest) => &manifest.context,
        }
    }

    pub fn e3_id(&self) -> &E3id {
        &self.context().e3_id
    }

    fn digest(&self) -> Result<B256> {
        match self {
            Self::V1(manifest) => manifest.digest(),
        }
    }

    pub fn replay_key(&self) -> LbfvKeyShareManifestReplayKey {
        match self {
            Self::V1(manifest) => LbfvKeyShareManifestReplayKey::V1 {
                e3_id: manifest.context.e3_id.clone(),
                proof_session_id: manifest.context.proof_session_id,
                party_id: manifest.context.party_id,
            },
        }
    }
}

/// Stable key for duplicate and conflicting manifest detection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvKeyShareManifestReplayKey {
    V1 {
        e3_id: E3id,
        proof_session_id: B256,
        party_id: u32,
    },
}

/// Ethereum signature over a versioned l-BFV key-share manifest.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct SignedLbfvKeyShareManifest {
    pub payload: LbfvKeyShareManifest,
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub signature: ArcBytes,
}

impl SignedLbfvKeyShareManifest {
    pub fn sign(payload: LbfvKeyShareManifest, signer: &PrivateKeySigner) -> Result<Self> {
        let digest = payload.digest()?;
        let signature = signer
            .sign_message_sync(digest.as_slice())
            .map_err(|error| anyhow!("failed to sign l-BFV key-share manifest: {error}"))?;
        Ok(Self {
            payload,
            signature: ArcBytes::from_bytes(&signature.as_bytes()),
        })
    }

    pub fn recover_address(&self) -> Result<Address> {
        let signature = Signature::try_from(&self.signature[..])
            .map_err(|error| anyhow!("invalid l-BFV key-share manifest signature: {error}"))?;
        let digest = self.payload.digest()?;
        signature
            .recover_address_from_msg(digest.as_slice())
            .map_err(|error| anyhow!("failed to recover l-BFV key-share manifest signer: {error}"))
    }

    pub fn verify_signer(&self, expected: Address) -> Result<()> {
        ensure!(
            self.recover_address()? == expected,
            "l-BFV key-share manifest signer is not the expected committee party"
        );
        Ok(())
    }

    /// Authorize the signature against the canonical finalized committee and party slot.
    pub fn verify_committee_signer(&self, committee: &[Address]) -> Result<()> {
        ensure!(
            !committee.is_empty() && committee.windows(2).all(|pair| pair[0] < pair[1]),
            "l-BFV key-share manifest requires a strictly ordered committee"
        );
        ensure!(
            hash_committee_addresses(committee)
                == self.payload.context().proof_domain.finalized_committee_hash,
            "l-BFV key-share manifest committee does not match the proof domain"
        );
        let party_id = self.payload.context().party_id as usize;
        let expected = committee.get(party_id).ok_or_else(|| {
            anyhow!("l-BFV key-share manifest party ID is outside the finalized committee")
        })?;
        self.verify_signer(*expected)
    }

    /// Validate both exact DHT records and require one signer for the complete bundle.
    pub fn validate_documents(
        &self,
        public_key: &LbfvKeyShareDocument,
        relinearization_key: &LbfvKeyShareDocument,
    ) -> Result<()> {
        self.validate_documents_with_preset(public_key, relinearization_key, None)
    }

    /// Validate both records against the exact row count for one BFV preset.
    pub fn validate_documents_for_preset(
        &self,
        public_key: &LbfvKeyShareDocument,
        relinearization_key: &LbfvKeyShareDocument,
        preset: BfvPreset,
    ) -> Result<()> {
        self.validate_documents_with_preset(public_key, relinearization_key, Some(preset))
    }

    fn validate_documents_with_preset(
        &self,
        public_key: &LbfvKeyShareDocument,
        relinearization_key: &LbfvKeyShareDocument,
        preset: Option<BfvPreset>,
    ) -> Result<()> {
        let manifest_signer = self.recover_address()?;
        let LbfvKeyShareManifest::V1(manifest) = &self.payload;
        let (public_key_context, public_key_hash) = match public_key {
            LbfvKeyShareDocument::PublicKeyV1(document) => {
                (&document.context, public_key.content_hash()?)
            }
            LbfvKeyShareDocument::PublicKeyV2(document) => {
                (&document.context, public_key.content_hash()?)
            }
            _ => {
                return Err(anyhow!(
                    "l-BFV manifest public-key record has the wrong document type"
                ))
            }
        };
        let (relinearization_key_context, relinearization_key_hash) = match relinearization_key {
            LbfvKeyShareDocument::RelinearizationKeyV1(document) => {
                (&document.context, relinearization_key.content_hash()?)
            }
            LbfvKeyShareDocument::RelinearizationKeyV2(document) => {
                (&document.context, relinearization_key.content_hash()?)
            }
            _ => {
                return Err(anyhow!(
                    "l-BFV manifest relinearization-key record has the wrong document type"
                ))
            }
        };

        ensure!(
            public_key_context == &manifest.context
                && relinearization_key_context == &manifest.context,
            "l-BFV manifest and document contexts do not match"
        );
        ensure!(
            public_key_hash == manifest.public_key_document_hash,
            "l-BFV public-key document hash does not match the manifest"
        );
        ensure!(
            relinearization_key_hash == manifest.relinearization_key_document_hash,
            "l-BFV relinearization-key document hash does not match the manifest"
        );
        let public_key_signer = match preset {
            Some(preset) => public_key.validate_for_preset(preset)?,
            None => public_key.validate()?,
        };
        let relinearization_key_signer = match preset {
            Some(preset) => relinearization_key.validate_for_preset(preset)?,
            None => relinearization_key.validate()?,
        };
        ensure!(
            public_key_signer == manifest_signer && relinearization_key_signer == manifest_signer,
            "l-BFV manifest and proof bundles have different signers"
        );
        Ok(())
    }
}

/// Local request to publish one versioned l-BFV key-share document to the DHT.
#[derive(Message, Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[derivative(Debug)]
pub struct LbfvKeyShareDocumentCreated {
    #[derivative(Debug = "ignore")]
    pub document: LbfvKeyShareDocument,
}

impl LbfvKeyShareDocumentCreated {
    pub fn e3_id(&self) -> &E3id {
        self.document.e3_id()
    }
}

/// Version 1 identity for one targeted l-BFV DHT fetch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvKeyShareDocumentFetchRequestedV1 {
    pub e3_id: E3id,
    pub proof_session_id: B256,
    pub party_id: u32,
    pub role: LbfvKeyShareDocumentRole,
    pub content_hash: B256,
    pub attempt: u32,
}

/// Targeted request for one l-BFV DHT document.
///
/// Bincode encodes variants by order. Append new versions and do not reorder existing variants.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub enum LbfvKeyShareDocumentFetchRequested {
    V1(LbfvKeyShareDocumentFetchRequestedV1),
}

impl LbfvKeyShareDocumentFetchRequested {
    pub fn request(&self) -> &LbfvKeyShareDocumentFetchRequestedV1 {
        match self {
            Self::V1(request) => request,
        }
    }

    pub fn e3_id(&self) -> &E3id {
        &self.request().e3_id
    }
}

/// Stable classification for a targeted l-BFV DHT fetch failure.
///
/// Bincode encodes variants by order. Append new classes and do not reorder existing variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvKeyShareDocumentFetchFailureClass {
    Unavailable,
    InvalidData,
}

/// Version 1 result identity for a failed targeted l-BFV DHT fetch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvKeyShareDocumentFetchFailedV1 {
    pub e3_id: E3id,
    pub proof_session_id: B256,
    pub party_id: u32,
    pub role: LbfvKeyShareDocumentRole,
    pub content_hash: B256,
    pub attempt: u32,
    pub failure_class: LbfvKeyShareDocumentFetchFailureClass,
    /// Absolute Unix time in seconds for a permitted retry. `None` means that retry cannot repair
    /// the failure.
    pub retry_at: Option<u64>,
}

/// Typed failure from one targeted l-BFV DHT fetch.
///
/// Bincode encodes variants by order. Append new versions and do not reorder existing variants.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub enum LbfvKeyShareDocumentFetchFailed {
    V1(LbfvKeyShareDocumentFetchFailedV1),
}

impl LbfvKeyShareDocumentFetchFailed {
    pub fn failure(&self) -> &LbfvKeyShareDocumentFetchFailedV1 {
        match self {
            Self::V1(failure) => failure,
        }
    }

    pub fn e3_id(&self) -> &E3id {
        &self.failure().e3_id
    }
}

/// One validated l-BFV key-share document received from the DHT.
#[derive(Message, Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[derivative(Debug)]
pub struct LbfvKeyShareDocumentReceived {
    #[derivative(Debug = "ignore")]
    pub document: LbfvKeyShareDocument,
    pub content_hash: B256,
}

impl LbfvKeyShareDocumentReceived {
    pub fn e3_id(&self) -> &E3id {
        self.document.e3_id()
    }
}

/// Compact signed reference to one party's PK and RLK DHT documents.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct LbfvKeyShareManifestPublished {
    pub manifest: SignedLbfvKeyShareManifest,
}

impl LbfvKeyShareManifestPublished {
    pub fn e3_id(&self) -> &E3id {
        self.manifest.payload.e3_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventId, InterfoldEventData, Proof, ProofPayload};

    fn signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn context() -> LbfvKeyShareDocumentContextV1 {
        let e3_id = E3id::new("7", 31_337);
        let proof_domain = LbfvProofDomainContext {
            protocol_version: 4,
            chain_id: e3_id.chain_id(),
            interfold_address: Address::repeat_byte(0x11),
            e3_id: U256::from(7),
            crypto_config_id: B256::repeat_byte(0x22),
            finalized_committee_hash: hash_committee_addresses(&committee()),
            lbfv_constants_version: 1,
            ciphertext_level: 0,
            key_level: 0,
        };
        LbfvKeyShareDocumentContextV1 {
            e3_id,
            proof_domain,
            proof_session_id: hash_lbfv_proof_session(proof_domain),
            party_id: 1,
        }
    }

    fn committee() -> [Address; 2] {
        [Address::ZERO, signer().address()]
    }

    fn signed_proof(
        context: &LbfvKeyShareDocumentContextV1,
        proof_type: ProofType,
        row: u32,
        signer: &PrivateKeySigner,
    ) -> SignedProofPayload {
        let circuit = proof_type.circuit_names()[0];
        let public_signals = if proof_type.is_multirow() {
            let layout = circuit.input_layout();
            let session = split_hash_to_field_limbs(context.proof_session_id);
            let field_count =
                layout.field_count().unwrap() + circuit.output_layout().field_count().unwrap();
            let mut signals = vec![0u8; field_count * FIELD_BYTE_LEN];
            let session_hi = layout.field_index("session_id_hi").unwrap();
            signals[session_hi * 32 + 16..session_hi * 32 + 32]
                .copy_from_slice(&session.hi.to_be_bytes());
            let session_lo = layout.field_index("session_id_lo").unwrap();
            signals[session_lo * 32 + 16..session_lo * 32 + 32]
                .copy_from_slice(&session.lo.to_be_bytes());
            let party_id = layout.field_index("party_id").unwrap();
            signals[party_id * 32 + 28..party_id * 32 + 32]
                .copy_from_slice(&context.party_id.to_be_bytes());
            let row_index = layout.field_index("row_index").unwrap();
            signals[row_index * 32 + 28..row_index * 32 + 32].copy_from_slice(&row.to_be_bytes());
            signals
        } else {
            vec![0; circuit.output_layout().field_count().unwrap() * FIELD_BYTE_LEN]
        };
        SignedProofPayload::sign(
            ProofPayload {
                e3_id: context.e3_id.clone(),
                proof_type,
                proof: Proof::new(
                    circuit,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&public_signals),
                ),
            },
            signer,
        )
        .unwrap()
    }

    fn documents() -> (PrivateKeySigner, LbfvKeyShareDocument, LbfvKeyShareDocument) {
        let signer = signer();
        let context = context();
        let public_key = LbfvKeyShareDocument::PublicKeyV1(LbfvPublicKeyShareDocumentV1 {
            context: context.clone(),
            share: ArcBytes::from_bytes(b"public key share"),
            signed_c1_proof: signed_proof(&context, ProofType::C1PkGeneration, 0, &signer),
            signed_row_proofs: std::array::from_fn(|row| {
                signed_proof(&context, ProofType::LbfvPkGeneration, row as u32, &signer)
            }),
        });
        let relinearization_key =
            LbfvKeyShareDocument::RelinearizationKeyV1(LbfvRelinearizationKeyShareDocumentV1 {
                context,
                share: ArcBytes::from_bytes(b"relinearization key share"),
                signed_row_proofs: std::array::from_fn(|row| {
                    signed_proof(
                        public_key.context(),
                        ProofType::RlkGeneration,
                        row as u32,
                        &signer,
                    )
                }),
            });
        (signer, public_key, relinearization_key)
    }

    fn dynamic_public_key_document(row_count: usize) -> LbfvKeyShareDocument {
        let signer = signer();
        let context = context();
        LbfvKeyShareDocument::PublicKeyV2(LbfvPublicKeyShareDocumentV2 {
            context: context.clone(),
            share: ArcBytes::from_bytes(b"dynamic public key share"),
            signed_c1_proof: signed_proof(&context, ProofType::C1PkGeneration, 0, &signer),
            signed_row_proofs: (0..row_count)
                .map(|row| signed_proof(&context, ProofType::LbfvPkGeneration, row as u32, &signer))
                .collect(),
        })
    }

    fn signed_manifest(
        signer: &PrivateKeySigner,
        public_key: &LbfvKeyShareDocument,
        relinearization_key: &LbfvKeyShareDocument,
    ) -> SignedLbfvKeyShareManifest {
        SignedLbfvKeyShareManifest::sign(
            LbfvKeyShareManifest::V1(LbfvKeyShareManifestV1 {
                context: public_key.context().clone(),
                public_key_document_hash: public_key.content_hash().unwrap(),
                relinearization_key_document_hash: relinearization_key.content_hash().unwrap(),
            }),
            signer,
        )
        .unwrap()
    }

    #[test]
    fn document_variants_have_append_only_bincode_discriminants() {
        let (signer, public_key, relinearization_key) = documents();
        assert_eq!(&public_key.to_bytes().unwrap()[..4], &[0, 0, 0, 0]);
        assert_eq!(&relinearization_key.to_bytes().unwrap()[..4], &[1, 0, 0, 0]);
        let manifest = signed_manifest(&signer, &public_key, &relinearization_key);
        assert_eq!(
            &bincode::serialize(&manifest.payload).unwrap()[..4],
            &[0, 0, 0, 0]
        );
    }

    #[test]
    fn signed_manifest_binds_documents_and_authorizes_signer() {
        let (signer, public_key, relinearization_key) = documents();
        let manifest = signed_manifest(&signer, &public_key, &relinearization_key);

        manifest
            .validate_documents(&public_key, &relinearization_key)
            .unwrap();
        manifest.verify_signer(signer.address()).unwrap();
        manifest.verify_committee_signer(&committee()).unwrap();
        assert!(manifest.verify_signer(Address::ZERO).is_err());
        assert!(manifest
            .verify_committee_signer(&[signer.address(), Address::ZERO])
            .is_err());
        assert_eq!(
            manifest.payload.replay_key(),
            LbfvKeyShareManifestReplayKey::V1 {
                e3_id: context().e3_id,
                proof_session_id: context().proof_session_id,
                party_id: 1,
            }
        );
    }

    #[test]
    fn signed_manifest_rejects_changed_document_bytes() {
        let (signer, public_key, relinearization_key) = documents();
        let manifest = signed_manifest(&signer, &public_key, &relinearization_key);
        let LbfvKeyShareDocument::PublicKeyV1(mut changed) = public_key else {
            unreachable!();
        };
        changed.share = ArcBytes::from_bytes(b"different public key share");

        assert!(manifest
            .validate_documents(
                &LbfvKeyShareDocument::PublicKeyV1(changed),
                &relinearization_key,
            )
            .unwrap_err()
            .to_string()
            .contains("document hash"));
    }

    #[test]
    fn document_rejects_reordered_row_proof() {
        let (_, public_key, _) = documents();
        let LbfvKeyShareDocument::PublicKeyV1(mut changed) = public_key else {
            unreachable!();
        };
        changed.signed_row_proofs.swap(0, 1);

        assert!(LbfvKeyShareDocument::PublicKeyV1(changed)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("document position"));
    }

    #[test]
    fn dynamic_document_requires_a_supported_and_matching_row_count() {
        let insecure = dynamic_public_key_document(3);
        insecure.validate().unwrap();
        insecure
            .validate_for_preset(BfvPreset::InsecureThreshold512)
            .unwrap();
        assert!(insecure
            .validate_for_preset(BfvPreset::SecureThreshold16384)
            .is_err());

        let secure = dynamic_public_key_document(5);
        secure.validate().unwrap();
        secure
            .validate_for_preset(BfvPreset::SecureThreshold16384)
            .unwrap();
        assert!(secure
            .validate_for_preset(BfvPreset::InsecureThreshold512)
            .is_err());

        assert!(dynamic_public_key_document(4).validate().is_err());
    }

    #[test]
    fn proof_identity_rejects_a_row_outside_the_selected_preset() {
        let context = context();
        let signed = signed_proof(&context, ProofType::LbfvPkGeneration, 3, &signer());
        assert!(signed
            .payload
            .proof_type
            .identity(&signed.payload.proof, Some(3))
            .is_err());
        assert_eq!(
            signed
                .payload
                .proof_type
                .identity(&signed.payload.proof, Some(5))
                .unwrap()
                .instance,
            3
        );
    }

    #[test]
    fn document_rejects_relabelled_proof_context_and_shape() {
        let (signer, public_key, _) = documents();
        let LbfvKeyShareDocument::PublicKeyV1(mut wrong_party) = public_key else {
            unreachable!();
        };
        let mut proof_context = wrong_party.context.clone();
        proof_context.party_id = 0;
        wrong_party.signed_row_proofs[0] =
            signed_proof(&proof_context, ProofType::LbfvPkGeneration, 0, &signer);
        assert!(LbfvKeyShareDocument::PublicKeyV1(wrong_party)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("party ID"));

        let (_, public_key, _) = documents();
        let LbfvKeyShareDocument::PublicKeyV1(mut wrong_session) = public_key else {
            unreachable!();
        };
        let mut proof_context = wrong_session.context.clone();
        proof_context.proof_session_id = B256::repeat_byte(0x99);
        wrong_session.signed_row_proofs[0] =
            signed_proof(&proof_context, ProofType::LbfvPkGeneration, 0, &signer);
        assert!(LbfvKeyShareDocument::PublicKeyV1(wrong_session)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("proof session"));

        let (_, public_key, _) = documents();
        let LbfvKeyShareDocument::PublicKeyV1(mut wrong_shape) = public_key else {
            unreachable!();
        };
        let mut payload = wrong_shape.signed_row_proofs[0].payload.clone();
        let shortened = &payload.proof.public_signals[..payload.proof.public_signals.len() - 32];
        payload.proof.public_signals = ArcBytes::from_bytes(shortened);
        wrong_shape.signed_row_proofs[0] = SignedProofPayload::sign(payload, &signer).unwrap();
        assert!(LbfvKeyShareDocument::PublicKeyV1(wrong_shape)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("public shape"));
    }

    #[test]
    fn context_rejects_a_session_from_another_domain() {
        let mut context = context();
        context.proof_domain.crypto_config_id = B256::repeat_byte(0x44);
        assert!(context.validate().is_err());
    }

    #[test]
    fn fetch_event_variants_append_without_changing_lbfv_ordinals() {
        let (signer, public_key, relinearization_key) = documents();
        let manifest = signed_manifest(&signer, &public_key, &relinearization_key);
        let request =
            LbfvKeyShareDocumentFetchRequested::V1(LbfvKeyShareDocumentFetchRequestedV1 {
                e3_id: public_key.e3_id().clone(),
                proof_session_id: public_key.context().proof_session_id,
                party_id: public_key.context().party_id,
                role: LbfvKeyShareDocumentRole::PublicKey,
                content_hash: public_key.content_hash().unwrap(),
                attempt: 1,
            });
        let failure = LbfvKeyShareDocumentFetchFailed::V1(LbfvKeyShareDocumentFetchFailedV1 {
            e3_id: request.e3_id().clone(),
            proof_session_id: request.request().proof_session_id,
            party_id: request.request().party_id,
            role: request.request().role,
            content_hash: request.request().content_hash,
            attempt: request.request().attempt,
            failure_class: LbfvKeyShareDocumentFetchFailureClass::Unavailable,
            retry_at: Some(100),
        });
        let payloads = [
            (
                InterfoldEventData::from(LbfvKeyShareDocumentCreated {
                    document: public_key.clone(),
                }),
                87u32,
            ),
            (
                InterfoldEventData::from(LbfvKeyShareDocumentReceived {
                    document: public_key,
                    content_hash: request.request().content_hash,
                }),
                88,
            ),
            (
                InterfoldEventData::from(LbfvKeyShareManifestPublished { manifest }),
                89,
            ),
            (InterfoldEventData::from(request), 90),
            (InterfoldEventData::from(failure), 91),
        ];

        for (payload, expected) in payloads {
            assert_eq!(
                &bincode::serialize(&payload).unwrap()[..4],
                &expected.to_le_bytes()
            );
        }
    }

    #[test]
    fn targeted_fetch_event_id_changes_with_attempt() {
        let (_, public_key, _) = documents();
        let request = |attempt| {
            InterfoldEventData::from(LbfvKeyShareDocumentFetchRequested::V1(
                LbfvKeyShareDocumentFetchRequestedV1 {
                    e3_id: public_key.e3_id().clone(),
                    proof_session_id: public_key.context().proof_session_id,
                    party_id: public_key.context().party_id,
                    role: public_key.role(),
                    content_hash: public_key.content_hash().unwrap(),
                    attempt,
                },
            ))
        };

        assert_ne!(EventId::hash(request(1)), EventId::hash(request(2)));
    }
}
