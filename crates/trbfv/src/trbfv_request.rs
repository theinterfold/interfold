// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::lbfv_operation::LbfvOperationId;
use crate::{
    calculate_decryption_key::{CalculateDecryptionKeyRequest, CalculateDecryptionKeyResponse},
    calculate_decryption_share::{
        CalculateDecryptionShareRequest, CalculateDecryptionShareResponse,
    },
    calculate_threshold_decryption::{
        CalculateThresholdDecryptionRequest, CalculateThresholdDecryptionResponse,
    },
    gen_esi_sss::{GenEsiSssRequest, GenEsiSssResponse},
    gen_lbfv_key_shares::{GenLbfvKeySharesRequest, GenLbfvKeySharesResponse},
    gen_pk_share_and_sk_sss::{GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse},
};
use core::fmt;
use serde::{Deserialize, Serialize};

// NOTE: All size values use u64 instead of usize to maintain a stable
// protocol that works across different architectures. Convert these
// u64 values to usize when entering the library's internal APIs.

/// Input format for TrBFVRequest.
///
/// Bincode encodes this enum by variant order. Add new variants at the end.
/// Keep existing variants and payloads unchanged for compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrBFVRequest {
    GenEsiSss(GenEsiSssRequest),
    GenPkShareAndSkSss(GenPkShareAndSkSssRequest),
    CalculateDecryptionKey(CalculateDecryptionKeyRequest),
    CalculateDecryptionShare(CalculateDecryptionShareRequest),
    CalculateThresholdDecryption(CalculateThresholdDecryptionRequest),
    GenLbfvKeyShares(GenLbfvKeySharesRequest),
}

impl TrBFVRequest {
    /// Return the stable identity for an l-BFV request.
    pub fn lbfv_operation_id(&self) -> Option<LbfvOperationId> {
        match self {
            Self::GenLbfvKeyShares(request) => request
                .validate_operation_id()
                .is_ok()
                .then_some(request.operation_id),
            _ => None,
        }
    }
}

/// Result format for TrBFVResponse.
///
/// Bincode encodes this enum by variant order. Add new variants at the end.
/// Keep existing variants and payloads unchanged for compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrBFVResponse {
    GenEsiSss(GenEsiSssResponse),
    GenPkShareAndSkSss(GenPkShareAndSkSssResponse),
    CalculateDecryptionKey(CalculateDecryptionKeyResponse),
    CalculateDecryptionShare(CalculateDecryptionShareResponse),
    CalculateThresholdDecryption(CalculateThresholdDecryptionResponse),
    GenLbfvKeyShares(GenLbfvKeySharesResponse),
}

impl TrBFVResponse {
    /// Return the stable identity for an l-BFV response.
    pub fn lbfv_operation_id(&self) -> Option<LbfvOperationId> {
        match self {
            Self::GenLbfvKeyShares(response) => Some(response.operation_id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrBFVError {
    GenEsiSss(TrBFVFailure),
    GenPkShareAndSkSss(TrBFVFailure),
    CalculateDecryptionKey(TrBFVFailure),
    CalculateDecryptionShare(TrBFVFailure),
    CalculateThresholdDecryption(TrBFVFailure),
    GenLbfvKeyShares(TrBFVFailure),
}

impl TrBFVError {
    /// The structured failure payload, regardless of which operation failed.
    pub fn failure(&self) -> &TrBFVFailure {
        match self {
            TrBFVError::GenEsiSss(f)
            | TrBFVError::GenPkShareAndSkSss(f)
            | TrBFVError::CalculateDecryptionKey(f)
            | TrBFVError::CalculateDecryptionShare(f)
            | TrBFVError::CalculateThresholdDecryption(f)
            | TrBFVError::GenLbfvKeyShares(f) => f,
        }
    }
}

impl std::error::Error for TrBFVError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl fmt::Display for TrBFVError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrBFVError::GenEsiSss(d) => write!(f, "GenEsiSss: {d}"),
            TrBFVError::GenPkShareAndSkSss(d) => write!(f, "GenPkShareAndSkSss: {d}"),
            TrBFVError::CalculateDecryptionKey(d) => write!(f, "CalculateDecryptionKey: {d}"),
            TrBFVError::CalculateDecryptionShare(d) => write!(f, "CalculateDecryptionShare: {d}"),
            TrBFVError::CalculateThresholdDecryption(d) => {
                write!(f, "CalculateThresholdDecryption: {d}")
            }
            TrBFVError::GenLbfvKeyShares(d) => write!(f, "GenLbfvKeyShares: {d}"),
        }
    }
}

/// Payload carried by every [`TrBFVError`] variant.
///
/// Always holds the human-readable `message`. When the underlying failure is a structured
/// threshold-BFV error from fhe.rs (`fhe::Error::Threshold(..)`), `threshold` is populated so
/// callers can react to a specific failure mode — including the implicated party — instead of
/// parsing `message`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrBFVFailure {
    pub message: String,
    pub threshold: Option<ThresholdFailure>,
}

impl TrBFVFailure {
    /// Build from an `anyhow` error, extracting a [`ThresholdFailure`] if a
    /// `fhe::Error::Threshold(..)` is anywhere in the error chain.
    pub fn from_error(err: &anyhow::Error) -> Self {
        Self {
            message: err.to_string(),
            threshold: ThresholdFailure::from_anyhow(err),
        }
    }
}

impl From<String> for TrBFVFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            threshold: None,
        }
    }
}

impl From<&str> for TrBFVFailure {
    fn from(message: &str) -> Self {
        Self::from(message.to_string())
    }
}

impl fmt::Display for TrBFVFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.threshold {
            Some(t) => write!(f, "{} ({t})", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

/// Structured detail extracted from a fhe.rs `ThresholdError`.
///
/// `party_id` identifies the implicated party when the underlying variant carries one. Note
/// the index space depends on the operation: for decryption-share reconstruction
/// (`decrypt_from_shares`) it is the 1-based Shamir party id; for share aggregation
/// (`aggregate_secret_key_shares`) it is the 0-based index into the collected-shares vector,
/// i.e. collection order. Callers attributing blame must map it accordingly.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdFailure {
    pub kind: ThresholdFailureKind,
    pub party_id: Option<usize>,
    pub message: String,
}

/// Mirror of fhe.rs `ThresholdError` variants, kept matchable across the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThresholdFailureKind {
    InvalidPartyId,
    InvalidPartyCount,
    DuplicatePartyId,
    InvalidThreshold,
    ShareCountMismatch,
    MalformedShares,
    NonInvertibleShares,
    SmudgingBoundInfeasible,
    PartyCountExceedsModulus,
}

impl ThresholdFailure {
    /// Find a `fhe::Error::Threshold(..)` anywhere in an `anyhow` error chain.
    pub fn from_anyhow(err: &anyhow::Error) -> Option<Self> {
        err.chain()
            .find_map(|e| e.downcast_ref::<fhe::Error>())
            .and_then(Self::from_fhe_error)
    }

    /// Extract from a `fhe::Error`, returning `None` for non-threshold errors.
    pub fn from_fhe_error(err: &fhe::Error) -> Option<Self> {
        match err {
            fhe::Error::Threshold(t) => Some(Self::from_threshold(t)),
            _ => None,
        }
    }

    fn from_threshold(t: &fhe::ThresholdError) -> Self {
        use fhe::ThresholdError as TE;
        use ThresholdFailureKind as K;
        // Exhaustive (ThresholdError is not #[non_exhaustive]) so new fhe.rs variants force an
        // explicit decision here rather than silently degrading to an unattributed failure.
        let (kind, party_id) = match t {
            TE::InvalidPartyId { party_id, .. } => (K::InvalidPartyId, Some(*party_id)),
            TE::InvalidPartyCount { .. } => (K::InvalidPartyCount, None),
            TE::DuplicatePartyId { party_id } => (K::DuplicatePartyId, Some(*party_id)),
            TE::MalformedShares { party_id, .. } => (K::MalformedShares, Some(*party_id)),
            TE::InvalidThreshold { .. } => (K::InvalidThreshold, None),
            TE::ShareCountMismatch { .. } => (K::ShareCountMismatch, None),
            TE::NonInvertibleShares => (K::NonInvertibleShares, None),
            TE::SmudgingBoundInfeasible { .. } => (K::SmudgingBoundInfeasible, None),
            TE::PartyCountExceedsModulus { .. } => (K::PartyCountExceedsModulus, None),
            TE::InvalidShamirThreshold { .. } => (K::InvalidThreshold, None),
            TE::EmptyBatchInversion => (K::NonInvertibleShares, None),
        };
        Self {
            kind,
            party_id,
            message: t.to_string(),
        }
    }
}

impl fmt::Display for ThresholdFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.party_id {
            Some(party_id) => write!(f, "{:?} [party {party_id}]: {}", self.kind, self.message),
            None => write!(f, "{:?}: {}", self.kind, self.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gen_esi_sss::GenEsiSssResponse,
        gen_lbfv_key_shares::{
            EncryptedRlkWitness, GenLbfvKeySharesRequest, GenLbfvKeySharesResponse,
        },
        TrBFVConfig,
    };
    use e3_crypto::SensitiveBytes;
    use e3_fhe_params::BfvPreset;
    use e3_utils::ArcBytes;

    fn operation_id() -> LbfvOperationId {
        LbfvOperationId([7; 32])
    }

    #[test]
    fn legacy_request_and_response_layouts_are_unchanged() {
        const LEGACY_REQUEST: &[u8] = &[
            0, 0, 0, 0, // TrBFVRequest::GenEsiSss
            0, 0, 0, 0, 0, 0, 0, 0, // empty parameter bytes
            3, 0, 0, 0, 0, 0, 0, 0, // num_parties
            1, 0, 0, 0, 0, 0, 0, 0, // threshold
            0, 0, 0, 0, 0, 0, 0, 0, // empty encrypted e_sm bytes
        ];
        const LEGACY_RESPONSE: &[u8] = &[
            0, 0, 0, 0, // TrBFVResponse::GenEsiSss
            0, 0, 0, 0, 0, 0, 0, 0, // empty esi_sss vector
        ];
        let request = TrBFVRequest::GenEsiSss(GenEsiSssRequest {
            trbfv_config: TrBFVConfig::new(ArcBytes::from_bytes(&[]), 3, 1),
            e_sm_raw: SensitiveBytes::from_encrypted(&[]),
        });
        let response = TrBFVResponse::GenEsiSss(GenEsiSssResponse {
            esi_sss: Vec::new(),
        });

        assert_eq!(bincode::serialize(&request).unwrap(), LEGACY_REQUEST);
        assert_eq!(
            bincode::deserialize::<TrBFVRequest>(LEGACY_REQUEST).unwrap(),
            request
        );
        assert_eq!(bincode::serialize(&response).unwrap(), LEGACY_RESPONSE);
        assert_eq!(
            bincode::deserialize::<TrBFVResponse>(LEGACY_RESPONSE).unwrap(),
            response
        );
    }

    #[test]
    fn lbfv_variants_are_appended_and_round_trip() {
        let request = TrBFVRequest::GenLbfvKeyShares(GenLbfvKeySharesRequest {
            operation_id: operation_id(),
            session_id: [1; 32],
            party_id: 0,
            secret_key_bytes: SensitiveBytes::from_encrypted(&[1]),
            generation_seed: SensitiveBytes::from_encrypted(&[8]),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        });
        let response = TrBFVResponse::GenLbfvKeyShares(GenLbfvKeySharesResponse {
            operation_id: operation_id(),
            public_key_share_bytes: ArcBytes::from_bytes(&[2]),
            rlk_share_bytes: ArcBytes::from_bytes(&[3]),
            witness: EncryptedRlkWitness {
                r_bytes: SensitiveBytes::from_encrypted(&[4]),
                errors_d0_bytes: vec![SensitiveBytes::from_encrypted(&[5]); 5],
                errors_d2_bytes: vec![SensitiveBytes::from_encrypted(&[6]); 5],
            },
        });
        let error = TrBFVError::GenLbfvKeyShares(TrBFVFailure::from("failure"));

        for encoded in [
            bincode::serialize(&request).unwrap(),
            bincode::serialize(&response).unwrap(),
            bincode::serialize(&error).unwrap(),
        ] {
            assert_eq!(&encoded[..4], &5u32.to_le_bytes());
        }
        assert_eq!(
            bincode::deserialize::<TrBFVRequest>(&bincode::serialize(&request).unwrap()).unwrap(),
            request
        );
        assert_eq!(
            bincode::deserialize::<TrBFVResponse>(&bincode::serialize(&response).unwrap()).unwrap(),
            response
        );
        assert_eq!(
            bincode::deserialize::<TrBFVError>(&bincode::serialize(&error).unwrap()).unwrap(),
            error
        );
    }

    #[test]
    fn lbfv_debug_omits_secret_and_witness_fields() {
        let request = TrBFVRequest::GenLbfvKeyShares(GenLbfvKeySharesRequest {
            operation_id: operation_id(),
            session_id: [1; 32],
            party_id: 0,
            secret_key_bytes: SensitiveBytes::from_encrypted(b"secret-key"),
            generation_seed: SensitiveBytes::from_encrypted(b"generation-seed"),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        });
        let response = TrBFVResponse::GenLbfvKeyShares(GenLbfvKeySharesResponse {
            operation_id: operation_id(),
            public_key_share_bytes: ArcBytes::from_bytes(&[]),
            rlk_share_bytes: ArcBytes::from_bytes(&[]),
            witness: EncryptedRlkWitness {
                r_bytes: SensitiveBytes::from_encrypted(b"r-secret"),
                errors_d0_bytes: vec![SensitiveBytes::from_encrypted(b"d0-secret")],
                errors_d2_bytes: vec![SensitiveBytes::from_encrypted(b"d2-secret")],
            },
        });

        let debug = format!("{request:?} {response:?}");
        for field in [
            "secret_key_bytes",
            "generation_seed",
            "witness",
            "r_bytes",
            "errors_d0_bytes",
            "errors_d2_bytes",
            "secret",
        ] {
            assert!(!debug.contains(field));
        }
    }

    #[test]
    fn extracts_malformed_shares_party_id_from_anyhow_chain() {
        // A malformed-shares error wrapped with context (as the handlers do) must still be
        // recognized and attributed to the offending party.
        let fhe_err = fhe::Error::malformed_shares(2, "bad shape".to_string());
        let wrapped = anyhow::Error::new(fhe_err).context("Failed to aggregate es_sss");

        let failure = TrBFVFailure::from_error(&wrapped);
        let threshold = failure
            .threshold
            .expect("threshold detail should be extracted");
        assert_eq!(threshold.kind, ThresholdFailureKind::MalformedShares);
        assert_eq!(threshold.party_id, Some(2));
    }

    #[test]
    fn non_threshold_errors_have_no_structured_detail() {
        let err = anyhow::anyhow!("some unrelated failure");
        let failure = TrBFVFailure::from_error(&err);
        assert!(failure.threshold.is_none());
        assert_eq!(failure.message, "some unrelated failure");
    }
}
