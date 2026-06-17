// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of `Interfold.sol` logs into `InterfoldEventData`.

use crate::contracts::IInterfold;
use alloy::primitives::{LogData, B256};
use alloy::sol_types::SolEvent;
use e3_events::E3id;
use e3_events::InterfoldEventData;
use e3_events::{E3Failed, E3Stage, E3StageChanged, FailureReason};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset};
use e3_trbfv::helpers::calculate_error_size;
use e3_utils::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use num_bigint::BigUint;
use tracing::{error, info, trace, warn};

struct E3RequestedWithChainId(pub IInterfold::E3Requested, pub u64);

impl E3RequestedWithChainId {
    fn try_into_e3_requested(self) -> anyhow::Result<e3_events::E3Requested> {
        // Derive threshold values from committee size enum
        let committee_size = match self.0.e3.committeeSize {
            0 => CiphernodesCommitteeSize::Minimum,
            1 => CiphernodesCommitteeSize::Micro,
            2 => CiphernodesCommitteeSize::Small,
            other => anyhow::bail!(
                "Unsupported committee size enum value {} — this node's binary does not recognize \
                 it (likely a version skew with the on-chain contracts). Upgrade the ciphernode to \
                 a version that supports this committee size.",
                other
            ),
        };
        let committee = committee_size.values();
        let threshold_m = committee.threshold;
        let threshold_n = committee.n;

        // Map on-chain ParamSet enum to BfvPreset
        let param_set_value = self.0.e3.paramSet;
        let params_preset = BfvPreset::from_on_chain_param_set(param_set_value).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown ParamSet enum value {} — this node's binary does not recognize this BFV \
                 preset (likely a version skew with the on-chain contracts). Upgrade the ciphernode \
                 to a version that supports this preset.",
                param_set_value
            )
        })?;

        // Build BFV parameters from the preset
        let params_arc = BfvParamSet::from(params_preset).build_arc();
        let params_bytes = encode_bfv_params(&params_arc);

        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = params_preset
            .lambda()
            .map_err(|e| anyhow::anyhow!("Failed to build lambda for preset: {}", e))?;
        let lambda_value = lambda.value();

        let error_size = match calculate_error_size(params_arc, threshold_n, threshold_m, lambda) {
            Ok(size) => {
                let size_bytes = size.to_bytes_be();
                info!(
                    "Calculated error_size for E3 (threshold_n={}, threshold_m={}, lambda={}): {} bytes",
                    threshold_n, threshold_m, lambda_value, size_bytes.len()
                );
                ArcBytes::from_bytes(&size_bytes)
            }
            Err(e) => {
                warn!(
                    "Failed to calculate error_size, using fallback: {}. \
                    This may cause decryption failures!",
                    e
                );
                ArcBytes::from_bytes(
                    &BigUint::from(36128399948547143872891754381312u128).to_bytes_be(),
                )
            }
        };

        Ok(e3_events::E3Requested {
            params_preset,
            params: ArcBytes::from_bytes(&params_bytes),
            threshold_m,
            threshold_n,
            seed: self.0.e3.seed.into(),
            error_size,
            e3_id: E3id::new(self.0.e3Id.to_string(), self.1),
            proof_aggregation_enabled: self.0.e3.proofAggregationEnabled,
        })
    }
}

struct CiphertextOutputPublishedWithChainId(pub IInterfold::CiphertextOutputPublished, pub u64);

impl From<CiphertextOutputPublishedWithChainId> for e3_events::CiphertextOutputPublished {
    fn from(value: CiphertextOutputPublishedWithChainId) -> Self {
        e3_events::CiphertextOutputPublished {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            // XXX: Ciphertext is an array of bytes this needs to be coordinated with interfold
            // contract
            ciphertext_output: vec![ArcBytes::from_bytes(value.0.ciphertextOutput.as_ref())],
        }
    }
}

impl From<CiphertextOutputPublishedWithChainId> for InterfoldEventData {
    fn from(value: CiphertextOutputPublishedWithChainId) -> Self {
        let payload: e3_events::CiphertextOutputPublished = value.into();
        payload.into()
    }
}

struct E3FailedWithChainId(pub IInterfold::E3Failed, pub u64);

fn convert_u8_to_e3_stage(stage_u8: u8) -> E3Stage {
    match stage_u8 {
        0 => E3Stage::None,
        1 => E3Stage::Requested,
        2 => E3Stage::CommitteeFinalized,
        3 => E3Stage::KeyPublished,
        4 => E3Stage::CiphertextReady,
        5 => E3Stage::Complete,
        6 => E3Stage::Failed,
        _ => E3Stage::None,
    }
}

// Helper function to convert u8 to Rust FailureReason
fn convert_u8_to_failure_reason(reason_u8: u8) -> FailureReason {
    match reason_u8 {
        0 => FailureReason::None,
        1 => FailureReason::CommitteeFormationTimeout,
        2 => FailureReason::InsufficientCommitteeMembers,
        3 => FailureReason::DKGTimeout,
        4 => FailureReason::DKGInvalidShares,
        5 => FailureReason::NoInputsReceived,
        6 => FailureReason::ComputeTimeout,
        7 => FailureReason::ComputeProviderExpired,
        8 => FailureReason::ComputeProviderFailed,
        9 => FailureReason::RequesterCancelled,
        10 => FailureReason::DecryptionTimeout,
        11 => FailureReason::DecryptionInvalidShares,
        12 => FailureReason::VerificationFailed,
        _ => FailureReason::None,
    }
}

impl From<E3FailedWithChainId> for E3Failed {
    fn from(value: E3FailedWithChainId) -> Self {
        E3Failed {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            failed_at_stage: convert_u8_to_e3_stage(value.0.failedAtStage),
            reason: convert_u8_to_failure_reason(value.0.reason),
        }
    }
}

impl From<E3FailedWithChainId> for InterfoldEventData {
    fn from(value: E3FailedWithChainId) -> Self {
        let payload: E3Failed = value.into();
        payload.into()
    }
}

struct E3StageChangedWithChainId(pub IInterfold::E3StageChanged, pub u64);

impl From<E3StageChangedWithChainId> for E3StageChanged {
    fn from(value: E3StageChangedWithChainId) -> Self {
        E3StageChanged {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            previous_stage: convert_u8_to_e3_stage(value.0.previousStage),
            new_stage: convert_u8_to_e3_stage(value.0.newStage),
        }
    }
}

impl From<E3StageChangedWithChainId> for InterfoldEventData {
    fn from(value: E3StageChangedWithChainId) -> Self {
        let payload: E3StageChanged = value.into();
        payload.into()
    }
}

pub(crate) fn extractor(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> Option<InterfoldEventData> {
    let topic0 = topics.first();
    match topic0 {
        Some(&IInterfold::E3Requested::SIGNATURE_HASH) => {
            let Ok(event) = IInterfold::E3Requested::decode_log_data(data) else {
                error!("Error parsing event E3Requested after topic matched!");
                return None;
            };
            match E3RequestedWithChainId(event, chain_id).try_into_e3_requested() {
                Ok(payload) => Some(payload.into()),
                Err(e) => {
                    error!(
                        chain_id = chain_id,
                        "Skipping E3Requested: this node cannot process it and will NOT participate \
                         in this E3. This usually indicates a version skew between the ciphernode \
                         binary and the on-chain contracts (unrecognized BFV preset or committee \
                         size). Cause: {}",
                        e
                    );
                    None
                }
            }
        }
        Some(&IInterfold::CiphertextOutputPublished::SIGNATURE_HASH) => {
            let Ok(mut event) = IInterfold::CiphertextOutputPublished::decode_log_data(data) else {
                error!("Error parsing event CiphertextOutputPublished after topic matched!");
                return None;
            };
            // e3Id is indexed → extract from topics[1], not log data
            if let Some(e3_id_topic) = topics.get(1) {
                event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id_topic.0);
            } else {
                error!("CiphertextOutputPublished missing indexed e3Id in topics!");
                return None;
            }
            Some(InterfoldEventData::from(
                CiphertextOutputPublishedWithChainId(event, chain_id),
            ))
        }
        Some(&IInterfold::E3Failed::SIGNATURE_HASH) => {
            let Ok(event) = IInterfold::E3Failed::decode_log_data(data) else {
                error!("Error parsing event E3Failed after topic matched!");
                return None;
            };
            info!(
                "E3Failed event received: e3_id={}, stage={:?}, reason={:?}",
                event.e3Id, event.failedAtStage, event.reason
            );
            Some(InterfoldEventData::from(E3FailedWithChainId(
                event, chain_id,
            )))
        }
        Some(&IInterfold::E3StageChanged::SIGNATURE_HASH) => {
            let Ok(mut event) = IInterfold::E3StageChanged::decode_log_data(data) else {
                error!("Error parsing event E3StageChanged after topic matched!");
                return None;
            };
            // e3Id is indexed → extract from topics[1], not log data
            if let Some(e3_id_topic) = topics.get(1) {
                event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id_topic.0);
            } else {
                error!("E3StageChanged missing indexed e3Id in topics!");
                return None;
            }
            trace!(
                "E3StageChanged event received: e3_id={}, {:?} -> {:?}",
                event.e3Id,
                event.previousStage,
                event.newStage
            );
            Some(InterfoldEventData::from(E3StageChangedWithChainId(
                event, chain_id,
            )))
        }
        _ => {
            trace!(
                topic=?topic0,
                "Unknown event received by Interfold.sol parser but was ignored"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[test]
    fn test_convert_u8_to_e3_stage_known_and_unknown() {
        assert_eq!(convert_u8_to_e3_stage(1), E3Stage::Requested);
        assert_eq!(convert_u8_to_e3_stage(6), E3Stage::Failed);
        // Out-of-range falls back to None
        assert_eq!(convert_u8_to_e3_stage(200), E3Stage::None);
    }

    #[test]
    fn test_convert_u8_to_failure_reason_known_and_unknown() {
        assert_eq!(convert_u8_to_failure_reason(3), FailureReason::DKGTimeout);
        assert_eq!(
            convert_u8_to_failure_reason(12),
            FailureReason::VerificationFailed
        );
        assert_eq!(convert_u8_to_failure_reason(200), FailureReason::None);
    }

    #[test]
    fn test_extractor_decodes_e3_stage_changed() {
        let event = IInterfold::E3StageChanged {
            e3Id: U256::from(42u64),
            previousStage: 1, // Requested
            newStage: 6,      // Failed
        };
        let log_data = event.encode_log_data();
        // e3Id is indexed → it must be in topics[1] (not in log data)
        let e3_id_bytes: [u8; 32] = U256::from(42u64).to_be_bytes();
        let e3_id_topic = B256::from(e3_id_bytes);
        let out = extractor(
            &log_data,
            &[IInterfold::E3StageChanged::SIGNATURE_HASH, e3_id_topic],
            7,
        );
        match out {
            Some(InterfoldEventData::E3StageChanged(data)) => {
                assert_eq!(data.previous_stage, E3Stage::Requested);
                assert_eq!(data.new_stage, E3Stage::Failed);
                assert_eq!(data.e3_id, E3id::new("42".to_string(), 7));
            }
            other => panic!("expected E3StageChanged, got {other:?}"),
        }
    }

    #[test]
    fn test_extractor_ignores_unknown_topic() {
        let log_data = LogData::default();
        assert!(extractor(&log_data, &[B256::ZERO], 1).is_none());
        assert!(extractor(&log_data, &[], 1).is_none());
    }
}
