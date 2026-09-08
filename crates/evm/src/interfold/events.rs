// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of `Interfold.sol` logs into `InterfoldEventData`.

use crate::contracts::IInterfold;
use alloy::primitives::{keccak256, LogData, B256};
use alloy::sol_types::{SolEvent, SolValue};
use anyhow::{anyhow, Context as _, Result};
use e3_events::E3id;
use e3_events::InterfoldEventData;
use e3_events::{
    CiphertextOutputReferencePublished, E3Failed, E3Stage, E3StageChanged, FailureReason,
    InputPublished, PlaintextOutputPublished, RewardClaimed, RewardCredited, RewardsDistributed,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset};
use e3_trbfv::helpers::calculate_error_size;
use e3_utils::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use num_bigint::BigUint;
use tracing::{info, trace, warn};

struct E3RequestedWithChainId(pub IInterfold::E3Requested, pub u64);

fn crypto_config_id(params: &[u8]) -> B256 {
    keccak256(
        (
            keccak256(b"fhe.rs:BFV"),
            keccak256(params),
            keccak256(b"interfold-bfv-v1"),
        )
            .abi_encode(),
    )
}

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
        let expected_config_id = crypto_config_id(&params_bytes);
        if self.0.cryptoConfigId != expected_config_id {
            anyhow::bail!(
                "Unsupported crypto configuration {} for E3 {}; this ciphernode was built for {}",
                self.0.cryptoConfigId,
                self.0.e3Id,
                expected_config_id
            );
        }

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
            request_block: self.0.e3.requestBlock.to(),
            error_size,
            e3_id: E3id::new(self.0.e3Id.to_string(), self.1),
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
            ciphertext_commitment: value.0.ciphertextCommitment.into(),
        }
    }
}

impl From<CiphertextOutputPublishedWithChainId> for InterfoldEventData {
    fn from(value: CiphertextOutputPublishedWithChainId) -> Self {
        let payload: e3_events::CiphertextOutputPublished = value.into();
        payload.into()
    }
}

struct CiphertextOutputReferenceWithChainId(
    pub IInterfold::CiphertextOutputReferencePublished,
    pub u64,
);

impl From<CiphertextOutputReferenceWithChainId> for CiphertextOutputReferencePublished {
    fn from(value: CiphertextOutputReferenceWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            content_hash: value.0.contentHash.into(),
            ciphertext_commitment: value.0.ciphertextCommitment.into(),
            availability_block: value.0.availabilityBlock,
            availability_leaf_index: value.0.availabilityLeafIndex,
        }
    }
}

impl From<CiphertextOutputReferenceWithChainId> for InterfoldEventData {
    fn from(value: CiphertextOutputReferenceWithChainId) -> Self {
        CiphertextOutputReferencePublished::from(value).into()
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

struct PlaintextOutputPublishedWithChainId(pub IInterfold::PlaintextOutputPublished, pub u64);

impl From<PlaintextOutputPublishedWithChainId> for PlaintextOutputPublished {
    fn from(value: PlaintextOutputPublishedWithChainId) -> Self {
        PlaintextOutputPublished {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            plaintext_output: ArcBytes::from_bytes(value.0.plaintextOutput.as_ref()),
            proof: ArcBytes::from_bytes(value.0.proof.as_ref()),
        }
    }
}

impl From<PlaintextOutputPublishedWithChainId> for InterfoldEventData {
    fn from(value: PlaintextOutputPublishedWithChainId) -> Self {
        let payload: PlaintextOutputPublished = value.into();
        payload.into()
    }
}

struct InputPublishedWithChainId(pub IInterfold::InputPublished, pub u64);

impl From<InputPublishedWithChainId> for InputPublished {
    fn from(value: InputPublishedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            data: ArcBytes::from_bytes(value.0.data.as_ref()),
            input_hash: value.0.inputHash.to_string(),
            index: value.0.index.to_string(),
        }
    }
}

impl From<InputPublishedWithChainId> for InterfoldEventData {
    fn from(value: InputPublishedWithChainId) -> Self {
        InputPublished::from(value).into()
    }
}

struct RewardsDistributedWithChainId(pub IInterfold::RewardsDistributed, pub u64);

impl From<RewardsDistributedWithChainId> for RewardsDistributed {
    fn from(value: RewardsDistributedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            nodes: value
                .0
                .nodes
                .into_iter()
                .map(|node| node.to_string())
                .collect(),
            amounts: value
                .0
                .amounts
                .into_iter()
                .map(|amount| amount.to_string())
                .collect(),
        }
    }
}

impl From<RewardsDistributedWithChainId> for InterfoldEventData {
    fn from(value: RewardsDistributedWithChainId) -> Self {
        RewardsDistributed::from(value).into()
    }
}

struct RewardCreditedWithChainId(pub IInterfold::RewardCredited, pub u64);

impl From<RewardCreditedWithChainId> for RewardCredited {
    fn from(value: RewardCreditedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            account: value.0.account.to_string(),
            token: value.0.token.to_string(),
            amount: value.0.amount.to_string(),
        }
    }
}

impl From<RewardCreditedWithChainId> for InterfoldEventData {
    fn from(value: RewardCreditedWithChainId) -> Self {
        RewardCredited::from(value).into()
    }
}

struct RewardClaimedWithChainId(pub IInterfold::RewardClaimed, pub u64);

impl From<RewardClaimedWithChainId> for RewardClaimed {
    fn from(value: RewardClaimedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            account: value.0.account.to_string(),
            token: value.0.token.to_string(),
            amount: value.0.amount.to_string(),
        }
    }
}

impl From<RewardClaimedWithChainId> for InterfoldEventData {
    fn from(value: RewardClaimedWithChainId) -> Self {
        RewardClaimed::from(value).into()
    }
}

fn indexed_u256(
    topics: &[B256],
    index: usize,
    event_type: &str,
) -> Result<alloy::primitives::U256> {
    topics
        .get(index)
        .map(|topic| alloy::primitives::U256::from_be_bytes(topic.0))
        .ok_or_else(|| anyhow!("{event_type} missing indexed topic {index}"))
}

pub(crate) fn extractor(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> Result<Option<InterfoldEventData>> {
    let topic0 = topics.first();
    match topic0 {
        Some(&IInterfold::E3Requested::SIGNATURE_HASH) => {
            let event = IInterfold::E3Requested::decode_log_data(data)
                .context("failed to decode E3Requested after its topic matched")?;
            match E3RequestedWithChainId(event, chain_id).try_into_e3_requested() {
                Ok(payload) => Ok(Some(payload.into())),
                Err(e) => {
                    warn!(
                        chain_id = chain_id,
                        "Skipping E3Requested: this node cannot process it and will NOT participate \
                         in this E3. This usually indicates a version skew between the ciphernode \
                         binary and the on-chain contracts (unrecognized BFV preset or committee \
                         size). Cause: {}",
                        e
                    );
                    Ok(None)
                }
            }
        }
        Some(&IInterfold::CiphertextOutputPublished::SIGNATURE_HASH) => {
            let mut event = IInterfold::CiphertextOutputPublished::decode_log_data(data)
                .context("failed to decode CiphertextOutputPublished after its topic matched")?;
            // e3Id is indexed → extract from topics[1], not log data
            if let Some(e3_id_topic) = topics.get(1) {
                event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id_topic.0);
            } else {
                return Err(anyhow!(
                    "CiphertextOutputPublished missing indexed e3Id in topics"
                ));
            }
            Ok(Some(InterfoldEventData::from(
                CiphertextOutputPublishedWithChainId(event, chain_id),
            )))
        }
        Some(&IInterfold::CiphertextOutputReferencePublished::SIGNATURE_HASH) => {
            let mut event = IInterfold::CiphertextOutputReferencePublished::decode_log_data(data)
                .context(
                "failed to decode CiphertextOutputReferencePublished after its topic matched",
            )?;
            event.e3Id = indexed_u256(topics, 1, "CiphertextOutputReferencePublished")?;
            Ok(Some(
                CiphertextOutputReferenceWithChainId(event, chain_id).into(),
            ))
        }
        Some(&IInterfold::InputPublished::SIGNATURE_HASH) => {
            let mut event = IInterfold::InputPublished::decode_log_data(data)
                .context("failed to decode InputPublished after its topic matched")?;
            event.e3Id = indexed_u256(topics, 1, "InputPublished")?;
            Ok(Some(InputPublishedWithChainId(event, chain_id).into()))
        }
        Some(&IInterfold::E3Failed::SIGNATURE_HASH) => {
            let mut event = IInterfold::E3Failed::decode_log_data(data)
                .context("failed to decode E3Failed after its topic matched")?;
            event.e3Id = indexed_u256(topics, 1, "E3Failed")?;
            info!(
                "E3Failed event received: e3_id={}, stage={:?}, reason={:?}",
                event.e3Id, event.failedAtStage, event.reason
            );
            Ok(Some(InterfoldEventData::from(E3FailedWithChainId(
                event, chain_id,
            ))))
        }
        Some(&IInterfold::E3StageChanged::SIGNATURE_HASH) => {
            let mut event = IInterfold::E3StageChanged::decode_log_data(data)
                .context("failed to decode E3StageChanged after its topic matched")?;
            // e3Id is indexed → extract from topics[1], not log data
            if let Some(e3_id_topic) = topics.get(1) {
                event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id_topic.0);
            } else {
                return Err(anyhow!("E3StageChanged missing indexed e3Id in topics"));
            }
            trace!(
                "E3StageChanged event received: e3_id={}, {:?} -> {:?}",
                event.e3Id,
                event.previousStage,
                event.newStage
            );
            Ok(Some(InterfoldEventData::from(E3StageChangedWithChainId(
                event, chain_id,
            ))))
        }
        Some(&IInterfold::PlaintextOutputPublished::SIGNATURE_HASH) => {
            let mut event = IInterfold::PlaintextOutputPublished::decode_log_data(data)
                .context("failed to decode PlaintextOutputPublished after its topic matched")?;
            // e3Id is indexed → extract from topics[1], not log data
            if let Some(e3_id_topic) = topics.get(1) {
                event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id_topic.0);
            } else {
                return Err(anyhow!(
                    "PlaintextOutputPublished missing indexed e3Id in topics"
                ));
            }
            info!(
                "PlaintextOutputPublished event received: e3_id={}",
                event.e3Id
            );
            Ok(Some(InterfoldEventData::from(
                PlaintextOutputPublishedWithChainId(event, chain_id),
            )))
        }
        Some(&IInterfold::RewardsDistributed::SIGNATURE_HASH) => {
            let mut event = IInterfold::RewardsDistributed::decode_log_data(data)
                .context("failed to decode RewardsDistributed after its topic matched")?;
            if event.nodes.len() != event.amounts.len() {
                anyhow::bail!(
                    "RewardsDistributed array lengths differ: nodes={}, amounts={}",
                    event.nodes.len(),
                    event.amounts.len()
                );
            }
            event.e3Id = indexed_u256(topics, 1, "RewardsDistributed")?;
            Ok(Some(RewardsDistributedWithChainId(event, chain_id).into()))
        }
        Some(&IInterfold::RewardCredited::SIGNATURE_HASH) => {
            let mut event = IInterfold::RewardCredited::decode_log_data(data)
                .context("failed to decode RewardCredited after its topic matched")?;
            event.e3Id = indexed_u256(topics, 1, "RewardCredited")?;
            Ok(Some(RewardCreditedWithChainId(event, chain_id).into()))
        }
        Some(&IInterfold::RewardClaimed::SIGNATURE_HASH) => {
            let mut event = IInterfold::RewardClaimed::decode_log_data(data)
                .context("failed to decode RewardClaimed after its topic matched")?;
            event.e3Id = indexed_u256(topics, 1, "RewardClaimed")?;
            Ok(Some(RewardClaimedWithChainId(event, chain_id).into()))
        }
        _ => {
            trace!(
                topic=?topic0,
                "Preserving event without a typed Interfold.sol decoder"
            );
            Ok(Some(crate::domain::evm_log_observation::observe(
                "Interfold",
                data,
                topics,
                chain_id,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, U256};

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
    fn preset_config_ids_are_accepted() {
        let expected = [
            (
                0,
                "0x04f3677e73b0f5066d6caf5cbd92e3fb2e38338edaf5cfc971ab28f7b684da78",
            ),
            (
                1,
                "0xd9c86e581f8291ffb5b63595600e8d096ed30b16e2e0a6634a76c22b1f58fb4e",
            ),
        ];

        for (param_set, expected_id) in expected {
            let preset = BfvPreset::from_on_chain_param_set(param_set).unwrap();
            let event = IInterfold::E3Requested {
                e3Id: U256::from(param_set),
                e3: IInterfold::E3 {
                    seed: U256::ZERO,
                    committeeSize: 0,
                    requestBlock: U256::ZERO,
                    inputWindow: [U256::ZERO; 2],
                    encryptionSchemeId: B256::ZERO,
                    e3Program: Address::ZERO,
                    paramSet: param_set,
                    customParams: Bytes::new(),
                    decryptionVerifier: Address::ZERO,
                    pkVerifier: Address::ZERO,
                    committeePublicKey: B256::ZERO,
                    ciphertextOutput: B256::ZERO,
                    plaintextOutput: Bytes::new(),
                    requester: Address::ZERO,
                    ciphertextCommitment: B256::ZERO,
                },
                cryptoConfigId: expected_id.parse::<B256>().unwrap(),
            };

            let converted = E3RequestedWithChainId(event, 1)
                .try_into_e3_requested()
                .unwrap();
            assert_eq!(converted.params_preset, preset);
        }
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
        )
        .unwrap();
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
    fn test_extractor_preserves_unknown_topic() {
        let log_data = LogData::default();
        assert!(matches!(
            extractor(&log_data, &[B256::ZERO], 1).unwrap(),
            Some(InterfoldEventData::EvmLogObserved(_))
        ));
        assert!(matches!(
            extractor(&log_data, &[], 1).unwrap(),
            Some(InterfoldEventData::EvmLogObserved(_))
        ));
    }

    #[test]
    fn test_extractor_decodes_input_and_reward_events() {
        let input = IInterfold::InputPublished {
            e3Id: U256::from(8),
            data: Bytes::from_static(b"ciphertext"),
            inputHash: U256::from(99),
            index: U256::from(3),
        };
        let input_log = input.encode_log_data();
        let out = extractor(&input_log, input_log.topics(), 10).unwrap();
        match out {
            Some(InterfoldEventData::InputPublished(event)) => {
                assert_eq!(event.e3_id, E3id::new("8", 10));
                assert_eq!(event.index, "3");
                assert_eq!(event.data.extract_bytes(), b"ciphertext");
            }
            other => panic!("expected InputPublished, got {other:?}"),
        }

        let reward = IInterfold::RewardCredited {
            e3Id: U256::from(8),
            account: Address::repeat_byte(0x11),
            token: Address::repeat_byte(0x22),
            amount: U256::from(500),
        };
        let reward_log = reward.encode_log_data();
        let out = extractor(&reward_log, reward_log.topics(), 10).unwrap();
        match out {
            Some(InterfoldEventData::RewardCredited(event)) => {
                assert_eq!(event.e3_id, E3id::new("8", 10));
                assert_eq!(event.amount, "500");
                assert_eq!(event.account, Address::repeat_byte(0x11).to_string());
            }
            other => panic!("expected RewardCredited, got {other:?}"),
        }
    }

    #[test]
    fn test_extractor_rejects_mismatched_reward_arrays() {
        let event = IInterfold::RewardsDistributed {
            e3Id: U256::from(8),
            nodes: vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)],
            amounts: vec![U256::from(500)],
        };
        let log = event.encode_log_data();

        let error = extractor(&log, log.topics(), 10).unwrap_err();

        assert!(error
            .to_string()
            .contains("RewardsDistributed array lengths differ"));
    }

    #[test]
    fn test_extractor_decodes_plaintext_publication() {
        let event = IInterfold::PlaintextOutputPublished {
            e3Id: U256::from(18),
            plaintextOutput: Bytes::from_static(b"plain"),
            proof: Bytes::from_static(b"c7"),
        };
        let log = event.encode_log_data();
        let out = extractor(&log, log.topics(), 100).unwrap();
        match out {
            Some(InterfoldEventData::PlaintextOutputPublished(event)) => {
                assert_eq!(event.e3_id, E3id::new("18", 100));
                assert_eq!(event.plaintext_output.extract_bytes(), b"plain");
                assert_eq!(event.proof.extract_bytes(), b"c7");
            }
            other => panic!("expected PlaintextOutputPublished, got {other:?}"),
        }
    }

    #[test]
    fn e3_request_keeps_the_contract_sortition_timepoint() {
        let event = IInterfold::E3Requested {
            e3Id: U256::from(19),
            e3: IInterfold::E3 {
                seed: U256::ZERO,
                committeeSize: 0,
                requestBlock: U256::from(77),
                inputWindow: [U256::ZERO; 2],
                encryptionSchemeId: B256::ZERO,
                e3Program: Address::ZERO,
                paramSet: 0,
                customParams: Bytes::new(),
                decryptionVerifier: Address::ZERO,
                pkVerifier: Address::ZERO,
                committeePublicKey: B256::ZERO,
                ciphertextOutput: B256::ZERO,
                plaintextOutput: Bytes::new(),
                requester: Address::ZERO,
                ciphertextCommitment: B256::ZERO,
            },
            cryptoConfigId: crypto_config_id(&encode_bfv_params(
                &BfvParamSet::from(BfvPreset::from_on_chain_param_set(0).unwrap()).build_arc(),
            )),
        };

        let converted = E3RequestedWithChainId(event, 100)
            .try_into_e3_requested()
            .unwrap();

        assert_eq!(converted.request_block, 77);
    }

    #[test]
    fn unsupported_e3_requested_is_a_benign_skip() {
        let event = IInterfold::E3Requested {
            e3Id: U256::from(19),
            e3: IInterfold::E3 {
                seed: U256::ZERO,
                committeeSize: u8::MAX,
                requestBlock: U256::ZERO,
                inputWindow: [U256::ZERO; 2],
                encryptionSchemeId: B256::ZERO,
                e3Program: Address::ZERO,
                paramSet: 0,
                customParams: Bytes::new(),
                decryptionVerifier: Address::ZERO,
                pkVerifier: Address::ZERO,
                committeePublicKey: B256::ZERO,
                ciphertextOutput: B256::ZERO,
                plaintextOutput: Bytes::new(),
                requester: Address::ZERO,
                ciphertextCommitment: B256::ZERO,
            },
            cryptoConfigId: crypto_config_id(&encode_bfv_params(
                &BfvParamSet::from(BfvPreset::from_on_chain_param_set(0).unwrap()).build_arc(),
            )),
        };
        let log = event.encode_log_data();

        assert!(extractor(&log, log.topics(), 100).unwrap().is_none());
    }

    #[test]
    fn malformed_e3_requested_is_rejected() {
        let malformed = LogData::new_unchecked(
            vec![IInterfold::E3Requested::SIGNATURE_HASH],
            Default::default(),
        );

        assert!(extractor(&malformed, malformed.topics(), 100).is_err());
    }
}
