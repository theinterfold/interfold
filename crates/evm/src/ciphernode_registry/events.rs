// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of `CiphernodeRegistry.sol` logs into `InterfoldEventData`.

use crate::contracts::ICiphernodeRegistry;
use alloy::{
    primitives::{keccak256, LogData, B256, U256},
    sol_types::{SolEvent, SolValue},
};
use e3_events::{
    CommitteeActivationChanged, CommitteeFinalized, CommitteeFormationFailed,
    CommitteePublicKeyChunkPublished, CommitteePublished, CommitteeViabilityUpdated,
    DkgFoldAttestationContext, DkgFoldAttestationContextEstablished, E3id, InterfoldEventData,
    Seed, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_utils::ArcBytes;
use tracing::{error, info, trace};

struct CiphernodeAddedWithChainId(pub ICiphernodeRegistry::CiphernodeAdded, pub u64);

impl From<CiphernodeAddedWithChainId> for e3_events::CiphernodeAdded {
    fn from(value: CiphernodeAddedWithChainId) -> Self {
        e3_events::CiphernodeAdded {
            address: value.0.node.to_string(),
            // TODO: limit index and numNodes to uint32 at the solidity level
            index: value
                .0
                .index
                .try_into()
                .expect("Index exceeds usize capacity"),
            num_nodes: value
                .0
                .numNodes
                .try_into()
                .expect("NumNodes exceeds usize capacity"),
            chain_id: value.1,
        }
    }
}

impl From<CiphernodeAddedWithChainId> for InterfoldEventData {
    fn from(value: CiphernodeAddedWithChainId) -> Self {
        let payload: e3_events::CiphernodeAdded = value.into();
        InterfoldEventData::from(payload)
    }
}

struct CiphernodeRemovedWithChainId(pub ICiphernodeRegistry::CiphernodeRemoved, pub u64);

impl From<CiphernodeRemovedWithChainId> for e3_events::CiphernodeRemoved {
    fn from(value: CiphernodeRemovedWithChainId) -> Self {
        e3_events::CiphernodeRemoved {
            address: value.0.node.to_string(),
            index: value
                .0
                .index
                .try_into()
                .expect("Index exceeds usize capacity"),
            num_nodes: value
                .0
                .numNodes
                .try_into()
                .expect("NumNodes exceeds usize capacity"),
            chain_id: value.1,
        }
    }
}

impl From<CiphernodeRemovedWithChainId> for InterfoldEventData {
    fn from(value: CiphernodeRemovedWithChainId) -> Self {
        let payload: e3_events::CiphernodeRemoved = value.into();
        InterfoldEventData::from(payload)
    }
}

struct CommitteeRequestedWithChainId(
    pub ICiphernodeRegistry::CommitteeRequested,
    pub u64,
    pub Seed,
);

impl From<CommitteeRequestedWithChainId> for e3_events::CommitteeRequested {
    fn from(value: CommitteeRequestedWithChainId) -> Self {
        e3_events::CommitteeRequested {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            seed: value.2,
            threshold: [value.0.threshold[0] as usize, value.0.threshold[1] as usize],
            request_block: value.0.requestBlock.to(),
            committee_deadline: value.0.committeeDeadline.to(),
            ticket_price: value.0.ticketPrice,
            chain_id: value.1,
        }
    }
}

impl From<CommitteeRequestedWithChainId> for InterfoldEventData {
    fn from(value: CommitteeRequestedWithChainId) -> Self {
        let payload: e3_events::CommitteeRequested = value.into();
        InterfoldEventData::from(payload)
    }
}

pub(crate) fn decode_committee_request(
    data: &LogData,
    topics: &[B256],
) -> Option<ICiphernodeRegistry::CommitteeRequested> {
    if topics.first() != Some(&ICiphernodeRegistry::CommitteeRequested::SIGNATURE_HASH) {
        return None;
    }
    ICiphernodeRegistry::CommitteeRequested::decode_log_data(data).ok()
}

pub(crate) fn extractor_with_sortition_seed(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
    seed: Seed,
) -> Option<InterfoldEventData> {
    let event = decode_committee_request(data, topics)?;
    Some(CommitteeRequestedWithChainId(event, chain_id, seed).into())
}

pub(crate) fn derive_sortition_seed(entropy: B256, e3_id: U256) -> Seed {
    let digest = keccak256((entropy, e3_id).abi_encode());
    Seed::from(U256::from_be_bytes(digest.0))
}

pub(crate) fn legacy_sortition_seed(value: U256) -> Seed {
    Seed(value.to_be_bytes())
}

struct CommitteeFinalizedWithChainId(
    pub ICiphernodeRegistry::SortitionCommitteeFinalized,
    pub u64,
);

struct CommitteePublicKeyChunkWithChainId(
    pub ICiphernodeRegistry::CommitteePublicKeyChunkPublished,
    pub u64,
);

impl From<CommitteePublicKeyChunkWithChainId> for CommitteePublicKeyChunkPublished {
    fn from(value: CommitteePublicKeyChunkWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            publisher: value.0.publisher.to_string(),
            candidate_hash: value.0.candidateHash.into(),
            nodes: value.0.nodes.iter().map(ToString::to_string).collect(),
            pk_commitment: value.0.pkCommitment.into(),
            chunk_index: value.0.chunkIndex,
            chunk_count: value.0.chunkCount,
            total_length: value.0.totalLength,
            chunk: ArcBytes::from_bytes(value.0.chunk.as_ref()),
        }
    }
}

impl From<CommitteePublicKeyChunkWithChainId> for InterfoldEventData {
    fn from(value: CommitteePublicKeyChunkWithChainId) -> Self {
        CommitteePublicKeyChunkPublished::from(value).into()
    }
}

impl From<CommitteeFinalizedWithChainId> for CommitteeFinalized {
    fn from(value: CommitteeFinalizedWithChainId) -> Self {
        let mut result = e3_events::CommitteeFinalized {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            committee: value
                .0
                .committee
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            scores: value.0.scores.iter().map(|s| s.to_string()).collect(),
            chain_id: value.1,
        };
        result.sort_by_address();
        result
    }
}

struct DkgFoldAttestationContextEstablishedWithChainId(
    pub ICiphernodeRegistry::DkgFoldAttestationContextEstablished,
    pub u64,
);

impl From<DkgFoldAttestationContextEstablishedWithChainId>
    for DkgFoldAttestationContextEstablished
{
    fn from(value: DkgFoldAttestationContextEstablishedWithChainId) -> Self {
        Self {
            schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            context: DkgFoldAttestationContext {
                registry: value.0.registry,
                verifying_contract: value.0.dkgFoldAttestationVerifier,
            },
        }
    }
}

impl From<DkgFoldAttestationContextEstablishedWithChainId> for InterfoldEventData {
    fn from(value: DkgFoldAttestationContextEstablishedWithChainId) -> Self {
        DkgFoldAttestationContextEstablished::from(value).into()
    }
}

impl From<CommitteeFinalizedWithChainId> for InterfoldEventData {
    fn from(value: CommitteeFinalizedWithChainId) -> Self {
        let payload: e3_events::CommitteeFinalized = value.into();
        InterfoldEventData::from(payload)
    }
}

struct TicketSubmittedWithChainId(pub ICiphernodeRegistry::TicketSubmitted, pub u64);

impl From<TicketSubmittedWithChainId> for e3_events::TicketSubmitted {
    fn from(value: TicketSubmittedWithChainId) -> Self {
        e3_events::TicketSubmitted {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            node: value.0.node.to_string(),
            ticket_id: value.0.ticketId.to(),
            score: value.0.score.to_string(),
            chain_id: value.1,
        }
    }
}

impl From<TicketSubmittedWithChainId> for InterfoldEventData {
    fn from(value: TicketSubmittedWithChainId) -> Self {
        let payload: e3_events::TicketSubmitted = value.into();
        InterfoldEventData::from(payload)
    }
}

struct CommitteeMemberExpelledWithChainId(
    pub ICiphernodeRegistry::CommitteeMemberExpelled,
    pub u64,
);

impl From<CommitteeMemberExpelledWithChainId> for e3_events::CommitteeMemberExpelled {
    fn from(value: CommitteeMemberExpelledWithChainId) -> Self {
        e3_events::CommitteeMemberExpelled {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            node: value.0.node,
            reason: value.0.reason.into(),
            active_count_after: value.0.activeCountAfter.to(),
            party_id: None,
        }
    }
}

impl From<CommitteeMemberExpelledWithChainId> for InterfoldEventData {
    fn from(value: CommitteeMemberExpelledWithChainId) -> Self {
        let payload: e3_events::CommitteeMemberExpelled = value.into();
        InterfoldEventData::from(payload)
    }
}

struct CommitteePublishedWithChainId(pub ICiphernodeRegistry::CommitteePublished, pub u64);

impl From<CommitteePublishedWithChainId> for CommitteePublished {
    fn from(value: CommitteePublishedWithChainId) -> Self {
        CommitteePublished {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            nodes: value.0.nodes.iter().map(|a| a.to_string()).collect(),
            public_key: ArcBytes::from_bytes(value.0.publicKey.as_ref()),
            proof: ArcBytes::from_bytes(value.0.proof.as_ref()),
        }
    }
}

impl From<CommitteePublishedWithChainId> for InterfoldEventData {
    fn from(value: CommitteePublishedWithChainId) -> Self {
        let payload: CommitteePublished = value.into();
        InterfoldEventData::from(payload)
    }
}

struct CommitteeFormationFailedWithChainId(
    pub ICiphernodeRegistry::CommitteeFormationFailed,
    pub u64,
);

impl From<CommitteeFormationFailedWithChainId> for CommitteeFormationFailed {
    fn from(value: CommitteeFormationFailedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            nodes_submitted: value.0.nodesSubmitted.to_string(),
            threshold_required: value.0.thresholdRequired.to_string(),
        }
    }
}

impl From<CommitteeFormationFailedWithChainId> for InterfoldEventData {
    fn from(value: CommitteeFormationFailedWithChainId) -> Self {
        CommitteeFormationFailed::from(value).into()
    }
}

struct CommitteeActivationChangedWithChainId(
    pub ICiphernodeRegistry::CommitteeActivationChanged,
    pub u64,
);

impl From<CommitteeActivationChangedWithChainId> for CommitteeActivationChanged {
    fn from(value: CommitteeActivationChangedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            active: value.0.active,
        }
    }
}

impl From<CommitteeActivationChangedWithChainId> for InterfoldEventData {
    fn from(value: CommitteeActivationChangedWithChainId) -> Self {
        CommitteeActivationChanged::from(value).into()
    }
}

struct CommitteeViabilityUpdatedWithChainId(
    pub ICiphernodeRegistry::CommitteeViabilityUpdated,
    pub u64,
);

impl From<CommitteeViabilityUpdatedWithChainId> for CommitteeViabilityUpdated {
    fn from(value: CommitteeViabilityUpdatedWithChainId) -> Self {
        Self {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            active_count: value.0.activeCount.to_string(),
            threshold_m: value.0.thresholdM.to_string(),
            viable: value.0.viable,
        }
    }
}

impl From<CommitteeViabilityUpdatedWithChainId> for InterfoldEventData {
    fn from(value: CommitteeViabilityUpdatedWithChainId) -> Self {
        CommitteeViabilityUpdated::from(value).into()
    }
}

pub(crate) fn extractor(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> Option<InterfoldEventData> {
    match topics.first() {
        Some(&ICiphernodeRegistry::CiphernodeAdded::SIGNATURE_HASH) => {
            let Ok(event) = ICiphernodeRegistry::CiphernodeAdded::decode_log_data(data) else {
                error!("Error parsing event CiphernodeAdded after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(CiphernodeAddedWithChainId(
                event, chain_id,
            )))
        }
        Some(&ICiphernodeRegistry::CiphernodeRemoved::SIGNATURE_HASH) => {
            let Ok(event) = ICiphernodeRegistry::CiphernodeRemoved::decode_log_data(data) else {
                error!("Error parsing event CiphernodeRemoved after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(CiphernodeRemovedWithChainId(
                event, chain_id,
            )))
        }
        Some(&ICiphernodeRegistry::CommitteeRequested::SIGNATURE_HASH) => {
            error!("CommitteeRequested requires its delayed sortition seed");
            None
        }
        Some(&ICiphernodeRegistry::SortitionCommitteeFinalized::SIGNATURE_HASH) => {
            let Ok(event) = ICiphernodeRegistry::SortitionCommitteeFinalized::decode_log_data(data)
            else {
                error!("Error parsing event SortitionCommitteeFinalized after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(CommitteeFinalizedWithChainId(
                event, chain_id,
            )))
        }
        Some(&ICiphernodeRegistry::DkgFoldAttestationContextEstablished::SIGNATURE_HASH) => {
            let Ok(event) =
                ICiphernodeRegistry::DkgFoldAttestationContextEstablished::decode_log_data(data)
            else {
                error!(
                    "Error parsing event DkgFoldAttestationContextEstablished after topic was matched!"
                );
                return None;
            };
            Some(DkgFoldAttestationContextEstablishedWithChainId(event, chain_id).into())
        }
        Some(&ICiphernodeRegistry::CommitteeFormationFailed::SIGNATURE_HASH) => {
            let Ok(mut event) =
                ICiphernodeRegistry::CommitteeFormationFailed::decode_log_data(data)
            else {
                error!("Error parsing event CommitteeFormationFailed after topic matched!");
                return None;
            };
            event.e3Id = topics
                .get(1)
                .map(|topic| alloy::primitives::U256::from_be_bytes(topic.0))?;
            Some(CommitteeFormationFailedWithChainId(event, chain_id).into())
        }
        Some(&ICiphernodeRegistry::TicketSubmitted::SIGNATURE_HASH) => {
            let Ok(event) = ICiphernodeRegistry::TicketSubmitted::decode_log_data(data) else {
                error!("Error parsing event TicketSubmitted after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(TicketSubmittedWithChainId(
                event, chain_id,
            )))
        }
        Some(&ICiphernodeRegistry::CommitteeMemberExpelled::SIGNATURE_HASH) => {
            let Ok(event) = ICiphernodeRegistry::CommitteeMemberExpelled::decode_log_data(data)
            else {
                error!("Error parsing event CommitteeMemberExpelled after topic was matched!");
                return None;
            };
            info!(
                "CommitteeMemberExpelled event received: e3_id={}, node={}, reason={:?}, active_count_after={}",
                event.e3Id, event.node, event.reason, event.activeCountAfter
            );
            Some(InterfoldEventData::from(
                CommitteeMemberExpelledWithChainId(event, chain_id),
            ))
        }
        Some(&ICiphernodeRegistry::CommitteePublished::SIGNATURE_HASH) => {
            let Ok(mut event) = ICiphernodeRegistry::CommitteePublished::decode_log_data(data)
            else {
                error!("Error parsing event CommitteePublished after topic was matched!");
                return None;
            };
            // e3Id is indexed → extract from topics[1], not log data
            if let Some(e3_id_topic) = topics.get(1) {
                event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id_topic.0);
            } else {
                error!("CommitteePublished missing indexed e3Id in topics!");
                return None;
            }
            info!(
                "CommitteePublished event received: e3_id={}, nodes={:?}",
                event.e3Id, event.nodes
            );
            Some(InterfoldEventData::from(CommitteePublishedWithChainId(
                event, chain_id,
            )))
        }
        Some(&ICiphernodeRegistry::CommitteePublicKeyChunkPublished::SIGNATURE_HASH) => {
            let Ok(mut event) =
                ICiphernodeRegistry::CommitteePublicKeyChunkPublished::decode_log_data(data)
            else {
                error!("Error parsing CommitteePublicKeyChunkPublished after topic was matched!");
                return None;
            };
            let (Some(e3_id), Some(publisher), Some(candidate_hash)) =
                (topics.get(1), topics.get(2), topics.get(3))
            else {
                error!("CommitteePublicKeyChunkPublished is missing indexed topics");
                return None;
            };
            event.e3Id = alloy::primitives::U256::from_be_bytes(e3_id.0);
            event.publisher = alloy::primitives::Address::from_slice(&publisher.0[12..]);
            event.candidateHash = *candidate_hash;
            Some(CommitteePublicKeyChunkWithChainId(event, chain_id).into())
        }
        Some(&ICiphernodeRegistry::CommitteeActivationChanged::SIGNATURE_HASH) => {
            let Ok(mut event) =
                ICiphernodeRegistry::CommitteeActivationChanged::decode_log_data(data)
            else {
                error!("Error parsing event CommitteeActivationChanged after topic matched!");
                return None;
            };
            event.e3Id = topics
                .get(1)
                .map(|topic| alloy::primitives::U256::from_be_bytes(topic.0))?;
            Some(CommitteeActivationChangedWithChainId(event, chain_id).into())
        }
        Some(&ICiphernodeRegistry::CommitteeViabilityUpdated::SIGNATURE_HASH) => {
            let Ok(mut event) =
                ICiphernodeRegistry::CommitteeViabilityUpdated::decode_log_data(data)
            else {
                error!("Error parsing event CommitteeViabilityUpdated after topic matched!");
                return None;
            };
            event.e3Id = topics
                .get(1)
                .map(|topic| alloy::primitives::U256::from_be_bytes(topic.0))?;
            Some(CommitteeViabilityUpdatedWithChainId(event, chain_id).into())
        }
        _ => {
            trace!(
                topic=?topics.first(),
                "Preserving event without a typed CiphernodeRegistry decoder"
            );
            Some(crate::domain::evm_log_observation::observe(
                "CiphernodeRegistry",
                data,
                topics,
                chain_id,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{b256, Address, Bytes, U256};

    #[test]
    fn test_extractor_decodes_ciphernode_added() {
        let event = ICiphernodeRegistry::CiphernodeAdded {
            node: Address::repeat_byte(0xAB),
            index: U256::from(2u64),
            numNodes: U256::from(5u64),
            size: U256::from(5u64),
        };
        let log_data = event.encode_log_data();
        let out = extractor(
            &log_data,
            &[ICiphernodeRegistry::CiphernodeAdded::SIGNATURE_HASH],
            10,
        );
        match out {
            Some(InterfoldEventData::CiphernodeAdded(data)) => {
                assert_eq!(data.index, 2);
                assert_eq!(data.num_nodes, 5);
                assert_eq!(data.chain_id, 10);
            }
            other => panic!("expected CiphernodeAdded, got {other:?}"),
        }
    }

    #[test]
    fn test_committee_finalized_is_sorted_by_address() {
        let a = Address::repeat_byte(0x02);
        let b = Address::repeat_byte(0x01);
        let event = ICiphernodeRegistry::SortitionCommitteeFinalized {
            e3Id: U256::from(1u64),
            committee: vec![a, b],
            scores: vec![U256::from(10u64), U256::from(99u64)],
        };
        let finalized: CommitteeFinalized = CommitteeFinalizedWithChainId(event, 1).into();
        // Committee is sorted by (lowercased) address; scores are reordered to follow.
        assert_eq!(
            finalized.committee.first().map(String::as_str),
            Some(b.to_string().as_str())
        );
        assert_eq!(finalized.scores.first().map(String::as_str), Some("99"));
    }

    #[test]
    fn committee_request_keeps_the_frozen_ticket_price() {
        let event = ICiphernodeRegistry::CommitteeRequested {
            e3Id: U256::from(7),
            entropyBlock: U256::from(8),
            threshold: [2, 3],
            requestBlock: U256::from(100),
            committeeDeadline: U256::from(110),
            ticketPrice: U256::from(25),
        };

        let seed = Seed::from(U256::from(9));
        let converted: e3_events::CommitteeRequested =
            CommitteeRequestedWithChainId(event, 1, seed).into();

        assert_eq!(converted.seed, seed);
        assert_eq!(converted.request_block, 100);
        assert_eq!(converted.ticket_price, U256::from(25));
    }

    #[test]
    fn sortition_seed_matches_solidity_abi_encoding() {
        let entropy = B256::repeat_byte(0x11);
        let expected = Seed::from(U256::from_be_bytes(
            b256!("ea2cda56caceff556aeeb2756e2c1a820445b6413765d79997510293af0f2e35").0,
        ));

        assert_eq!(derive_sortition_seed(entropy, U256::from(7)), expected);
    }

    #[test]
    fn legacy_sortition_seed_keeps_the_previous_byte_order() {
        let mut expected = [0_u8; 32];
        expected[30..].copy_from_slice(&[0x01, 0x02]);

        assert_eq!(legacy_sortition_seed(U256::from(0x0102)), Seed(expected));
    }

    #[test]
    fn test_dkg_fold_context_keeps_request_time_addresses() {
        let event = ICiphernodeRegistry::DkgFoldAttestationContextEstablished {
            e3Id: U256::from(1u64),
            registry: Address::repeat_byte(0x44),
            dkgFoldAttestationVerifier: Address::repeat_byte(0x55),
        };
        let context: DkgFoldAttestationContextEstablished =
            DkgFoldAttestationContextEstablishedWithChainId(event, 1).into();
        assert_eq!(
            context.context,
            DkgFoldAttestationContext {
                registry: Address::repeat_byte(0x44),
                verifying_contract: Address::repeat_byte(0x55),
            }
        );
    }

    #[test]
    fn test_extractor_preserves_unknown_topic() {
        let log_data = LogData::default();
        assert!(matches!(
            extractor(&log_data, &[B256::ZERO], 1),
            Some(InterfoldEventData::EvmLogObserved(_))
        ));
    }

    #[test]
    fn test_extractor_decodes_committee_publication() {
        let node = Address::repeat_byte(0x33);
        let event = ICiphernodeRegistry::CommitteePublished {
            e3Id: U256::from(12),
            nodes: vec![node],
            publicKey: Bytes::from_static(b"public-key"),
            pkCommitment: B256::repeat_byte(0x44),
            proof: Bytes::from_static(b"proof"),
        };
        let log = event.encode_log_data();
        let out = extractor(&log, log.topics(), 100);
        match out {
            Some(InterfoldEventData::CommitteePublished(event)) => {
                assert_eq!(event.e3_id, E3id::new("12", 100));
                assert_eq!(event.nodes, vec![node.to_string()]);
                assert_eq!(event.public_key.extract_bytes(), b"public-key");
            }
            other => panic!("expected CommitteePublished, got {other:?}"),
        }
    }
}
