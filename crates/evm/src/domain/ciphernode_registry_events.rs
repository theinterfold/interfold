// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of `CiphernodeRegistry.sol` logs into `InterfoldEventData`.

use crate::contracts::ICiphernodeRegistry;
use alloy::{
    primitives::{LogData, B256},
    sol_types::SolEvent,
};
use e3_events::{CommitteeFinalized, E3id, InterfoldEventData, Seed};
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

struct CommitteeRequestedWithChainId(pub ICiphernodeRegistry::CommitteeRequested, pub u64);

impl From<CommitteeRequestedWithChainId> for e3_events::CommitteeRequested {
    fn from(value: CommitteeRequestedWithChainId) -> Self {
        e3_events::CommitteeRequested {
            e3_id: E3id::new(value.0.e3Id.to_string(), value.1),
            seed: Seed(value.0.seed.to_be_bytes()),
            threshold: [value.0.threshold[0] as usize, value.0.threshold[1] as usize],
            request_block: value.0.requestBlock.to(),
            committee_deadline: value.0.committeeDeadline.to(),
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

struct CommitteeFinalizedWithChainId(
    pub ICiphernodeRegistry::SortitionCommitteeFinalized,
    pub u64,
);

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
        result.sort_by_score();
        result
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
            let Ok(event) = ICiphernodeRegistry::CommitteeRequested::decode_log_data(data) else {
                error!("Error parsing event CommitteeRequested after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(CommitteeRequestedWithChainId(
                event, chain_id,
            )))
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
        _ => {
            trace!(
                topic=?topics.first(),
                "Unknown event was received by CiphernodeRegistry.sol parser but was ignored"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};

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
    fn test_extractor_ignores_unknown_topic() {
        let log_data = LogData::default();
        assert!(extractor(&log_data, &[B256::ZERO], 1).is_none());
    }
}
