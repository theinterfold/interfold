// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::{LogData, B256, U256};
use e3_events::{E3id, EvmLogObserved, InterfoldEventData};
use e3_utils::ArcBytes;

use super::evm_event_catalog;

/// Preserve a watched contract log losslessly and attach the current ABI name
/// when it is not one of the protocol-driving typed events.
pub(crate) fn observe(
    contract: &str,
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> InterfoldEventData {
    let definition = topics
        .first()
        .and_then(|topic| evm_event_catalog::find(contract, *topic));
    let e3_id = definition
        .and_then(|event| event.e3_id_topic)
        .and_then(|index| topics.get(index))
        .map(|topic| E3id::new(U256::from_be_bytes(topic.0).to_string(), chain_id));

    EvmLogObserved {
        contract: contract.to_owned(),
        chain_id,
        e3_id,
        event_name: definition
            .map(|event| event.name.to_owned())
            .unwrap_or_else(|| "UnknownEvmLog".to_owned()),
        signature: definition.map(|event| event.signature.to_owned()),
        known: definition.is_some(),
        topics: topics.iter().map(ToString::to_string).collect(),
        data: ArcBytes::from_bytes(data.data.as_ref()),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;

    #[test]
    fn names_known_logs_and_extracts_indexed_e3_id() {
        let topic0 = keccak256("TreasuryCredited(uint256,address,address,uint256)");
        let e3_id = B256::from(U256::from(17).to_be_bytes::<32>());
        let event = observe("Interfold", &LogData::default(), &[topic0, e3_id], 31337);

        match event {
            InterfoldEventData::EvmLogObserved(event) => {
                assert!(event.known);
                assert_eq!(event.event_name, "TreasuryCredited");
                assert_eq!(event.e3_id, Some(E3id::new("17", 31337)));
            }
            other => panic!("expected EvmLogObserved, got {other:?}"),
        }
    }

    #[test]
    fn unknown_logs_remain_lossless_and_explicit() {
        let data = LogData::new_unchecked(vec![B256::ZERO], vec![1, 2, 3].into());
        let event = observe("Interfold", &data, &[B256::ZERO], 1);
        match event {
            InterfoldEventData::EvmLogObserved(event) => {
                assert!(!event.known);
                assert_eq!(event.event_name, "UnknownEvmLog");
                assert_eq!(event.data.extract_bytes(), &[1, 2, 3]);
            }
            other => panic!("expected EvmLogObserved, got {other:?}"),
        }
    }
}
