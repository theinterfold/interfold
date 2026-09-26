// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::Result;
use e3_events::{InterfoldEvent, Unsequenced};

use crate::{
    domain::net_event_batch::{BatchCursor, EventBatch, FetchEventsSince},
    events::ProtocolResponse,
    NetworkPolicy,
};

/// A bootstrap peer has no event archive. Reply in the existing sync format so older peers
/// can finish their connection setup. Recovery history must come from ciphernodes.
pub(crate) fn history_response(
    request: Vec<u8>,
    network: &NetworkPolicy,
) -> Result<ProtocolResponse> {
    let fetch = match FetchEventsSince::try_from(request) {
        Ok(fetch) => fetch,
        Err(_) => {
            return Ok(ProtocolResponse::BadRequest(
                "malformed historical sync request".into(),
            ))
        }
    };
    if fetch.limit() == 0 {
        return Ok(ProtocolResponse::BadRequest(
            "limit must be greater than 0".into(),
        ));
    }
    let Some(chain_id) = fetch.aggregate_id().to_chain_id() else {
        return Ok(ProtocolResponse::BadRequest(
            "aggregate ID does not contain a chain ID".into(),
        ));
    };
    if !network.allows_chain(chain_id) {
        return Ok(ProtocolResponse::BadRequest(
            "aggregate chain is not part of this network".into(),
        ));
    }
    Ok(ProtocolResponse::Ok(
        EventBatch::<InterfoldEvent<Unsequenced>> {
            events: Vec::new(),
            next: BatchCursor::Done,
            aggregate_id: fetch.aggregate_id(),
        }
        .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_config::NetworkProfile;
    use e3_events::AggregateId;

    #[test]
    fn empty_history_uses_the_existing_bounded_sync_format() -> Result<()> {
        let network = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])])?;
        let request = FetchEventsSince::new(AggregateId::new(1), 42, usize::MAX);
        let ProtocolResponse::Ok(bytes) = history_response(request.try_into()?, &network)? else {
            panic!("expected an empty history batch");
        };
        let batch = EventBatch::<InterfoldEvent<Unsequenced>>::try_from(bytes)?;
        assert!(batch.events.is_empty());
        assert!(matches!(batch.next, BatchCursor::Done));
        assert_eq!(batch.aggregate_id, AggregateId::new(1));
        Ok(())
    }

    #[test]
    fn malformed_local_foreign_and_zero_limit_requests_are_rejected() -> Result<()> {
        let network = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])])?;
        for request in [
            vec![0; 4],
            FetchEventsSince::new(AggregateId::new(0), 0, 10).try_into()?,
            FetchEventsSince::new(AggregateId::new(2), 0, 10).try_into()?,
            FetchEventsSince::new(AggregateId::new(1), 0, 0).try_into()?,
        ] {
            assert!(matches!(
                history_response(request, &network)?,
                ProtocolResponse::BadRequest(_)
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod network_tests;
