// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of fulfilled randomness into the existing committee request event.

use alloy::primitives::U256;
use e3_events::{E3id, InterfoldEventData, Seed};

pub(crate) struct SortitionRequestContext {
    pub e3_id: U256,
    pub seed: U256,
    pub threshold: [u32; 2],
    pub request_block: U256,
    pub committee_deadline: U256,
    pub ticket_price: U256,
    pub chain_id: u64,
}

pub(crate) fn committee_requested(context: SortitionRequestContext) -> InterfoldEventData {
    e3_events::CommitteeRequested {
        e3_id: E3id::new(context.e3_id.to_string(), context.chain_id),
        // Sortition decodes `Seed` bytes as little-endian, so the score hashes the registry's
        // uint256 seed exactly as `RegistrySortitionLib.ticketScore` does.
        seed: Seed::from(context.seed),
        threshold: [context.threshold[0] as usize, context.threshold[1] as usize],
        request_block: context.request_block.to(),
        committee_deadline: context.committee_deadline.to(),
        ticket_price: context.ticket_price,
        chain_id: context.chain_id,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};
    use e3_sortition::hash_to_score;
    use num_bigint::BigUint;

    #[test]
    fn vrf_seed_scores_tickets_like_the_registry() {
        let seed = U256::from_be_bytes(
            b256!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").0,
        );
        let e3_id: U256 =
            "18458939420885977824981152629962741023865184457287647280899939019117062782978"
                .parse()
                .unwrap();
        let event = committee_requested(SortitionRequestContext {
            e3_id,
            seed,
            threshold: [14, 19],
            request_block: U256::from(13),
            committee_deadline: U256::from(17),
            ticket_price: U256::from(19),
            chain_id: 1,
        });

        let InterfoldEventData::CommitteeRequested(request) = event else {
            panic!("expected CommitteeRequested");
        };
        // keccak256(abi.encodePacked(node, ticketNumber, e3Id, seed)), computed with
        // ethers `solidityPackedKeccak256` for the same inputs.
        let expected = BigUint::from_bytes_be(
            &b256!("54839d0ce89af4ea0767d9ea472d9129c58222e25a0e38a65c2ba3ef522e758b").0,
        );
        assert_eq!(
            hash_to_score(
                address!("1111111111111111111111111111111111111111"),
                1,
                request.e3_id,
                request.seed,
            ),
            expected
        );
    }

    #[test]
    fn preserves_the_vrf_request_context() {
        let event = committee_requested(SortitionRequestContext {
            e3_id: U256::from(7),
            seed: U256::from(11),
            threshold: [2, 3],
            request_block: U256::from(13),
            committee_deadline: U256::from(17),
            ticket_price: U256::from(19),
            chain_id: 1,
        });

        let InterfoldEventData::CommitteeRequested(request) = event else {
            panic!("expected CommitteeRequested");
        };
        assert_eq!(request.e3_id, E3id::new("7", 1));
        assert_eq!(request.seed, Seed(U256::from(11).to_le_bytes()));
        assert_eq!(request.threshold, [2, 3]);
        assert_eq!(request.request_block, 13);
        assert_eq!(request.committee_deadline, 17);
        assert_eq!(request.ticket_price, U256::from(19));
    }
}
