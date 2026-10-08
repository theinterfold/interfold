// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Requester-provided census.
//!
//! When a round declares `CensusMode::ByRequester`, the requester contract names its electorate
//! through `getCensus(uint256 e3Id) returns (address[])` and the server uses it verbatim, after
//! dropping zero addresses and duplicates.
//!
//! There is no fallback. A round that declared `ByRequester` and cannot be answered is an error,
//! not a round that quietly becomes a token vote with the wrong electorate.

use crate::server::rpc;
use alloy::primitives::{Address, U256};
use alloy::sol;
use eyre::{ensure, Context, Result};
use std::collections::HashSet;

/// Largest census the server accepts: the capacity of the depth-20 eligibility tree. The depth is
/// fixed in the Noir circuit and mirrored by `MERKLE_TREE_MAX_DEPTH` in `@crisp-e3/sdk`; a larger
/// electorate produces proofs the circuit cannot check.
///
/// It is also the trust boundary on requester input: dedup, hashing and tree construction are all
/// linear in the census length.
pub(super) const MAX_CENSUS_SIZE: usize = 1 << 20;

sol! {
    #[sol(rpc)]
    contract ICensusProvider {
        function getCensus(uint256 e3Id) external view returns (address[]);
    }
}

/// Reads the eligible voter set from the E3 requester.
///
/// Returns `None` when the E3 id is invalid, the requester lacks `getCensus`, the call reverts or
/// times out, the census exceeds [`MAX_CENSUS_SIZE`], or nothing usable remains. Under
/// `ByRequester` the caller turns that into a hard error.
pub async fn try_fetch_requester_census(
    requester: Address,
    e3_id: &str,
    rpc_url: &str,
) -> Option<Vec<Address>> {
    match fetch_census(requester, e3_id, rpc_url).await {
        Ok(census) => {
            log::info!(
                "[e3_id={e3_id}] Using requester-provided census from {requester}: {} eligible addresses",
                census.len()
            );
            Some(census)
        }
        Err(error) => {
            log::warn!("[e3_id={e3_id}] Requester {requester} provided no census: {error:#}");
            None
        }
    }
}

async fn fetch_census(requester: Address, e3_id: &str, rpc_url: &str) -> Result<Vec<Address>> {
    let e3_id = U256::from_str_radix(e3_id, 10).wrap_err("invalid E3 id")?;
    let contract = ICensusProvider::new(requester, rpc::http_provider(rpc_url)?);

    // Read at head: the E3's `requestBlock` is an EIP-6372 timestamp, so there is no block height
    // to pin to. Head and snapshot agree because `getCensus(e3Id)` MUST be immutable once the round
    // is open; otherwise ballots cast against one eligibility tree would be checked against another.
    let census = contract
        .getCensus(e3_id)
        .call()
        .await
        .wrap_err("getCensus did not answer")?;

    // Checked before dedup and hashing, which are what scale with the array.
    ensure!(
        census.len() <= MAX_CENSUS_SIZE,
        "{} census addresses exceed the {MAX_CENSUS_SIZE} the eligibility tree can hold",
        census.len()
    );
    sanitize_census(census).ok_or_else(|| eyre::eyre!("no usable census addresses"))
}

/// Drops zero addresses and duplicates, keeping first-seen order so the leaf order is
/// deterministic. A duplicate would get two leaves and so two ballots. `None` when nothing is left.
fn sanitize_census(census: Vec<Address>) -> Option<Vec<Address>> {
    let mut seen = HashSet::new();
    let deduped: Vec<Address> = census
        .into_iter()
        .filter(|address| !address.is_zero() && seen.insert(*address))
        .collect();

    (!deduped.is_empty()).then_some(deduped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    #[test]
    fn dedupes_in_first_seen_order_and_drops_zero_addresses() {
        let census = vec![addr(3), addr(1), Address::ZERO, addr(3), addr(2), addr(1)];
        assert_eq!(
            sanitize_census(census),
            Some(vec![addr(3), addr(1), addr(2)])
        );
    }

    #[test]
    fn a_census_with_no_usable_address_is_rejected() {
        assert_eq!(sanitize_census(vec![]), None);
        assert_eq!(sanitize_census(vec![Address::ZERO, Address::ZERO]), None);
    }
}
