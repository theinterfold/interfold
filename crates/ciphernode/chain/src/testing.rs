// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Contracts, RawLog};
use alloy_primitives::{Address, B256};
use alloy_sol_types::SolEvent;
use e3_protocol::node::LogPosition;
use std::collections::BTreeSet;

pub const CONFIG: B256 = B256::repeat_byte(0xcc);

pub const RANDOMNESS: Address = Address::repeat_byte(0x4a);

pub fn contracts() -> Contracts {
    Contracts {
        chain_id: 1,
        interfold: Address::repeat_byte(0x1f),
        registry: Address::repeat_byte(0x2e),
        bonding: Address::repeat_byte(0x3b),
        randomness: BTreeSet::from([RANDOMNESS]),
        crypto_config: CONFIG,
    }
}

/// `event` as the contract at `address` logs it in `block`, in transaction `transaction`, at
/// `index`. A block's time is ten times its number.
pub fn log(
    address: Address,
    event: &impl SolEvent,
    block: u64,
    transaction: u8,
    index: u64,
) -> RawLog {
    let data = event.encode_log_data();
    RawLog {
        address,
        topics: data.topics().to_vec(),
        data: data.data,
        at: LogPosition {
            chain_id: 1,
            block,
            log_index: index,
        },
        time: block * 10,
        transaction: B256::repeat_byte(transaction),
    }
}
