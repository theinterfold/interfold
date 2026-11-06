// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Contracts, RawLog};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolEvent;
use e3_evm_contracts::IInterfold;
use e3_protocol::node::LogPosition;
use std::collections::{BTreeMap, BTreeSet};

pub const CONFIG: B256 = B256::repeat_byte(0xcc);

pub const RANDOMNESS: Address = Address::repeat_byte(0x4a);

pub fn contracts() -> Contracts {
    Contracts {
        chain_id: 1,
        interfold: Address::repeat_byte(0x1f),
        registry: Address::repeat_byte(0x2e),
        bonding: Address::repeat_byte(0x3b),
        slashing: BTreeSet::from([Address::repeat_byte(0x4c)]),
        randomness: BTreeSet::from([RANDOMNESS]),
        crypto_configs: BTreeMap::from([(1, CONFIG)]),
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

/// E3 7's request, Minimum committee, parameter set 1, under crypto configuration `config`.
pub fn e3_requested(config: B256) -> IInterfold::E3Requested {
    IInterfold::E3Requested {
        e3Id: U256::from(7),
        e3: IInterfold::E3 {
            seed: U256::from(42),
            committeeSize: 0,
            requestBlock: U256::from(999),
            inputWindow: [U256::ZERO; 2],
            encryptionSchemeId: B256::ZERO,
            e3Program: Address::ZERO,
            paramSet: 1,
            customParams: Bytes::new(),
            decryptionVerifier: Address::ZERO,
            pkVerifier: Address::ZERO,
            committeePublicKey: B256::ZERO,
            ciphertextOutput: B256::ZERO,
            plaintextOutput: Bytes::new(),
            requester: Address::ZERO,
            ciphertextCommitment: B256::ZERO,
        },
        cryptoConfigId: config,
    }
}
