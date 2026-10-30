// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_committee_hash::LbfvProofDomainContext;
pub fn sample_lbfv_proof_domain() -> LbfvProofDomainContext {
    LbfvProofDomainContext {
        protocol_version: 4,
        chain_id: 31_337,
        interfold_address: Address::repeat_byte(0x11),
        e3_id: U256::from(7),
        crypto_config_id: B256::repeat_byte(0x22),
        finalized_committee_hash: B256::repeat_byte(0x33),
        lbfv_constants_version: LBFV_CONSTANTS_VERSION,
        ciphertext_level: 0,
        key_level: 0,
    }
}

use alloy_primitives::{Address, B256, U256};
use e3_fhe_params::LBFV_CONSTANTS_VERSION;
