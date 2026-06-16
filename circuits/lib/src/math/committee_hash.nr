// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `keccak256(abi.encodePacked(addresses))` split into hi/lo 128-bit limbs.
//! Must match `CommitteeHashLib.sol` and `e3_utils::committee_hash`.
//!
//! The hash is taken over the **full registered committee** of size `N_PARTIES`
//! (matches `topNodes` on-chain). It is not parameterised by `H` (the
//! folded honest-set size) because `topNodes` always carries the full committee.

// Same value as `configs::default::N_PARTIES`, but pulled from `committee::active` to
// break the cycle math -> default -> insecure::threshold -> math. `committee::active`
// is regenerated atomically with `default/mod.nr` by `scripts/build-circuits.ts`.
use crate::configs::committee::active::N_PARTIES;
use keccak256::keccak256;

global ADDRESS_BYTES: u32 = 20;
global COMMITTEE_PACKED_BYTES: u32 = N_PARTIES * ADDRESS_BYTES;

fn field_to_address_bytes(member: Field) -> [u8; 20] {
    let be: [u8; 32] = member.to_be_bytes();
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = be[12 + i];
    }
    out
}

fn bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut value: Field = 0;
    for i in 0..32 {
        value = value * 256 + bytes[i] as Field;
    }
    value
}

/// Hash the ordered full committee (`N_PARTIES` members, matching on-chain `topNodes`) and
/// return `(committee_hash_hi, committee_hash_lo)` public limbs.
pub fn committee_hash_limbs(members: [Field; N_PARTIES]) -> (Field, Field) {
    let mut packed = [0u8; COMMITTEE_PACKED_BYTES];
    for i in 0..N_PARTIES {
        let addr = field_to_address_bytes(members[i]);
        for j in 0..20 {
            packed[i * 20 + j] = addr[j];
        }
    }

    let hash_bytes = keccak256(packed, COMMITTEE_PACKED_BYTES);

    // Match `CommitteeHashLib.hi` / `lo`: each limb is a bytes32 with its 128 bits
    // right-aligned (same as `bytes32(uint256(hash) >> 128)` and `& _LO_MASK`).
    let mut hi_bytes = [0u8; 32];
    let mut lo_bytes = [0u8; 32];
    for i in 0..16 {
        hi_bytes[16 + i] = hash_bytes[i];
        lo_bytes[16 + i] = hash_bytes[16 + i];
    }

    (bytes32_to_field(hi_bytes), bytes32_to_field(lo_bytes))
}
