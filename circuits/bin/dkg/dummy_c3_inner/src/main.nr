// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deliberately noncanonical compatible dummy inner circuit for the `c3_fold` adversarial tests.
//!
//! It exposes the exact 5-field public ABI of `share_encryption` — `[pk_commitment,
//! msg_commitment, party_idx, mod_idx, ct_commitment]` — so its proof is verifiable inside
//! `c3_fold`'s `verify_honk_proof` call, but its VK hash differs from the canonical
//! `share_encryption` VK hash. `c3_fold` must reject a proof minted under this VK.

fn main(
    expected_pk_commitment: pub Field,
    expected_message_commitment: pub Field,
    party_idx: pub u32,
    mod_idx: pub u32,
) -> pub Field {
    // No constraints beyond the public ABI shape; `ct_commitment` is the public return.
    let _ = expected_pk_commitment;
    let _ = expected_message_commitment;
    let _ = party_idx;
    let _ = mod_idx;
    expected_message_commitment
}
