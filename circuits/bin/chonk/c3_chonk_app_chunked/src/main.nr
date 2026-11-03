// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! l-BFV Chonk app for C3: `c3_chonk_app` for the chunked C3 leaf, which also exposes its party
//! and modulus. Each real leaf must name the slot it is written to. The kernels, tube and
//! accumulator are the trBFV ones. See `lib::math::chonk`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::c3_fold::place_leaves;
use lib::math::chonk::C3_CHONK_LEAVES;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    proofs: [UltraHonkZKProof; C3_CHONK_LEAVES],
    c3_public_inputs: [[Field; 5]; C3_CHONK_LEAVES],
    slot_indices: [u32; C3_CHONK_LEAVES],
) -> return_data [Field; 3 * C3_SLOTS + 1] {
    let mut rows = [[0; 3]; C3_CHONK_LEAVES];
    for k in 0..C3_CHONK_LEAVES {
        verify_honk_proof(leaf_vk, proofs[k], c3_public_inputs[k], leaf_key_hash);
        rows[k] = leaf_row(c3_public_inputs[k], slot_indices[k]);
    }
    let (pk, msg, ct) = place_leaves(
        [0; C3_SLOTS],
        [0; C3_SLOTS],
        [0; C3_SLOTS],
        rows,
        slot_indices,
    );
    let mut out = [0; 3 * C3_SLOTS + 1];
    for i in 0..C3_SLOTS {
        out[i] = pk[i];
        out[C3_SLOTS + i] = msg[i];
        out[2 * C3_SLOTS + i] = ct[i];
    }
    out[3 * C3_SLOTS] = leaf_key_hash;
    out
}

/// The `(pk, msg, ct)` row of a leaf whose public inputs are `[pk, msg, party, modulus, ct]`. An
/// empty place (slot `C3_SLOTS`) writes nothing, so only a real leaf is bound to its slot.
fn leaf_row(public: [Field; 5], slot: u32) -> [Field; 3] {
    if slot < C3_SLOTS {
        assert(public[2] == (slot / L_THRESHOLD) as Field, "leaf party differs from its slot");
        assert(public[3] == (slot % L_THRESHOLD) as Field, "leaf modulus differs from its slot");
    }
    [public[0], public[1], public[4]]
}

/// A leaf at `slot` naming that slot's party and modulus.
fn leaf_at(slot: u32) -> [Field; 5] {
    [1, 2, (slot / L_THRESHOLD) as Field, (slot % L_THRESHOLD) as Field, 3]
}

#[test]
fn a_real_leaf_at_its_slot_writes_pk_msg_and_ct() {
    let slot = C3_SLOTS - 1;
    assert(leaf_row(leaf_at(slot), slot) == [1, 2, 3]);
}

#[test(should_fail_with = "leaf party differs from its slot")]
fn a_real_leaf_of_another_party_is_rejected() {
    let slot = C3_SLOTS - 1;
    let mut public = leaf_at(slot);
    public[2] += 1;
    let _ = leaf_row(public, slot);
}

#[test(should_fail_with = "leaf modulus differs from its slot")]
fn a_real_leaf_of_another_modulus_is_rejected() {
    let slot = C3_SLOTS - 1;
    let mut public = leaf_at(slot);
    public[3] += 1;
    let _ = leaf_row(public, slot);
}

#[test]
fn an_empty_place_is_not_bound_to_a_slot() {
    // The repeated leaf belongs to another slot; the sentinel neither checks nor writes it.
    let _ = leaf_row(leaf_at(0), C3_SLOTS);
}
