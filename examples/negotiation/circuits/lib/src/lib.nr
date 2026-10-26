// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The validity rules of a negotiation offer, shared by the two offer circuits.
//!
//! An offer is 3 ciphertexts of one party (the seller, `role` 0, or the buyer, `role` 1). All of them
//! are SIMD-encoded. Slot `g * LEVELS + i` is group `g` (0..8), level `i` (0..16). `DESIGN.md` explains
//! the encoding and `sdk/src/layout.ts` is the reference implementation.
//!
//! ```text
//!   ciphertext 0   lane tensor, lanes 0..8     slot g * 16 + i = tensor(g, i)
//!   ciphertext 1   lane tensor, lanes 8..16    slot g * 16 + i = tensor(g + 8, i)
//!   ciphertext 2   mask                        sum over g of slot g * 16 + i = 0 mod t, for each level i
//! ```
//!
//! The circuit computes the tensor from the private price `step` and the private `share` (4 bits).
//! `role` and `levels` are public. The tensor of the seller and that of the buyer are both computed, and
//! `role` selects one of them with an arithmetic selection, so the circuit has no branch.
//!
//! One proof must cover the three Interfold `user_data_encryption` proofs (each ciphertext is a
//! well-formed encryption of its `k1` under the committee key). In one circuit that is more than 2^22
//! gates, and the browser can prove at most 2^21 (the WASM heap is 4 GiB). So the offer is a tree of
//! circuits, each below 2^21 gates:
//!
//! ```text
//!   negotiation_offer_lanes   ciphertexts 0 and 1: both wrapper proofs and the lane tensor
//!   negotiation_offer         the lanes proof and the wrapper proof of the mask   (EVM verifier)
//! ```
//!
//! `k1` is the plaintext as the user-data encryption proof sees it: `reverse([Q_MOD_T * m]_t)` for the
//! plaintext polynomial `m`. The SIMD map is linear, so `k1` is the sum of the rows of `TABLE_UNIT`, each
//! row times the value of its slot, mod `t`. The circuit checks the integer equation
//! `sum_s value_s * TABLE_UNIT[s][i] = k1[i] + t * q[i]` for every coefficient `i`. A range check on `q`
//! (and, for the mask, on the values) keeps both sides below the field modulus. As `k1[i] < t`, `q[i]`
//! is the floor of the sum over `t`, so only the plaintext `sum_s value_s * unit_s mod t` satisfies the
//! equation.
//!
//! The commitment of `k1` is the one with the digit asserts, so that the packing is injective and a
//! commitment has one opening. The encryption circuit range-checks `k1` to `[0, t - 1]`, and equal
//! commitments transfer that bound to this `k1`.
//!
//! The on-chain commitment of an l-BFV committee key covers every public-key row and the
//! relinearization key, while the encryption proof commits only to row 0, the encryption key. The client
//! supplies the other commitments (`openLbfvKeyEnvelope`), and the top circuit rebuilds the on-chain
//! commitment from them with row 0 taken from the proofs.
mod constants;
mod tests;
mod vectors;

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
pub use constants::SLOTS;
use constants::{TABLE_N, TABLE_PLAINTEXT_MODULUS, TABLE_Q_MOD_T, TABLE_UNIT};
// The insecure SIMD preset, like the user-data encryption circuits `compile.sh` bundles.
use interfold_lib::configs::insecure_simd::threshold::{
    GADGET_DIM, N, PLAINTEXT_MODULUS, Q_MOD_T, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
};
use interfold_lib::math::commitments::{
    compute_lbfv_key_envelope_commitment, compute_lbfv_public_key_commitment,
    compute_single_polynomial_commitment_checked, DS_USER_DATA_ENCRYPTION_COMMITMENT,
};
use interfold_lib::math::polynomial::Polynomial;

/// The most price levels: the slots of one group. A price step is in `0..LEVELS`.
pub global LEVELS: u32 = 16;
/// The groups of `LEVELS` slots in a plaintext.
pub global GROUPS: u32 = 8;
/// The lanes of the tensor: one for each value of `SHARE_BITS` bits.
pub global LANES: u32 = 16;
/// The bits of the random share of a party.
pub global SHARE_BITS: u32 = 4;
/// The lanes that one ciphertext holds.
pub global LANES_PER_CIPHERTEXT: u32 = 8;

/// `levels` fits in `LEVELS_BITS` bits. `LEVELS` is 16, so 8 bits are enough.
pub global LEVELS_BITS: u32 = 8;
/// A mask value is below `2^MASK_VALUE_BITS`. This is more than `t - 1` and it does not matter: a value
/// `v` and `v - t` give the same plaintext mod `t`.
pub global MASK_VALUE_BITS: u32 = 9;
/// The quotient of the table equation for a mask is below `SLOTS * 2^MASK_VALUE_BITS * t / t`, so
/// below `2^16`.
pub global MASK_QUOTIENT_BITS: u32 = 16;
/// The quotient of the table equation for a lane ciphertext (every value is 0 or 1) is below
/// `SLOTS * (t - 1) / t`, so below `2^7`.
pub global LANE_QUOTIENT_BITS: u32 = 7;
/// The sum over the groups of a mask level is `t * z`: it is below `GROUPS * 2^MASK_VALUE_BITS`, so
/// `z` is below `2^MASK_ZERO_SUM_BITS`.
pub global MASK_ZERO_SUM_BITS: u32 = 4;

/// Length of the public inputs of a `user_data_encryption_chunked` wrapper proof: `ct0_vk_chain`,
/// `ct1_vk_chain`, `pk_commitment`, `ct_commitment`, `k1_commitment`.
pub global UDE_PUBLIC_LEN: u32 = 5;
/// `ct_commitment[0]`, `ct_commitment[1]`, `role`, `levels`, then `pk_row0`, `ude_key_hash`,
/// `ct0_chain` and `ct1_chain`: the public inputs of `negotiation_offer_lanes`.
pub global LANES_PUBLIC_LEN: u32 = 8;

/// The step `step` as a one-hot vector. `step` is in `0..LEVELS`, and no other value has a witness.
fn one_hot(step: Field) -> [Field; LEVELS] {
    // Safety: `e` is constrained below to be the one-hot vector of `step`.
    let e = unsafe { one_hot_hint(step) };
    let mut count = 0;
    let mut weighted = 0;
    for l in 0..LEVELS {
        assert(e[l] * (e[l] - 1) == 0, "the one-hot vector is boolean");
        count += e[l];
        weighted += (l as Field) * e[l];
    }
    assert(count == 1, "the step is in 0..LEVELS");
    assert(weighted == step, "the one-hot vector is the step");
    e
}

unconstrained fn one_hot_hint(step: Field) -> [Field; LEVELS] {
    let mut e = [0; LEVELS];
    for l in 0..LEVELS {
        if step == l as Field {
            e[l] = 1;
        }
    }
    e
}

/// The bits of `share`, least significant first. `share` is in `0..LANES`.
fn share_bits(share: Field) -> [Field; SHARE_BITS] {
    // Safety: `bits` is constrained below to be the binary decomposition of `share`.
    let bits = unsafe { share_bits_hint(share) };
    let mut weighted = 0;
    let mut weight = 1;
    for k in 0..SHARE_BITS {
        assert(bits[k] * (bits[k] - 1) == 0, "the share bits are boolean");
        weighted += bits[k] * weight;
        weight *= 2;
    }
    assert(weighted == share, "the share is not below LANES");
    bits
}

unconstrained fn share_bits_hint(share: Field) -> [Field; SHARE_BITS] {
    let value = share as u64;
    let mut bits = [0; SHARE_BITS];
    for k in 0..SHARE_BITS {
        bits[k] = ((value >> (k as u64)) & 1) as Field;
    }
    bits
}

/// Bit `k` of `value`.
fn bit(value: u32, k: u32) -> u32 {
    (value >> k) & 1
}

/// The largest level below `i` that beats `i` when the pointer bit `k` is 0 and `i` has the bit `k`:
/// `i` with the bit `k` cleared and every lower bit set. See `leftReach` in `sdk/src/layout.ts`.
fn left_reach(i: u32, k: u32) -> u32 {
    ((i >> (k + 1)) << (k + 1)) | ((1 << k) - 1)
}

/// The smallest level above `i` that beats `i` when the pointer bit `k` is 1 and `i` has not the bit
/// `k`: `i` with the bit `k` set and every lower bit cleared. See `rightReach` in `sdk/src/layout.ts`.
fn right_reach(i: u32, k: u32) -> u32 {
    ((i >> (k + 1)) << (k + 1)) | (1 << k)
}

/// The pointer bit `k` of the lane `theta` against the party's own share bit: `share_k xor theta_k`.
fn pointer_bit(share_bits: [Field; SHARE_BITS], theta: u32, k: u32) -> Field {
    if bit(theta, k) == 1 {
        1 - share_bits[k]
    } else {
        share_bits[k]
    }
}

/// The seller's tensor entry of the lane `theta` at the level `i`. `le[c]` is `[step <= c]`.
fn seller_entry(le: [Field; LEVELS], share_bits: [Field; SHARE_BITS], theta: u32, i: u32) -> Field {
    let mut entry = le[i];
    for k in 0..SHARE_BITS {
        let pointer = pointer_bit(share_bits, theta, k);
        if bit(i, k) == 1 {
            // The own side: the factor is 0 if the pointer bit is 0 and a level in reach beats `i`.
            entry *= 1 - (1 - pointer) * le[left_reach(i, k)];
        } else {
            // The other side: the lane holds the own bit.
            entry *= 1 - pointer;
        }
    }
    entry
}

/// The buyer's tensor entry of the lane `theta` at the level `i`. `ge[c]` is `[step >= c]`.
fn buyer_entry(ge: [Field; LEVELS], share_bits: [Field; SHARE_BITS], theta: u32, i: u32) -> Field {
    let mut entry = ge[i];
    for k in 0..SHARE_BITS {
        let pointer = pointer_bit(share_bits, theta, k);
        if bit(i, k) == 0 {
            // The own side: the factor is 0 if the pointer bit is 1 and a level in reach beats `i`.
            entry *= 1 - pointer * ge[right_reach(i, k)];
        } else {
            // The other side: the lane holds the own bit.
            entry *= 1 - pointer;
        }
    }
    entry
}

/// The 128 slots of the lane ciphertexts of the party `role` with the price `step` and the share
/// `share`: lanes 0..8 in the first array, lanes 8..16 in the second, as `laneSlots` in
/// `sdk/src/layout.ts`. `role` must be 0 or 1, `step` in `0..LEVELS`, `share` in `0..LANES`.
pub fn lane_slots(role: Field, step: Field, share: Field) -> [[Field; SLOTS]; 2] {
    assert(role * (role - 1) == 0, "the role is not 0 or 1");
    let e = one_hot(step);
    let bits = share_bits(share);
    // `le[c]` is the sum of `e[l]` for `l <= c`, `ge[c]` the sum for `l >= c`.
    let mut le = [0; LEVELS];
    let mut ge = [0; LEVELS];
    let mut run = 0;
    for l in 0..LEVELS {
        run += e[l];
        le[l] = run;
        ge[l] = 1 - run + e[l];
    }
    let mut slots = [[0; SLOTS]; 2];
    for theta in 0..LANES {
        for i in 0..LEVELS {
            let seller = seller_entry(le, bits, theta, i);
            let buyer = buyer_entry(ge, bits, theta, i);
            let half = theta / LANES_PER_CIPHERTEXT;
            let slot = (theta % LANES_PER_CIPHERTEXT) * LEVELS + i;
            slots[half][slot] = seller + role * (buyer - seller);
        }
    }
    slots
}

/// The integer `sum_s values[s] * TABLE_UNIT[s][i]` of every coefficient `i`.
fn slot_sums(values: [Field; SLOTS]) -> [Field; N] {
    let mut sums = [0; N];
    for i in 0..N {
        for s in 0..SLOTS {
            sums[i] += values[s] * TABLE_UNIT[s][i];
        }
    }
    sums
}

/// The floor of every slot sum over `t`, the quotient of the table equation for an honest `k1`.
unconstrained fn slot_quotients(values: [Field; SLOTS]) -> [Field; N] {
    let sums = slot_sums(values);
    let mut quotients = [0; N];
    for i in 0..N {
        quotients[i] = ((sums[i] as u64) / (PLAINTEXT_MODULUS as u64)) as Field;
    }
    quotients
}

/// `k1` is the combination mod `t` of the units of `TABLE_UNIT` with the weights `values`: the
/// plaintext with the slot values `values`. The caller bounds `values` so that the quotient of the
/// equation is below `2^QUOTIENT_BITS`.
pub fn k1_is_slots<let QUOTIENT_BITS: u32>(k1: Polynomial<N>, values: [Field; SLOTS]) {
    // The table is generated for the parameters of the preset.
    std::static_assert(TABLE_N == N, "the table is for another degree");
    std::static_assert(
        TABLE_PLAINTEXT_MODULUS == PLAINTEXT_MODULUS,
        "the table is for another plaintext modulus",
    );
    std::static_assert(
        TABLE_Q_MOD_T == Q_MOD_T,
        "the table is for another modulus chain",
    );
    // Safety: the equation below constrains each quotient, and the range check keeps it exact.
    let quotients = unsafe { slot_quotients(values) };
    for i in 0..N {
        quotients[i].assert_max_bit_size::<QUOTIENT_BITS>();
    }
    let sums = slot_sums(values);
    for i in 0..N {
        assert(
            sums[i] == k1.coefficients[i] + PLAINTEXT_MODULUS * quotients[i],
            "k1 is not the plaintext of the claimed slots",
        );
    }
}

/// The public parameters of an offer are valid: `role` is 0 or 1, `levels` is in `2..=LEVELS`, and
/// `step` is below `levels`. (`lane_slots` checks the range of `step` and `role` again.)
pub fn check_parameters(role: Field, levels: Field, step: Field) {
    assert(role * (role - 1) == 0, "the role is not 0 or 1");
    // `levels` is a small integer first, so the comparisons below cannot wrap around the field.
    levels.assert_max_bit_size::<LEVELS_BITS>();
    assert((levels as u32 >= 2) & (levels as u32 <= LEVELS), "levels is not in 2..=LEVELS");
    // `step` is below `LEVELS` (`lane_slots`), so the cast keeps its value.
    step.assert_max_bit_size::<LEVELS_BITS>();
    assert((step as u32) < (levels as u32), "the step is not below levels");
}

/// `k1s` are the lane ciphertexts of the party `role` with the price `step` and the share `share`, for
/// a negotiation of `levels` price levels.
pub fn check_lanes(k1s: [Polynomial<N>; 2], role: Field, levels: Field, step: Field, share: Field) {
    check_parameters(role, levels, step);
    let slots = lane_slots(role, step, share);
    k1_is_slots::<LANE_QUOTIENT_BITS>(k1s[0], slots[0]);
    k1_is_slots::<LANE_QUOTIENT_BITS>(k1s[1], slots[1]);
}

/// `k1` is a mask: the plaintext of the private slot values `mask`, with zero sum mod `t` over the 8
/// groups of every level.
pub fn check_mask(k1: Polynomial<N>, mask: [Field; SLOTS]) {
    for s in 0..SLOTS {
        mask[s].assert_max_bit_size::<MASK_VALUE_BITS>();
    }
    // Zero sum: the integer sum over the groups of a level is `t * z` with a small `z`. The sum is
    // below `GROUPS * 2^MASK_VALUE_BITS`, so it does not wrap around the field.
    for i in 0..LEVELS {
        let mut sum = 0;
        for g in 0..GROUPS {
            sum += mask[g * LEVELS + i];
        }
        // Safety: the assert below constrains `z`.
        let z = unsafe { zero_sum_quotient(sum) };
        z.assert_max_bit_size::<MASK_ZERO_SUM_BITS>();
        assert(sum == PLAINTEXT_MODULUS * z, "the mask does not sum to 0 over the groups");
    }
    k1_is_slots::<MASK_QUOTIENT_BITS>(k1, mask);
}

unconstrained fn zero_sum_quotient(sum: Field) -> Field {
    ((sum as u64) / (PLAINTEXT_MODULUS as u64)) as Field
}

/// The commitment of `k1` the user-data encryption proof exposes as its last public input.
pub fn k1_commitment(k1: Polynomial<N>) -> Field {
    compute_single_polynomial_commitment_checked::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    )
}

/// Verifies the wrapper proof of one ciphertext, and that it is about `ct_commitment` and about the key
/// row and VK chains every other wrapper proof of the offer uses.
///
/// `ude_public_inputs` is `ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment,
/// k1_commitment`. The `k1_commitment` is returned for the caller to open.
pub fn verify_wrapper(
    verification_key: UltraHonkVerificationKey,
    proof: UltraHonkProof,
    ude_public_inputs: [Field; UDE_PUBLIC_LEN],
    ude_key_hash: Field,
    ct_commitment: Field,
    pk_row0: Field,
    ct0_chain: Field,
    ct1_chain: Field,
) -> Field {
    verify_honk_proof_non_zk(verification_key, proof, ude_public_inputs, ude_key_hash);
    assert(ude_public_inputs[0] == ct0_chain, "different ct0 vk chains");
    assert(ude_public_inputs[1] == ct1_chain, "different ct1 vk chains");
    // The wrapper's `pk_commitment` is `pk_aggregation(pk0, pk1)` of the encryption key: row 0.
    assert(ude_public_inputs[2] == pk_row0, "different encryption keys");
    assert(ude_public_inputs[3] == ct_commitment, "the proof is for another ciphertext");
    ude_public_inputs[4]
}

/// The on-chain commitment of the committee key, from row 0 of the proofs and the other
/// commitments the client opens.
pub fn committee_key_commitment(
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
) -> Field {
    compute_lbfv_key_envelope_commitment(
        compute_lbfv_public_key_commitment(public_key_row_commitments),
        relinearization_key_commitment,
    )
}
