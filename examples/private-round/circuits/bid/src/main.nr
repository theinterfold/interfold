// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof of the private round.
//!
//! One bid is two ciphertexts. Both are SIMD plaintexts with `SLOTS` = 128 slots.
//!
//! The bid ciphertext (role 0):
//!
//! ```text
//!   slot g * LEVELS + l     for g in 0..COPIES, l in 0..LEVELS    1 if l <= b, else 0
//!   slot GATE_BASE + k      for k in 0..COPIES                    1 if b >= reserve_step, else 0
//!   slot VERSION_BASE + i                                         version (i is the bidder index)
//!   every other slot                                              0
//! ```
//!
//! The thermometer of the bid is in `COPIES` = 6 lane copies, and the gate bit is in 6 slots. The
//! program uses every copy as an independent check. `b` is the private index of the highest price
//! step the bidder accepts, below `levels`, the number of steps the round has. `reserve_step`,
//! `bidder_index` and `version` are public: the contract takes them from the round and from its
//! storage, so a bidder cannot forge them.
//!
//! The mask ciphertext (role 1) holds 128 random slots that the bidder chooses. The circuit does
//! not constrain its plaintext. It only proves that the mask is a valid encryption under the same
//! committee key. The program multiplies the mask by the lane products, so the decryption of a lane
//! that is not zero is uniform and shows nothing of the demand.
//!
//! The circuit proves:
//!
//! - **The encryptions.** The Interfold user-data encryption proofs show that the ciphertexts of
//!   `ct_commitment_bid` and `ct_commitment_mask` encrypt a plaintext `k1` each, under the committee
//!   key of `pk_commitment`. The proofs take the wrapper proofs as witnesses and verify them here.
//!   The VK anchor covers the wrapper circuit and its two VK chains, so a proof of another circuit
//!   fails. Both wrappers use the same key hash, the same two chains and the same row 0 of the key.
//! - **The plaintext of the bid.** `k1` is `reverse([Q_MOD_T * m]_t)`. The SIMD map is linear, so
//!   `k1` is the combination of the rows of `TABLE_UNIT` (`k1` of the indicator of one slot) with
//!   the slot values of `m`. The circuit checks the integer equation
//!   `sum_s w_s * unit_s[j] = k1[j] + t * q[j]` for every coefficient `j`. The range check of `q`
//!   keeps both sides below `2^15`, far below the field, and `k1[j] < t`, so only the plaintext `m`
//!   satisfies the equation.
//! - **The bid.** `b < levels`, `levels` is in 2 to 16, `reserve_step < levels`,
//!   `bidder_index < MAX_BIDDERS` and `version` is 1, 2 or 3.
//! - **The commitment.** `bid_commitment = poseidon2([BID_DOMAIN, b, salt, bidder, e3_id])`.
//!   The claim circuit opens the same commitment. `bidder` and `e3_id` are public, so a copy of a
//!   commitment is useless to another bidder or in another round.
//!
//! Public inputs, in order: `ct_commitment_bid`, `ct_commitment_mask`, `bid_commitment`, `bidder`,
//! `e3_id`, `levels`, `reserve_step`, `bidder_index`, `version`, then the returned `pk_commitment`
//! and `vk_anchor`. See `circuits/PUBLIC_INPUTS.md`.
//!
//! The on-chain commitment of an l-BFV committee key covers every public-key row and the
//! relinearization key, while the encryption proofs commit only to row 0, the encryption key. The
//! client supplies the other commitments (`openLbfvKeyEnvelope`), and the circuit rebuilds the
//! on-chain commitment from them with row 0 taken from the proofs.
//!
//! The commitment of `k1` is the one with the digit asserts, so that the packing is injective and a
//! commitment has one opening. The encryption circuit range-checks `k1` to `[0, t - 1]`, and equal
//! commitments transfer that bound to this `k1`.
mod constants;

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use constants::{LEVELS, SLOTS, TABLE_N, TABLE_PLAINTEXT_MODULUS, TABLE_Q_MOD_T, TABLE_UNIT};
use interfold_lib::configs::insecure_simd::threshold::{
    GADGET_DIM, N, PLAINTEXT_MODULUS, Q_MOD_T, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
};
use interfold_lib::math::commitments::{
    compute_lbfv_key_envelope_commitment, compute_lbfv_public_key_commitment,
    compute_single_polynomial_commitment_checked, compute_vk_hash,
    DS_USER_DATA_ENCRYPTION_COMMITMENT,
};
use interfold_lib::math::polynomial::Polynomial;
use poseidon::poseidon2::Poseidon2;

/// The independent copies of every lane: the thermometer groups and the gate slots.
pub global COPIES: u32 = 6;

/// The first gate slot. The thermometer groups use the slots below it.
pub global GATE_BASE: u32 = COPIES * LEVELS;

/// The first version slot: the slot of the bidder 0. The slots between the gate slots and this one
/// are 0.
pub global VERSION_BASE: u32 = 115;

/// The most bidders of a round: the version slots.
pub global MAX_BIDDERS: u32 = SLOTS - VERSION_BASE;

/// `levels` fits in `LEVELS_BITS` bits. `LEVELS` is 16, so 8 bits are enough.
pub global LEVELS_BITS: u32 = 8;

/// The quotient of the plaintext equation is at most `105 * (t - 1) / t`: a sum has at most
/// `COPIES * LEVELS` thermometer units, `COPIES` gate units and the version (at most 3) in one unit,
/// so at most 105 terms below `t`. The quotient is below 105, so below `2^7`.
pub global QUOTIENT_BITS: u32 = 7;

/// The domain of the bid commitment: the ASCII bytes of `prnd-bid-v1`.
pub global BID_DOMAIN: Field = 0x70726e642d6269642d7631;

/// Length of the public inputs of a `user_data_encryption_chunked` wrapper proof: `ct0_vk_chain`,
/// `ct1_vk_chain`, `pk_commitment`, `ct_commitment`, `k1_commitment`.
pub global UDE_PUBLIC_LEN: u32 = 5;

/// `x` as a one-hot vector of length `M`. `x` is in `0..M`, and no other `x` has a witness.
fn one_hot<let M: u32>(x: Field) -> [Field; M] {
    // Safety: `e` is constrained below to be the one-hot vector of `x`.
    let e = unsafe { one_hot_hint::<M>(x) };
    let mut count = 0;
    let mut weighted = 0;
    for l in 0..M {
        assert(e[l] * (e[l] - 1) == 0, "the one-hot vector is boolean");
        count += e[l];
        weighted += (l as Field) * e[l];
    }
    assert(count == 1, "the index is out of range");
    assert(weighted == x, "the one-hot vector is the index");
    e
}

unconstrained fn one_hot_hint<let M: u32>(x: Field) -> [Field; M] {
    let mut e = [0; M];
    for l in 0..M {
        if x == l as Field {
            e[l] = 1;
        }
    }
    e
}

/// The integer `sum_s w_s * TABLE_UNIT[s][j]` of every coefficient `j`, for the plaintext with the
/// thermometer of `b` (one-hot `e`) in every group, the gate bit `gate` in the gate slots, `version`
/// in the slot of the bidder (`version_index[i]` is `version` for the bidder `i` and 0 otherwise)
/// and 0 elsewhere. The thermometer is the sum of the units of the slots `g * LEVELS + l'` with
/// `l' <= b`: the unit of the slot `l'` of every group enters the sum for each `e[l]` with
/// `l >= l'`. The sums of units below are constants for each `l`, so each `e[l]` enters the equation
/// with one constant row.
fn plaintext_sums(
    e: [Field; LEVELS],
    gate: Field,
    version_index: [Field; MAX_BIDDERS],
) -> [Field; N] {
    let mut sums = [0; N];
    // The prefix sum over the groups of the units of the steps `0..=l`, a constant for each `l`.
    let mut prefix = [0; N];
    for l in 0..LEVELS {
        for g in 0..COPIES {
            for j in 0..N {
                prefix[j] += TABLE_UNIT[g * LEVELS + l][j];
            }
        }
        for j in 0..N {
            sums[j] += e[l] * prefix[j];
        }
    }
    // The sum of the units of the gate slots, a constant row.
    let mut gate_row = [0; N];
    for k in 0..COPIES {
        for j in 0..N {
            gate_row[j] += TABLE_UNIT[GATE_BASE + k][j];
        }
    }
    for j in 0..N {
        sums[j] += gate * gate_row[j];
    }
    for i in 0..MAX_BIDDERS {
        for j in 0..N {
            sums[j] += version_index[i] * TABLE_UNIT[VERSION_BASE + i][j];
        }
    }
    sums
}

/// The floor of every sum over `t`, the quotient of the plaintext equation for an honest `k1`.
unconstrained fn plaintext_quotients(sums: [Field; N]) -> [Field; N] {
    let mut quotients = [0; N];
    for j in 0..N {
        quotients[j] = ((sums[j] as u64) / (PLAINTEXT_MODULUS as u64)) as Field;
    }
    quotients
}

/// `k1` is the plaintext of a bid `b` of a round with `levels` steps and the reserve step
/// `reserve_step`, from the bidder `bidder_index` with the version `version`.
pub fn check_plaintext(
    k1: Polynomial<N>,
    b: Field,
    levels: Field,
    reserve_step: Field,
    bidder_index: Field,
    version: Field,
) {
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
    std::static_assert(SLOTS == N, "the slots are the coefficients");
    std::static_assert(GATE_BASE + COPIES <= VERSION_BASE, "the gate slots overlap the version slots");

    // `levels` is a small integer first, so the comparisons below cannot wrap around the field.
    levels.assert_max_bit_size::<LEVELS_BITS>();
    assert((levels as u32 >= 2) & (levels as u32 <= LEVELS), "levels is not in 2..=LEVELS");
    let e = one_hot::<LEVELS>(b);
    // `b` is below `LEVELS` here, so the cast keeps its value.
    assert((b as u32) < (levels as u32), "the bid is not below levels");
    reserve_step.assert_max_bit_size::<LEVELS_BITS>();
    assert((reserve_step as u32) < (levels as u32), "the reserve step is not below levels");
    let index = one_hot::<MAX_BIDDERS>(bidder_index);
    assert((version - 1) * (version - 2) * (version - 3) == 0, "the version is not 1, 2 or 3");

    // The gate bit: 1 if `b >= reserve_step`. Both are below `LEVELS` here.
    let gate = ((b as u32) >= (reserve_step as u32)) as Field;
    let mut version_index = [0; MAX_BIDDERS];
    for i in 0..MAX_BIDDERS {
        version_index[i] = index[i] * version;
    }

    let sums = plaintext_sums(e, gate, version_index);
    // Safety: the equation below constrains each quotient, and the range checks keep it exact.
    let quotients = unsafe { plaintext_quotients(sums) };
    for j in 0..N {
        quotients[j].assert_max_bit_size::<QUOTIENT_BITS>();
        assert(
            sums[j] == k1.coefficients[j] + PLAINTEXT_MODULUS * quotients[j],
            "k1 is not the plaintext of the claimed bid",
        );
    }
}

/// The commitment of `k1` the user-data encryption proof exposes as its last public input.
pub fn k1_commitment(k1: Polynomial<N>) -> Field {
    compute_single_polynomial_commitment_checked::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    )
}

/// The commitment of a bid: it opens to `b` and `salt` for one bidder in one round.
pub fn compute_bid_commitment(b: Field, salt: Field, bidder: Field, e3_id: Field) -> Field {
    Poseidon2::hash([BID_DOMAIN, b, salt, bidder, e3_id], 5)
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

/// Verifies one wrapper proof and checks its public inputs against the shared values. Returns the
/// `k1_commitment` of the wrapper, for the caller to open (the bid) or to ignore (the mask).
fn verify_wrapper(
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
    // The wrapper's `pk_commitment` is the commitment of row 0, the encryption key.
    assert(ude_public_inputs[2] == pk_row0, "different encryption keys");
    assert(ude_public_inputs[3] == ct_commitment, "the proof is for another ciphertext");
    ude_public_inputs[4]
}

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    // Role 0 (the bid), then role 1 (the mask).
    user_data_encryption_proofs: [UltraHonkProof; 2],
    // Per role: ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [[Field; UDE_PUBLIC_LEN]; 2],
    user_data_encryption_key_hash: Field,
    ct_commitments: pub [Field; 2],
    bid_commitment: pub Field,
    bidder: pub Field,
    e3_id: pub Field,
    levels: pub Field,
    reserve_step: pub Field,
    bidder_index: pub Field,
    version: pub Field,
    k1: Polynomial<N>,
    b: Field,
    salt: Field,
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
) -> pub (Field, Field) {
    // A public input is part of the proof transcript, so the proof verifies only for that
    // `bidder`. The circuit also constrains it, so no compiler pass can treat it as unused.
    assert(bidder != 0);
    check_plaintext(k1, b, levels, reserve_step, bidder_index, version);
    assert(
        compute_bid_commitment(b, salt, bidder, e3_id) == bid_commitment,
        "the bid commitment does not open to the bid",
    );

    // Both wrappers share the key, the chains and the encryption key (row 0 of the committee key).
    let ct0_chain = user_data_encryption_public_inputs[0][0];
    let ct1_chain = user_data_encryption_public_inputs[0][1];
    let pk_row0 = public_key_row_commitments[0];
    let committed_bid = verify_wrapper(
        user_data_encryption_verification_key,
        user_data_encryption_proofs[0],
        user_data_encryption_public_inputs[0],
        user_data_encryption_key_hash,
        ct_commitments[0],
        pk_row0,
        ct0_chain,
        ct1_chain,
    );
    assert(k1_commitment(k1) == committed_bid, "k1 is not the encrypted plaintext");
    // The mask has no plaintext constraint: the encryption circuit range-checks its `k1`.
    let _ = verify_wrapper(
        user_data_encryption_verification_key,
        user_data_encryption_proofs[1],
        user_data_encryption_public_inputs[1],
        user_data_encryption_key_hash,
        ct_commitments[1],
        pk_row0,
        ct0_chain,
        ct1_chain,
    );

    let pk_commitment =
        committee_key_commitment(public_key_row_commitments, relinearization_key_commitment);
    let vk_anchor = compute_vk_hash([user_data_encryption_key_hash, ct0_chain, ct1_chain].as_vector());
    (pk_commitment, vk_anchor)
}

/// `k1` of the plaintext with the thermometer of `b` in the groups `0..groups`, the gate bit `gate`
/// in the first `gate_slots` gate slots, `version` in the slot of `index`, and 0 elsewhere: the
/// combination mod `t` of the units.
fn plaintext_k1(
    b: u32,
    groups: u32,
    gate: u32,
    gate_slots: u32,
    index: u32,
    version: u32,
) -> Polynomial<N> {
    let t = PLAINTEXT_MODULUS as u64;
    let mut k1 = Polynomial { coefficients: [0; N] };
    for j in 0..N {
        let mut sum: u64 = 0;
        for g in 0..groups {
            for l in 0..=b {
                sum += TABLE_UNIT[g * LEVELS + l][j] as u64;
            }
        }
        for k in 0..gate_slots {
            sum += (gate as u64) * (TABLE_UNIT[GATE_BASE + k][j] as u64);
        }
        sum += (version as u64) * (TABLE_UNIT[VERSION_BASE + index][j] as u64);
        k1.coefficients[j] = (sum % t) as Field;
    }
    k1
}

/// The honest `k1` of a bid.
fn honest_k1(b: u32, reserve_step: u32, index: u32, version: u32) -> Polynomial<N> {
    plaintext_k1(b, COPIES, (b >= reserve_step) as u32, COPIES, index, version)
}

/// `k1` plus the unit of the slot `slot`, mod `t`.
fn with_unit(k1: Polynomial<N>, slot: u32) -> Polynomial<N> {
    let t = PLAINTEXT_MODULUS as u64;
    let mut out = k1;
    for j in 0..N {
        out.coefficients[j] =
            (((k1.coefficients[j] as u64) + (TABLE_UNIT[slot][j] as u64)) % t) as Field;
    }
    out
}

fn accepts(b: u32, levels: Field, reserve_step: u32, index: u32, version: u32) {
    check_plaintext(
        honest_k1(b, reserve_step, index, version),
        b as Field,
        levels,
        reserve_step as Field,
        index as Field,
        version as Field,
    );
}

#[test]
fn accepts_an_honest_bid() {
    accepts(5, 16, 2, 3, 1);
}

#[test]
fn accepts_the_extreme_bids_indexes_and_versions() {
    accepts(0, 16, 0, 0, 1);
    accepts(LEVELS - 1, 16, LEVELS - 1, MAX_BIDDERS - 1, 3);
    accepts(0, 2, 0, 0, 3);
    accepts(1, 2, 1, MAX_BIDDERS - 1, 2);
}

#[test]
fn accepts_the_top_step_of_a_shorter_round() {
    accepts(5, 6, 3, 10, 2);
}

#[test]
fn accepts_a_bid_at_the_reserve_and_on_both_sides_of_it() {
    // The gate bit is 1 for `b >= reserve_step`, 0 below it.
    accepts(5, 16, 5, 3, 1);
    accepts(5, 16, 4, 3, 1);
    accepts(5, 16, 6, 3, 1);
    accepts(0, 16, 1, 3, 1);
    accepts(15, 16, 0, 3, 1);
}

#[test]
fn accepts_every_bid_with_the_largest_sums() {
    // The largest sums of units: the top bid sums 96 thermometer units, 6 gate units and the version.
    for b in 0..LEVELS {
        accepts(b, 16, 0, 7, 3);
        accepts(b, 16, 8, 12, 3);
    }
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_higher_bid() {
    check_plaintext(honest_k1(6, 2, 3, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_lower_bid() {
    check_plaintext(honest_k1(4, 2, 3, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_thermometer_in_fewer_groups() {
    // The thermometer in 5 of the 6 groups.
    check_plaintext(plaintext_k1(5, 5, 1, COPIES, 3, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_thermometer_in_one_group_only() {
    check_plaintext(plaintext_k1(5, 1, 1, COPIES, 3, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_another_version() {
    check_plaintext(honest_k1(5, 2, 3, 2), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_another_bidder_index() {
    check_plaintext(honest_k1(5, 2, 4, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_plaintext_with_a_second_bidder_slot() {
    // The bid of the index 3, plus the version in the slot of the index 4.
    let k1 = with_unit(honest_k1(5, 2, 3, 1), VERSION_BASE + 4);
    check_plaintext(k1, 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_non_thermometer() {
    let mut k1 = honest_k1(5, 2, 3, 1);
    k1.coefficients[3] = (((k1.coefficients[3] as u64) + 1) % (PLAINTEXT_MODULUS as u64)) as Field;
    check_plaintext(k1, 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_thermometer_with_a_gap() {
    // The slots 0..=5 and the slot 7 of the group 0, with the bid 5.
    check_plaintext(with_unit(honest_k1(5, 2, 3, 1), 7), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_first_unused_slot() {
    check_plaintext(with_unit(honest_k1(5, 2, 3, 1), GATE_BASE + COPIES), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_last_unused_slot() {
    check_plaintext(with_unit(honest_k1(5, 2, 3, 1), VERSION_BASE - 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_zero_plaintext() {
    check_plaintext(Polynomial { coefficients: [0; N] }, 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_gate_bit_of_0_for_a_bid_at_or_above_the_reserve() {
    // `b >= reserve_step`, but the gate slots are 0.
    check_plaintext(plaintext_k1(5, COPIES, 0, COPIES, 3, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_gate_bit_of_1_for_a_bid_below_the_reserve() {
    // `b < reserve_step`, but the gate slots are 1.
    check_plaintext(plaintext_k1(5, COPIES, 1, COPIES, 3, 1), 5, 16, 6, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_gate_bit_in_fewer_slots() {
    check_plaintext(plaintext_k1(5, COPIES, 1, COPIES - 1, 3, 1), 5, 16, 2, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_gate_bit_of_another_reserve() {
    // The plaintext of a bid for the reserve step 2 does not hold for the reserve step 6.
    check_plaintext(honest_k1(5, 2, 3, 1), 5, 16, 6, 3, 1);
}

#[test(should_fail)]
fn rejects_a_bid_beyond_the_slots() {
    check_plaintext(honest_k1(15, 2, 3, 1), LEVELS as Field, 16, 2, 3, 1);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_bid_equal_to_the_levels() {
    check_plaintext(honest_k1(5, 2, 3, 1), 5, 5, 2, 3, 1);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_bid_above_the_levels() {
    check_plaintext(honest_k1(9, 2, 3, 1), 9, 5, 2, 3, 1);
}

#[test(should_fail_with = "the reserve step is not below levels")]
fn rejects_a_reserve_step_equal_to_the_levels() {
    check_plaintext(honest_k1(3, 5, 3, 1), 3, 5, 5, 3, 1);
}

#[test(should_fail_with = "the reserve step is not below levels")]
fn rejects_a_reserve_step_above_the_levels() {
    check_plaintext(honest_k1(3, 9, 3, 1), 3, 5, 9, 3, 1);
}

#[test(should_fail)]
fn rejects_a_reserve_step_beyond_the_range_check() {
    // `2^32 + 1` would be 1 after a truncation to `u32`.
    check_plaintext(honest_k1(3, 1, 3, 1), 3, 5, 0x100000001, 3, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_one_level() {
    check_plaintext(honest_k1(0, 0, 3, 1), 0, 1, 0, 3, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_zero_levels() {
    check_plaintext(honest_k1(0, 0, 3, 1), 0, 0, 0, 3, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_more_levels_than_slots() {
    check_plaintext(honest_k1(0, 0, 3, 1), 0, 17, 0, 3, 1);
}

#[test(should_fail)]
fn rejects_a_levels_value_beyond_the_range_check() {
    // `2^32 + 2` would be 2 after a truncation to `u32`.
    check_plaintext(honest_k1(0, 0, 3, 1), 0, 0x100000002, 0, 3, 1);
}

#[test(should_fail_with = "the index is out of range")]
fn rejects_the_first_index_beyond_the_bidders() {
    // The slot 128 does not exist, so the plaintext of the index 13 has no table row.
    check_plaintext(honest_k1(5, 2, 0, 1), 5, 16, 2, MAX_BIDDERS as Field, 1);
}

#[test(should_fail_with = "the version is not 1, 2 or 3")]
fn rejects_version_zero() {
    check_plaintext(honest_k1(5, 2, 3, 0), 5, 16, 2, 3, 0);
}

#[test(should_fail_with = "the version is not 1, 2 or 3")]
fn rejects_version_four() {
    check_plaintext(honest_k1(5, 2, 3, 1), 5, 16, 2, 3, 4);
}

#[test]
fn the_layout_matches_the_table() {
    assert(GATE_BASE == 96);
    assert(VERSION_BASE == 115);
    assert(MAX_BIDDERS == 13);
}

#[test]
fn the_commitment_opens_for_the_bid() {
    let commitment = compute_bid_commitment(7, 12345, 0xabc, 4);
    assert(commitment == compute_bid_commitment(7, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(8, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 12346, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 12345, 0xabd, 4));
    assert(commitment != compute_bid_commitment(7, 12345, 0xabc, 5));
}
