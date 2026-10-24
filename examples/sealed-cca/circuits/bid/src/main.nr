// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof of the sealed CCA token sale.
//!
//! One bid is one ciphertext. Its SIMD plaintext `m` has `SLOTS` = 128 slots:
//!
//! ```text
//!   slot l            for l in 0..LEVELS      1 if l <= b, else 0     (the thermometer of the bid)
//!   slot LEVELS + i                           version                 (i is the index of the bidder)
//!   every other slot                          0
//! ```
//!
//! `b` is the private index of the highest price step the bidder accepts, below `levels`, the
//! number of steps the sale has. `i` and `version` are public: the contract takes them from
//! storage (`i` from the deposit of the bidder, `version` from the number of bids so far), so a
//! bidder cannot forge them. The program adds the selected ciphertexts. After the decryption, the
//! slots `0..LEVELS` hold the demand at each step, and the slot `LEVELS + i` holds the counted
//! version of the bidder `i` (0 for a bidder that the program dropped).
//!
//! The circuit proves:
//!
//! - **The encryption.** The Interfold user-data encryption proof shows that the ciphertext of
//!   `ct_commitment` encrypts a plaintext `k1` under the committee key of `pk_commitment`. The
//!   proof takes the wrapper proof as a witness and verifies it here. The VK anchor covers the
//!   wrapper circuit and its two VK chains, so a proof of another circuit fails.
//! - **The plaintext.** `k1` is `reverse([Q_MOD_T * m]_t)`. The SIMD map is linear, so `k1` is the
//!   combination of the rows of `TABLE_UNIT` (`k1` of the indicator of one slot) with the slot values
//!   of `m`. The circuit checks the integer equation `sum_s w_s * unit_s[j] = k1[j] + t * q[j]` for
//!   every coefficient `j`. Range checks keep both sides below `2^13`, far below the field, and
//!   `k1[j] < t`, so only the plaintext `m` satisfies the equation.
//! - **The bid.** `b < levels`, `levels` is in 2 to 16, `bidder_index < MAX_BIDDERS` and `version`
//!   is 1, 2 or 3.
//! - **The commitment.** `bid_commitment = poseidon2([BID_DOMAIN, b, salt, bidder, e3_id])`.
//!   The claim circuit opens the same commitment. `bidder` and `e3_id` are public, so a copy of a
//!   commitment is useless to another bidder or in another sale.
//!
//! Public inputs, in order: `ct_commitment`, `bid_commitment`, `bidder`, `e3_id`, `levels`,
//! `bidder_index`, `version`, then the returned `pk_commitment` and `vk_anchor`.
//! See `circuits/PUBLIC_INPUTS.md`.
//!
//! The on-chain commitment of an l-BFV committee key covers every public-key row and the
//! relinearization key, while the encryption proof commits only to row 0, the encryption key. The
//! client supplies the other commitments (`openLbfvKeyEnvelope`), and the circuit rebuilds the
//! on-chain commitment from them with row 0 taken from the proof.
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

/// The most bidders of a sale: the slots after the thermometer.
pub global MAX_BIDDERS: u32 = SLOTS - LEVELS;

/// `levels` fits in `LEVELS_BITS` bits. `LEVELS` is 16, so 8 bits are enough.
pub global LEVELS_BITS: u32 = 8;

/// The quotient of the plaintext equation is below `(LEVELS + 3) * (t - 1) / t`, so below 32.
pub global QUOTIENT_BITS: u32 = 6;

/// The domain of the bid commitment: the ASCII bytes of `scca-bid-v1`.
pub global BID_DOMAIN: Field = 0x736363612d6269642d7631;

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
/// thermometer of `b` (one-hot `e`), `version` in the slot of the bidder (one-hot `index`) and 0
/// elsewhere. The thermometer is the sum of the units of the slots `0..=b`: the weight of the unit
/// `s` is `sum_{l >= s} e[l]`, so the unit of the slot `s` enters the sum for each `e[l]` with
/// `l >= s`. The sums of units below are constants.
fn plaintext_sums(
    e: [Field; LEVELS],
    index: [Field; SLOTS - LEVELS],
    version: Field,
) -> [Field; N] {
    let mut sums = [0; N];
    // The prefix sum of the units of the slots `0..=l`, a constant for each `l`.
    let mut prefix = [0; N];
    for l in 0..LEVELS {
        for j in 0..N {
            prefix[j] += TABLE_UNIT[l][j];
        }
        for j in 0..N {
            sums[j] += e[l] * prefix[j];
        }
    }
    for j in 0..N {
        let mut selected = 0;
        for i in 0..(SLOTS - LEVELS) {
            selected += index[i] * TABLE_UNIT[LEVELS + i][j];
        }
        sums[j] += version * selected;
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

/// `k1` is the plaintext of a bid `b` of a sale with `levels` steps, from the bidder `bidder_index`
/// with the version `version`.
pub fn check_plaintext(
    k1: Polynomial<N>,
    b: Field,
    levels: Field,
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

    // `levels` is a small integer first, so the comparisons below cannot wrap around the field.
    levels.assert_max_bit_size::<LEVELS_BITS>();
    assert((levels as u32 >= 2) & (levels as u32 <= LEVELS), "levels is not in 2..=LEVELS");
    let e = one_hot::<LEVELS>(b);
    // `b` is below `LEVELS` here, so the cast keeps its value.
    assert((b as u32) < (levels as u32), "the bid is not below levels");
    let index = one_hot::<SLOTS - LEVELS>(bidder_index);
    assert((version - 1) * (version - 2) * (version - 3) == 0, "the version is not 1, 2 or 3");

    let sums = plaintext_sums(e, index, version);
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

/// The commitment of a bid: it opens to `b` and `salt` for one bidder in one sale.
pub fn compute_bid_commitment(b: Field, salt: Field, bidder: Field, e3_id: Field) -> Field {
    Poseidon2::hash([BID_DOMAIN, b, salt, bidder, e3_id], 5)
}

/// The on-chain commitment of the committee key, from row 0 of the proof and the other
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

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proof: UltraHonkProof,
    // ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [Field; UDE_PUBLIC_LEN],
    user_data_encryption_key_hash: Field,
    ct_commitment: pub Field,
    bid_commitment: pub Field,
    bidder: pub Field,
    e3_id: pub Field,
    levels: pub Field,
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
    check_plaintext(k1, b, levels, bidder_index, version);
    assert(
        compute_bid_commitment(b, salt, bidder, e3_id) == bid_commitment,
        "the bid commitment does not open to the bid",
    );

    // The wrapper's `pk_commitment` is the commitment of row 0, the encryption key.
    let pk_row0 = public_key_row_commitments[0];
    verify_honk_proof_non_zk(
        user_data_encryption_verification_key,
        user_data_encryption_proof,
        user_data_encryption_public_inputs,
        user_data_encryption_key_hash,
    );
    assert(user_data_encryption_public_inputs[2] == pk_row0, "different encryption keys");
    assert(
        user_data_encryption_public_inputs[3] == ct_commitment,
        "the proof is for another ciphertext",
    );
    assert(
        k1_commitment(k1) == user_data_encryption_public_inputs[4],
        "k1 is not the encrypted plaintext",
    );

    let pk_commitment =
        committee_key_commitment(public_key_row_commitments, relinearization_key_commitment);
    let ct0_chain = user_data_encryption_public_inputs[0];
    let ct1_chain = user_data_encryption_public_inputs[1];
    let vk_anchor = compute_vk_hash([user_data_encryption_key_hash, ct0_chain, ct1_chain].as_vector());
    (pk_commitment, vk_anchor)
}

/// `k1` of the plaintext with the thermometer of `b`, `version` in the slot of `index`, and 0
/// elsewhere: the combination mod `t` of the units.
fn honest_k1(b: u32, index: u32, version: u32) -> Polynomial<N> {
    let t = PLAINTEXT_MODULUS as u64;
    let mut k1 = Polynomial { coefficients: [0; N] };
    for j in 0..N {
        let mut sum: u64 = 0;
        for s in 0..=b {
            sum += TABLE_UNIT[s][j] as u64;
        }
        sum += (version as u64) * (TABLE_UNIT[LEVELS + index][j] as u64);
        k1.coefficients[j] = (sum % t) as Field;
    }
    k1
}

fn accepts(b: u32, levels: Field, index: u32, version: u32) {
    check_plaintext(
        honest_k1(b, index, version),
        b as Field,
        levels,
        index as Field,
        version as Field,
    );
}

#[test]
fn accepts_an_honest_bid() {
    accepts(5, 16, 3, 1);
}

#[test]
fn accepts_the_extreme_bids_indexes_and_versions() {
    accepts(0, 16, 0, 1);
    accepts(LEVELS - 1, 16, MAX_BIDDERS - 1, 3);
    accepts(0, 2, 0, 3);
    accepts(1, 2, 111, 2);
}

#[test]
fn accepts_the_top_step_of_a_shorter_sale() {
    accepts(5, 6, 10, 2);
}

#[test]
fn accepts_every_bid_with_the_largest_sums() {
    // The largest sum of units: the top bid sums 16 units and the version 3 one more.
    for b in 0..LEVELS {
        accepts(b, 16, 7, 3);
    }
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_higher_bid() {
    check_plaintext(honest_k1(6, 3, 1), 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_lower_bid() {
    check_plaintext(honest_k1(4, 3, 1), 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_another_version() {
    check_plaintext(honest_k1(5, 3, 2), 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_another_bidder_index() {
    check_plaintext(honest_k1(5, 4, 1), 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_plaintext_with_a_second_bidder_slot() {
    // The bid of the index 3, plus the version in the slot of the index 4.
    let mut k1 = honest_k1(5, 3, 1);
    let t = PLAINTEXT_MODULUS as u64;
    for j in 0..N {
        k1.coefficients[j] =
            (((k1.coefficients[j] as u64) + (TABLE_UNIT[LEVELS + 4][j] as u64)) % t) as Field;
    }
    check_plaintext(k1, 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_non_thermometer() {
    let mut k1 = honest_k1(5, 3, 1);
    k1.coefficients[3] = (((k1.coefficients[3] as u64) + 1) % (PLAINTEXT_MODULUS as u64)) as Field;
    check_plaintext(k1, 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_thermometer_with_a_gap() {
    // The slots 0..=5 and the slot 7, with the bid 5.
    let mut k1 = honest_k1(5, 3, 1);
    let t = PLAINTEXT_MODULUS as u64;
    for j in 0..N {
        k1.coefficients[j] =
            (((k1.coefficients[j] as u64) + (TABLE_UNIT[7][j] as u64)) % t) as Field;
    }
    check_plaintext(k1, 5, 16, 3, 1);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_zero_plaintext() {
    check_plaintext(Polynomial { coefficients: [0; N] }, 5, 16, 3, 1);
}

#[test(should_fail)]
fn rejects_a_bid_beyond_the_slots() {
    check_plaintext(honest_k1(15, 3, 1), LEVELS as Field, 16, 3, 1);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_bid_equal_to_the_levels() {
    check_plaintext(honest_k1(5, 3, 1), 5, 5, 3, 1);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_bid_above_the_levels() {
    check_plaintext(honest_k1(9, 3, 1), 9, 5, 3, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_one_level() {
    check_plaintext(honest_k1(0, 3, 1), 0, 1, 3, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_zero_levels() {
    check_plaintext(honest_k1(0, 3, 1), 0, 0, 3, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_more_levels_than_slots() {
    check_plaintext(honest_k1(0, 3, 1), 0, 17, 3, 1);
}

#[test(should_fail)]
fn rejects_a_levels_value_beyond_the_range_check() {
    // `2^32 + 2` would be 2 after a truncation to `u32`.
    check_plaintext(honest_k1(0, 3, 1), 0, 0x100000002, 3, 1);
}

#[test(should_fail_with = "the index is out of range")]
fn rejects_the_first_index_beyond_the_bidders() {
    // The slot 128 does not exist, so the plaintext of the index 112 has no table row.
    check_plaintext(honest_k1(5, 0, 1), 5, 16, MAX_BIDDERS as Field, 1);
}

#[test(should_fail_with = "the version is not 1, 2 or 3")]
fn rejects_version_zero() {
    check_plaintext(honest_k1(5, 3, 0), 5, 16, 3, 0);
}

#[test(should_fail_with = "the version is not 1, 2 or 3")]
fn rejects_version_four() {
    check_plaintext(honest_k1(5, 3, 1), 5, 16, 3, 4);
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
