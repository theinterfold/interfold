// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof of the token launch.
//!
//! One bid is ONE plaintext `m`, encrypted twice: once under the committee key of each of the two
//! E3s of the sale (round 1 and round 2), with independent randomness. One proof covers both
//! ciphertexts. `m` has `TABLE_N` = 128 SIMD slots:
//!
//! ```text
//!   slot l * LANES + j      d_j if l <= b, else 0       (cell (l, j): digit j of the budget B)
//!   slot FLAG_BASE + i / 8  2^(i % 8)                   (i is the index of the bidder)
//!   every other slot        0
//! ```
//!
//! `b` is the private index of the highest price step the bidder accepts, below `levels`. `B` is
//! the private budget in budget units, with the base-4 digits `d_0..d_5` (little endian). `i`,
//! `levels` and the escrow `X` are public: the contract takes them from the sale and from storage,
//! so a bidder cannot forge them. The program only adds the selected ciphertexts, so after the
//! decryption the cell `(l, j)` holds the sum of the digits `j` of the budgets of the counted bids
//! with step `>= l`, and the flag cells hold the bitmap of the counted bids.
//!
//! The circuit proves:
//!
//! - **The encryption**, twice. The Interfold user-data encryption proof of each ciphertext shows
//!   that it encrypts a plaintext `k1` under the key of that E3. The proofs are witnesses and are
//!   verified here. Both use the same wrapper circuit, and the VK anchor covers it and its two VK
//!   chains, so a proof of another circuit fails.
//! - **The plaintext.** `k1` is `reverse([Q_MOD_T * m]_t)`. The SIMD map is linear, so `k1` is the
//!   combination of the rows of `TABLE_UNIT` (`k1` of the indicator of one slot) with the slot
//!   values of `m`. The circuit checks the integer equation
//!   `sum_c v_c * unit_c[j] = k1[j] + t * q[j]` for every coefficient `j`. Every `v_c` is a small
//!   integer by construction, so the left side is below `QUOTIENT_BITS`-bit quotients times `t`, far
//!   below the field, and `k1[j] < t`: only the plaintext `m` satisfies the equation. The same `k1`
//!   is committed in both wrappers, so both ciphertexts hold the same `m`.
//! - **The bid.** The digits are below 4, `B = sum d_j * 4^j`, `1 <= B <= X <= 4095`, `b < levels`,
//!   `levels` is in 8 to 16, `bidder_index < MAX_BIDDERS`, `bidder != 0`.
//! - **The commitment.** `bid_commitment = Poseidon2([BID_DOMAIN, b, B, X, salt, bidder, sale_id])`.
//!   The claim circuit opens the same commitment. `bidder` and `sale_id` are public, so a copy of
//!   a commitment is useless to another bidder or in another sale.
//!
//! Public inputs, in order: `ct_commitment_1`, `ct_commitment_2`, `bid_commitment`, `bidder`,
//! `sale_id`, `levels`, `bidder_index`, `escrow_units`, then the returned `pk_commitment_1`,
//! `pk_commitment_2` and `vk_anchor`. See `circuits/PUBLIC_INPUTS.md`.
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
use constants::{
    CELLS, FLAG_BASE, FLAG_CELLS, FLAGS_PER_CELL, LANES, LEVELS_MAX, MAX_BIDDERS, QUOTIENT_BITS,
    TABLE_N, TABLE_PLAINTEXT_MODULUS, TABLE_Q_MOD_T, TABLE_UNIT,
};
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

/// A sale has at least this many price steps.
pub global MIN_LEVELS: u32 = 8;

/// `levels` fits in `LEVELS_BITS` bits. `LEVELS_MAX` is 16, so 8 bits are enough.
pub global LEVELS_BITS: u32 = 8;

/// The escrow and the budget are integers of at most `BUDGET_BITS` bits: `LANES` base-4 digits.
pub global BUDGET_BITS: u32 = 12;

/// The domain of the bid commitment: the ASCII bytes of `tlaunch-bid-v1`. The claim circuit uses
/// the same value.
pub global BID_DOMAIN: Field = 0x746c61756e63682d6269642d7631;

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

/// The integer `sum_c v_c * TABLE_UNIT[c][j]` of every coefficient `j`, for the plaintext of the
/// step one-hot `e`, the digits `digits` and the bidder one-hot `index`. The cell `(l, j)` is
/// `digits[j] * thermometer[l]`, with `thermometer[l] = sum_{l' >= l} e[l']`, the flag cell of the
/// bidder `i` is `2^(i % FLAGS_PER_CELL)`.
fn plaintext_sums(
    e: [Field; LEVELS_MAX],
    digits: [Field; LANES],
    index: [Field; MAX_BIDDERS],
) -> [Field; N] {
    let mut thermometer = [0; LEVELS_MAX];
    let mut above = 0;
    for r in 0..LEVELS_MAX {
        let l = LEVELS_MAX - 1 - r;
        above += e[l];
        thermometer[l] = above;
    }
    let mut sums = [0; N];
    for l in 0..LEVELS_MAX {
        for j in 0..LANES {
            let cell = digits[j] * thermometer[l];
            for k in 0..N {
                sums[k] += cell * TABLE_UNIT[l * LANES + j][k];
            }
        }
    }
    for i in 0..MAX_BIDDERS {
        let flag = index[i] * ((1 as u32) << (i % FLAGS_PER_CELL)) as Field;
        for k in 0..N {
            sums[k] += flag * TABLE_UNIT[FLAG_BASE + i / FLAGS_PER_CELL][k];
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

/// `k1` is the plaintext of a bid of the step `b` and the budget with the digits `digits`, from
/// the bidder `bidder_index`, in a sale with `levels` steps and the escrow `escrow_units`. Returns
/// the budget.
pub fn check_bid(
    k1: Polynomial<N>,
    digits: [Field; LANES],
    b: Field,
    levels: Field,
    bidder_index: Field,
    escrow_units: Field,
) -> Field {
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
    std::static_assert(CELLS <= TABLE_N, "the cells do not fit the slots");
    std::static_assert(
        BUDGET_BITS == 2 * LANES,
        "the budget is LANES base-4 digits",
    );

    // `levels` is a small integer first, so the comparisons below cannot wrap around the field.
    levels.assert_max_bit_size::<LEVELS_BITS>();
    assert(
        (levels as u32 >= MIN_LEVELS) & (levels as u32 <= LEVELS_MAX),
        "levels is not in 8..=16",
    );
    let e = one_hot::<LEVELS_MAX>(b);
    // `b` is below `LEVELS_MAX` here, so the cast keeps its value.
    assert((b as u32) < (levels as u32), "the bid is not below levels");
    let index = one_hot::<MAX_BIDDERS>(bidder_index);

    let mut budget = 0;
    let mut weight = 1;
    for j in 0..LANES {
        let d = digits[j];
        assert(d * (d - 1) * (d - 2) * (d - 3) == 0, "a budget digit is not below 4");
        budget += d * weight;
        weight *= 4;
    }
    escrow_units.assert_max_bit_size::<BUDGET_BITS>();
    assert(budget != 0, "the budget is zero");
    // Both are below 2^12, so the comparison cannot wrap around the field.
    assert((budget as u32) <= (escrow_units as u32), "the budget is above the escrow");

    let sums = plaintext_sums(e, digits, index);
    // Safety: the equation below constrains each quotient, and the range checks keep it exact.
    let quotients = unsafe { plaintext_quotients(sums) };
    for j in 0..N {
        quotients[j].assert_max_bit_size::<QUOTIENT_BITS>();
        assert(
            sums[j] == k1.coefficients[j] + PLAINTEXT_MODULUS * quotients[j],
            "k1 is not the plaintext of the claimed bid",
        );
    }
    budget
}

/// The commitment of `k1` the user-data encryption proof exposes as its last public input.
pub fn k1_commitment(k1: Polynomial<N>) -> Field {
    compute_single_polynomial_commitment_checked::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    )
}

/// The commitment of a bid: it opens to the step `b`, the budget and the escrow, with a salt, for
/// one bidder in one sale.
pub fn compute_bid_commitment(
    b: Field,
    budget: Field,
    escrow_units: Field,
    salt: Field,
    bidder: Field,
    sale_id: Field,
) -> Field {
    Poseidon2::hash(
        [BID_DOMAIN, b, budget, escrow_units, salt, bidder, sale_id],
        7,
    )
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
    // The two wrapper proofs: the ciphertext under the key of E3-1, the ciphertext under the key of E3-2.
    user_data_encryption_proofs: [UltraHonkProof; 2],
    // Per ciphertext: ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [[Field; UDE_PUBLIC_LEN]; 2],
    user_data_encryption_key_hash: Field,
    ct_commitments: pub [Field; 2],
    bid_commitment: pub Field,
    bidder: pub Field,
    sale_id: pub Field,
    levels: pub Field,
    bidder_index: pub Field,
    escrow_units: pub Field,
    k1: Polynomial<N>,
    digits: [Field; LANES],
    b: Field,
    salt: Field,
    public_key_row_commitments: [[Field; GADGET_DIM]; 2],
    relinearization_key_commitments: [Field; 2],
) -> pub (Field, Field, Field) {
    // A public input is part of the proof transcript, so the proof verifies only for that
    // `bidder`. The circuit also constrains it, so no compiler pass can treat it as unused.
    assert(bidder != 0);
    let budget = check_bid(k1, digits, b, levels, bidder_index, escrow_units);
    assert(
        compute_bid_commitment(b, budget, escrow_units, salt, bidder, sale_id) == bid_commitment,
        "the bid commitment does not open to the bid",
    );

    let ct0_chain = user_data_encryption_public_inputs[0][0];
    let ct1_chain = user_data_encryption_public_inputs[0][1];
    let committed_k1 = k1_commitment(k1);
    let mut pk_commitments = [0; 2];
    for r in 0..2 {
        verify_honk_proof_non_zk(
            user_data_encryption_verification_key,
            user_data_encryption_proofs[r],
            user_data_encryption_public_inputs[r],
            user_data_encryption_key_hash,
        );
        let wrapper = user_data_encryption_public_inputs[r];
        assert(wrapper[0] == ct0_chain, "different ct0 vk chains");
        assert(wrapper[1] == ct1_chain, "different ct1 vk chains");
        // The wrapper's `pk_commitment` is the commitment of row 0, the encryption key.
        assert(wrapper[2] == public_key_row_commitments[r][0], "different encryption keys");
        assert(wrapper[3] == ct_commitments[r], "the proof is for another ciphertext");
        assert(wrapper[4] == committed_k1, "k1 is not the encrypted plaintext");
        pk_commitments[r] = committee_key_commitment(
            public_key_row_commitments[r],
            relinearization_key_commitments[r],
        );
    }
    let vk_anchor = compute_vk_hash([user_data_encryption_key_hash, ct0_chain, ct1_chain].as_vector());
    (pk_commitments[0], pk_commitments[1], vk_anchor)
}

/// The slots of the plaintext of a bid, in the order of `TABLE_UNIT`.
fn bid_slots(b: u32, budget: u32, index: u32) -> [u64; CELLS] {
    let mut slots = [0; CELLS];
    for l in 0..=b {
        for j in 0..LANES {
            slots[l * LANES + j] = ((budget >> (2 * j)) & 3) as u64;
        }
    }
    slots[FLAG_BASE + index / FLAGS_PER_CELL] = ((1 as u32) << (index % FLAGS_PER_CELL)) as u64;
    slots
}

/// `k1` of the plaintext with these slots: the combination mod `t` of the units.
fn k1_of(slots: [u64; CELLS]) -> Polynomial<N> {
    let t = PLAINTEXT_MODULUS as u64;
    let mut k1 = Polynomial { coefficients: [0; N] };
    for j in 0..N {
        let mut sum: u64 = 0;
        for c in 0..CELLS {
            sum += slots[c] * (TABLE_UNIT[c][j] as u64);
        }
        k1.coefficients[j] = (sum % t) as Field;
    }
    k1
}

fn digits_of(budget: u32) -> [Field; LANES] {
    let mut digits = [0; LANES];
    for j in 0..LANES {
        digits[j] = ((budget >> (2 * j)) & 3) as Field;
    }
    digits
}

/// An honest bid is accepted, with the escrow `escrow`.
fn accepts(b: u32, levels: Field, index: u32, budget: u32, escrow: u32) {
    let got = check_bid(
        k1_of(bid_slots(b, budget, index)),
        digits_of(budget),
        b as Field,
        levels,
        index as Field,
        escrow as Field,
    );
    assert(got == budget as Field);
}

#[test]
fn accepts_an_honest_bid() {
    accepts(5, 16, 3, 1234, 2000);
}

#[test]
fn accepts_the_extreme_bids() {
    accepts(0, 16, 0, 1, 1);
    accepts(LEVELS_MAX - 1, 16, MAX_BIDDERS - 1, 4095, 4095);
    accepts(7, 8, 84, 3, 4095);
    accepts(LEVELS_MAX - 1, 16, 7, 4095, 4095);
}

#[test]
fn accepts_every_step() {
    for b in 0..LEVELS_MAX {
        accepts(b, 16, 3, 4095 - b, 4095);
    }
}

#[test]
fn accepts_every_flag_bit_and_flag_cell() {
    // Every bit of a cell (indexes 0..8), and the first and last index of every flag cell.
    for index in 0..FLAGS_PER_CELL {
        accepts(index, 16, index, 77, 100);
    }
    for cell in 0..FLAG_CELLS {
        accepts(cell, 16, cell * FLAGS_PER_CELL, 4095, 4095);
        let last = cell * FLAGS_PER_CELL + FLAGS_PER_CELL - 1;
        accepts(
            cell,
            16,
            if last < MAX_BIDDERS {
                last
            } else {
                MAX_BIDDERS - 1
            },
            5,
            4095,
        );
    }
}

#[test]
fn accepts_the_top_step_of_a_shorter_sale() {
    accepts(7, 8, 10, 100, 100);
    accepts(11, 12, 10, 100, 4095);
}

/// The honest bid of the tests below.
fn honest_slots() -> [u64; CELLS] {
    bid_slots(5, 1234, 3)
}

fn rejects_slots(slots: [u64; CELLS]) {
    let _ = check_bid(k1_of(slots), digits_of(1234), 5, 16, 3, 2000);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_plaintext_of_a_higher_step() {
    rejects_slots(bid_slots(6, 1234, 3));
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_plaintext_of_a_lower_step() {
    rejects_slots(bid_slots(4, 1234, 3));
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_plaintext_of_another_budget() {
    rejects_slots(bid_slots(5, 1235, 3));
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_plaintext_of_another_bidder_index() {
    rejects_slots(bid_slots(5, 1234, 4));
    // The same flag cell, another bit.
    rejects_slots(bid_slots(5, 1234, 2));
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_wrong_flag_weight() {
    // Index 3 sets the bit 3 of the cell 0 (weight 8); weight 16 is the bit of the index 4.
    let mut slots = honest_slots();
    slots[FLAG_BASE] = 16;
    rejects_slots(slots);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_flag_weight_of_two_bits() {
    let mut slots = honest_slots();
    slots[FLAG_BASE] = 8 + 1;
    rejects_slots(slots);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_second_flag_cell() {
    let mut slots = honest_slots();
    slots[FLAG_BASE + 1] = 1;
    rejects_slots(slots);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_cell_beyond_the_step() {
    // A digit above the thermometer: the level 6, which is above the step 5.
    let mut slots = honest_slots();
    slots[6 * LANES] = slots[0];
    rejects_slots(slots);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_cell_below_the_step_with_a_wrong_digit() {
    let mut slots = honest_slots();
    slots[2 * LANES + 2] = (slots[2 * LANES + 2] + 1) % 4;
    rejects_slots(slots);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_non_plaintext_k1() {
    let mut k1 = k1_of(honest_slots());
    k1.coefficients[3] = (((k1.coefficients[3] as u64) + 1) % (PLAINTEXT_MODULUS as u64)) as Field;
    let _ = check_bid(k1, digits_of(1234), 5, 16, 3, 2000);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_zero_plaintext() {
    let _ = check_bid(
        Polynomial { coefficients: [0; N] },
        digits_of(1234),
        5,
        16,
        3,
        2000,
    );
}

#[test(should_fail_with = "a budget digit is not below 4")]
fn rejects_a_digit_of_four() {
    // 4 + 4 * 4^0... the digits `[4, 0, ..]` have the sum 4, the same budget as `[0, 1, 0, ..]`.
    let mut digits = [0; LANES];
    digits[0] = 4;
    let _ = check_bid(k1_of(bid_slots(5, 4, 3)), digits, 5, 16, 3, 2000);
}

#[test(should_fail_with = "a budget digit is not below 4")]
fn rejects_a_negative_digit() {
    // `-1 * 1 + 1 * 4 = 3` would pass a sum check, but the digit is not in 0..4.
    let mut digits = [0; LANES];
    digits[0] = -1;
    digits[1] = 1;
    let _ = check_bid(k1_of(bid_slots(5, 3, 3)), digits, 5, 16, 3, 2000);
}

#[test(should_fail_with = "the budget is zero")]
fn rejects_a_zero_budget() {
    let _ = check_bid(k1_of(bid_slots(5, 0, 3)), [0; LANES], 5, 16, 3, 2000);
}

#[test(should_fail_with = "the budget is above the escrow")]
fn rejects_a_budget_above_the_escrow() {
    let _ = check_bid(
        k1_of(bid_slots(5, 1234, 3)),
        digits_of(1234),
        5,
        16,
        3,
        1233,
    );
}

#[test(should_fail_with = "the budget is above the escrow")]
fn rejects_the_budget_that_is_one_above_the_escrow() {
    let _ = check_bid(
        k1_of(bid_slots(5, 4095, 3)),
        digits_of(4095),
        5,
        16,
        3,
        4094,
    );
}

#[test(should_fail)]
fn rejects_an_escrow_beyond_the_budget_bits() {
    // 4096 is not a budget; its low bits (0) would be below any budget.
    let _ = check_bid(k1_of(honest_slots()), digits_of(1234), 5, 16, 3, 4096);
}

#[test(should_fail)]
fn rejects_an_escrow_that_wraps_the_u32() {
    let _ = check_bid(
        k1_of(honest_slots()),
        digits_of(1234),
        5,
        16,
        3,
        0x100000000 + 2000,
    );
}

#[test(should_fail_with = "the index is out of range")]
fn rejects_a_step_beyond_the_slots() {
    let _ = check_bid(
        k1_of(honest_slots()),
        digits_of(1234),
        LEVELS_MAX as Field,
        16,
        3,
        2000,
    );
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_step_equal_to_the_levels() {
    let _ = check_bid(k1_of(bid_slots(8, 1234, 3)), digits_of(1234), 8, 8, 3, 2000);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_step_above_the_levels() {
    let _ = check_bid(
        k1_of(bid_slots(12, 1234, 3)),
        digits_of(1234),
        12,
        9,
        3,
        2000,
    );
}

#[test(should_fail_with = "levels is not in 8..=16")]
fn rejects_seven_levels() {
    let _ = check_bid(k1_of(bid_slots(0, 1234, 3)), digits_of(1234), 0, 7, 3, 2000);
}

#[test(should_fail_with = "levels is not in 8..=16")]
fn rejects_zero_levels() {
    let _ = check_bid(k1_of(bid_slots(0, 1234, 3)), digits_of(1234), 0, 0, 3, 2000);
}

#[test(should_fail_with = "levels is not in 8..=16")]
fn rejects_seventeen_levels() {
    let _ = check_bid(k1_of(honest_slots()), digits_of(1234), 5, 17, 3, 2000);
}

#[test(should_fail)]
fn rejects_a_levels_value_beyond_the_range_check() {
    // `2^32 + 8` would be 8 after a truncation to `u32`.
    let _ = check_bid(
        k1_of(honest_slots()),
        digits_of(1234),
        5,
        0x100000008,
        3,
        2000,
    );
}

#[test(should_fail_with = "the index is out of range")]
fn rejects_the_first_index_beyond_the_bidders() {
    let _ = check_bid(
        k1_of(bid_slots(5, 1234, 0)),
        digits_of(1234),
        5,
        16,
        MAX_BIDDERS as Field,
        2000,
    );
}

#[test(should_fail_with = "the index is out of range")]
fn rejects_a_negative_index() {
    let _ = check_bid(k1_of(honest_slots()), digits_of(1234), 5, 16, -1, 2000);
}

#[test]
fn the_commitment_opens_for_the_bid() {
    let commitment = compute_bid_commitment(7, 1234, 2000, 12345, 0xabc, 4);
    assert(commitment == compute_bid_commitment(7, 1234, 2000, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(8, 1234, 2000, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 1235, 2000, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 1234, 2001, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 1234, 2000, 12346, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 1234, 2000, 12345, 0xabd, 4));
    assert(commitment != compute_bid_commitment(7, 1234, 2000, 12345, 0xabc, 5));
}

/// The value `sdk/src/commitments.ts` (Barretenberg Poseidon2) computes for the same inputs:
/// `sdk/src/prover.test.ts` pins it as well.
#[test]
fn the_commitment_equals_the_sdk_value() {
    let bidder = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    assert(
        compute_bid_commitment(7, 1500, 2000, 12345, bidder, 4)
            == 0x2324c51ea4ffd7d2c8e6f0f4f2a34c869e5781e72ebd51021d6b19e7f0771a61,
    );
}
