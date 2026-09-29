// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crisp_lib::ciphertext_addition::{CiphertextAddition, select_addend};
use crisp_lib::ecdsa::{address_to_field, derive_address, digest_from_halves, validate_signature};
use crisp_lib::utils::{check_coefficient_values_with_balance, check_coefficient_zero};
use interfold_lib::configs::default::threshold::{
    L, N, Q_MOD_T, QIS, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_K,
};
use interfold_lib::math::{
    commitments::{
        compute_ciphertext_commitment, compute_single_polynomial_commitment,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    },
    polynomial::Polynomial,
};

/// Main circuit function for CRISP vote verification, on-chain eligibility variant.
///
/// This circuit does the same work as the `crisp` circuit, but it takes the voting power of the
/// slot from the contract instead of from a census Merkle tree. The contract reads the voting
/// power from the token at the snapshot of the round, and supplies it as a public input.
///
/// The `crisp` circuit is for a census that the contract cannot compute, such as an address
/// allowlist. This circuit is for a census that comes from an on-chain token. Removing the tree
/// removes the trusted census producer, and it removes the Merkle path from each proof.
///
/// The circuit covers three operations:
/// 1. **Voting**: An eligible voter casts a ballot into an empty slot
/// 2. **Updating**: The same voter replaces the ballot in their slot
/// 3. **Masking**: Anyone adds a zero ballot to any eligible slot
///
/// Votes are stored in an on-chain Merkle tree, where each vote ciphertext is stored at a specific
/// index. A mapping stores the slot address (Ethereum address) to the index in the Merkle tree.
///   - For actual votes: the slot address must match the address derived from the signature
///   - For mask votes: the slot address can be any address (no address match required)
/// In both cases, the contract must confirm that the slot has voting power before it accepts the
/// input. The circuit cannot make that check, because it has no view of the token.
///
/// Mask votes prevent receipt sharing attacks by creating ambiguity: anyone can submit a zero vote
/// to any slot, creating a different ciphertext that decrypts to the same value. This makes it
/// impossible for a voter to prove which ciphertext was their actual vote, preventing them from
/// providing a verifiable receipt to a coercer or briber.
///
/// # One relation for all three operations
///
/// The circuit proves the same statement whichever operation is being performed:
///
/// ```text
///   new slot ciphertext = addend + ballot ciphertext
/// ```
///
/// where the ballot ciphertext is a fresh BFV encryption of `k1`, and the addend is the ciphertext
/// already in the slot for a mask, or the zero ciphertext for a vote, an update, and any input to
/// an empty slot. `is_mask_vote` chooses between them and is private, so the returned commitment,
/// the public inputs, and the published ciphertext have the same shape in every case. An observer
/// cannot tell a vote from an update from a mask; distinguishing them would mean distinguishing a
/// fresh BFV ciphertext from a sum, which is what the encryption scheme hides.
///
/// The circuit returns:
/// - `sum_ct_commitment` - the commitment to the ciphertext that becomes the slot, and the value
///   the E3 program stores and the ballot digest is built over
/// - `ct_commitment` - the commitment to the ballot ciphertext, which ties this proof to the
///   `user_data_encryption` proof in the fold circuit
/// - `k1_commitment` - the commitment to the ballot plaintext, for the same reason
///
fn main(
    // Ciphertext Addition Section
    prev_ct0is: [Polynomial<N>; L],
    prev_ct1is: [Polynomial<N>; L],
    prev_ct_commitment: pub Field,
    sum_ct0is: [Polynomial<N>; L],
    sum_ct1is: [Polynomial<N>; L],
    sum_r0is: [Polynomial<N>; L],
    sum_r1is: [Polynomial<N>; L],
    // User Data Encryption Section.
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    k1: Polynomial<N>,
    // ECDSA Section.
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    digest_hi: pub Field,
    digest_lo: pub Field,
    // Eligibility Section. The contract supplies both values.
    slot_address: pub Field,
    voting_power: pub Field,
    // Other inputs.
    is_first_vote: pub bool,
    is_mask_vote: bool,
    num_options: pub u32,
) -> pub (Field, Field, Field) {
    // ============================================================================
    // STEP 1: Pre-compute Commitments
    // ============================================================================
    // Compute commitments for ciphertext and plaintext that link this circuit to the
    // user_data_encryption circuit proofs in the fold circuit, where the 2 recursive
    // proofs are verified.
    let ct_commitment =
        compute_ciphertext_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(ct0is, ct1is);
    let k1_commitment = compute_single_polynomial_commitment::<N, USER_DATA_ENCRYPTION_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    );
    let sum_ct_commitment =
        compute_ciphertext_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(sum_ct0is, sum_ct1is);

    // ============================================================================
    // STEP 2: Eligibility
    // ============================================================================
    // There is no Merkle proof in this circuit. `slot_address` and `voting_power` are public
    // inputs that the contract sets from the token at the snapshot of the round, so the prover
    // cannot change either value.
    //
    // The contract must reject an input when the slot has no voting power. That check applies to
    // actual votes and to mask votes, and it replaces the tree membership proof of the `crisp`
    // circuit.

    // ============================================================================
    // STEP 3: The Previous Ciphertext
    // ============================================================================
    // Only a mask keeps what the slot holds. A real vote replaces it, and an empty slot holds
    // nothing, so both add the ballot to the zero ciphertext. The selector is derived rather than
    // taken as a witness: a voter cannot add their new ballot on top of their old one and count
    // twice, and a masker cannot discard what the slot holds and erase a vote.
    let keep_previous = is_mask_vote & !is_first_vote;
    let addend_ct0is = select_addend(prev_ct0is, keep_previous);
    let addend_ct1is = select_addend(prev_ct1is, keep_previous);

    // A mask has to open `prev_ct_commitment`, the commitment the E3 program recorded for the entry
    // this input names as its parent. Without it a mask could add its zero ballot to a ciphertext of
    // its own choosing, and publish that as the slot.
    //
    // Asserted only where the addend is used. A vote adds to nothing, so it has nothing to open,
    // and it can write to its own slot whatever the parent turns out to be — which matters, because
    // the E3 program cannot tell whether the bytes published beside a commitment deserialize to the
    // ciphertext that commitment describes. Only the Secure Process can, and only once the input
    // window closes.
    let recomputed_prev_ct_commitment =
        compute_ciphertext_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(prev_ct0is, prev_ct1is);

    if keep_previous {
        assert(prev_ct_commitment == recomputed_prev_ct_commitment);
    }

    // ============================================================================
    // STEP 4: Ciphertext Addition
    // ============================================================================
    // Prove that sum_ct = addend_ct + ct, where ct = (ct0is, ct1is) is the ballot ciphertext and
    // sum_ct = (sum_ct0is, sum_ct1is) is what the E3 program will store for this slot.
    //
    // The verification uses commitments and the Fiat-Shamir transform with the Schwartz-Zippel
    // lemma to prove the homomorphic addition without decrypting anything.
    //
    // Asserted on every path. That is what constrains the published ciphertext: it is the ballot
    // the `user_data_encryption` proof covers, added to the ciphertext the slot already held, and
    // nothing else. Without it a submitter could publish arbitrary bytes into someone's slot.
    let ct_add: CiphertextAddition<N, L, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_CT> = CiphertextAddition::new(
        QIS,
        ct0is,
        ct1is,
        ct_commitment,
        addend_ct0is,
        addend_ct1is,
        prev_ct_commitment,
        sum_ct0is,
        sum_ct1is,
        sum_ct_commitment,
        sum_r0is,
        sum_r1is,
    );

    assert(ct_add.execute());

    // ============================================================================
    // STEP 5: Ballot Rules
    // ============================================================================
    // CASE 1: ACTUAL VOTE (is_mask_vote == false)
    //   - This is an eligible voter casting or replacing a ballot
    //   - Verify the ballot is well formed and worth no more than the voting power (valid_vote)
    //   - Validate the signature over the public digest (valid_signature) to authenticate the
    //     voter for this ballot
    //   - Verify the signing address matches the slot address (valid_address)
    //
    // CASE 2: MASK VOTE (is_mask_vote == true)
    //   - This is anyone adding a zero ballot to mask slot activity
    //   - Verify the plaintext is zero everywhere (valid_zero_vote), so a mask cannot change what
    //     the slot decrypts to, and cannot carry a payload a coercer could read back out of the
    //     tally
    //   - No signature is required, which is what lets a third party mask a slot at all
    let valid_vote =
        check_coefficient_values_with_balance(k1, Q_MOD_T, voting_power, num_options);

    // The digest is a public input, so the prover cannot select the message that the signature
    // covers. The contract computes the digest from the round, the slot, and this ballot, which
    // binds the signature to all three.
    let hashed_message = digest_from_halves(digest_hi, digest_lo);
    let valid_signature = validate_signature(hashed_message, public_key_x, public_key_y, signature);
    let valid_address =
        slot_address == address_to_field(derive_address(public_key_x, public_key_y));

    let valid_zero_vote = check_coefficient_zero(k1, num_options);

    if is_mask_vote {
        assert(valid_zero_vote);
    } else {
        assert(valid_vote);
        assert(valid_signature);
        assert(valid_address);
    }

    (sum_ct_commitment, ct_commitment, k1_commitment)
}
