// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One on-chain proof per auction ciphertext.
//!
//! Verifies the Interfold `user_data_encryption` proof (the ciphertext is a well-formed encryption of
//! `k1` under the committee key) and the `auction_bid` proof (`k1` is a valid ciphertext for `role`
//! of one bid `b`), and checks that both proofs talk about the same plaintext. The inner proofs stay
//! on the client.
//!
//! Public inputs, in order: `role`, `ct_commitment`, `bid_commitment`, `bidder`, then the returned
//! `pk_commitment` and `vk_anchor`. `bid_commitment` is `poseidon2(b, salt)` for the roles 0 and 1,
//! and 0 for the mask. The contract requires the same `bid_commitment` for the roles 0 and 1 of one
//! bidder. The program contract supplies the sender as `bidder`, the committee key commitment of the
//! E3 and the deployment anchor, so a proof built for another sender, another key, or with another
//! circuit in any position of the proof tree, fails verification.
//!
//! A public input is part of the proof transcript, so the proof verifies only for that `bidder`,
//! and a copy of the proof sent from another address fails. Making a new proof needs the inner
//! proofs, which never leave the bidder's machine. The circuit also constrains `bidder` to be
//! non-zero, so no compiler pass can treat it as unused.
//!
//! The on-chain commitment of an l-BFV committee key covers every public-key row and the
//! relinearization key, while the encryption proof commits only to row 0, the encryption key. The
//! client supplies the other commitments (`openLbfvKeyEnvelope`), and this circuit rebuilds the
//! on-chain commitment from them with row 0 taken from the proof.
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
// The insecure SIMD preset, like the user-data encryption circuits `compile_circuits.sh` bundles.
use interfold_lib::configs::insecure_simd::threshold::GADGET_DIM;
use interfold_lib::math::commitments::{
    compute_lbfv_key_envelope_commitment, compute_lbfv_public_key_commitment, compute_vk_hash,
};

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proof: UltraHonkProof,
    // ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [Field; 5],
    user_data_encryption_key_hash: Field,
    record_verification_key: UltraHonkVerificationKey,
    record_proof: UltraHonkProof,
    record_key_hash: Field,
    role: pub Field,
    ct_commitment: pub Field,
    bid_commitment: pub Field,
    bidder: pub Field,
    k1_commitment: Field,
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
) -> pub (Field, Field) {
    verify_honk_proof_non_zk(
        user_data_encryption_verification_key,
        user_data_encryption_proof,
        user_data_encryption_public_inputs,
        user_data_encryption_key_hash,
    );
    verify_honk_proof_non_zk(
        record_verification_key,
        record_proof,
        [role, k1_commitment, bid_commitment],
        record_key_hash,
    );

    assert(ct_commitment == user_data_encryption_public_inputs[3]);
    assert(k1_commitment == user_data_encryption_public_inputs[4]);
    assert(bidder != 0);

    // The wrapper's `pk_commitment` is `pk_aggregation(pk0, pk1)` of the encryption key: row 0.
    assert(public_key_row_commitments[0] == user_data_encryption_public_inputs[2]);
    let pk_commitment = compute_lbfv_key_envelope_commitment(
        compute_lbfv_public_key_commitment(public_key_row_commitments),
        relinearization_key_commitment,
    );

    // The same chain CRISP pins: both top-level keys, then the per-leg chains the wrapper folded
    // from every circuit below it.
    let vk_anchor = compute_vk_hash(
        [
            user_data_encryption_key_hash,
            record_key_hash,
            user_data_encryption_public_inputs[0],
            user_data_encryption_public_inputs[1],
        ]
            .as_vector(),
    );

    (pk_commitment, vk_anchor)
}
