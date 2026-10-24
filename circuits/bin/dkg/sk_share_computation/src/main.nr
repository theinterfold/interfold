// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2a over a verified chunk chain. Verifies the `SHARE_COMPUTATION_N_BATCHES` batch proofs,
//! opens C1's `sk` commitment and checks the chain dealt that `sk`, from fresh sponges to the
//! share commitments it returns. See `lib::core::dkg::share_computation_chain`.
//!
//! Public: `[expected_secret_commitment, shares[N_PARTIES][L], key_tree]`, where `key_tree` hashes
//! the batch key and the two chunk keys. The first `1 + N_PARTIES * L` fields are the unchunked
//! C2a's public inputs.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{
    L_THRESHOLD, N, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_N_BATCHES,
    SHARE_COMPUTATION_SK_BIT_SECRET,
};
use lib::configs::default::N_PARTIES;
use lib::core::dkg::share_computation_chain::sk_share_computation_final;
use lib::math::commitments::compute_vk_hash;
use lib::math::polynomial::Polynomial;

fn main(
    expected_secret_commitment: pub Field,
    sk_secret: Polynomial<N>,
    batch_vk: UltraHonkVerificationKey,
    batch_key_hash: Field,
    batch_proofs: [UltraHonkProof; SHARE_COMPUTATION_N_BATCHES],
    batch_publics: [[Field; 5]; SHARE_COMPUTATION_N_BATCHES],
    chain_outputs: [Field; N_PARTIES * L_THRESHOLD + 1],
) -> pub ([[Field; L_THRESHOLD]; N_PARTIES], Field) {
    let mut batch_indices = [0; SHARE_COMPUTATION_N_BATCHES];
    let mut batch_links = [[0; 2]; SHARE_COMPUTATION_N_BATCHES];
    for b in 0..SHARE_COMPUTATION_N_BATCHES {
        verify_honk_proof_non_zk(batch_vk, batch_proofs[b], batch_publics[b], batch_key_hash);
        assert(batch_publics[b][1] == batch_publics[0][1], "Chunk key mismatch");
        assert(batch_publics[b][2] == batch_publics[0][2], "Chunk key mismatch");
        batch_indices[b] = batch_publics[b][0];
        batch_links[b] = [batch_publics[b][3], batch_publics[b][4]];
    }

    let shares = sk_share_computation_final::<SHARE_COMPUTATION_N_BATCHES, N, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_SK_BIT_SECRET, SHARE_COMPUTATION_BIT_SHARE>(
        expected_secret_commitment,
        sk_secret,
        batch_indices,
        batch_links,
        chain_outputs,
    );
    let key_tree = compute_vk_hash([batch_key_hash, batch_publics[0][1], batch_publics[0][2]]
        .as_vector());
    (shares, key_tree)
}
