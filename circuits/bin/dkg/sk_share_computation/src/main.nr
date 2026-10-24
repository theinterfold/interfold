// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2a over a verified chunk chain. Verifies the `SHARE_COMPUTATION_SK_N_CHUNKS` chunk proofs (the
//! last with the last-chunk key, the others with the full-chunk key), opens C1's `sk` commitment and
//! checks the chain dealt that `sk`, from fresh sponges to the share commitments it returns. See
//! `lib::core::dkg::share_computation_chain`.
//!
//! Public: `[expected_secret_commitment, shares[N_PARTIES][L], key_tree]`, where `key_tree` hashes
//! the full-chunk and last-chunk keys. The first `1 + N_PARTIES * L` fields are the unchunked C2a's
//! public inputs.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{
    L_THRESHOLD, N, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_SK_BIT_SECRET,
    SHARE_COMPUTATION_SK_N_CHUNKS,
};
use lib::configs::default::N_PARTIES;
use lib::core::dkg::share_computation_chain::sk_share_computation_final;
use lib::math::commitments::compute_vk_hash;
use lib::math::polynomial::Polynomial;

fn main(
    expected_secret_commitment: pub Field,
    sk_secret: Polynomial<N>,
    full_vk: UltraHonkVerificationKey,
    full_key_hash: Field,
    last_vk: UltraHonkVerificationKey,
    last_key_hash: Field,
    chunk_proofs: [UltraHonkProof; SHARE_COMPUTATION_SK_N_CHUNKS],
    chunk_links: [[Field; 2]; SHARE_COMPUTATION_SK_N_CHUNKS],
    chain_outputs: [Field; N_PARTIES * L_THRESHOLD + 1],
) -> pub ([[Field; L_THRESHOLD]; N_PARTIES], Field) {
    // The chunk's place fixes its key: only the chain's last place takes the last-chunk circuit.
    for c in 0..SHARE_COMPUTATION_SK_N_CHUNKS - 1 {
        verify_honk_proof_non_zk(full_vk, chunk_proofs[c], chunk_links[c], full_key_hash);
    }
    let last = SHARE_COMPUTATION_SK_N_CHUNKS - 1;
    verify_honk_proof_non_zk(
        last_vk,
        chunk_proofs[last],
        chunk_links[last],
        last_key_hash,
    );

    let shares = sk_share_computation_final::<SHARE_COMPUTATION_SK_N_CHUNKS, N, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_SK_BIT_SECRET, SHARE_COMPUTATION_BIT_SHARE>(
        expected_secret_commitment,
        sk_secret,
        chunk_links,
        chain_outputs,
    );
    (shares, compute_vk_hash([full_key_hash, last_key_hash].as_vector()))
}
