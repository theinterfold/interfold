// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2b over a verified chunk chain. Verifies the `SHARE_COMPUTATION_E_SM_N_CHUNKS` chunk proofs (the
//! last with the last-chunk key, the others with the full-chunk key), opens C1's `e_sm` commitment
//! and checks the chain dealt that `e_sm`, from fresh sponges to the share commitments it returns.
//! See `lib::core::dkg::share_computation_chain`.
//!
//! Public: `[expected_secret_commitment, shares[N_PARTIES][L], key_tree]`, as for C2a.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{
    L_THRESHOLD, N, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_E_SM_BIT_SECRET,
    SHARE_COMPUTATION_E_SM_CHUNK_SIZE, SHARE_COMPUTATION_E_SM_CONFIGS,
    SHARE_COMPUTATION_E_SM_LAST_CHUNK_SIZE, SHARE_COMPUTATION_E_SM_N_CHUNKS,
};
use lib::configs::default::N_PARTIES;
use lib::core::dkg::share_computation_chain::e_sm_share_computation_final;
use lib::math::commitments::compute_vk_hash;
use lib::math::polynomial::Polynomial;

fn main(
    expected_secret_commitment: pub Field,
    e_sm_secret: [Polynomial<N>; L_THRESHOLD],
    full_vk: UltraHonkVerificationKey,
    full_key_hash: Field,
    last_vk: UltraHonkVerificationKey,
    last_key_hash: Field,
    chunk_proofs: [UltraHonkProof; SHARE_COMPUTATION_E_SM_N_CHUNKS],
    chunk_links: [[Field; 2]; SHARE_COMPUTATION_E_SM_N_CHUNKS],
    chain_outputs: [Field; N_PARTIES * L_THRESHOLD + 1],
) -> pub ([[Field; L_THRESHOLD]; N_PARTIES], Field) {
    // The chunks cover every coefficient once; otherwise the chain's commitment could never match
    // the one C1, C3 and C4 recompute.
    std::static_assert(
        (SHARE_COMPUTATION_E_SM_N_CHUNKS - 1) * SHARE_COMPUTATION_E_SM_CHUNK_SIZE
            + SHARE_COMPUTATION_E_SM_LAST_CHUNK_SIZE
            == N,
        "the chunk layout must cover the polynomial degree",
    );
    // The chunk's place fixes its key: only the chain's last place takes the last-chunk circuit.
    for c in 0..SHARE_COMPUTATION_E_SM_N_CHUNKS - 1 {
        verify_honk_proof_non_zk(full_vk, chunk_proofs[c], chunk_links[c], full_key_hash);
    }
    let last = SHARE_COMPUTATION_E_SM_N_CHUNKS - 1;
    verify_honk_proof_non_zk(
        last_vk,
        chunk_proofs[last],
        chunk_links[last],
        last_key_hash,
    );

    let shares = e_sm_share_computation_final::<SHARE_COMPUTATION_E_SM_N_CHUNKS, N, L_THRESHOLD, N_PARTIES, SHARE_COMPUTATION_E_SM_BIT_SECRET, SHARE_COMPUTATION_BIT_SHARE>(
        SHARE_COMPUTATION_E_SM_CONFIGS,
        expected_secret_commitment,
        e_sm_secret,
        chunk_links,
        chain_outputs,
    );
    (shares, compute_vk_hash([full_key_hash, last_key_hash].as_vector()))
}
