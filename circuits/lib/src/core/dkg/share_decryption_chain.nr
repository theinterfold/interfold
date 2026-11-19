// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Share decryption (C4) split by CRT limb, with C4's commitments unchanged.
//!
//! C4 opens `H * L` share commitments, which at 28 honest parties is a 2^24 circuit. The openings
//! and sums are independent per limb, and the aggregate commitment C6 reads is one SAFE sponge over
//! the normalized limbs in order (limb 0, then 1, then 2). So limb `l`'s proof runs C4's statement
//! for that limb ([`aggregate_limb`]) and continues the aggregate sponge from the state limb
//! `l - 1` left; the last limb squeezes the commitment the unchunked C4 returns.
//!
//! Each limb packs into its own carriers, so a limb can start mid-block. The start position follows
//! from the limb index alone, so each limb has its own circuit and every absorb position is known
//! when it is compiled.
//!
//! **Links.** Limb `l` proves `out` from `h_in`, a hash of the carried sponge state; `out` is the
//! next limb's `h_in`, or the aggregate commitment for the last limb. The final C4 circuit verifies
//! every limb, links them and starts the chain from the fresh sponge.

use crate::core::dkg::share_decryption::aggregate_limb;
use crate::math::commitments::{
    compute_commitment, DS_AGGREGATED_SHARES, DS_SHARE_DECRYPTION_CHAIN_STATE,
};
use crate::math::helpers::{pack, packing_layout};
use crate::math::polynomial::Polynomial;
use crate::math::safe::{absorb_from, initial_state, squeeze_one_after_absorb, STATE_SIZE};

/// SAFE IO pattern of the aggregate commitment (`compute_aggregated_shares_commitment`).
pub fn aggregated_io_pattern<let N: u32, let L: u32, let BIT_AGG: u32>() -> [u32; 2] {
    let (_, group) = packing_layout::<BIT_AGG>();
    [0x80000000 | (L * ((N + group - 1) / group)), 1]
}

/// The aggregate sponge's absorb position when limb `LIMB` starts: the earlier limbs absorbed
/// `LIMB` limbs' carriers.
fn limb_start_pos<let N: u32, let BIT_AGG: u32, let LIMB: u32>() -> u32 {
    let (_, group) = packing_layout::<BIT_AGG>();
    let absorbed = LIMB * ((N + group - 1) / group);
    if absorbed == 0 {
        0
    } else {
        (absorbed - 1) % 3 + 1
    }
}

/// Hash of the carried aggregate sponge state.
pub fn limb_state_hash(state: [Field; STATE_SIZE]) -> Field {
    compute_commitment(state.as_vector(), DS_SHARE_DECRYPTION_CHAIN_STATE)
}

/// The chain's start: the aggregate sponge fresh.
pub fn limb_chain_start_hash<let N: u32, let L: u32, let BIT_AGG: u32>() -> Field {
    limb_state_hash(
        initial_state(
            aggregated_io_pattern::<N, L, BIT_AGG>(),
            DS_AGGREGATED_SHARES,
        ),
    )
}

/// Limb `LIMB` of `L`: C4's statement for that limb, continuing the aggregate sponge from `state_in`.
/// Returns the next limb's input hash, or for the last limb the aggregate commitment.
pub fn share_decryption_limb<let LIMB: u32, let N: u32, let L: u32, let H: u32, let BIT_MSG: u32, let BIT_AGG: u32>(
    qis: [Field; L],
    expected_commitments: [Field; H],
    decrypted_shares: [Polynomial<N>; H],
    h_in: Field,
    state_in: [Field; STATE_SIZE],
) -> Field {
    std::static_assert(LIMB < L, "limb index out of range");
    assert(limb_state_hash(state_in) == h_in, "Chain state mismatch");
    let normalized =
        aggregate_limb::<N, H, BIT_MSG>(expected_commitments, decrypted_shares, qis[LIMB]);
    let (state, pos) = absorb_from(
        state_in,
        limb_start_pos::<N, BIT_AGG, LIMB>(),
        pack::<N, BIT_AGG>(normalized.coefficients),
    );
    if LIMB == L - 1 {
        squeeze_one_after_absorb(aggregated_io_pattern::<N, L, BIT_AGG>(), state, pos)
    } else {
        limb_state_hash(state)
    }
}

/// Checks the limbs' `(h_in, out)` links cover the chain in order from the fresh sponge, and returns
/// the last limb's output, the aggregate commitment.
pub fn check_limb_chain<let N: u32, let L: u32, let BIT_AGG: u32>(links: [[Field; 2]; L]) -> Field {
    assert(links[0][0] == limb_chain_start_hash::<N, L, BIT_AGG>(), "Chain must start fresh");
    for l in 0..L - 1 {
        assert(links[l][1] == links[l + 1][0], "Limb link mismatch");
    }
    links[L - 1][1]
}

// ------------------------------------------------------------------------------------------------
// Tests: 4 coefficients, 3 parties, 3 limbs.
// ------------------------------------------------------------------------------------------------

global TQ: [Field; 3] = [97, 89, 83];

/// Shares `[party][limb]` in `[0, q)`, their commitments, and the C4 aggregate commitment.
fn test_limbs() -> ([[Polynomial<4>; 3]; 3], [[Field; 3]; 3], Field) {
    let mut shares = [[Polynomial::new([0; 4]); 3]; 3];
    let mut commitments = [[0; 3]; 3];
    for party in 0..3 {
        for limb in 0..3 {
            let q: u64 = if limb == 0 {
                97
            } else if limb == 1 {
                89
            } else {
                83
            };
            let mut coeffs = [0; 4];
            for i in 0..4 {
                coeffs[i] = (((party * 31 + limb * 7 + i * 13 + 5) as u64) % q) as Field;
            }
            shares[party][limb] = Polynomial::new(coeffs);
            let mut reversed = [0; 4];
            for i in 0..4 {
                reversed[3 - i] = coeffs[i];
            }
            commitments[party][limb] = crate::math::commitments::compute_share_encryption_commitment_from_message::<4, 60>(
                Polynomial::new(reversed),
            );
        }
    }
    let expected = crate::core::dkg::share_decryption::ShareDecryption::<4, 3, 3, 60, 60>::new(
        commitments,
        shares,
    )
        .execute(TQ);
    (shares, commitments, expected)
}

fn limb_inputs(
    shares: [[Polynomial<4>; 3]; 3],
    commitments: [[Field; 3]; 3],
    limb: u32,
) -> ([Field; 3], [Polynomial<4>; 3]) {
    let mut c = [0; 3];
    let mut s = [Polynomial::new([0; 4]); 3];
    for party in 0..3 {
        c[party] = commitments[party][limb];
        s[party] = shares[party][limb];
    }
    (c, s)
}

/// The limb chain reproduces the unchunked C4 aggregate commitment.
#[test]
fn limb_chain_equals_the_unchunked_c4_commitment() {
    let (shares, commitments, expected) = test_limbs();
    let fresh = initial_state(aggregated_io_pattern::<4, 3, 60>(), DS_AGGREGATED_SHARES);
    let h0 = limb_state_hash(fresh);

    // Replay the sponge to hand each limb its carried state.
    let (c0, s0) = limb_inputs(shares, commitments, 0);
    let h1 = share_decryption_limb::<0, 4, 3, 3, 60, 60>(TQ, c0, s0, h0, fresh);
    let n0 = aggregate_limb::<4, 3, 60>(c0, s0, TQ[0]);
    let (st1, _) = absorb_from(fresh, 0, pack::<4, 60>(n0.coefficients));
    assert(limb_state_hash(st1) == h1);

    let (c1, s1) = limb_inputs(shares, commitments, 1);
    let h2 = share_decryption_limb::<1, 4, 3, 3, 60, 60>(TQ, c1, s1, h1, st1);
    let n1 = aggregate_limb::<4, 3, 60>(c1, s1, TQ[1]);
    let (st2, _) = absorb_from(
        st1,
        limb_start_pos::<4, 60, 1>(),
        pack::<4, 60>(n1.coefficients),
    );
    assert(limb_state_hash(st2) == h2);

    let (c2, s2) = limb_inputs(shares, commitments, 2);
    let agg = share_decryption_limb::<2, 4, 3, 3, 60, 60>(TQ, c2, s2, h2, st2);
    assert(agg == expected);
    assert(check_limb_chain::<4, 3, 60>([[h0, h1], [h1, h2], [h2, agg]]) == expected);
}

#[test(should_fail_with = "Commitment mismatch")]
fn a_limb_rejects_a_share_that_does_not_open_its_commitment() {
    let (mut shares, commitments, _) = test_limbs();
    shares[1][0].coefficients[2] = shares[1][0].coefficients[2] + 1;
    let fresh = initial_state(aggregated_io_pattern::<4, 3, 60>(), DS_AGGREGATED_SHARES);
    let (c0, s0) = limb_inputs(shares, commitments, 0);
    let _ = share_decryption_limb::<0, 4, 3, 3, 60, 60>(TQ, c0, s0, limb_state_hash(fresh), fresh);
}

#[test(should_fail_with = "Limb link mismatch")]
fn the_limb_chain_rejects_unlinked_limbs() {
    let start = limb_chain_start_hash::<4, 3, 60>();
    let _ = check_limb_chain::<4, 3, 60>([[start, 1], [2, 3], [3, 4]]);
}
