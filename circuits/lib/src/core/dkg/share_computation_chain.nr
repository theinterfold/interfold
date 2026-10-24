// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Share computation (C2) split by coefficient range, with C2's commitments unchanged.
//!
//! One C2 proof covers every coefficient of every party's share, which grows with the committee
//! (2^25 at 39 parties). Each share commitment is one SAFE sponge over the share's packed
//! coefficients, and SAFE lets an absorb continue from a carried `(state, absorb_pos)`
//! ([`absorb_from_block_boundary`]). So a chunk proof runs C2's per-coefficient checks on its coefficients and
//! continues every party's sponge where the previous chunk stopped. The last chunk squeezes the
//! commitments the unchunked C2 returns, and C1, C3, C4 and the folds above C2 do not change.
//!
//! **Order.** C2 commits each share highest-degree first, so chunk `c` covers absorb positions
//! `[c * K, c * K + K)`, which is `y_chunk[i] = y[N - 1 - (c * K + i)]`. `K` holds whole share
//! carriers and whole sponge blocks, so every chunk starts on both boundaries and the circuit knows
//! every absorb position. Only the last chunk is shorter.
//!
//! **Secret.** Each chunk also absorbs the shares' column 0, the dealt secret, into a chain sponge
//! of its own. The final circuit opens C1's secret commitment as C2 does and checks the secret
//! hashes to the same chain digest, so the chunks shared C1's secret.
//!
//! **Links.** A chunk proves `h_out` from `h_in`, each a hash of every carried sponge. Collision
//! resistance makes consecutive chunks agree on the whole carried state. The batch circuit links
//! chunks and pins their keys by position; the final circuit links batches, starts the chain from
//! fresh sponges and ends it on the commitments it exposes.

use crate::core::dkg::share_computation::{
    check_range_bounds, Configs, verify_e_sm_secret_commitment, verify_shamir_finite_differences,
    verify_sk_secret_commitment,
};
use crate::math::commitments::{
    compute_commitment, DS_SHARE_COMPUTATION_CHAIN_OUTPUT, DS_SHARE_COMPUTATION_CHAIN_SECRET,
    DS_SHARE_COMPUTATION_CHAIN_STATE, DS_SHARE_ENCRYPTION,
};
use crate::math::helpers::{pack, packing_layout};
use crate::math::polynomial::Polynomial;
use crate::math::safe::{
    absorb_from_block_boundary, initial_state, squeeze_one_after_absorb, STATE_SIZE,
};

/// SAFE IO pattern of one share commitment over `N` coefficients: the one used by
/// `compute_share_encryption_commitment_from_message`.
pub fn share_io_pattern<let N: u32, let BIT_SHARE: u32>() -> [u32; 2] {
    let (_, group) = packing_layout::<BIT_SHARE>();
    [0x80000000 | ((N + group - 1) / group), 1]
}

/// SAFE IO pattern of the secret chain digest: `SECRET_LIMBS` values per coefficient.
pub fn secret_io_pattern<let N: u32, let SECRET_LIMBS: u32>() -> [u32; 2] {
    [0x80000000 | (N * SECRET_LIMBS), 1]
}

/// Hashes every carried sponge: the `N_PARTIES * L` share sponges, then the secret sponge.
pub fn chain_state_hash<let S: u32>(
    states: [[Field; STATE_SIZE]; S],
    positions: [u32; S],
) -> Field {
    let mut inputs = [0; S * (STATE_SIZE + 1)];
    for s in 0..S {
        for j in 0..STATE_SIZE {
            inputs[s * (STATE_SIZE + 1) + j] = states[s][j];
        }
        inputs[s * (STATE_SIZE + 1) + STATE_SIZE] = positions[s] as Field;
    }
    compute_commitment(inputs.as_vector(), DS_SHARE_COMPUTATION_CHAIN_STATE)
}

/// The chain's start: every sponge fresh.
pub fn chain_start_hash<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>() -> Field {
    let share = initial_state(share_io_pattern::<N, BIT_SHARE>(), DS_SHARE_ENCRYPTION);
    let secret = initial_state(
        secret_io_pattern::<N, SECRET_LIMBS>(),
        DS_SHARE_COMPUTATION_CHAIN_SECRET,
    );
    let mut states = [share; N_PARTIES * L + 1];
    states[N_PARTIES * L] = secret;
    chain_state_hash(states, [0; N_PARTIES * L + 1])
}

/// Hashes what the last chunk hands the final circuit: the secret chain digest, then the share
/// commitments in `[party][limb]` order.
pub fn chain_output_hash<let M: u32>(outputs: [Field; M]) -> Field {
    compute_commitment(outputs.as_vector(), DS_SHARE_COMPUTATION_CHAIN_OUTPUT)
}

/// For C2a the secret is `sk`, the same value at every limb (C2's `y[i][j][0] == sk[i]`), so only
/// limb 0 enters the secret chain. C2b's `e_sm` differs per limb, so every limb does.
fn check_secret_column<let K: u32, let L: u32, let N_PARTIES: u32, let SECRET_LIMBS: u32>(
    y_chunk: [[[Field; N_PARTIES + 1]; L]; K],
) {
    std::static_assert(
        (SECRET_LIMBS == 1) | (SECRET_LIMBS == L),
        "the secret enters the chain as one limb (sk) or every limb (e_sm)",
    );
    if SECRET_LIMBS == 1 {
        for i in 0..K {
            for mod_idx in 1..L {
                assert(
                    y_chunk[i][mod_idx][0] == y_chunk[i][0][0],
                    "Secret consistency check failed",
                );
            }
        }
    }
}

/// Continues every sponge over this chunk's coefficients.
fn absorb_chunk<let K: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>(
    states: [[Field; STATE_SIZE]; N_PARTIES * L + 1],
    positions: [u32; N_PARTIES * L + 1],
    y_chunk: [[[Field; N_PARTIES + 1]; L]; K],
) -> ([[Field; STATE_SIZE]; N_PARTIES * L + 1], [u32; N_PARTIES * L + 1]) {
    let mut states = states;
    let mut positions = positions;
    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L {
            let mut values = [0; K];
            for i in 0..K {
                values[i] = y_chunk[i][mod_idx][party_idx + 1];
            }
            let s = party_idx * L + mod_idx;
            let (state, pos) =
                absorb_from_block_boundary(states[s], positions[s], pack::<K, BIT_SHARE>(values));
            states[s] = state;
            positions[s] = pos;
        }
    }

    let mut secret = [0; K * SECRET_LIMBS];
    for i in 0..K {
        for mod_idx in 0..SECRET_LIMBS {
            secret[i * SECRET_LIMBS + mod_idx] = y_chunk[i][mod_idx][0];
        }
    }
    let s = N_PARTIES * L;
    let (state, pos) = absorb_from_block_boundary(states[s], positions[s], secret.as_vector());
    states[s] = state;
    positions[s] = pos;

    (states, positions)
}

/// C2's per-coefficient statement over one chunk.
fn check_chunk<let K: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>(
    configs: Configs<L>,
    h_in: Field,
    states_in: [[Field; STATE_SIZE]; N_PARTIES * L + 1],
    positions_in: [u32; N_PARTIES * L + 1],
    y_chunk: [[[Field; N_PARTIES + 1]; L]; K],
) {
    assert(chain_state_hash(states_in, positions_in) == h_in, "Chain state mismatch");
    check_secret_column::<K, L, N_PARTIES, SECRET_LIMBS>(y_chunk);
    check_range_bounds::<K, L, N_PARTIES, BIT_SHARE>(configs.qis, y_chunk);
    verify_shamir_finite_differences::<K, L, N_PARTIES, T>(configs.qis, y_chunk);
}

/// A chunk other than the last: proves `h_out` from `h_in`.
pub fn share_computation_chunk<let K: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>(
    configs: Configs<L>,
    h_in: Field,
    states_in: [[Field; STATE_SIZE]; N_PARTIES * L + 1],
    positions_in: [u32; N_PARTIES * L + 1],
    y_chunk: [[[Field; N_PARTIES + 1]; L]; K],
) -> Field {
    // Whole carriers, so the next chunk starts on a carrier boundary, and whole sponge blocks, so
    // every sponge hands the next chunk a block boundary. Only the last chunk may end mid-carrier
    // or mid-block; `pack` pads its last carrier exactly as the unchunked commitment does.
    let (_, group) = packing_layout::<BIT_SHARE>();
    std::static_assert(
        K % (3 * group) == 0,
        "a chunk must hold whole share carriers and blocks",
    );
    std::static_assert(
        (K * SECRET_LIMBS) % 3 == 0,
        "a chunk must hold whole secret blocks",
    );
    check_chunk::<K, L, N_PARTIES, T, BIT_SHARE, SECRET_LIMBS>(
        configs,
        h_in,
        states_in,
        positions_in,
        y_chunk,
    );
    let (states, positions) =
        absorb_chunk::<K, L, N_PARTIES, BIT_SHARE, SECRET_LIMBS>(states_in, positions_in, y_chunk);
    chain_state_hash(states, positions)
}

/// The last chunk of `N` coefficients: squeezes every sponge and returns
/// [`chain_output_hash`] of the digests.
pub fn share_computation_last_chunk<let R: u32, let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>(
    configs: Configs<L>,
    h_in: Field,
    states_in: [[Field; STATE_SIZE]; N_PARTIES * L + 1],
    positions_in: [u32; N_PARTIES * L + 1],
    y_chunk: [[[Field; N_PARTIES + 1]; L]; R],
) -> Field {
    check_chunk::<R, L, N_PARTIES, T, BIT_SHARE, SECRET_LIMBS>(
        configs,
        h_in,
        states_in,
        positions_in,
        y_chunk,
    );
    let (states, positions) =
        absorb_chunk::<R, L, N_PARTIES, BIT_SHARE, SECRET_LIMBS>(states_in, positions_in, y_chunk);
    chain_output_hash(
        chain_outputs::<N, L, N_PARTIES, BIT_SHARE, SECRET_LIMBS>(states, positions),
    )
}

/// Squeezes the secret chain digest and every share commitment.
fn chain_outputs<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>(
    states: [[Field; STATE_SIZE]; N_PARTIES * L + 1],
    positions: [u32; N_PARTIES * L + 1],
) -> [Field; N_PARTIES * L + 1] {
    let share_io = share_io_pattern::<N, BIT_SHARE>();
    let mut outputs = [0; N_PARTIES * L + 1];
    outputs[0] = squeeze_one_after_absorb(
        secret_io_pattern::<N, SECRET_LIMBS>(),
        states[N_PARTIES * L],
        positions[N_PARTIES * L],
    );
    for s in 0..N_PARTIES * L {
        outputs[1 + s] = squeeze_one_after_absorb(share_io, states[s], positions[s]);
    }
    outputs
}

/// Links the `CPB` chunks of batch `batch_idx` and pins each chunk's verification key by its
/// place in the chain: the chain's last chunk uses `last_key_hash`, every other `full_key_hash`.
/// Returns the batch's `(h_in, h_out)`.
pub fn link_chunk_batch<let CPB: u32, let N_CHUNKS: u32>(
    batch_idx: u32,
    links: [[Field; 2]; CPB],
    key_hashes: [Field; CPB],
    full_key_hash: Field,
    last_key_hash: Field,
) -> (Field, Field) {
    for i in 0..CPB {
        let expected = if batch_idx * CPB + i == N_CHUNKS - 1 {
            last_key_hash
        } else {
            full_key_hash
        };
        assert(key_hashes[i] == expected, "Chunk key mismatch");
    }
    for i in 0..CPB - 1 {
        assert(links[i][1] == links[i + 1][0], "Chunk link mismatch");
    }
    (links[0][0], links[CPB - 1][1])
}

/// Checks the batches cover the chain in order, from fresh sponges to `outputs`.
pub fn check_chain<let N_BATCHES: u32, let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SHARE: u32, let SECRET_LIMBS: u32>(
    batch_indices: [Field; N_BATCHES],
    batch_links: [[Field; 2]; N_BATCHES],
    outputs: [Field; N_PARTIES * L + 1],
) {
    for b in 0..N_BATCHES {
        assert(batch_indices[b] == b as Field, "Batch index mismatch");
    }
    assert(
        batch_links[0][0] == chain_start_hash::<N, L, N_PARTIES, BIT_SHARE, SECRET_LIMBS>(),
        "Chain must start from fresh sponges",
    );
    for b in 0..N_BATCHES - 1 {
        assert(batch_links[b][1] == batch_links[b + 1][0], "Batch link mismatch");
    }
    assert(batch_links[N_BATCHES - 1][1] == chain_output_hash(outputs), "Chain output mismatch");
}

/// The secret chain digest of `sk`, absorbed in the chunks' order: `sk[N - 1 - m]` at position `m`.
pub fn sk_secret_digest<let N: u32>(sk_secret: Polynomial<N>) -> Field {
    let mut stream = [0; N];
    for m in 0..N {
        stream[m] = sk_secret.coefficients[N - 1 - m];
    }
    compute_commitment(stream.as_vector(), DS_SHARE_COMPUTATION_CHAIN_SECRET)
}

/// The secret chain digest of `e_sm`: every limb of `e_sm[.][N - 1 - m]` at position `m`.
pub fn e_sm_secret_digest<let N: u32, let L: u32>(e_sm_secret: [Polynomial<N>; L]) -> Field {
    let mut stream = [0; N * L];
    for m in 0..N {
        for mod_idx in 0..L {
            stream[m * L + mod_idx] = e_sm_secret[mod_idx].coefficients[N - 1 - m];
        }
    }
    compute_commitment(stream.as_vector(), DS_SHARE_COMPUTATION_CHAIN_SECRET)
}

/// Splits the chain outputs into the share commitments C2 returns.
fn share_commitments<let L: u32, let N_PARTIES: u32>(
    outputs: [Field; N_PARTIES * L + 1],
) -> [[Field; L]; N_PARTIES] {
    let mut commitments = [[0; L]; N_PARTIES];
    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L {
            commitments[party_idx][mod_idx] = outputs[1 + party_idx * L + mod_idx];
        }
    }
    commitments
}

/// C2a's statement over a verified chunk chain: the chain dealt C1's `sk`, and these are its share
/// commitments.
pub fn sk_share_computation_final<let N_BATCHES: u32, let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SECRET: u32, let BIT_SHARE: u32>(
    expected_secret_commitment: Field,
    sk_secret: Polynomial<N>,
    batch_indices: [Field; N_BATCHES],
    batch_links: [[Field; 2]; N_BATCHES],
    outputs: [Field; N_PARTIES * L + 1],
) -> [[Field; L]; N_PARTIES] {
    verify_sk_secret_commitment::<N, BIT_SECRET>(sk_secret, expected_secret_commitment);
    assert(outputs[0] == sk_secret_digest(sk_secret), "Secret consistency check failed");
    check_chain::<N_BATCHES, N, L, N_PARTIES, BIT_SHARE, 1>(batch_indices, batch_links, outputs);
    share_commitments(outputs)
}

/// C2b's statement over a verified chunk chain: the chain dealt C1's `e_sm`, and these are its
/// share commitments.
pub fn e_sm_share_computation_final<let N_BATCHES: u32, let N: u32, let L: u32, let N_PARTIES: u32, let BIT_SECRET: u32, let BIT_SHARE: u32>(
    configs: Configs<L>,
    expected_secret_commitment: Field,
    e_sm_secret: [Polynomial<N>; L],
    batch_indices: [Field; N_BATCHES],
    batch_links: [[Field; 2]; N_BATCHES],
    outputs: [Field; N_PARTIES * L + 1],
) -> [[Field; L]; N_PARTIES] {
    verify_e_sm_secret_commitment::<N, L, BIT_SECRET>(
        configs.qis,
        e_sm_secret,
        expected_secret_commitment,
    );
    assert(outputs[0] == e_sm_secret_digest(e_sm_secret), "Secret consistency check failed");
    check_chain::<N_BATCHES, N, L, N_PARTIES, BIT_SHARE, L>(batch_indices, batch_links, outputs);
    share_commitments(outputs)
}

// ------------------------------------------------------------------------------------------------
// Tests: a 19-coefficient degree-1 sharing among 3 parties at two moduli, in chunks of 9, 9, 1.
// ------------------------------------------------------------------------------------------------

global TQ: [Field; 2] = [97, 89];

/// `y[i][j][x] = (s_i + a_i * x) mod q_j`, with secret `s_i = sk[i]` (trinary) at every limb.
fn test_sharing() -> ([[[Field; 4]; 2]; 19], Polynomial<19>) {
    let sk = [1, -1, 0, 1, 1, 0, -1, -1, 0, 1, -1, 1, 0, 0, 1, -1, 1, 0, -1];
    let a = [5, 17, 3, 44, 21, 9, 60, 2, 33, 70, 8, 12, 50, 4, 27, 66, 39, 15, 81];
    let mut y = [[[0; 4]; 2]; 19];
    for i in 0..19 {
        for j in 0..2 {
            y[i][j][0] = sk[i];
            for x in 1..4 {
                // a_i * x >= 2 > -s_i, so the integer value is positive.
                let v = (a[i] as u64) * (x as u64) + ((sk[i] + 1) as u64) - 1;
                let q: u64 = if j == 0 { 97 } else { 89 };
                y[i][j][x] = (v % q) as Field;
            }
        }
    }
    (y, Polynomial::new(sk))
}

/// The chunk of `y` at absorb positions `[start, start + K)`.
fn test_chunk<let K: u32>(y: [[[Field; 4]; 2]; 19], start: u32) -> [[[Field; 4]; 2]; K] {
    let mut chunk = [[[0; 4]; 2]; K];
    for i in 0..K {
        chunk[i] = y[19 - 1 - (start + i)];
    }
    chunk
}

/// Runs the chain through chunks of 9, 9 and 1 and returns the last chunk's output hash.
fn run_test_chain_with<let SECRET_LIMBS: u32>(y: [[[Field; 4]; 2]; 19]) -> Field {
    let configs = Configs::new(TQ);
    let share = initial_state(share_io_pattern::<19, 60>(), DS_SHARE_ENCRYPTION);
    let secret = initial_state(
        secret_io_pattern::<19, SECRET_LIMBS>(),
        DS_SHARE_COMPUTATION_CHAIN_SECRET,
    );
    let mut states = [share; 7];
    states[6] = secret;
    let mut positions = [0; 7];
    let mut h = chain_start_hash::<19, 2, 3, 60, SECRET_LIMBS>();
    for c in 0..2 {
        let chunk = test_chunk::<9>(y, c * 9);
        h = share_computation_chunk::<9, 2, 3, 1, 60, SECRET_LIMBS>(
            configs,
            h,
            states,
            positions,
            chunk,
        );
        let (next_states, next_positions) =
            absorb_chunk::<9, 2, 3, 60, SECRET_LIMBS>(states, positions, chunk);
        states = next_states;
        positions = next_positions;
    }
    share_computation_last_chunk::<1, 19, 2, 3, 1, 60, SECRET_LIMBS>(
        configs,
        h,
        states,
        positions,
        test_chunk::<1>(y, 18),
    )
}

fn run_test_chain(y: [[[Field; 4]; 2]; 19]) -> Field {
    run_test_chain_with::<1>(y)
}

#[test]
fn chunked_commitments_equal_the_unchunked_c2_commitments() {
    let (y, sk) = test_sharing();
    let expected = crate::core::dkg::share_computation::commit_to_party_shares::<19, 2, 3, 60>(y);

    let mut outputs = [0; 7];
    outputs[0] = sk_secret_digest(sk);
    for party_idx in 0..3 {
        for mod_idx in 0..2 {
            outputs[1 + party_idx * 2 + mod_idx] = expected[party_idx][mod_idx];
        }
    }
    assert(run_test_chain(y) == chain_output_hash(outputs));
}

#[test(should_fail_with = "Divisibility check failed")]
fn a_chunk_rejects_shares_off_a_degree_t_polynomial() {
    let (mut y, _) = test_sharing();
    y[4][1][2] = y[4][1][2] + 1;
    let _ = run_test_chain(y);
}

#[test(should_fail_with = "Secret consistency check failed")]
fn a_chunk_rejects_an_sk_column_that_differs_between_limbs() {
    let (mut y, _) = test_sharing();
    y[7][1][0] = 0;
    let _ = run_test_chain(y);
}

#[test(should_fail_with = "Chain state mismatch")]
fn a_chunk_rejects_a_carried_state_that_does_not_match_its_input_hash() {
    let (y, _) = test_sharing();
    let share = initial_state(share_io_pattern::<19, 60>(), DS_SHARE_ENCRYPTION);
    let mut states = [share; 7];
    states[3][1] = 1;
    let _ = share_computation_chunk::<9, 2, 3, 1, 60, 1>(
        Configs::new(TQ),
        chain_start_hash::<19, 2, 3, 60, 1>(),
        states,
        [0; 7],
        test_chunk::<9>(y, 0),
    );
}

#[test]
fn the_final_check_accepts_the_chain_of_the_dealt_secret() {
    let (y, sk) = test_sharing();
    let commitments =
        crate::core::dkg::share_computation::commit_to_party_shares::<19, 2, 3, 60>(y);
    let mut outputs = [0; 7];
    outputs[0] = sk_secret_digest(sk);
    for party_idx in 0..3 {
        for mod_idx in 0..2 {
            outputs[1 + party_idx * 2 + mod_idx] = commitments[party_idx][mod_idx];
        }
    }
    let links = [[chain_start_hash::<19, 2, 3, 60, 1>(), run_test_chain(y)]];
    check_chain::<1, 19, 2, 3, 60, 1>([0], links, outputs);
    assert(outputs[0] == sk_secret_digest(sk));
}

#[test]
fn chunked_e_sm_chain_carries_every_limb_of_the_secret() {
    // e_sm differs per limb: shift limb 1's sharing by a constant so column 0 differs too.
    let (mut y, _) = test_sharing();
    let mut e_sm = [Polynomial::new([0; 19]); 2];
    for i in 0..19 {
        for x in 0..4 {
            let v = y[i][1][x] + 7;
            y[i][1][x] = if x == 0 {
                v
            } else {
                ((v as u64) % 89) as Field
            };
        }
        e_sm[0].coefficients[i] = y[i][0][0];
        e_sm[1].coefficients[i] = y[i][1][0];
    }
    let commitments =
        crate::core::dkg::share_computation::commit_to_party_shares::<19, 2, 3, 60>(y);
    let mut outputs = [0; 7];
    outputs[0] = e_sm_secret_digest(e_sm);
    for party_idx in 0..3 {
        for mod_idx in 0..2 {
            outputs[1 + party_idx * 2 + mod_idx] = commitments[party_idx][mod_idx];
        }
    }
    assert(run_test_chain_with::<2>(y) == chain_output_hash(outputs));
}

#[test(should_fail_with = "Chain must start from fresh sponges")]
fn the_final_check_rejects_a_chain_that_does_not_start_fresh() {
    let (y, sk) = test_sharing();
    let mut outputs = [0; 7];
    outputs[0] = sk_secret_digest(sk);
    check_chain::<1, 19, 2, 3, 60, 1>([0], [[1, run_test_chain(y)]], outputs);
}

#[test(should_fail_with = "Chunk key mismatch")]
fn a_batch_rejects_a_full_chunk_key_in_the_last_place() {
    let _ = link_chunk_batch::<2, 4>(1, [[1, 2], [2, 3]], [7, 7], 7, 8);
}

#[test]
fn a_batch_pins_the_last_key_only_in_the_chains_last_place() {
    let (h_in, h_out) = link_chunk_batch::<2, 4>(1, [[1, 2], [2, 3]], [7, 8], 7, 8);
    assert((h_in, h_out) == (1, 3));
}
