// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: coefficient-level chunk leaf for ct0's merged main+r1 grid (P3).
//! One instance of this circuit (same VK) is proven once per `chunk_idx` in `0..N_CHUNKS` (2 at
//! this preset - the minimum that's still genuinely "chunking"), each handling a `CHUNK_SIZE = N
//! / N_CHUNKS` slice of `u`/`e0`/`k1`/`r2is` and a `R1_CHUNK_SIZE = 2N / R1_N_CHUNKS` slice of
//! `r1is` at the same index. `r1is` was originally its own grid (own leaf/root/combine family),
//! but since `R1_N_CHUNKS == N_CHUNKS` its chunk boundaries already line up 1:1 with main's, so
//! folding it into this leaf drops three circuit kinds (`ct0_chunk_r1`, `ct0_chunk_r1_root`,
//! `ct0_chunk_combine_roots`) at the cost of a larger per-leaf gate count - still comfortably
//! under 2M (~800K main + ~600K r1 ~= 1.4M), but with less headroom before `N_CHUNKS` needs to
//! grow again as L increases, since main and r1 now share one 2M budget instead of two.
//!
//! Range-checks and CRT-consistency for the slice, then emits one chunk commitment *per
//! polynomial* (not bundled - `u_commitment`/`k1_commitment` must stay independently
//! recoverable: the wrapper cross-checks ct0's and ct1's `u_commitment` directly, and
//! `k1_commitment` survives into ct0's final output tuple unchanged). At N_CHUNKS=2, exactly 2 of
//! these leaves combine directly into `ct0_chunk_main_root` - no intermediate pair/quad level
//! needed.
//!
//! `r2is` and `r1is` are padded from their native degrees (`N-1` and `2N-1`) to `N` and `2N`
//! coefficients respectively by one leading zero (see `Polynomial`'s descending-degree
//! convention); the padding slot lives at global index 0, i.e. chunk_idx 0's local offset 0.

use lib::configs::default::threshold::{
    L, N, QIS, USER_DATA_ENCRYPTION_BIT_E0, USER_DATA_ENCRYPTION_BIT_E0_QUOTIENT,
    USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_BIT_R1, USER_DATA_ENCRYPTION_BIT_R2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_E0_BOUND,
    USER_DATA_ENCRYPTION_E0_QUOTIENT_BOUNDS, USER_DATA_ENCRYPTION_K1_LOW_BOUND,
    USER_DATA_ENCRYPTION_K1_UP_BOUND, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
    USER_DATA_ENCRYPTION_R1_LOW_BOUNDS, USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS,
    USER_DATA_ENCRYPTION_R1_UP_BOUNDS, USER_DATA_ENCRYPTION_R2_BOUNDS, USER_DATA_ENCRYPTION_U_BOUND,
};

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

use lib::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_multi_chunk_commitment, UDE_KIND_CT0_E0,
    UDE_KIND_CT0_K1, UDE_KIND_CT0_R1, UDE_KIND_CT0_R2, UDE_KIND_CT0_U,
};
use lib::math::polynomial::Polynomial;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    e0is_chunk: [Polynomial<CHUNK_SIZE>; L],
    e0_quotients_chunk: [Polynomial<CHUNK_SIZE>; L],
    r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    r1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
) -> pub (Field, Field, Field, Field, Field) {
    assert(N_CHUNKS == R1_N_CHUNKS, "merged main+r1 grid requires equal chunk counts");
    assert(chunk_idx < N_CHUNKS);

    if chunk_idx == 0 {
        for i in 0..L {
            assert(r2is_chunk[i].coefficients[0] == 0, "r2is padding coefficient must be zero");
            assert(r1is_chunk[i].coefficients[0] == 0, "r1is padding coefficient must be zero");
        }
    }

    u_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_U>(
        USER_DATA_ENCRYPTION_U_BOUND,
        USER_DATA_ENCRYPTION_U_BOUND,
    );
    e0_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_E0>(
        USER_DATA_ENCRYPTION_E0_BOUND,
        USER_DATA_ENCRYPTION_E0_BOUND,
    );
    k1_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_K>(
        USER_DATA_ENCRYPTION_K1_UP_BOUND,
        USER_DATA_ENCRYPTION_K1_LOW_BOUND,
    );
    for i in 0..L {
        r2is_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_R2>(
            USER_DATA_ENCRYPTION_R2_BOUNDS[i],
            USER_DATA_ENCRYPTION_R2_BOUNDS[i],
        );
        r1is_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_R1>(
            USER_DATA_ENCRYPTION_R1_UP_BOUNDS[i],
            USER_DATA_ENCRYPTION_R1_LOW_BOUNDS[i],
        );
        // The CRT-consistency assert below holds in F_p, not Z: an unbounded e0_quotients[i]
        // lets a prover satisfy it for an arbitrary e0is[i] by solving
        // e0_quotients[i] := (e0 - e0is[i]) / QIS[i] via the modular inverse, which then reaches
        // the identity check unmediated. This range check closes that gap - see
        // user_data_encryption_ct0.nr's check_range_bounds for the full analysis.
        e0_quotients_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_E0_QUOTIENT>(
            USER_DATA_ENCRYPTION_E0_QUOTIENT_BOUNDS[i],
            USER_DATA_ENCRYPTION_E0_QUOTIENT_BOUNDS[i],
        );
    }

    for i in 0..L {
        for j in 0..CHUNK_SIZE {
            assert(
                e0_chunk.coefficients[j]
                    == e0is_chunk[i].coefficients[j]
                        + e0_quotients_chunk[i].coefficients[j] * QIS[i],
            );
        }
    }

    let u_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_U>(
        UDE_KIND_CT0_U,
        chunk_idx,
        N,
        u_chunk,
    );
    let e0_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_E0>(
        UDE_KIND_CT0_E0,
        chunk_idx,
        N,
        e0_chunk,
    );
    let k1_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_K>(
        UDE_KIND_CT0_K1,
        chunk_idx,
        N,
        k1_chunk,
    );
    let r2_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_R2>(
        UDE_KIND_CT0_R2,
        chunk_idx,
        N,
        r2is_chunk,
    );
    let r1_commit = compute_ude_multi_chunk_commitment::<R1_CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_R1>(
        UDE_KIND_CT0_R1,
        chunk_idx,
        N,
        r1is_chunk,
    );

    (u_commit, e0_commit, k1_commit, r2_commit, r1_commit)
}
