// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub const DEFAULT_C2_CHUNK_SIZE: usize = 512;

/// Coefficients per C2 chunk for a polynomial degree and committee size.
///
/// A C2 leaf proves every party's share of its coefficients, so its cost grows with
/// `chunk_size * n_parties`. At degree 16384 the size keeps the leaves at 2^21-2^22 gates (measured:
/// 8192 with 3 parties gives 1.93M for sk and 3.06M for e_sm, which carries the smudging bound; 512
/// with 19 parties gives 0.81M and 0.88M, so 2048 stays at 2^22), which cuts the leaf and batch count
/// and keeps the finalizer at one or two recursive verifications. Other degrees use the default.
/// The config generator writes the same rule into each preset's `dkg.nr` as an expression over the
/// active committee's `N_PARTIES`; [`c2_chunk_size_noir`] renders it.
pub fn c2_chunk_size(degree: usize, n_parties: usize) -> usize {
    let size = if degree >= 16384 {
        if n_parties <= 4 {
            LARGE_DEGREE_FEW_PARTIES_C2_CHUNK_SIZE
        } else {
            LARGE_DEGREE_C2_CHUNK_SIZE
        }
    } else {
        DEFAULT_C2_CHUNK_SIZE
    };
    size.min(degree)
}

const LARGE_DEGREE_FEW_PARTIES_C2_CHUNK_SIZE: usize = 8192;
const LARGE_DEGREE_C2_CHUNK_SIZE: usize = 2048;

/// [`c2_chunk_size`] as a Noir expression over the active committee's `N_PARTIES`.
pub fn c2_chunk_size_noir(degree: usize) -> String {
    if degree >= 16384 {
        format!(
            "if crate::configs::committee::active::N_PARTIES <= 4 {{\n    {LARGE_DEGREE_FEW_PARTIES_C2_CHUNK_SIZE}\n}} else {{\n    {LARGE_DEGREE_C2_CHUNK_SIZE}\n}}"
        )
    } else {
        DEFAULT_C2_CHUNK_SIZE.min(degree).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_noir_expression_states_the_rust_rule() {
        assert_eq!(c2_chunk_size(16384, 4), 8192);
        assert_eq!(c2_chunk_size(16384, 5), 2048);
        assert_eq!(
            c2_chunk_size_noir(16384),
            "if crate::configs::committee::active::N_PARTIES <= 4 {\n    8192\n} else {\n    2048\n}"
        );
        for degree in [64, 128, 512, 8192] {
            assert_eq!(
                c2_chunk_size_noir(degree),
                c2_chunk_size(degree, 3).to_string()
            );
        }
    }
}
