// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub mod circuit;
pub mod codegen;
pub mod computation;
pub mod sample;
pub mod utils;

pub use circuit::{ShareComputationCircuit, ShareComputationCircuitData};
pub use computation::{Bits, Bounds, Configs, Inputs, ShareComputationOutput};
pub use sample::SecretShares;

/// Default coefficient count per l-BFV C2 chunk outside degree 16384.
pub const DEFAULT_C2_CHUNK_SIZE: usize = 512;

/// Coefficients per C2 chunk for a polynomial degree and committee size.
///
/// A C2 leaf proves every party's share of its coefficients, so its cost grows with
/// `chunk_size * n_parties`. At degree 16384 the size keeps the leaves near 2^21 gates (measured:
/// 4096 with 3 parties gives 1.29M for sk and 2.19M for e_sm), which cuts the leaf and batch count
/// and keeps the finalizer at one or a few recursive verifications. Other degrees use the default.
/// The config generator writes the same rule into each preset's `dkg.nr` as an expression over the
/// active committee's `N_PARTIES`.
pub fn c2_chunk_size(degree: usize, n_parties: usize) -> usize {
    let size = if degree >= 16384 {
        if n_parties <= 4 {
            4096
        } else if n_parties <= 12 {
            1024
        } else {
            DEFAULT_C2_CHUNK_SIZE
        }
    } else {
        DEFAULT_C2_CHUNK_SIZE
    };
    size.min(degree)
}
