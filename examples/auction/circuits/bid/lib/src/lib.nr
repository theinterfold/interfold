// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bid proof for the `vickrey` and `vickrey-compact` designs: "the SIMD plaintexts of my bid
//! ciphertexts come from one bid `b`".
//!
//! The proof binds to the `user_data_encryption` proofs through the `k1` commitments. `k1` is the
//! plaintext `m` scaled by `Q mod t` and reversed: `k1[i] = [Q · m[N - 1 - i]]_t`.
//!
//! Two strategies prove the same statement:
//! - [`ntt::prove`] runs a forward negacyclic NTT of `k1` in the circuit. It costs `O(N log N)`
//!   and does not depend on the number of levels `B`.
//! - [`table::prove`] writes `k1` as a combination of `B` public polynomials. It costs `O(N · B)`
//!   in the worst case, and less when the public polynomials are sparse.
//! - [`sparse::prove`] uses the fact that `k1` has only `2B - 1` non-zero coefficients when the
//!   slots have the same period as the levels. It costs `O(B · B)`, and the commitment dominates.

mod bid;
pub mod ntt;
pub mod sparse;
pub mod table;

pub use interfold_lib::math::polynomial::Polynomial;

mod fixture;
mod fixture_compact;
mod tests;
