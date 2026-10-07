// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Decrypted shares aggregation circuit for threshold BFV.
//!
//! Proves correct aggregation of T+1 decryption shares (Lagrange interpolation at 0 per modulus,
//! CRT reconstruction to u_global, and CRT quotients). Public inputs include C6 `d` commitments
//! (checked in-circuit against recomputed commitments from witness shares), party IDs, and message;
//! secret witnesses: decryption shares, u_global, crt_quotients.

pub mod circuit;
pub mod codegen;
pub mod computation;
pub mod sample;
pub mod utils;
pub use circuit::*;
pub use codegen::*;
pub use computation::*;
pub use utils::*;
