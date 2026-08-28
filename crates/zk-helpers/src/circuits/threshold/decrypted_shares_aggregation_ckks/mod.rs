// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Decrypted shares aggregation for threshold CKKS (C7-CKKS).
//!
//! Same Lagrange + CRT combination as the BFV
//! [`crate::threshold::decrypted_shares_aggregation`], but WITHOUT the BFV
//! modular decode: the public output is the reconstructed ring element
//! `u_global = delta*m + e` itself. Off-circuit, the application centers
//! each coefficient mod Q and divides by `delta`.

pub mod circuit;
pub mod codegen;
pub mod computation;
pub use circuit::*;
pub use codegen::*;
pub use computation::*;
