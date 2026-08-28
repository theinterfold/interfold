// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS user data encryption circuit.
//!
//! CKKS variant of `user_data_encryption`. Proves data encryption with a CKKS
//! public key `(pk0, pk1)` and produces the witness inputs for the
//! `user_data_encryption_ckks_ct0` Noir circuit (the ct1 leg reuses the BFV
//! ct1 circuit unchanged, as it carries no message term).

pub mod circuit;
pub mod codegen;
pub mod computation;
pub use circuit::*;
pub use codegen::*;
pub use computation::*;
