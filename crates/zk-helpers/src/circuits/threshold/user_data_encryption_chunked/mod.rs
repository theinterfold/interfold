// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User data encryption circuit.
//!
//! This module computes the raw BFV witness and configuration for the recursive proof-tree
//! builder. See [`UserDataEncryptionCircuit`] and [`UserDataEncryptionCircuitInput`].

pub mod circuit;
pub mod codegen;
pub mod computation;
pub mod sample;
pub mod utils;
pub use circuit::*;
pub use codegen::*;
pub use computation::*;
pub use utils::*;
