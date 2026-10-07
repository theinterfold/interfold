// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User data encryption circuit.
//!
//! This circuit proves data encryption with a BFV public key (pk0, pk1) and produces
//! Prover.toml and configs.nr for the Noir prover. See [`UserDataEncryptionCircuit`] and
//! [`UserDataEncryptionCircuitInput`].

pub mod circuit;
pub mod codegen;
pub mod computation;
pub mod sample;
pub mod utils;
pub use circuit::*;
pub use codegen::*;
pub use computation::*;
pub use utils::*;
