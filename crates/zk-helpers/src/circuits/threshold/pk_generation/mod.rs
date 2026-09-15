// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Public key generation circuit.
//!
//! This circuit proves public key generation for pk0 (pk1 is the CRS polynomial `a`) and produces
//! Prover.toml and configs.nr for the Noir prover. See [`PkGenerationCircuit`] and
//! [`PkGenerationCircuitInput`].

pub mod circuit;
pub mod codegen;
pub mod computation;
pub mod lbfv;
pub mod sample;
pub mod utils;
pub use circuit::*;
pub use codegen::*;
pub use computation::*;
pub use lbfv::*;
