// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! # lib - Interfold ZK library
//! - **`core`**: DKG and threshold TrBFV circuit logic (PV-TBFV / publicly verifiable
//!   threshold BFV).
//! - **`math`**: Polynomials, SAFE sponge (Poseidon2 + Keccak per `safe.nr`), helpers,
//!   `ModU128` / `ModU64`, commitments.
//! - **`configs`**: Parameter presets (default -> secure / insecure / committee) for DKG
//!   and threshold packages under `circuits/bin/`.

pub mod math;
pub mod core;
pub mod configs;
