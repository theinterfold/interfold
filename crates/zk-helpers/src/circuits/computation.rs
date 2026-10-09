// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation traits and artifact types.
//!
//! [`Computation`] is a generic trait for computing values from parameters and input.
//! [`CircuitComputation`] extends it for circuits that produce inputs/bounds/bits.
//! [`Toml`] and [`Configs`] are the string types used for Prover.toml and configs.nr.

use serde::{Deserialize, Serialize};

/// Variant for input types for DKG.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Hash)]
pub enum DkgInputType {
    /// The input type that generates shares of a secret key using secret sharing.
    SecretKey,
    /// The input type that generates shares of smudging noise instead of secret key shares.
    SmudgingNoise,
}

/// Generic computation from parameters and input to a result.
pub trait Computation: Sized {
    type Preset;
    type Data;
    type Error;

    /// Computes the result from parameters and input.
    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error>;

    /// Converts the result to a JSON [`serde_json::Value`] for serialization.
    /// Default: `serde_json::to_value(self)` when `Self: serde::Serialize`.
    fn to_json(&self) -> serde_json::Result<serde_json::Value>
    where
        Self: serde::Serialize,
    {
        serde_json::to_value(self)
    }
}

/// Circuit-specific computation: parameters and input produce bounds, bits, circuit inputs, etc.
pub trait CircuitComputation: crate::metadata::Circuit {
    type Preset;
    type Data;
    type Output;
    type Error;

    /// Computes circuit-specific data (bounds, bits, inputs) from parameters and input.
    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error>;
}
