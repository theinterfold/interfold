// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use anyhow::{bail, Result};
use ndarray::{Array, Array2};
use std::ops::Deref;

/// Represents a complete secret shared across all moduli using Shamir polynomials
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SharedSecret {
    // Each Array2 represents polynomial evaluations for one modulus
    // Rows = parties, Columns = polynomial coefficients
    moduli_data: Vec<Array2<u64>>,
}

impl SharedSecret {
    /// Create a new shared secret from modulus polynomial data
    pub fn new(moduli_data: Vec<Array2<u64>>) -> Self {
        Self { moduli_data }
    }

    pub fn moduli_data(&self) -> &Vec<Array2<u64>> {
        &self.moduli_data
    }

    /// Extract one party's complete share across all moduli.
    pub fn extract_party_share(&self, party_id: usize) -> Result<ShamirShare> {
        let Some(first) = self.moduli_data.first() else {
            bail!("Secret must have at least one modulus in order to extract share");
        };

        let (_, degree) = first.dim();
        let mut share_data = Array::zeros((0, degree));

        for modulus_poly in &self.moduli_data {
            if modulus_poly.nrows() <= party_id {
                bail!(
                    "party_id {} exceeds available rows ({})",
                    party_id,
                    modulus_poly.nrows()
                );
            }
            let party_row = modulus_poly.row(party_id);
            share_data.push_row(party_row)?;
        }

        Ok(ShamirShare::new(share_data))
    }
}

impl From<Vec<Array2<u64>>> for SharedSecret {
    fn from(moduli_data: Vec<Array2<u64>>) -> Self {
        Self::new(moduli_data)
    }
}

/// Represents one party's complete Shamir share across all moduli
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ShamirShare {
    // Rows = moduli, Columns = polynomial coefficients
    data: Array2<u64>,
}

impl ShamirShare {
    /// Create a new Shamir share from raw data
    pub fn new(data: Array2<u64>) -> Self {
        Self { data }
    }
}

impl Deref for ShamirShare {
    type Target = Array2<u64>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Extension trait for converting slices of ShamirShare to array data
pub trait ShamirShareSliceExt {
    fn to_array_data(&self) -> Vec<Array2<u64>>;
}

impl ShamirShareSliceExt for [ShamirShare] {
    fn to_array_data(&self) -> Vec<Array2<u64>> {
        self.iter().map(|s| s.data.clone()).collect()
    }
}
