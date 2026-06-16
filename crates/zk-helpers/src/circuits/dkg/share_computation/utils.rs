// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared utilities for the share-computation circuit (e.g. parity matrix).

use crate::utils::bigint_to_field;
use crate::CircuitsErrors;
use e3_parity_matrix::build_generator_matrix;
use e3_parity_matrix::{null_space, ParityMatrix, ParityMatrixConfig};
use num_bigint::{BigInt, BigUint};

/// Computes the parity check matrix (null space of the Reed–Solomon generator) per modulus.
///
/// Returns one `ParityMatrix` per modulus in `moduli`, each of shape `[n_parties - threshold][n_parties + 1]`.
pub fn compute_parity_matrix(
    moduli: &[u64],
    n_parties: usize,
    threshold: usize,
) -> Result<Vec<ParityMatrix>, String> {
    let mut parity_matrix = Vec::with_capacity(moduli.len());
    for &qi in moduli {
        let q = BigUint::from(qi);
        let g = build_generator_matrix(&ParityMatrixConfig {
            q: q.clone(),
            t: threshold,
            n: n_parties,
        })
        .map_err(|e| format!("Failed to build generator matrix: {:?}", e))?;
        let h = null_space(&g, &q).map_err(|e| format!("Failed to compute null space: {:?}", e))?;
        parity_matrix.push(h);
    }
    Ok(parity_matrix)
}

/// Builds the PARITY_MATRIX constant string for Noir (one matrix per modulus via null_space).
pub fn parity_matrix_constant_string(
    threshold_params: &std::sync::Arc<fhe::bfv::BfvParameters>,
    n_parties: usize,
    threshold: usize,
) -> Result<String, CircuitsErrors> {
    let parity_matrix = compute_parity_matrix(threshold_params.moduli(), n_parties, threshold)
        .map_err(CircuitsErrors::Sample)?;

    let parity_matrix_strings: Vec<String> = parity_matrix
        .iter()
        .map(|h_mod| {
            let modulus_rows: Vec<String> = h_mod
                .data()
                .iter()
                .map(|row| {
                    let row_values: Vec<String> = row
                        .iter()
                        .map(|val| {
                            let bigint_val = BigInt::from(val.clone());
                            let field_val = bigint_to_field(&bigint_val);
                            field_val.to_string()
                        })
                        .collect();
                    format!("[{}]", row_values.join(", "))
                })
                .collect();
            format!("[\n        {}]", modulus_rows.join(",\n        "))
        })
        .collect();

    Ok(format!(
        "pub global PARITY_MATRIX: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L_THRESHOLD] = [\n    {}];",
        parity_matrix_strings.join(",\n    ")
    ))
}
