// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Coefficient representations for polynomial computations.

use crate::{CrtPolynomial, CrtPolynomialError, ToPowerBasisPoly};
use ndarray::Array2;
use num_bigint::BigInt;

/// Copy an Array2 of unsigned coefficients into BigInt coefficients.
pub fn array2_u64_to_bigint(arr: &Array2<u64>) -> Array2<BigInt> {
    let (rows, cols) = arr.dim();
    let mut out = Array2::<BigInt>::zeros((rows, cols));
    for i in 0..rows {
        for j in 0..cols {
            out[[i, j]] = BigInt::from(arr[[i, j]]);
        }
    }
    out
}

/// Convert an FHE polynomial to reversed, centered CRT coefficients.
pub fn fhe_poly_to_crt_centered(
    poly: &impl ToPowerBasisPoly,
    moduli: &[u64],
) -> Result<CrtPolynomial, CrtPolynomialError> {
    let mut crt = CrtPolynomial::from_fhe_polynomial(poly);
    crt.reverse();
    crt.center(moduli)?;
    Ok(crt)
}
