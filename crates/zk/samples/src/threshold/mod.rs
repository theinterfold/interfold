// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub mod decrypted_shares_aggregation;
pub mod lbfv_pk_aggregation;
pub mod lbfv_pk_generation;
pub mod pk_aggregation;
pub mod pk_generation;
pub mod rlk_aggregation;
pub mod rlk_generation;
pub mod share_decryption;
pub mod user_data_encryption;
pub mod user_data_encryption_chunked;

use fhe::bfv::BfvParameters;
use ndarray::Array2;

/// Transpose one dealer's generated [modulus][receiver][coefficient] shares into [modulus, coefficient].
/// ShareManager supplies one correctly shaped receiver matrix per modulus.
fn receiver_shares(shares: &[Array2<u64>], receiver: usize, params: &BfvParameters) -> Array2<u64> {
    let mut collected = Array2::zeros((params.moduli().len(), params.degree()));
    for (modulus, mut row) in collected.rows_mut().into_iter().enumerate() {
        row.assign(&shares[modulus].row(receiver));
    }
    collected
}

/// Sum share rows limb by limb, then reduce and center: an independent restatement of the l-BFV
/// aggregation builders for their sample tests.
#[cfg(test)]
fn aggregate_rows(
    rows: &[e3_polynomial::CrtPolynomial],
    moduli: &[u64],
    degree: usize,
) -> Result<e3_polynomial::CrtPolynomial, e3_zk_witness::WitnessError> {
    let limbs = (0..moduli.len())
        .map(|limb| {
            rows.iter().fold(
                e3_polynomial::Polynomial::new(vec![num_bigint::BigInt::from(0); degree]),
                |sum, row| sum.add(row.limb(limb)),
            )
        })
        .collect();
    let mut sum = e3_polynomial::CrtPolynomial::new(limbs);
    sum.reduce(moduli)?;
    sum.center(moduli)?;
    Ok(sum)
}
