// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub mod decrypted_shares_aggregation;
pub mod pk_aggregation;
pub mod pk_generation;
pub mod share_decryption;
pub mod user_data_encryption;

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
