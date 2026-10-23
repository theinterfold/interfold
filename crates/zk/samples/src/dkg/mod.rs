// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub mod pk;
pub mod share_computation;
pub mod share_decryption;
pub mod share_encryption;

use e3_zk_witness::WitnessError;
use fhe::bfv::SecretKey;
use fhe::trbfv::{smudging::SmudgingNoiseGenerator, ShareManager};
use rand::{CryptoRng, RngCore};

/// Select receiver zero's first-modulus row from a fresh SK or smudging secret.
/// A supplied noise generator selects smudging noise; otherwise, sample a secret key.
fn share_row(
    manager: &mut ShareManager,
    noise: Option<&SmudgingNoiseGenerator>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u64>, WitnessError> {
    let secret = match noise {
        Some(noise) => manager.bigints_to_poly(&noise.generate_smudging_error(rng)?)?,
        None => manager
            .coeffs_to_poly_level0(SecretKey::random(&manager.params, rng).coeffs.as_ref())?,
    };
    Ok(manager.generate_secret_shares_from_poly(secret, rng)?[0]
        .row(0)
        .to_vec())
}
