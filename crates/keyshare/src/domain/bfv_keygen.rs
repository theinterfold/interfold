// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure BFV keygen and Shamir-share helper logic used by the DKG flow.
//!
//! No actix/persistence/bus dependencies — plain synchronous crypto helpers
//! that are directly unit-testable.

use anyhow::{bail, Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_trbfv::{helpers::serialize_secret_key, shares::ShamirShare};
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{PublicKey, SecretKey};
use fhe_traits::Serialize as _;
use ndarray::Array2;
use rand::rngs::OsRng;
use rand_core::UnwrapErr;

/// Freshly generated BFV keypair material for the encryption-key phase.
///
/// `sk_bfv` is the secret key encrypted at rest with the node cipher and
/// `pk_bfv` is the serialized public key broadcast to the committee.
pub(crate) struct BfvKeypairMaterial {
    pub sk_bfv: SensitiveBytes,
    pub pk_bfv: ArcBytes,
}

/// Generate a fresh BFV keypair for the given `preset`, serialise it and encrypt
/// the secret key at rest. Uses OS RNG (not the thread-local `rand::rng()`).
pub(crate) fn generate_bfv_keypair(
    preset: &BfvPreset,
    cipher: &Cipher,
) -> Result<BfvKeypairMaterial> {
    let params = BfvParamSet::from(*preset).build_arc();
    let mut rng = UnwrapErr(OsRng);
    let sk_bfv = SecretKey::random(&params, &mut rng);
    let pk_bfv = PublicKey::new(&sk_bfv, &mut rng);

    let sk_bytes = serialize_secret_key(&sk_bfv)?;
    let sk_bfv = SensitiveBytes::new(sk_bytes, cipher)?;
    let pk_bfv = ArcBytes::from_bytes(&pk_bfv.to_bytes());

    Ok(BfvKeypairMaterial { sk_bfv, pk_bfv })
}

/// Build a `ShamirShare` (rows = moduli, cols = `N` coefficients) from a `Vec<Vec<u64>>`
/// of shape `[L][N]`. Used to lift our own plaintext DKG share into the same matrix
/// shape as BFV-decrypted external shares.
pub(crate) fn vec_of_rows_to_shamir_share(rows: &[Vec<u64>], degree: usize) -> Result<ShamirShare> {
    if rows.iter().any(|r| r.len() != degree) {
        bail!(
            "ShamirShare row length mismatch: each row must have {} coefficients",
            degree
        );
    }
    let l = rows.len();
    let flat: Vec<u64> = rows.iter().flatten().copied().collect();
    let arr = Array2::from_shape_vec((l, degree), flat)
        .context("Failed to build Array2 for ShamirShare")?;
    Ok(ShamirShare::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_traits::DeserializeParametrized as _;

    #[actix::test]
    async fn generate_bfv_keypair_roundtrips_public_key() {
        let cipher = Cipher::from_password("test-password")
            .await
            .expect("cipher");
        let preset = BfvPreset::InsecureThreshold512;
        let material = generate_bfv_keypair(&preset, &cipher).expect("keypair");

        // Public key bytes must deserialize against the same params.
        let params = BfvParamSet::from(preset).build_arc();
        let pk = PublicKey::from_bytes(&material.pk_bfv, &params);
        assert!(pk.is_ok(), "public key should deserialize");

        // Secret key bytes are recoverable through the cipher.
        let sk_bytes = material.sk_bfv.access(&cipher).expect("sk access");
        assert!(!sk_bytes.is_empty());
    }

    #[test]
    fn vec_of_rows_builds_share_with_matching_degree() {
        let rows = vec![vec![1u64, 2, 3], vec![4, 5, 6]];
        let share = vec_of_rows_to_shamir_share(&rows, 3).expect("share");
        assert_eq!(share.nrows(), 2);
    }

    #[test]
    fn vec_of_rows_rejects_degree_mismatch() {
        let rows = vec![vec![1u64, 2, 3], vec![4, 5]];
        assert!(vec_of_rows_to_shamir_share(&rows, 3).is_err());
    }
}
