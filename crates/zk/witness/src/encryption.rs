// SPDX-License-Identifier: LGPL-3.0-only

//! Sensitive encryption values carried with the exact ciphertext being prepared.

use fhe::bfv::{Ciphertext, Plaintext, PublicKey};
use fhe_math::rq::{Ntt, Poly};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// The `(u, e0, e1)` returned by the encryption that produced a ciphertext.
/// Deliberately does not implement `Debug` or `Clone`.
pub struct EncryptionIntermediates {
    randomness: Zeroizing<Poly<Ntt>>,
    error_0: Zeroizing<Poly<Ntt>>,
    error_1: Zeroizing<Poly<Ntt>>,
}

impl EncryptionIntermediates {
    pub fn from_parts(randomness: Poly<Ntt>, error_0: Poly<Ntt>, error_1: Poly<Ntt>) -> Self {
        Self {
            randomness: Zeroizing::new(randomness),
            error_0: Zeroizing::new(error_0),
            error_1: Zeroizing::new(error_1),
        }
    }

    pub fn randomness(&self) -> &Poly<Ntt> {
        &self.randomness
    }
    pub fn error_0(&self) -> &Poly<Ntt> {
        &self.error_0
    }
    pub fn error_1(&self) -> &Poly<Ntt> {
        &self.error_1
    }
}

pub fn encrypt_with_intermediates<R: RngCore + CryptoRng>(
    public_key: &PublicKey,
    plaintext: &Plaintext,
    rng: &mut R,
) -> Result<(Ciphertext, EncryptionIntermediates), fhe::Error> {
    let (ct, u, e0, e1) = public_key.try_encrypt_extended(plaintext, rng)?;
    Ok((ct, EncryptionIntermediates::from_parts(u, e0, e1)))
}
