// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use fhe::bfv::{BfvParameters, SecretKey};
use fhe::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// The keys of the decrypting party. Interfold splits `secret` across the committee.
pub struct Keys {
    pub secret: SecretKey,
    pub public: LBFVPublicKey,
    pub relinearization: LBFVRelinearizationKey,
}

impl Keys {
    pub fn generate<R: RngCore + CryptoRng>(params: &Arc<BfvParameters>, rng: &mut R) -> Self {
        let secret = SecretKey::random(params, rng);
        let public = LBFVPublicKey::new(&secret, rng).expect("public key from a fresh secret");
        let relinearization = LBFVRelinearizationKey::new(&secret, &public, None, rng)
            .expect("relinearization key from a fresh secret");
        Keys {
            secret,
            public,
            relinearization,
        }
    }
}
