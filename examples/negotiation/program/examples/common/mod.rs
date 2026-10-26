// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the measurement examples share: a local committee that uses the production key-generation
//! path, and the helpers to build an offer, run the real program and decrypt.

#![allow(dead_code)]

use anyhow::Result;
use e3_compute_provider::FHEProcessorInput;
use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed};
use e3_user_program::layout::{PLAINTEXT_MODULUS, Role, SLOTS, mask_slots, offer_slots};
use e3_user_program::{config_input, fhe_processor};
use fhe::aggregate::AggregateIter;
use fhe::bfv::{BfvParameters, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
use fhe::trlbfv::{
    LBFVPublicKey, LBFVRelinearizationKey, PublicKeyShare, RelinKeyShare,
    aggregate_relinearization_key,
};
use fhe_traits::{DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
use rand::{CryptoRng, Rng};
use std::sync::Arc;

/// The preset of the negotiation: parameter set 5 (degree 128, plaintext modulus 257).
pub const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

/// A committee of `parties` members that all run in this process. The public key and the
/// relinearization key are the sums of the contributions of the members, as the real committee
/// computes them from the same common random polynomials. The secret key is the sum of the member
/// keys, which only a test can form.
pub struct Committee {
    pub parties: usize,
    pub params: Arc<BfvParameters>,
    pub secret_key: SecretKey,
    pub public_key: LBFVPublicKey,
    pub relinearization_key: LBFVRelinearizationKey,
}

impl Committee {
    pub fn generate(parties: usize) -> Result<Self> {
        assert!(parties >= 1, "a committee has one member at least");
        let mut rng = rand::rng();
        let (params, _) = build_pair_for_preset(PRESET)?;
        let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).unwrap())?;
        let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(PRESET).unwrap())?;
        let keys: Vec<SecretKey> = (0..parties)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let shares = keys
            .iter()
            .map(|key| PublicKeyShare::contribute_with_crp(key, &crs, &mut rng))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let public_key: LBFVPublicKey = shares.into_iter().aggregate()?;
        let rlk_shares = keys
            .iter()
            .map(|key| RelinKeyShare::contribution_with_crp(key, &urs, &crs, 0, 0, &mut rng))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let relinearization_key = aggregate_relinearization_key(&rlk_shares, &public_key)?;
        let mut sum = vec![0i64; params.degree()];
        for key in &keys {
            for (total, coefficient) in sum.iter_mut().zip(key.coeffs.iter()) {
                *total += coefficient;
            }
        }
        Ok(Self {
            parties,
            secret_key: SecretKey::new(sum, &params),
            params,
            public_key,
            relinearization_key,
        })
    }

    pub fn encrypt(&self, slots: &[u64], rng: &mut (impl Rng + CryptoRng)) -> Result<Ciphertext> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &self.params)?;
        Ok(self.public_key.try_encrypt(&plaintext, rng)?)
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u64>> {
        let plaintext = self.secret_key.try_decrypt(ciphertext)?;
        Ok(Vec::<u64>::try_decode(&plaintext, Encoding::simd())?)
    }

    /// The noise of `ciphertext` in bits, as `SecretKey::measure_noise` reports it.
    pub fn noise_bits(&self, ciphertext: &Ciphertext) -> usize {
        // SAFETY: `measure_noise` is unsafe because its run time depends on the noise, which depends
        // on the secret key. The committee key is local and the numbers are only printed.
        unsafe { self.secret_key.measure_noise(ciphertext) }.expect("a ciphertext of this committee")
    }

    /// `log2(q / t) - 1`: the largest noise, in bits, that the decryption tolerates.
    pub fn noise_limit_bits(&self) -> f64 {
        let log2_q: f64 = self.params.moduli().iter().map(|&q| (q as f64).log2()).sum();
        log2_q - (self.params.plaintext() as f64).log2() - 1.0
    }

    /// The three ciphertexts of the offer of `role`, with a uniform mask.
    pub fn offer(&self, role: Role, step: usize, share: usize, rng: &mut (impl Rng + CryptoRng)) -> Result<Vec<Ciphertext>> {
        let mask = mask_slots(|| rng.random_range(0..PLAINTEXT_MODULUS));
        offer_slots(role, step, share, mask)
            .iter()
            .map(|slots| self.encrypt(slots, rng))
            .collect()
    }

    /// Runs the real program over the configuration and the two offers.
    pub fn run_program(&self, seller: &[Ciphertext], buyer: &[Ciphertext]) -> Result<Ciphertext> {
        let inputs = std::iter::once(config_input())
            .chain(seller.iter().chain(buyer).map(|ct| ct.to_bytes()))
            .enumerate()
            .map(|(index, bytes)| (bytes, index as u64));
        let output = fhe_processor(FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &self.params,
            relinearization_key: Some(&self.relinearization_key),
        });
        Ok(Ciphertext::from_bytes(&output, &self.params)?)
    }
}

pub const OUTPUT_SLOTS: usize = SLOTS;
