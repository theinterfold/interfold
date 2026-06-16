// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Context, Result};
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize as FheSerialize,
};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::sync::Arc;

use super::{ShamirShare, SharedSecret};

// Re-export helper functions from helpers module
pub use crate::helpers::{deserialize_secret_key, serialize_secret_key};

/// A BFV-encrypted Shamir share for secure transmission.
///
/// Each share is encrypted as multiple BFV ciphertexts (one per modulus level).
/// The recipient can only decrypt using their corresponding BFV secret key.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[derivative(Debug)]
pub struct BfvEncryptedShare {
    /// BFV ciphertexts, one per modulus level
    #[derivative(Debug(format_with = "debug_vec_arcbytes"))]
    ciphertexts: Vec<ArcBytes>,
}

/// Per-row encryption witness needed for C3 ZK proofs.
pub struct BfvEncryptionWitness {
    /// The share row coefficients that were encrypted.
    pub share_row: Vec<u64>,
    /// The BFV ciphertext produced.
    pub ciphertext: Ciphertext,
    /// Encryption randomness u (RNS form).
    pub u_rns: Poly<Ntt>,
    /// Encryption error e0 (RNS form).
    pub e0_rns: Poly<Ntt>,
    /// Encryption error e1 (RNS form).
    pub e1_rns: Poly<Ntt>,
}

/// Debug helper for Vec<ArcBytes>
fn debug_vec_arcbytes(v: &[ArcBytes], f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(
        f,
        "[{} ciphertexts, total {} bytes]",
        v.len(),
        v.iter().map(|c| c.len()).sum::<usize>()
    )
}

impl BfvEncryptedShare {
    /// Encrypt a Shamir share for a specific recipient.
    ///
    /// # Arguments
    /// * `share` - The Shamir share to encrypt (contains data for all moduli)
    /// * `recipient_pk` - The recipient's BFV public key
    /// * `params` - BFV parameters for share encryption
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// An encrypted share that can only be decrypted by the recipient
    pub fn encrypt<R: RngCore + CryptoRng>(
        share: &ShamirShare,
        recipient_pk: &PublicKey,
        params: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        let data: &Array2<u64> = share.deref(); // Array2<u64> with rows = moduli, cols = coefficients
        let num_moduli = data.nrows();

        let mut ciphertexts = Vec::with_capacity(num_moduli);

        for m in 0..num_moduli {
            let row = data.row(m);
            let share_vec: Vec<u64> = row.to_vec();

            let pt = Plaintext::try_encode(&share_vec, Encoding::poly(), params)
                .context("Failed to encode share as plaintext")?;

            let ct = recipient_pk
                .try_encrypt(&pt, rng)
                .context("Failed to encrypt share")?;

            ciphertexts.push(ArcBytes::from_bytes(&ct.to_bytes()));
        }

        Ok(Self { ciphertexts })
    }

    /// Encrypt a Shamir share and return encryption randomness for ZK proofs.
    ///
    /// Same as `encrypt` but uses `try_encrypt_extended` to capture the
    /// encryption randomness (u, e0, e1) needed for C3a/C3b share encryption proofs.
    pub fn encrypt_extended<R: RngCore + CryptoRng>(
        share: &ShamirShare,
        recipient_pk: &PublicKey,
        params: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<(Self, Vec<BfvEncryptionWitness>)> {
        let data: &Array2<u64> = share.deref();
        let num_moduli = data.nrows();

        let mut ciphertexts = Vec::with_capacity(num_moduli);
        let mut witnesses = Vec::with_capacity(num_moduli);

        for m in 0..num_moduli {
            let row = data.row(m);
            let share_vec: Vec<u64> = row.to_vec();

            let pt = Plaintext::try_encode(&share_vec, Encoding::poly(), params)
                .context("Failed to encode share as plaintext")?;

            let (ct, u_rns, e0_rns, e1_rns) = recipient_pk
                .try_encrypt_extended(&pt, rng)
                .context("Failed to encrypt share (extended)")?;

            ciphertexts.push(ArcBytes::from_bytes(&ct.to_bytes()));
            witnesses.push(BfvEncryptionWitness {
                share_row: share_vec,
                ciphertext: ct,
                u_rns,
                e0_rns,
                e1_rns,
            });
        }

        Ok((Self { ciphertexts }, witnesses))
    }

    /// Decrypt an encrypted share using the recipient's secret key.
    ///
    /// # Arguments
    /// * `sk` - The recipient's BFV secret key
    /// * `params` - BFV parameters for share encryption
    /// * `degree` - Polynomial degree (for reconstructing the share matrix)
    ///
    /// # Returns
    /// The decrypted Shamir share
    /// Get the raw ciphertext bytes (one per CRT modulus).
    pub fn ciphertext_bytes(&self) -> &[ArcBytes] {
        &self.ciphertexts
    }

    /// Number of CRT moduli (ciphertexts per share).
    pub fn num_moduli(&self) -> usize {
        self.ciphertexts.len()
    }

    pub fn decrypt(
        self,
        sk: &SecretKey,
        params: &Arc<BfvParameters>,
        degree: usize,
    ) -> Result<ShamirShare> {
        let num_moduli = self.ciphertexts.len();
        let mut data = Array2::zeros((num_moduli, degree));

        for (m, ct_bytes) in self.ciphertexts.into_iter().enumerate() {
            let ct = Ciphertext::from_bytes(&ct_bytes, params)
                .context("Failed to deserialize ciphertext")?;

            let pt = sk
                .try_decrypt(&ct)
                .context("Failed to decrypt ciphertext")?;

            let decrypted: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly())
                .context("Failed to decode plaintext")?;

            for (i, val) in decrypted.into_iter().take(degree).enumerate() {
                data[[m, i]] = val;
            }
        }

        Ok(ShamirShare::new(data))
    }
}

/// A collection of BFV-encrypted shares for all recipients.
///
/// A collection of BFV-encrypted shares for all recipients.
///
/// When a party generates Shamir shares, they encrypt each recipient's share
/// with that recipient's public key. This struct holds all encrypted shares
/// from a single sender. A `None` slot indicates the recipient was deliberately
/// skipped (e.g. the sender does not encrypt their own share during DKG).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[derivative(Debug)]
pub struct BfvEncryptedShares {
    /// Encrypted shares indexed by recipient party_id (0-based).
    /// `None` means the recipient slot was skipped (no ciphertext produced).
    shares: Vec<Option<BfvEncryptedShare>>,
}

impl BfvEncryptedShares {
    /// Encrypt shares for all recipients (no skipping).
    pub fn encrypt_all<R: RngCore + CryptoRng>(
        secret: &SharedSecret,
        recipient_pks: &[PublicKey],
        params: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        let num_parties = recipient_pks.len();
        let mut shares = Vec::with_capacity(num_parties);

        for (party_id, recipient_pk) in recipient_pks.iter().enumerate() {
            let share = secret
                .extract_party_share(party_id)
                .context(format!("Failed to extract share for party {}", party_id))?;

            let encrypted = BfvEncryptedShare::encrypt(&share, recipient_pk, params, rng)?;

            shares.push(Some(encrypted));
        }

        Ok(Self { shares })
    }

    /// Encrypt shares for all recipients and capture per-row randomness (u, e0, e1) for C3 proofs.
    ///
    /// `skip_idx == Some(idx)` leaves that slot as `None` with an empty witness vec — a DKG
    /// party never encrypts its own share (bound via C2, consumed locally by C4).
    pub fn encrypt_all_extended<R: RngCore + CryptoRng>(
        secret: &SharedSecret,
        recipient_pks: &[PublicKey],
        params: &Arc<BfvParameters>,
        rng: &mut R,
        skip_idx: Option<usize>,
    ) -> Result<(Self, Vec<Vec<BfvEncryptionWitness>>)> {
        let recipient_share_indices: Vec<_> = (0..recipient_pks.len()).collect();
        Self::encrypt_all_extended_for_share_indices(
            secret,
            recipient_pks,
            &recipient_share_indices,
            params,
            rng,
            skip_idx,
        )
    }

    /// Encrypt shares for all recipient slots while selecting Shamir rows by real party index.
    ///
    /// `recipient_share_indices[slot]` is the row in `secret` encrypted for `recipient_pks[slot]`.
    /// This supports sparse recipient vectors after expulsions while keeping the encrypted-share
    /// vector compact and positional.
    pub fn encrypt_all_extended_for_share_indices<R: RngCore + CryptoRng>(
        secret: &SharedSecret,
        recipient_pks: &[PublicKey],
        recipient_share_indices: &[usize],
        params: &Arc<BfvParameters>,
        rng: &mut R,
        skip_idx: Option<usize>,
    ) -> Result<(Self, Vec<Vec<BfvEncryptionWitness>>)> {
        if recipient_pks.len() != recipient_share_indices.len() {
            bail!(
                "recipient_pks length ({}) must match recipient_share_indices length ({})",
                recipient_pks.len(),
                recipient_share_indices.len()
            );
        }

        let num_parties = recipient_pks.len();
        let mut shares = Vec::with_capacity(num_parties);
        let mut all_witnesses = Vec::with_capacity(num_parties);

        for (slot_idx, (recipient_pk, &share_idx)) in recipient_pks
            .iter()
            .zip(recipient_share_indices.iter())
            .enumerate()
        {
            if Some(slot_idx) == skip_idx {
                shares.push(None);
                all_witnesses.push(Vec::new());
                continue;
            }

            let share = secret.extract_party_share(share_idx).context(format!(
                "Failed to extract share for party {} at recipient slot {}",
                share_idx, slot_idx
            ))?;

            let (encrypted, witnesses) =
                BfvEncryptedShare::encrypt_extended(&share, recipient_pk, params, rng)?;

            shares.push(Some(encrypted));
            all_witnesses.push(witnesses);
        }

        Ok((Self { shares }, all_witnesses))
    }

    /// Get the encrypted share for a specific recipient. Returns `None` for skipped slots.
    pub fn get_share(&self, party_id: usize) -> Option<&BfvEncryptedShare> {
        self.shares.get(party_id).and_then(|s| s.as_ref())
    }

    /// Clone the encrypted share for a specific recipient. Returns `None` for skipped slots.
    pub fn clone_share(&self, party_id: usize) -> Option<BfvEncryptedShare> {
        self.shares.get(party_id).and_then(|s| s.clone())
    }

    /// Extract only the share for a specific party (for bandwidth optimization).
    /// Returns `None` if the slot is empty/skipped or out of range.
    pub fn extract_for_party(&self, party_id: usize) -> Option<Self> {
        let share = self.shares.get(party_id).and_then(|s| s.as_ref())?;
        Some(Self {
            shares: vec![Some(share.clone())],
        })
    }

    /// Number of recipient slots (including any skipped slots).
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::{BfvParamSet, BfvPreset};

    #[test]
    fn test_encrypt_decrypt_share() {
        let params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
        let mut rng = rand::rng();

        // Generate key pair
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        // Create a test share (1 modulus row, 512 coefficients)
        let degree = params.degree();
        let test_data: Vec<u64> = (0..degree as u64).collect();
        let mut data = Array2::zeros((1, degree));
        for (i, val) in test_data.iter().enumerate() {
            data[[0, i]] = *val;
        }
        let share = ShamirShare::new(data.clone());

        // Encrypt
        let encrypted = BfvEncryptedShare::encrypt(&share, &pk, &params, &mut rng)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted = encrypted
            .decrypt(&sk, &params, degree)
            .expect("Decryption should succeed");

        // Verify
        assert_eq!(share.deref(), decrypted.deref());
    }

    #[test]
    fn test_secret_key_serialization() {
        let params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
        let mut rng = rand::rng();

        // Generate a secret key
        let sk = SecretKey::random(&params, &mut rng);

        // Serialize
        let bytes = serialize_secret_key(&sk).expect("Serialization should succeed");

        // Deserialize
        let sk_restored =
            deserialize_secret_key(&bytes, &params).expect("Deserialization should succeed");

        // Verify coefficients match
        assert_eq!(sk.coeffs, sk_restored.coeffs);
    }

    #[test]
    fn test_encrypt_all_extended_for_share_indices_uses_real_share_rows() {
        let params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
        let mut rng = rand::rng();

        let _sk_one = SecretKey::random(&params, &mut rng);
        let pk_one = PublicKey::new(&_sk_one, &mut rng);
        let sk_two = SecretKey::random(&params, &mut rng);
        let pk_two = PublicKey::new(&sk_two, &mut rng);

        let degree = params.degree();
        let mut data = Array2::zeros((3, degree));
        for party_id in 0..3 {
            for coeff_idx in 0..degree {
                data[[party_id, coeff_idx]] = ((party_id as u64) + 1) * 10_000 + coeff_idx as u64;
            }
        }
        let secret = SharedSecret::new(vec![data]);

        let (encrypted, witnesses) = BfvEncryptedShares::encrypt_all_extended_for_share_indices(
            &secret,
            &[pk_one, pk_two],
            &[1, 2],
            &params,
            &mut rng,
            Some(0),
        )
        .expect("sparse recipient encryption should succeed");

        assert!(encrypted.clone_share(0).is_none());
        assert!(witnesses[0].is_empty());

        let decrypted = encrypted
            .clone_share(1)
            .expect("slot 1 should be encrypted")
            .decrypt(&sk_two, &params, degree)
            .expect("recipient should decrypt its share");
        let expected = secret.extract_party_share(2).unwrap();
        assert_eq!(decrypted.deref(), expected.deref());
    }
}
