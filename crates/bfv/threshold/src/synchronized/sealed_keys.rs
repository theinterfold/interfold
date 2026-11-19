// SPDX-License-Identifier: LGPL-3.0-only

use super::PrfKey;
use anyhow::{ensure, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_fhe_params::BfvProfile;
use zeroize::Zeroizing;

/// Local encrypted key bytes, including their request/owner identity inside authenticated
/// encryption. Raw keys deliberately do not implement a general-purpose persistence encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SealedPrfKeys(SensitiveBytes);

impl SealedPrfKeys {
    pub fn seal(
        profile: BfvProfile,
        binding: [u128; 2],
        owner: u32,
        keys: &[PrfKey],
        cipher: &Cipher,
    ) -> Result<Self> {
        ensure!(
            profile.prf_key_bits().is_some(),
            "SS has no directed PRF keys"
        );
        ensure!(!keys.is_empty(), "directed keys cannot be empty");
        for key in keys {
            PrfKey::from_bytes(profile, *key.as_bytes())?;
        }
        let bytes = Zeroizing::new(keys.iter().map(|key| *key.as_bytes()).collect::<Vec<_>>());
        Ok(Self(SensitiveBytes::new(
            bincode::serialize(&(1u8, profile, binding, owner, &*bytes))?,
            cipher,
        )?))
    }

    pub fn open(
        &self,
        profile: BfvProfile,
        binding: [u128; 2],
        owner: u32,
        count: usize,
        cipher: &Cipher,
    ) -> Result<Vec<PrfKey>> {
        ensure!(
            profile.prf_key_bits().is_some() && count > 0,
            "invalid directed-key profile or count"
        );
        let decrypted = self.0.access(cipher)?;
        let (version, saved_profile, saved_binding, saved_owner, bytes): (
            u8,
            BfvProfile,
            [u128; 2],
            u32,
            Vec<[u8; 32]>,
        ) = bincode::deserialize(&decrypted)?;
        let bytes = Zeroizing::new(bytes);
        ensure!(
            version == 1
                && saved_profile == profile
                && saved_binding == binding
                && saved_owner == owner,
            "directed keys belong to another DKG request or owner"
        );
        ensure!(
            bytes.len() == count,
            "directed-key count does not match the DKG statement"
        );
        bytes
            .iter()
            .map(|bytes| PrfKey::from_bytes(profile, *bytes))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[tokio::test]
    async fn restart_restores_the_same_keys_and_rejects_request_owner_or_ciphertext_substitution() {
        let cipher = Cipher::from_password("sync-dkg-sealed-keys").await.unwrap();
        let profile = BfvProfile::SyncDecInsecure64;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(245603);
        let keys: Vec<_> = (0..3)
            .map(|_| PrfKey::random(profile, &mut rng).unwrap())
            .collect();
        let sealed = SealedPrfKeys::seal(profile, [1, 2], 2, &keys, &cipher).unwrap();
        let encoded = bincode::serialize(&sealed).unwrap();
        let restored: SealedPrfKeys = bincode::deserialize(&encoded).unwrap();
        let opened = restored.open(profile, [1, 2], 2, 3, &cipher).unwrap();
        assert!(opened
            .iter()
            .zip(&keys)
            .all(|(left, right)| left.as_bytes() == right.as_bytes()));
        assert!(restored.open(profile, [1, 3], 2, 3, &cipher).is_err());
        assert!(restored.open(profile, [1, 2], 1, 3, &cipher).is_err());
        assert!(restored.open(profile, [1, 2], 2, 2, &cipher).is_err());
        assert!(restored
            .open(BfvProfile::SsInsecure64, [1, 2], 2, 3, &cipher)
            .is_err());
        let mut corrupted = encoded;
        *corrupted.last_mut().unwrap() ^= 1;
        let corrupted: SealedPrfKeys = bincode::deserialize(&corrupted).unwrap();
        assert!(corrupted.open(profile, [1, 2], 2, 3, &cipher).is_err());
    }
}
