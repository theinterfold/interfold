// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use anyhow::Result;
use e3_crypto::{Cipher, SensitiveBytes};

pub trait DeserializableValue:
    serde::Serialize + serde::de::DeserializeOwned + Eq + PartialEq
{
}

impl<T> DeserializableValue for T where
    T: serde::Serialize + serde::de::DeserializeOwned + Eq + PartialEq
{
}

/// Encrypted version of T for secure storage/transmission
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Encrypted<T>(SensitiveBytes, std::marker::PhantomData<T>);

impl<T> Encrypted<T>
where
    T: DeserializableValue,
{
    /// Create a new encrypted wrapper from data of type T
    pub fn new(data: T, cipher: &Cipher) -> Result<Self> {
        Ok(Self(
            SensitiveBytes::new(bincode::serialize(&data)?, cipher)?,
            std::marker::PhantomData,
        ))
    }

    /// Decrypt and deserialize back to type T
    pub fn decrypt(self, cipher: &Cipher) -> Result<T> {
        let value = self.0;
        Ok(bincode::deserialize(&value.access_raw(cipher)?)?)
    }
}

/// Trait to add decrypt functionality to Vec<Encrypted<T>>
pub trait DecryptVec<T> {
    /// Decrypt all encrypted values in the vector
    /// Returns a vector of decrypted values or the first error encountered
    fn decrypt(self, cipher: &Cipher) -> Result<Vec<T>>;
}

impl<T> DecryptVec<T> for Vec<Encrypted<T>>
where
    T: DeserializableValue,
{
    fn decrypt(self, cipher: &Cipher) -> Result<Vec<T>> {
        self.into_iter()
            .map(|encrypted| encrypted.decrypt(cipher))
            .collect()
    }
}

/// Trait to add decrypt functionality to Vec<Encrypted<T>>
pub trait EncryptableVec<T> {
    /// Decrypt all encrypted values in the vector
    /// Returns a vector of decrypted values or the first error encountered
    fn encrypt(self, cipher: &Cipher) -> Result<Vec<Encrypted<T>>>;
}

impl<T> EncryptableVec<T> for Vec<T>
where
    T: DeserializableValue,
{
    fn encrypt(self, cipher: &Cipher) -> Result<Vec<Encrypted<T>>> {
        self.into_iter()
            .map(|encryptable| Encrypted::new(encryptable, cipher))
            .collect()
    }
}
