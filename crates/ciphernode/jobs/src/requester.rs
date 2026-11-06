// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{trbfv, Blobs, JobError};
use e3_protocol::{node::CryptoParams, BlobRef};
use fhe::bfv::{Encoding, Plaintext, PublicKey};
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use rand::rngs::OsRng;
use rand_core::UnwrapErr;

/// What a requester's computation publishes: `values` encrypted under the committee key, in the
/// ciphertext blob format the decryption jobs read.
pub fn encrypt(
    blobs: &impl Blobs,
    params: &CryptoParams,
    public_key: &BlobRef,
    values: &[u64],
) -> Result<BlobRef, JobError> {
    let threshold = trbfv::threshold_params(params)?;
    let key =
        PublicKey::from_bytes(&blobs.get(public_key)?, &threshold).map_err(JobError::crypto)?;
    let plaintext =
        Plaintext::try_encode(values, Encoding::poly(), &threshold).map_err(JobError::crypto)?;
    let ciphertext = key
        .try_encrypt(&plaintext, &mut UnwrapErr(OsRng))
        .map_err(JobError::crypto)?;
    Ok(blobs.put(&ciphertext.to_bytes())?)
}
