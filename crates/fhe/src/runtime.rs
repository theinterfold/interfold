// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use async_trait::async_trait;
use e3_bfv_client::{decode_plaintext_to_vec_u64, encode_vec_u64_to_bytes};
use e3_data::{FromSnapshotWithParams, Snapshot};
use e3_events::OrderedSet;
use e3_fhe_params::{
    build_bfv_params_arc, create_deterministic_crp_from_default_seed, decode_bfv_params_arc,
    BfvParamSet, BfvPreset,
};
use e3_utils::{ArcBytes, SharedRng};
use fhe::{
    bfv::{BfvParameters, Ciphertext, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{Deserialize, DeserializeParametrized, Serialize};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};

pub struct GetAggregatePublicKey {
    pub keyshares: OrderedSet<ArcBytes>,
}

pub struct GetAggregatePlaintext {
    pub decryptions: OrderedSet<Vec<u8>>,
    pub ciphertext_output: Vec<u8>,
}

pub struct DecryptCiphertext {
    pub unsafe_secret: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Fhe library adaptor.
#[derive(Clone)]
pub struct Fhe {
    pub params: Arc<BfvParameters>,
    pub crp: CommonRandomPoly,
    rng: SharedRng,
}

impl Fhe {
    pub fn new(params: Arc<BfvParameters>, crp: CommonRandomPoly, rng: SharedRng) -> Self {
        Self { params, crp, rng }
    }

    pub fn from_encoded(bytes: &[u8], rng: SharedRng) -> Result<Self> {
        let params = decode_bfv_params_arc(bytes).expect("Failed to decode BFV params");
        let crp = create_deterministic_crp_from_default_seed(&params);

        Ok(Fhe::new(params, crp, rng))
    }

    pub fn from_raw_params(
        moduli: &[u64],
        degree: usize,
        plaintext_modulus: u64,
        crp: &[u8],
        rng: Arc<Mutex<ChaCha20Rng>>,
    ) -> Result<Self> {
        let params = build_bfv_params_arc(degree, plaintext_modulus, moduli, None);

        Ok(Fhe::new(
            params.clone(),
            CommonRandomPoly::deserialize(crp, &params)?,
            rng,
        ))
    }

    pub fn generate_keyshare(&self) -> Result<(Vec<u8>, ArcBytes)> {
        let sk_share = { SecretKey::random(&self.params, &mut *self.rng.lock().unwrap()) };
        let pk_share =
            { PublicKeyShare::new(&sk_share, self.crp.clone(), &mut *self.rng.lock().unwrap())? };

        Ok((
            SecretKeySerializer::to_bytes(sk_share)?,
            ArcBytes::from_bytes(&pk_share.to_bytes()),
        ))
    }

    pub fn decrypt_ciphertext(&self, msg: DecryptCiphertext) -> Result<Vec<u8>> {
        let DecryptCiphertext {
            unsafe_secret,
            ciphertext,
        } = msg;

        let secret_key = SecretKeySerializer::from_bytes(&unsafe_secret, self.params.clone())?;
        let ct = Arc::new(
            Ciphertext::from_bytes(&ciphertext, &self.params)
                .context("Error deserializing ciphertext")?,
        );
        let decryption_share =
            DecryptionShare::new(&secret_key, &ct, &mut *self.rng.lock().unwrap()).unwrap();
        Ok(decryption_share.to_bytes())
    }

    pub fn get_aggregate_public_key(&self, msg: GetAggregatePublicKey) -> Result<Vec<u8>> {
        let public_key: PublicKey = msg
            .keyshares
            .iter()
            .map(|k| PublicKeyShare::deserialize(k, &self.params, self.crp.clone()))
            .aggregate()?;

        Ok(public_key.to_bytes())
    }

    pub fn get_aggregate_plaintext(&self, msg: GetAggregatePlaintext) -> Result<Vec<u8>> {
        let arc_ct = Arc::new(Ciphertext::from_bytes(
            &msg.ciphertext_output,
            &self.params,
        )?);

        let plaintext: Plaintext = msg
            .decryptions
            .iter()
            .map(|k| DecryptionShare::deserialize(k, &self.params, arc_ct.clone()))
            .aggregate()?;
        let decoded =
            decode_plaintext_to_vec_u64(&plaintext).context("Could not decode plaintext")?;
        let bytes = encode_vec_u64_to_bytes(&decoded);
        Ok(bytes)
    }
}

impl Snapshot for Fhe {
    type Snapshot = FheSnapshot;
    fn snapshot(&self) -> Result<Self::Snapshot> {
        Ok(FheSnapshot {
            crp: self.crp.to_bytes(),
            params: self.params.to_bytes(),
        })
    }
}

#[async_trait]
impl FromSnapshotWithParams for Fhe {
    type Params = SharedRng;
    async fn from_snapshot(rng: SharedRng, snapshot: FheSnapshot) -> Result<Self> {
        let params = deserialize_snapshot_params(&snapshot.params)?;
        let crp = CommonRandomPoly::deserialize(&snapshot.crp, &params)?;
        Ok(Fhe::new(params, crp, rng))
    }
}

fn deserialize_snapshot_params(bytes: &[u8]) -> Result<Arc<BfvParameters>> {
    let params = BfvParameters::try_deserialize(bytes)?;
    if protobuf_has_length_delimited_field(bytes, 6) {
        return Ok(Arc::new(params));
    }
    let Some(preset) =
        BfvPreset::from_threshold_parameters(params.degree(), params.plaintext(), params.moduli())
    else {
        return Ok(Arc::new(params));
    };
    Ok(BfvParamSet::from(preset).build_arc())
}

fn protobuf_has_length_delimited_field(bytes: &[u8], wanted_field: u64) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(key) = read_protobuf_varint(bytes, &mut cursor) else {
            return false;
        };
        let field = key >> 3;
        let wire_type = key & 0x07;
        if field == wanted_field && wire_type == 2 {
            return true;
        }
        if !skip_protobuf_value(bytes, &mut cursor, wire_type, field) {
            return false;
        }
    }
    false
}

fn read_protobuf_varint(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn skip_protobuf_value(bytes: &[u8], cursor: &mut usize, wire_type: u64, field: u64) -> bool {
    let length = match wire_type {
        0 => return read_protobuf_varint(bytes, cursor).is_some(),
        1 => 8,
        2 => {
            match read_protobuf_varint(bytes, cursor).and_then(|value| usize::try_from(value).ok())
            {
                Some(value) => value,
                None => return false,
            }
        }
        3 => loop {
            let Some(key) = read_protobuf_varint(bytes, cursor) else {
                return false;
            };
            let nested_field = key >> 3;
            let nested_wire_type = key & 0x07;
            if nested_wire_type == 4 {
                return nested_field == field;
            }
            if !skip_protobuf_value(bytes, cursor, nested_wire_type, nested_field) {
                return false;
            }
        },
        4 => return false,
        5 => 4,
        _ => return false,
    };
    let Some(next) = cursor.checked_add(length) else {
        return false;
    };
    if next > bytes.len() {
        return false;
    }
    *cursor = next;
    true
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FheSnapshot {
    crp: Vec<u8>,
    params: Vec<u8>,
}

struct SecretKeySerializer {
    pub inner: SecretKey,
}

impl SecretKeySerializer {
    pub fn to_bytes(inner: SecretKey) -> Result<Vec<u8>> {
        let value = Self { inner };
        Ok(value.unsafe_serialize()?)
    }

    pub fn from_bytes(bytes: &[u8], params: Arc<BfvParameters>) -> Result<SecretKey> {
        Ok(Self::deserialize(bytes, params)?.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_SECURE_8192_PARAMS: &[u8] = &[
        8, 128, 64, 18, 27, 129, 128, 128, 134, 128, 128, 128, 128, 4, 129, 128, 144, 133, 128,
        128, 128, 128, 4, 129, 128, 228, 132, 128, 128, 128, 128, 4, 24, 192, 132, 61, 32, 10,
    ];

    #[test]
    fn restores_preset_variance_from_legacy_snapshot_params() {
        let expected = BfvParamSet::from(BfvPreset::SecureThreshold8192).build();
        let decoded = BfvParameters::try_deserialize(LEGACY_SECURE_8192_PARAMS).unwrap();
        assert_ne!(
            decoded.get_error1_variance(),
            expected.get_error1_variance()
        );
        let restored = deserialize_snapshot_params(LEGACY_SECURE_8192_PARAMS).unwrap();
        assert_eq!(
            restored.get_error1_variance(),
            expected.get_error1_variance()
        );
    }

    #[test]
    fn preserves_present_variance_with_unknown_protobuf_fields() {
        let preset = BfvParamSet::from(BfvPreset::SecureThreshold8192);
        let expected = e3_fhe_params::build_bfv_params(
            preset.degree,
            preset.plaintext_modulus,
            preset.moduli,
            Some("123"),
        );
        let mut encoded = expected.to_bytes();
        encoded.extend_from_slice(&[0x38, 0x01]);

        let restored = deserialize_snapshot_params(&encoded).unwrap();
        assert_eq!(
            restored.get_error1_variance(),
            expected.get_error1_variance()
        );
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SecretKeyData {
    coeffs: Box<[i64]>,
}

impl SecretKeySerializer {
    pub fn unsafe_serialize(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&SecretKeyData {
            coeffs: self.inner.coeffs.clone(),
        })?)
    }

    pub fn deserialize(bytes: &[u8], params: Arc<BfvParameters>) -> Result<SecretKeySerializer> {
        let SecretKeyData { coeffs } = bincode::deserialize(bytes)?;
        Ok(Self {
            inner: SecretKey::new(coeffs.to_vec(), &params),
        })
    }
}
