// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Versioned transport and proof-backed validation for operational l-BFV keys.

use anyhow::{anyhow, ensure, Context, Result};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::CrtPolynomial;
use e3_zk_helpers::{
    compute_lbfv_key_envelope_commitment, compute_lbfv_public_key_commitment,
    compute_lbfv_rlk_commitment, compute_modulus_bit, compute_pk_aggregation_commitment,
    compute_rlk_aggregation_commitment,
};
use fhe::bfv::{CommonRandomPolyVec, PublicKey};
use fhe::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use fhe::proto::lbfv::LbfvRelinearizationKey as LbfvRelinearizationKeyProto;
use fhe::trlbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe_math::rq::{NttShoup, Poly};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize as FheSerialize};
use num_bigint::{BigInt, Sign};
use prost::Message;

const MAGIC: [u8; 8] = *b"IFLBFVKE";
const SCHEMA_VERSION: u16 = 1;
const HEADER_LEN: usize = MAGIC.len() + 2 + 4 + 4;

/// Return `true` when bytes start with the l-BFV key-envelope identifier.
pub fn is_lbfv_key_envelope(encoded: &[u8]) -> bool {
    encoded.starts_with(&MAGIC)
}

/// The canonical key payloads in an l-BFV key envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LbfvKeyEnvelope {
    pub public_key: Vec<u8>,
    pub relinearization_key: Vec<u8>,
}

/// The proof commitments derived from an l-BFV key envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbfvKeyEnvelopeCommitments {
    pub public_key: [u8; 32],
    pub relinearization_key: [u8; 32],
    pub envelope: [u8; 32],
}

/// Encode the two canonical fhe.rs key payloads in the version-1 envelope.
pub fn encode_lbfv_key_envelope(public_key: &[u8], relinearization_key: &[u8]) -> Result<Vec<u8>> {
    ensure!(!public_key.is_empty(), "l-BFV public key is empty");
    ensure!(
        !relinearization_key.is_empty(),
        "l-BFV relinearization key is empty"
    );
    let public_key_len =
        u32::try_from(public_key.len()).context("l-BFV public key is too large")?;
    let relinearization_key_len = u32::try_from(relinearization_key.len())
        .context("l-BFV relinearization key is too large")?;
    let payload_len = public_key
        .len()
        .checked_add(relinearization_key.len())
        .and_then(|length| length.checked_add(HEADER_LEN))
        .ok_or_else(|| anyhow!("l-BFV key envelope length overflow"))?;

    let mut encoded = Vec::with_capacity(payload_len);
    encoded.extend_from_slice(&MAGIC);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    encoded.extend_from_slice(&public_key_len.to_be_bytes());
    encoded.extend_from_slice(&relinearization_key_len.to_be_bytes());
    encoded.extend_from_slice(public_key);
    encoded.extend_from_slice(relinearization_key);
    Ok(encoded)
}

/// Decode one version-1 l-BFV key envelope.
pub fn decode_lbfv_key_envelope(encoded: &[u8]) -> Result<LbfvKeyEnvelope> {
    ensure!(
        encoded.len() >= HEADER_LEN,
        "l-BFV key envelope is truncated"
    );
    ensure!(
        encoded[..MAGIC.len()] == MAGIC,
        "invalid l-BFV key envelope magic"
    );
    let version = u16::from_be_bytes(encoded[8..10].try_into().expect("fixed version field"));
    ensure!(
        version == SCHEMA_VERSION,
        "unsupported l-BFV key envelope version {version}"
    );
    let public_key_len = u32::from_be_bytes(
        encoded[10..14]
            .try_into()
            .expect("fixed public-key length field"),
    ) as usize;
    let relinearization_key_len = u32::from_be_bytes(
        encoded[14..18]
            .try_into()
            .expect("fixed relinearization-key length field"),
    ) as usize;
    ensure!(public_key_len > 0, "l-BFV public key is empty");
    ensure!(
        relinearization_key_len > 0,
        "l-BFV relinearization key is empty"
    );
    let public_key_end = HEADER_LEN
        .checked_add(public_key_len)
        .ok_or_else(|| anyhow!("l-BFV public-key length overflow"))?;
    let envelope_end = public_key_end
        .checked_add(relinearization_key_len)
        .ok_or_else(|| anyhow!("l-BFV relinearization-key length overflow"))?;
    ensure!(
        envelope_end == encoded.len(),
        "l-BFV key envelope length does not match its header"
    );

    Ok(LbfvKeyEnvelope {
        public_key: encoded[HEADER_LEN..public_key_end].to_vec(),
        relinearization_key: encoded[public_key_end..envelope_end].to_vec(),
    })
}

/// Validate an envelope against its circuit commitment and return the component-0 encryption key.
pub fn validate_lbfv_key_envelope(
    encoded: &[u8],
    expected_commitment: [u8; 32],
    preset: BfvPreset,
) -> Result<(LbfvKeyEnvelopeCommitments, Vec<u8>)> {
    let result = inspect_lbfv_key_envelope(encoded, preset)?;
    ensure!(
        result.0.envelope == expected_commitment,
        "l-BFV key envelope does not match the proof commitment"
    );
    Ok(result)
}

/// Inspect an envelope and return its proof commitments and component-0 encryption key.
pub fn inspect_lbfv_key_envelope(
    encoded: &[u8],
    preset: BfvPreset,
) -> Result<(LbfvKeyEnvelopeCommitments, Vec<u8>)> {
    let envelope = decode_lbfv_key_envelope(encoded)?;
    let (params, _) = build_pair_for_preset(preset)?;
    let public_key = LBFVPublicKey::from_bytes(&envelope.public_key, &params)
        .context("failed to decode the l-BFV public key")?;
    let relinearization_key =
        LBFVRelinearizationKey::from_bytes(&envelope.relinearization_key, &params)
            .context("failed to decode the l-BFV relinearization key")?;
    ensure!(
        relinearization_key.ciphertext_level() == 0 && relinearization_key.key_level() == 0,
        "l-BFV relinearization key must use level zero"
    );

    let rlk_proto = LbfvRelinearizationKeyProto::decode(envelope.relinearization_key.as_slice())
        .context("failed to decode the l-BFV relinearization-key payload")?;
    let r_to_s = rlk_proto
        .ksk_r_to_s
        .as_ref()
        .ok_or_else(|| anyhow!("l-BFV relinearization key has no r-to-s key"))?;
    let s_to_r = rlk_proto
        .ksk_s_to_r
        .as_ref()
        .ok_or_else(|| anyhow!("l-BFV relinearization key has no s-to-r key"))?;
    validate_ksk_shape(r_to_s, public_key.l, "r-to-s")?;
    validate_ksk_shape(s_to_r, public_key.l, "s-to-r")?;
    ensure!(
        rlk_proto.b_vec.len() == public_key.l,
        "l-BFV relinearization-key b-vector length does not match the public key"
    );

    let key_context = params.context_at_level(0)?.clone();
    let crs_seed =
        lbfv_crs_seed(preset).ok_or_else(|| anyhow!("the preset has no l-BFV CRS seed"))?;
    let urs_seed =
        lbfv_urs_seed(preset).ok_or_else(|| anyhow!("the preset has no l-BFV URS seed"))?;
    let crs = CommonRandomPolyVec::from_seed(&params, crs_seed)?.to_polys();
    let urs = CommonRandomPolyVec::from_seed(&params, urs_seed)?.to_polys();
    ensure!(
        public_key.c.len() == public_key.l
            && crs.len() == public_key.l
            && urs.len() == public_key.l,
        "l-BFV key row count does not match the preset"
    );

    let d0_rows = decode_ksk_polynomials(&r_to_s.c0, &key_context, "r-to-s c0")?;
    let d2_rows = decode_ksk_polynomials(&s_to_r.c0, &key_context, "s-to-r c0")?;
    let b_vec = decode_ksk_polynomials(&rlk_proto.b_vec, &key_context, "b-vector")?;
    validate_shared_polynomials(r_to_s, urs_seed, &urs, &key_context, "r-to-s c1")?;
    validate_shared_polynomials(s_to_r, crs_seed, &crs, &key_context, "s-to-r c1")?;
    let bit = compute_modulus_bit(&params);
    let mut public_key_rows = Vec::with_capacity(public_key.l);
    let mut d0_commitments = Vec::with_capacity(public_key.l);
    let mut d2_commitments = Vec::with_capacity(public_key.l);

    for row in 0..public_key.l {
        let ciphertext = public_key
            .c
            .get(row)
            .ok_or_else(|| anyhow!("l-BFV public key is missing row {row}"))?;
        let b = &ciphertext[0];
        let a = &ciphertext[1];
        let b_crt = CrtPolynomial::from_fhe_polynomial(b);
        let a_crt = CrtPolynomial::from_fhe_polynomial(a);
        ensure!(
            a_crt == CrtPolynomial::from_fhe_polynomial(&crs[row]),
            "l-BFV public-key row {row} does not use the preset CRS"
        );
        ensure!(
            CrtPolynomial::from_fhe_polynomial(&b_vec[row]) == b_crt,
            "l-BFV relinearization-key b-vector differs at row {row}"
        );
        public_key_rows.push(compute_pk_aggregation_commitment(&b_crt, &a_crt, bit));
        d0_commitments.push(compute_rlk_aggregation_commitment(
            &CrtPolynomial::from_fhe_polynomial(&d0_rows[row]),
            bit,
        ));
        d2_commitments.push(compute_rlk_aggregation_commitment(
            &CrtPolynomial::from_fhe_polynomial(&d2_rows[row]),
            bit,
        ));
    }

    let public_key_commitment = compute_lbfv_public_key_commitment(&public_key_rows);
    let rlk_commitment = compute_lbfv_rlk_commitment(&d0_commitments, &d2_commitments)?;
    let envelope_commitment =
        compute_lbfv_key_envelope_commitment(&public_key_commitment, &rlk_commitment);
    let commitments = LbfvKeyEnvelopeCommitments {
        public_key: field_bytes(&public_key_commitment)?,
        relinearization_key: field_bytes(&rlk_commitment)?,
        envelope: field_bytes(&envelope_commitment)?,
    };
    let encryption_key = PublicKey {
        params,
        c: public_key
            .c
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("l-BFV public key has no encryption component"))?,
    }
    .to_bytes();
    Ok((commitments, encryption_key))
}

fn validate_ksk_shape(ksk: &KeySwitchingKeyProto, rows: usize, name: &str) -> Result<()> {
    ensure!(
        ksk.ciphertext_level == 0 && ksk.ksk_level == 0 && ksk.log_base == 0,
        "l-BFV {name} key has noncanonical levels or decomposition"
    );
    ensure!(
        ksk.c0.len() == rows,
        "l-BFV {name} key row count does not match the public key"
    );
    ensure!(
        (ksk.seed.is_empty() && ksk.c1.len() == rows)
            || (!ksk.seed.is_empty() && ksk.c1.is_empty()),
        "l-BFV {name} key has invalid shared-polynomial encoding"
    );
    Ok(())
}

fn validate_shared_polynomials(
    ksk: &KeySwitchingKeyProto,
    expected_seed: [u8; 32],
    expected_rows: &[Poly<fhe_math::rq::Ntt>],
    context: &std::sync::Arc<fhe_math::rq::Context>,
    name: &str,
) -> Result<()> {
    if !ksk.seed.is_empty() {
        ensure!(
            ksk.seed == expected_seed,
            "l-BFV {name} seed does not match the preset"
        );
        return Ok(());
    }

    let actual_rows = decode_ksk_polynomials(&ksk.c1, context, name)?;
    ensure!(
        actual_rows.len() == expected_rows.len(),
        "l-BFV {name} row count does not match the preset"
    );
    for (row, (actual, expected)) in actual_rows.iter().zip(expected_rows).enumerate() {
        ensure!(
            CrtPolynomial::from_fhe_polynomial(actual)
                == CrtPolynomial::from_fhe_polynomial(expected),
            "l-BFV {name} differs at row {row}"
        );
    }
    Ok(())
}

fn decode_ksk_polynomials(
    encoded: &[Vec<u8>],
    context: &std::sync::Arc<fhe_math::rq::Context>,
    name: &str,
) -> Result<Vec<Poly<NttShoup>>> {
    encoded
        .iter()
        .enumerate()
        .map(|(row, bytes)| {
            Poly::<NttShoup>::from_bytes(bytes, context)
                .map_err(|error| anyhow!("failed to decode l-BFV {name} row {row}: {error}"))
        })
        .collect()
}

fn field_bytes(value: &BigInt) -> Result<[u8; 32]> {
    let (sign, bytes) = value.to_bytes_be();
    ensure!(
        sign != Sign::Minus && bytes.len() <= 32,
        "commitment does not fit one field"
    );
    let mut encoded = [0u8; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::SecretKey;
    use fhe::trlbfv::{aggregate_relinearization_key, PublicKeyShare, RelinKeyShare};

    fn envelope() -> Result<Vec<u8>> {
        let preset = BfvPreset::InsecureThreshold512;
        let (params, _) = build_pair_for_preset(preset)?;
        let crs = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_crs_seed(preset).expect("the insecure preset has an l-BFV CRS"),
        )?;
        let urs = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_urs_seed(preset).expect("the insecure preset has an l-BFV URS"),
        )?;
        let mut rng = rand::rng();
        let secret_keys = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect::<Vec<_>>();
        let public_key_shares = secret_keys
            .iter()
            .map(|secret_key| PublicKeyShare::contribute_with_crp(secret_key, &crs, &mut rng))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let rlk_shares = secret_keys
            .iter()
            .map(|secret_key| {
                RelinKeyShare::contribution_with_crp(secret_key, &urs, &crs, 0, 0, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let public_key: LBFVPublicKey = public_key_shares.into_iter().aggregate()?;
        let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
        encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes())
    }

    #[test]
    fn envelope_round_trips_and_validates() -> Result<()> {
        let envelope = envelope()?;
        let (commitments, encryption_key) =
            inspect_lbfv_key_envelope(&envelope, BfvPreset::InsecureThreshold512)?;
        validate_lbfv_key_envelope(
            &envelope,
            commitments.envelope,
            BfvPreset::InsecureThreshold512,
        )?;
        let (params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512)?;
        PublicKey::from_bytes(&encryption_key, &params)?;
        Ok(())
    }

    #[test]
    fn envelope_rejects_a_different_proof_commitment() -> Result<()> {
        let envelope = envelope()?;
        let error =
            validate_lbfv_key_envelope(&envelope, [0x55; 32], BfvPreset::InsecureThreshold512)
                .expect_err("a different proof commitment must fail");
        assert!(error
            .to_string()
            .contains("does not match the proof commitment"));
        Ok(())
    }
}
