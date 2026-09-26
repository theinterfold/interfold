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
    compute_rlk_aggregation_commitment, fhe_poly_to_crt_centered_checked,
};
use fhe::bfv::{CommonRandomPolyVec, PublicKey};
use fhe::trlbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe_math::rq::{Ntt, NttShoup, Poly};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use num_bigint::{BigInt, Sign};

const MAGIC: [u8; 8] = *b"IFLBFVKE";
const SCHEMA_VERSION: u16 = 3;
const HEADER_LEN: usize = MAGIC.len() + 2 + 4 + 4;

/// Return `true` when bytes start with the l-BFV key-envelope identifier.
pub fn is_lbfv_key_envelope(encoded: &[u8]) -> bool {
    encoded.starts_with(&MAGIC)
}

/// The canonical key payload in an l-BFV key envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LbfvKeyEnvelope {
    pub relinearization_key: Vec<u8>,
}

/// The proof commitments derived from an l-BFV key envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbfvKeyEnvelopeCommitments {
    pub public_key: [u8; 32],
    pub relinearization_key: [u8; 32],
    pub envelope: [u8; 32],
}

/// Encode one canonical fhe.rs relinearization key in the version-3 envelope.
pub fn encode_lbfv_key_envelope(
    public_key: &[u8],
    relinearization_key: &[u8],
    preset: BfvPreset,
) -> Result<Vec<u8>> {
    ensure!(!public_key.is_empty(), "l-BFV public key is empty");
    ensure!(
        !relinearization_key.is_empty(),
        "l-BFV relinearization key is empty"
    );
    let (params, _) = build_pair_for_preset(preset)?;
    let public_key = LBFVPublicKey::from_bytes(public_key, &params)
        .context("failed to decode the l-BFV public key")?;
    let relinearization_key_value =
        LBFVRelinearizationKey::from_bytes(relinearization_key, &params)
            .context("failed to decode the l-BFV relinearization key")?;
    let reconstructed_public_key = relinearization_key_value
        .reconstruct_public_key()
        .context("failed to reconstruct the l-BFV public key")?;
    ensure_same_public_key_material(&public_key, &reconstructed_public_key)?;

    let relinearization_key_len = u32::try_from(relinearization_key.len())
        .context("l-BFV relinearization key is too large")?;
    let payload_len = relinearization_key
        .len()
        .checked_add(HEADER_LEN)
        .ok_or_else(|| anyhow!("l-BFV key envelope length overflow"))?;

    let mut encoded = Vec::with_capacity(payload_len);
    encoded.extend_from_slice(&MAGIC);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&relinearization_key_len.to_be_bytes());
    encoded.extend_from_slice(relinearization_key);
    Ok(encoded)
}

/// Decode one version-3 l-BFV key envelope.
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
    ensure!(
        public_key_len == 0,
        "version-3 l-BFV key envelope must reconstruct its public key"
    );
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
    let relinearization_key =
        LBFVRelinearizationKey::from_bytes(&envelope.relinearization_key, &params)
            .context("failed to decode the l-BFV relinearization key")?;
    let public_key = relinearization_key
        .reconstruct_public_key()
        .context("failed to reconstruct the l-BFV public key")?;
    ensure!(
        relinearization_key.parameters().as_ref() == params.as_ref(),
        "l-BFV relinearization-key parameters do not match the preset"
    );
    ensure!(
        relinearization_key.ciphertext_level() == 0 && relinearization_key.key_level() == 0,
        "l-BFV relinearization key must use level zero"
    );
    ensure!(
        relinearization_key.decomposition_log_base() == 0,
        "l-BFV relinearization key must use RNS decomposition"
    );

    let crs_seed =
        lbfv_crs_seed(preset).ok_or_else(|| anyhow!("the preset has no l-BFV CRS seed"))?;
    let urs_seed =
        lbfv_urs_seed(preset).ok_or_else(|| anyhow!("the preset has no l-BFV URS seed"))?;
    let crs = CommonRandomPolyVec::from_seed(&params, crs_seed)?.to_polys();
    let urs = CommonRandomPolyVec::from_seed(&params, urs_seed)?.to_polys();
    if let Some(seed) = public_key.seed() {
        ensure!(
            seed == crs_seed,
            "l-BFV public-key seed does not match the preset CRS"
        );
    }
    let key_context = params.context_at_level(0)?.clone();
    let public_key_rows = public_key.rows();
    let public_key_row_count = public_key.row_count();
    let d0_rows = relinearization_key.d0_components();
    let d1_rows = relinearization_key.d1_components();
    let d2_rows = relinearization_key.d2_components();
    let a_rows = relinearization_key.a_components();
    let b_rows = relinearization_key.b_components();
    ensure!(
        public_key_rows.len() == public_key_row_count
            && public_key_row_count == params.moduli().len()
            && crs.len() == public_key_row_count
            && urs.len() == public_key_row_count
            && d0_rows.len() == public_key_row_count
            && d1_rows.len() == public_key_row_count
            && d2_rows.len() == public_key_row_count
            && a_rows.len() == public_key_row_count
            && b_rows.len() == public_key_row_count,
        "l-BFV key row count does not match the preset"
    );

    ensure_components_at_level(d0_rows, &key_context, "d0")?;
    ensure_components_at_level(d1_rows, &key_context, "d1")?;
    ensure_components_at_level(d2_rows, &key_context, "d2")?;
    ensure_components_at_level(a_rows, &key_context, "a")?;
    ensure_components_at_level(b_rows, &key_context, "b")?;
    validate_shared_polynomials(d1_rows, &urs, "d1")?;
    validate_shared_polynomials(a_rows, &crs, "a")?;
    let bit = compute_modulus_bit(&params);
    let moduli = params.moduli();
    let degree = params.degree();
    let mut public_key_commitment_rows = Vec::with_capacity(public_key_row_count);
    let mut d0_commitments = Vec::with_capacity(public_key_row_count);
    let mut d2_commitments = Vec::with_capacity(public_key_row_count);

    for row in 0..public_key_row_count {
        let ciphertext = public_key_rows
            .get(row)
            .ok_or_else(|| anyhow!("l-BFV public key is missing row {row}"))?;
        ensure!(
            ciphertext.len() == 2,
            "l-BFV public-key row {row} must have two components"
        );
        let b = ciphertext
            .first()
            .ok_or_else(|| anyhow!("l-BFV public-key row {row} has no b component"))?;
        let a = ciphertext
            .get(1)
            .ok_or_else(|| anyhow!("l-BFV public-key row {row} has no a component"))?;
        let b_raw = CrtPolynomial::from_fhe_polynomial(b);
        let a_raw = CrtPolynomial::from_fhe_polynomial(a);
        ensure!(
            a_raw == CrtPolynomial::from_fhe_polynomial(&crs[row]),
            "l-BFV public-key row {row} does not use the preset CRS"
        );
        ensure!(
            CrtPolynomial::from_fhe_polynomial(&b_rows[row]) == b_raw,
            "l-BFV relinearization-key b-vector differs at row {row}"
        );
        let b_crt = fhe_poly_to_crt_centered_checked(b, moduli, degree)?;
        let a_crt = fhe_poly_to_crt_centered_checked(a, moduli, degree)?;
        public_key_commitment_rows.push(compute_pk_aggregation_commitment(&b_crt, &a_crt, bit));
        d0_commitments.push(compute_rlk_aggregation_commitment(
            &fhe_poly_to_crt_centered_checked(&d0_rows[row], moduli, degree)?,
            bit,
        ));
        d2_commitments.push(compute_rlk_aggregation_commitment(
            &fhe_poly_to_crt_centered_checked(&d2_rows[row], moduli, degree)?,
            bit,
        ));
    }

    let public_key_commitment = compute_lbfv_public_key_commitment(&public_key_commitment_rows);
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
        c: public_key_rows
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("l-BFV public key has no encryption component"))?,
    }
    .to_bytes();
    Ok((commitments, encryption_key))
}

fn ensure_same_public_key_material(
    expected: &LBFVPublicKey,
    reconstructed: &LBFVPublicKey,
) -> Result<()> {
    ensure!(
        expected.parameters() == reconstructed.parameters()
            && expected.row_count() == reconstructed.row_count()
            && expected.rows().len() == reconstructed.rows().len(),
        "l-BFV relinearization key does not contain the public key"
    );
    for (expected_row, reconstructed_row) in expected.rows().iter().zip(reconstructed.rows()) {
        ensure!(
            expected_row.level == reconstructed_row.level
                && expected_row.iter().eq(reconstructed_row.iter()),
            "l-BFV relinearization key does not contain the public key"
        );
    }
    Ok(())
}

fn ensure_components_at_level(
    components: &[Poly<NttShoup>],
    expected_context: &std::sync::Arc<fhe_math::rq::Context>,
    name: &str,
) -> Result<()> {
    for (row, component) in components.iter().enumerate() {
        ensure!(
            component.ctx() == expected_context,
            "l-BFV {name} row {row} has an unexpected context"
        );
    }
    Ok(())
}

fn validate_shared_polynomials(
    actual_rows: &[Poly<NttShoup>],
    expected_rows: &[Poly<Ntt>],
    name: &str,
) -> Result<()> {
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
    use e3_zk_helpers::circuits::threshold::lbfv_pk_aggregation::{
        LbfvPkAggregationCircuitData, LbfvPkAggregationInputs,
    };
    use e3_zk_helpers::circuits::threshold::lbfv_proof_domain::sample_lbfv_proof_domain;
    use e3_zk_helpers::circuits::threshold::pk_generation::LbfvPkGenerationAdapter;
    use e3_zk_helpers::circuits::threshold::rlk_aggregation::{
        RlkAggregationCircuitData, RlkAggregationInputs,
    };
    use e3_zk_helpers::{CiphernodesCommitteeSize, Computation};
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::SecretKey;
    use fhe::trlbfv::{aggregate_relinearization_key, PublicKeyShare, RelinKeyShare};

    type OperationalKeyMaterial = (
        BfvPreset,
        Vec<PublicKeyShare>,
        Vec<RelinKeyShare>,
        LBFVPublicKey,
        LBFVRelinearizationKey,
    );

    fn operational_key_material() -> Result<OperationalKeyMaterial> {
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
        let public_key: LBFVPublicKey = public_key_shares.iter().cloned().aggregate()?;
        let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
        Ok((preset, public_key_shares, rlk_shares, public_key, rlk))
    }

    fn operational_keys() -> Result<(BfvPreset, LBFVPublicKey, LBFVRelinearizationKey)> {
        let (preset, _, _, public_key, rlk) = operational_key_material()?;
        Ok((preset, public_key, rlk))
    }

    fn envelope() -> Result<Vec<u8>> {
        let (preset, public_key, rlk) = operational_keys()?;
        encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), preset)
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
    fn envelope_commitment_matches_aggregation_circuit_outputs() -> Result<()> {
        let (preset, public_key_shares, rlk_shares, public_key, rlk) = operational_key_material()?;
        let encoded = encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), preset)?;
        let (actual, _) = inspect_lbfv_key_envelope(&encoded, preset)?;
        let (params, _) = build_pair_for_preset(preset)?;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let proof_domain = sample_lbfv_proof_domain();
        let party_ids = vec![0, 1];
        let bit = compute_modulus_bit(&params);
        let pk_adapter = LbfvPkGenerationAdapter::new(preset)?;
        let mut pk_rows = Vec::with_capacity(params.moduli().len());
        let mut d0_rows = Vec::with_capacity(params.moduli().len());
        let mut d2_rows = Vec::with_capacity(params.moduli().len());

        for row_index in 0..params.moduli().len() {
            let row_index = u32::try_from(row_index)?;
            let pk_inputs = LbfvPkAggregationInputs::compute(
                preset,
                &LbfvPkAggregationCircuitData {
                    committee: committee.clone(),
                    proof_domain: proof_domain.clone(),
                    aggregator_party_id: 0,
                    party_ids: party_ids.clone(),
                    row_index,
                    shares: public_key_shares.clone(),
                },
            )?;
            let rlk_inputs = RlkAggregationInputs::compute(
                preset,
                &RlkAggregationCircuitData {
                    committee: committee.clone(),
                    proof_domain: proof_domain.clone(),
                    aggregator_party_id: 0,
                    party_ids: party_ids.clone(),
                    row_index,
                    shares: rlk_shares.clone(),
                },
            )?;
            pk_rows.push(compute_pk_aggregation_commitment(
                &pk_inputs.pk0_agg,
                &pk_adapter.crs_row(row_index)?,
                bit,
            ));
            d0_rows.push(compute_rlk_aggregation_commitment(&rlk_inputs.d0_agg, bit));
            d2_rows.push(compute_rlk_aggregation_commitment(&rlk_inputs.d2_agg, bit));
        }

        let expected_public_key = compute_lbfv_public_key_commitment(&pk_rows);
        let expected_rlk = compute_lbfv_rlk_commitment(&d0_rows, &d2_rows)?;
        let expected_envelope =
            compute_lbfv_key_envelope_commitment(&expected_public_key, &expected_rlk);
        assert_eq!(actual.public_key, field_bytes(&expected_public_key)?);
        assert_eq!(actual.relinearization_key, field_bytes(&expected_rlk)?);
        assert_eq!(actual.envelope, field_bytes(&expected_envelope)?);
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

    #[test]
    fn envelope_rejects_a_different_parameter_preset() -> Result<()> {
        let envelope = envelope()?;
        let error = inspect_lbfv_key_envelope(&envelope, BfvPreset::SecureThreshold16384)
            .expect_err("a key from another preset must fail");
        assert!(error.to_string().contains("failed to decode"));
        Ok(())
    }

    #[test]
    fn envelope_rejects_the_pre_cutover_outer_version() -> Result<()> {
        for version in [1_u16, 2_u16] {
            let mut envelope = envelope()?;
            envelope[8..10].copy_from_slice(&version.to_be_bytes());
            let error = decode_lbfv_key_envelope(&envelope)
                .expect_err("the pre-cutover operational envelope must be rejected");
            assert!(error
                .to_string()
                .contains(&format!("unsupported l-BFV key envelope version {version}")));
        }
        Ok(())
    }

    #[test]
    fn envelope_rejects_a_relinearization_key_for_another_public_key() -> Result<()> {
        let (preset, public_key, _) = operational_keys()?;
        let (_, _, other_rlk) = operational_keys()?;
        let error = encode_lbfv_key_envelope(&public_key.to_bytes(), &other_rlk.to_bytes(), preset)
            .expect_err("the relinearization key must contain the public key");
        assert!(error
            .to_string()
            .contains("does not contain the public key"));
        Ok(())
    }

    #[test]
    fn contribution_envelopes_round_trip_and_do_not_cross_key_boundaries() -> Result<()> {
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
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key_share = PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng)?;
        let (relinearization_key_share, _) =
            RelinKeyShare::contribution_with_crp_extended(&secret_key, &urs, &crs, 0, 0, &mut rng)?;
        assert_eq!(
            PublicKeyShare::from_bytes(&public_key_share.to_bytes(), &params)?,
            public_key_share
        );
        assert_eq!(
            RelinKeyShare::from_bytes(&relinearization_key_share.to_bytes(), &params)?,
            relinearization_key_share
        );

        let encoded_rlk_share = relinearization_key_share.to_bytes();
        let public_key: LBFVPublicKey = [public_key_share].into_iter().aggregate()?;
        let operational_rlk =
            aggregate_relinearization_key(&[relinearization_key_share], &public_key)?;
        // The old public-key contribution format was the bare operational-key payload.
        assert!(PublicKeyShare::from_bytes(&public_key.to_bytes(), &params).is_err());
        // The old RLK contribution format was the inner contribution message without its
        // LBFVRelinKeyShare envelope. Verify that persisted pre-cutoff bytes remain rejected.
        let (body_start, body_len) = protobuf_length_delimited_body(&encoded_rlk_share)?;
        assert!(RelinKeyShare::from_bytes(
            &encoded_rlk_share[body_start..body_start + body_len],
            &params
        )
        .is_err());
        assert!(RelinKeyShare::from_bytes(&operational_rlk.to_bytes(), &params).is_err());
        Ok(())
    }

    fn protobuf_length_delimited_body(encoded: &[u8]) -> Result<(usize, usize)> {
        ensure!(
            encoded.first() == Some(&0x0a),
            "missing protobuf envelope field"
        );
        let mut offset = 1;
        let mut length = 0usize;
        let mut shift = 0;
        loop {
            let byte = *encoded
                .get(offset)
                .ok_or_else(|| anyhow!("truncated protobuf envelope length"))?;
            offset += 1;
            length |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            ensure!(
                shift < usize::BITS as usize,
                "protobuf envelope length overflows usize"
            );
        }
        ensure!(
            encoded.len() >= offset + length,
            "truncated protobuf envelope body"
        );
        Ok((offset, length))
    }
}
