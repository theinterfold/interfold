// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Versioned transport and proof-backed validation for operational l-BFV keys.

use anyhow::{anyhow, ensure, Context, Result};
use e3_fhe_params::utils::compute_modulus_bit;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_witness::commitments::{
    compute_lbfv_key_envelope_commitment, compute_lbfv_public_key_commitment,
    compute_lbfv_rlk_commitment, compute_pk_aggregation_commitment,
    compute_rlk_aggregation_commitment,
};
use e3_zk_witness::encoding::fhe_poly_to_crt_centered_checked;
use fhe::bfv::traits::TryConvertFrom;
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, PublicKey};
use fhe::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use fhe::proto::lbfv::LbfvRelinearizationKey as RelinearizationKeyProto;
use fhe::trlbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe_math::rq::{Context as RingContext, Ntt, NttShoup, Poly};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize as FheSerialize};
use num_bigint::{BigInt, Sign};
use prost::Message;
use std::sync::Arc;

const MAGIC: [u8; 8] = *b"IFLBFVKE";
const SCHEMA_VERSION: u16 = 3;
/// Magic, schema version, then two big-endian `u32` lengths: the reserved public-key length and
/// the relinearization-key length.
const HEADER_LEN: usize = MAGIC.len() + 2 + 4 + 4;

/// Return `true` when bytes start with the l-BFV key-envelope identifier.
pub fn is_lbfv_key_envelope(encoded: &[u8]) -> bool {
    encoded.starts_with(&MAGIC)
}

/// The canonical key payload in an l-BFV key envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbfvKeyEnvelope<'a> {
    pub relinearization_key: &'a [u8],
}

/// The proof commitments derived from an l-BFV key envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbfvKeyEnvelopeCommitments {
    pub public_key: [u8; 32],
    pub relinearization_key: [u8; 32],
    pub envelope: [u8; 32],
}

/// Encode one canonical fhe.rs relinearization key in the version-3 envelope.
///
/// The header keeps a public-key length field, always zero: the TypeScript SDK and the aggregator
/// read the same 18-byte header, and the public key is rebuilt from the relinearization key.
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
    let (_, _, reconstructed_public_key) = read_relinearization_key(relinearization_key, &params)?;
    ensure_same_public_key_material(&public_key, &reconstructed_public_key)?;

    let relinearization_key_len = u32::try_from(relinearization_key.len())
        .context("l-BFV relinearization key is too large")?;

    let mut encoded = Vec::with_capacity(HEADER_LEN + relinearization_key.len());
    encoded.extend_from_slice(&MAGIC);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u32.to_be_bytes());
    encoded.extend_from_slice(&relinearization_key_len.to_be_bytes());
    encoded.extend_from_slice(relinearization_key);
    Ok(encoded)
}

/// Decode one version-3 l-BFV key envelope.
pub fn decode_lbfv_key_envelope(encoded: &[u8]) -> Result<LbfvKeyEnvelope<'_>> {
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
    );
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
    ensure!(
        encoded.len() - HEADER_LEN == relinearization_key_len,
        "l-BFV key envelope length does not match its header"
    );

    Ok(LbfvKeyEnvelope {
        relinearization_key: &encoded[HEADER_LEN..],
    })
}

/// Validate an envelope against its circuit commitment and return its commitments, the
/// component-0 encryption key and the parsed relinearization key.
pub fn validate_lbfv_key_envelope(
    encoded: &[u8],
    expected_commitment: [u8; 32],
    preset: BfvPreset,
) -> Result<(LbfvKeyEnvelopeCommitments, Vec<u8>, LBFVRelinearizationKey)> {
    let result = inspect_lbfv_key_envelope(encoded, preset)?;
    ensure!(
        result.0.envelope == expected_commitment,
        "l-BFV key envelope does not match the proof commitment"
    );
    Ok(result)
}

/// Inspect an envelope and return its proof commitments, the component-0 encryption key and the
/// parsed relinearization key.
pub fn inspect_lbfv_key_envelope(
    encoded: &[u8],
    preset: BfvPreset,
) -> Result<(LbfvKeyEnvelopeCommitments, Vec<u8>, LBFVRelinearizationKey)> {
    let parsed = parse_envelope(encoded, preset)?;
    let commitments = parsed.commitments()?;
    let encryption_key = parsed.encryption_key();
    Ok((commitments, encryption_key, parsed.relinearization_key))
}

/// Validate an envelope and return its component-0 encryption key, without computing the proof
/// commitments.
pub fn lbfv_key_envelope_encryption_key(encoded: &[u8], preset: BfvPreset) -> Result<Vec<u8>> {
    Ok(parse_envelope(encoded, preset)?.encryption_key())
}

/// An envelope whose rows are decoded and checked against the preset's fixed URS and CRS.
struct ParsedEnvelope {
    params: Arc<BfvParameters>,
    relinearization_key: LBFVRelinearizationKey,
    rows: RelinearizationKeyRows,
    public_key: LBFVPublicKey,
}

fn parse_envelope(encoded: &[u8], preset: BfvPreset) -> Result<ParsedEnvelope> {
    let envelope = decode_lbfv_key_envelope(encoded)?;
    let (params, _) = build_pair_for_preset(preset)?;
    let (relinearization_key, rows, public_key) =
        read_relinearization_key(envelope.relinearization_key, &params)?;

    let crs_seed =
        lbfv_crs_seed(preset).ok_or_else(|| anyhow!("the preset has no l-BFV CRS seed"))?;
    let urs_seed =
        lbfv_urs_seed(preset).ok_or_else(|| anyhow!("the preset has no l-BFV URS seed"))?;
    let crs = CommonRandomPolyVec::from_seed(&params, crs_seed)?.to_polys();
    let urs = CommonRandomPolyVec::from_seed(&params, urs_seed)?.to_polys();
    if let Some(seed) = public_key.seed {
        ensure!(
            seed == crs_seed,
            "l-BFV public-key seed does not match the preset CRS"
        );
    }
    let key_context = params.context_at_level(0)?;
    let row_count = public_key.l;
    ensure!(
        public_key.c.len() == row_count
            && row_count == params.moduli().len()
            && crs.len() == row_count
            && urs.len() == row_count
            && rows.d0.len() == row_count
            && rows.d1.len() == row_count
            && rows.d2.len() == row_count
            && rows.a.len() == row_count,
        "l-BFV key row count does not match the preset"
    );
    ensure!(
        public_key.c.iter().all(|row| row.len() == 2),
        "l-BFV public-key rows must have two components"
    );

    ensure_components_at_level(&rows.d0, key_context, "d0")?;
    ensure_components_at_level(&rows.d1, key_context, "d1")?;
    ensure_components_at_level(&rows.d2, key_context, "d2")?;
    ensure_components_at_level(&rows.a, key_context, "a")?;
    validate_shared_polynomials(&rows.d1, &urs, "d1")?;
    validate_shared_polynomials(&rows.a, &crs, "a")?;

    Ok(ParsedEnvelope {
        params,
        relinearization_key,
        rows,
        public_key,
    })
}

impl ParsedEnvelope {
    /// The component-0 encryption key: public-key row 0.
    fn encryption_key(&self) -> Vec<u8> {
        PublicKey {
            params: self.params.clone(),
            c: self.public_key.c[0].clone(),
        }
        .to_bytes()
    }

    /// The row-set commitments that the aggregation circuits output.
    fn commitments(&self) -> Result<LbfvKeyEnvelopeCommitments> {
        let bit = compute_modulus_bit(&self.params);
        let moduli = self.params.moduli();
        let degree = self.params.degree();
        let row_count = self.public_key.l;
        let mut public_key_commitment_rows = Vec::with_capacity(row_count);
        let mut d0_commitments = Vec::with_capacity(row_count);
        let mut d2_commitments = Vec::with_capacity(row_count);

        for row in 0..row_count {
            let b_crt =
                fhe_poly_to_crt_centered_checked(&self.public_key.c[row][0], moduli, degree)?;
            let a_crt =
                fhe_poly_to_crt_centered_checked(&self.public_key.c[row][1], moduli, degree)?;
            public_key_commitment_rows.push(compute_pk_aggregation_commitment(&b_crt, &a_crt, bit));
            d0_commitments.push(compute_rlk_aggregation_commitment(
                &fhe_poly_to_crt_centered_checked(&self.rows.d0[row], moduli, degree)?,
                bit,
            ));
            d2_commitments.push(compute_rlk_aggregation_commitment(
                &fhe_poly_to_crt_centered_checked(&self.rows.d2[row], moduli, degree)?,
                bit,
            ));
        }

        let public_key_commitment = compute_lbfv_public_key_commitment(&public_key_commitment_rows);
        let rlk_commitment = compute_lbfv_rlk_commitment(&d0_commitments, &d2_commitments)?;
        let envelope_commitment =
            compute_lbfv_key_envelope_commitment(&public_key_commitment, &rlk_commitment);
        Ok(LbfvKeyEnvelopeCommitments {
            public_key: field_bytes(&public_key_commitment)?,
            relinearization_key: field_bytes(&rlk_commitment)?,
            envelope: field_bytes(&envelope_commitment)?,
        })
    }
}

/// Rows that an operational relinearization key keeps private in fhe.rs.
///
/// fhe.rs 0.7 exposes no accessors for them, so they are read from the key's protobuf form.
/// Building the key from the same protobuf has already validated them.
struct RelinearizationKeyRows {
    d0: Vec<Poly<NttShoup>>,
    d1: Vec<Poly<NttShoup>>,
    d2: Vec<Poly<NttShoup>>,
    a: Vec<Poly<NttShoup>>,
}

/// Decode a relinearization key, its rows, and the level-zero public key it embeds.
///
/// The embedded public key pairs the key's `b` vector with the `a` rows of its `s -> r`
/// key-switching key, and keeps that key's CRS seed when it carries one.
fn read_relinearization_key(
    bytes: &[u8],
    params: &Arc<BfvParameters>,
) -> Result<(
    LBFVRelinearizationKey,
    RelinearizationKeyRows,
    LBFVPublicKey,
)> {
    let proto = RelinearizationKeyProto::decode(bytes)
        .context("failed to read the l-BFV relinearization key rows")?;
    let key = LBFVRelinearizationKey::try_convert_from(&proto, params)
        .context("failed to decode the l-BFV relinearization key")?;
    ensure!(
        key.ciphertext_level() == 0 && key.key_level() == 0,
        "reconstructing an l-BFV public key requires a level-0 relinearization key"
    );
    let context = params.context_at_level(0)?;
    let missing = || anyhow!("l-BFV relinearization key is missing a key-switching key");
    let r_to_s = proto.ksk_r_to_s.as_ref().ok_or_else(missing)?;
    let s_to_r = proto.ksk_s_to_r.as_ref().ok_or_else(missing)?;
    let explicit_rows = |rows: &[Vec<u8>]| -> Result<Vec<Poly<NttShoup>>> {
        rows.iter()
            .map(|row| Ok(Poly::<NttShoup>::from_bytes(row, context)?))
            .collect()
    };
    let d0 = explicit_rows(&r_to_s.c0)?;
    let d2 = explicit_rows(&s_to_r.c0)?;
    let b = explicit_rows(&proto.b_vec)?;
    // A seeded key-switching key serializes its seed instead of its shared `c1` rows.
    let shared_rows =
        |ksk: &KeySwitchingKeyProto| -> Result<(Vec<Poly<NttShoup>>, Option<[u8; 32]>)> {
            if ksk.seed.is_empty() {
                return Ok((explicit_rows(&ksk.c1)?, None));
            }
            let seed: [u8; 32] = ksk
                .seed
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("l-BFV key-switching seed must be 32 bytes"))?;
            let rows = CommonRandomPolyVec::from_seed(params, seed)?
                .to_polys()
                .into_iter()
                .take(d0.len())
                .map(Poly::<Ntt>::into_ntt_shoup)
                .collect();
            Ok((rows, Some(seed)))
        };
    let (d1, _) = shared_rows(r_to_s)?;
    let (a, a_seed) = shared_rows(s_to_r)?;
    let public_key = LBFVPublicKey::from_parts(
        b.into_iter().map(Poly::<NttShoup>::into_ntt).collect(),
        a.iter().cloned().map(Poly::<NttShoup>::into_ntt).collect(),
        params.clone(),
        a_seed,
    )
    .context("failed to reconstruct the l-BFV public key")?;
    let rows = RelinearizationKeyRows { d0, d1, d2, a };
    Ok((key, rows, public_key))
}

fn ensure_same_public_key_material(
    expected: &LBFVPublicKey,
    reconstructed: &LBFVPublicKey,
) -> Result<()> {
    ensure!(
        expected.par == reconstructed.par
            && expected.l == reconstructed.l
            && expected.c.len() == reconstructed.c.len(),
        "l-BFV relinearization key does not contain the public key"
    );
    for (expected_row, reconstructed_row) in expected.c.iter().zip(&reconstructed.c) {
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
    expected_context: &Arc<RingContext>,
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
pub(crate) mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_zk_samples::lbfv_proof_domain::sample_lbfv_proof_domain;
    use e3_zk_witness::threshold::lbfv_pk_aggregation::{
        LbfvPkAggregationCircuitData, LbfvPkAggregationInputs,
    };
    use e3_zk_witness::threshold::pk_generation::LbfvPkGenerationAdapter;
    use e3_zk_witness::threshold::rlk_aggregation::{
        RlkAggregationCircuitData, RlkAggregationComponent, RlkAggregationInputs,
    };
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

    /// Keys of two parties on the given URS and CRS rows.
    fn operational_key_material_on(
        preset: BfvPreset,
        urs: &CommonRandomPolyVec,
        crs: &CommonRandomPolyVec,
    ) -> Result<OperationalKeyMaterial> {
        let (params, _) = build_pair_for_preset(preset)?;
        let mut rng = rand::rng();
        let secret_keys = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect::<Vec<_>>();
        let public_key_shares = secret_keys
            .iter()
            .map(|secret_key| PublicKeyShare::contribute_with_crp(secret_key, crs, &mut rng))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let rlk_shares = secret_keys
            .iter()
            .map(|secret_key| {
                RelinKeyShare::contribute_with_crp(secret_key, urs, crs, 0, 0, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let public_key: LBFVPublicKey = public_key_shares.iter().cloned().aggregate()?;
        let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
        Ok((preset, public_key_shares, rlk_shares, public_key, rlk))
    }

    fn operational_key_material() -> Result<OperationalKeyMaterial> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let (params, _) = build_pair_for_preset(preset)?;
        let crs = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_crs_seed(preset).expect("the insecure preset has an l-BFV CRS"),
        )?;
        let urs = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_urs_seed(preset).expect("the insecure preset has an l-BFV URS"),
        )?;
        operational_key_material_on(preset, &urs, &crs)
    }

    fn operational_keys() -> Result<(BfvPreset, LBFVPublicKey, LBFVRelinearizationKey)> {
        let (preset, _, _, public_key, rlk) = operational_key_material()?;
        Ok((preset, public_key, rlk))
    }

    pub(crate) fn envelope() -> Result<Vec<u8>> {
        let (preset, public_key, rlk) = operational_keys()?;
        encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), preset)
    }

    #[test]
    fn envelope_round_trips_and_validates() -> Result<()> {
        let envelope = envelope()?;
        let (commitments, encryption_key, _) =
            inspect_lbfv_key_envelope(&envelope, BfvPreset::InsecureThresholdLbfv)?;
        validate_lbfv_key_envelope(
            &envelope,
            commitments.envelope,
            BfvPreset::InsecureThresholdLbfv,
        )?;
        assert_eq!(
            lbfv_key_envelope_encryption_key(&envelope, BfvPreset::InsecureThresholdLbfv)?,
            encryption_key
        );
        let (params, _) = build_pair_for_preset(BfvPreset::InsecureThresholdLbfv)?;
        PublicKey::from_bytes(&encryption_key, &params)?;
        Ok(())
    }

    #[test]
    fn envelope_commitment_matches_aggregation_circuit_outputs() -> Result<()> {
        let (preset, public_key_shares, rlk_shares, public_key, rlk) = operational_key_material()?;
        let encoded = encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), preset)?;
        let (actual, _, _) = inspect_lbfv_key_envelope(&encoded, preset)?;
        let (params, _) = build_pair_for_preset(preset)?;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let pk_config = e3_zk_config::threshold::pk_generation::Configs::new(
            preset,
            &params,
            CiphernodesCommitteeSize::Minimum,
        )?;
        let pk_aggregation_config =
            e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::new(
                preset,
                &params,
                CiphernodesCommitteeSize::Minimum,
            )?;
        let rlk_aggregation_config =
            e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::new(
                preset,
                &params,
                CiphernodesCommitteeSize::Minimum,
            )?;
        let proof_domain = sample_lbfv_proof_domain();
        let party_ids = vec![0, 1];
        let bit = compute_modulus_bit(&params);
        let pk_adapter = LbfvPkGenerationAdapter::from_config(&pk_config)?;
        let mut pk_rows = Vec::with_capacity(params.moduli().len());
        let mut d0_rows = Vec::with_capacity(params.moduli().len());
        let mut d2_rows = Vec::with_capacity(params.moduli().len());

        for row_index in 0..params.moduli().len() {
            let row_index = u32::try_from(row_index)?;
            let pk_inputs = LbfvPkAggregationInputs::compute(
                &pk_aggregation_config,
                &LbfvPkAggregationCircuitData {
                    committee: committee.clone(),
                    proof_domain: proof_domain.clone(),
                    aggregator_party_id: 0,
                    party_ids: party_ids.clone(),
                    row_index,
                    shares: public_key_shares.clone(),
                },
            )?;
            let rlk_agg = |component| -> Result<_> {
                let inputs = RlkAggregationInputs::compute(
                    &rlk_aggregation_config,
                    &RlkAggregationCircuitData {
                        committee: committee.clone(),
                        proof_domain: proof_domain.clone(),
                        aggregator_party_id: 0,
                        party_ids: party_ids.clone(),
                        row_index,
                        component,
                        shares: rlk_shares.clone(),
                    },
                )?;
                Ok(compute_rlk_aggregation_commitment(&inputs.agg, bit))
            };
            pk_rows.push(compute_pk_aggregation_commitment(
                &pk_inputs.pk0_agg,
                &pk_adapter.crs_row(row_index)?,
                bit,
            ));
            d0_rows.push(rlk_agg(RlkAggregationComponent::D0)?);
            d2_rows.push(rlk_agg(RlkAggregationComponent::D2)?);
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

    /// The user-data-encryption wrapper commits the encryption key as
    /// `H_PKAGG(commit(pk0), commit(pk1))`. The envelope's encryption key is public-key row 0, so
    /// that commitment must equal the row-0 `pk_agg_commitment` that `lbfv_pk_aggregation`
    /// outputs, with the same packing width.
    #[test]
    fn encryption_key_commitment_matches_row_zero_aggregation_output() -> Result<()> {
        use e3_zk_witness::commitments::compute_pk_aggregation_component_commitment;
        use e3_zk_witness::threshold::user_data_encryption::UserDataEncryptionCircuitData;
        use e3_zk_witness::threshold::user_data_encryption_chunked::Inputs as UdeInputs;
        use fhe::bfv::{Encoding, Plaintext};
        use fhe_traits::FheEncoder;

        let (preset, public_key_shares, _, public_key, rlk) = operational_key_material()?;
        let encoded = encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), preset)?;
        let (_, encryption_key, _) = inspect_lbfv_key_envelope(&encoded, preset)?;
        let (params, _) = build_pair_for_preset(preset)?;
        let bit = compute_modulus_bit(&params);
        let pk_config = e3_zk_config::threshold::pk_generation::Configs::new(
            preset,
            &params,
            CiphernodesCommitteeSize::Minimum,
        )?;
        let pk_aggregation_config =
            e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::new(
                preset,
                &params,
                CiphernodesCommitteeSize::Minimum,
            )?;

        let row_zero = LbfvPkAggregationInputs::compute(
            &pk_aggregation_config,
            &LbfvPkAggregationCircuitData {
                committee: CiphernodesCommitteeSize::Minimum.values(),
                proof_domain: sample_lbfv_proof_domain(),
                aggregator_party_id: 0,
                party_ids: vec![0, 1],
                row_index: 0,
                shares: public_key_shares,
            },
        )?;
        let crs_row_zero = LbfvPkGenerationAdapter::from_config(&pk_config)?.crs_row(0)?;
        let aggregation_output =
            compute_pk_aggregation_commitment(&row_zero.pk0_agg, &crs_row_zero, bit);

        let ude_config =
            e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(&params)?;
        let data = UserDataEncryptionCircuitData {
            public_key: PublicKey::from_bytes(&encryption_key, &params)?,
            plaintext: Plaintext::try_encode(&[1u64], Encoding::poly(), &params)?,
        };
        let (ciphertext, intermediates) = data
            .public_key
            .try_encrypt_with_intermediates(&data.plaintext, &mut rand::rng())?;
        let ude = UdeInputs::compute(&ude_config, &data, &ciphertext, &intermediates)?;
        let ude_bit = ude_config.bits.pk_bit;

        assert_eq!(ude_bit, bit);
        assert_eq!(
            ude.pk0_commitment,
            compute_pk_aggregation_component_commitment(&row_zero.pk0_agg, bit)
        );
        assert_eq!(
            ude.pk1_commitment,
            compute_pk_aggregation_component_commitment(&crs_row_zero, bit)
        );
        assert_eq!(
            compute_pk_aggregation_commitment(&ude.pk0is, &ude.pk1is, ude_bit),
            aggregation_output
        );
        Ok(())
    }

    #[test]
    fn envelope_rejects_a_different_proof_commitment() -> Result<()> {
        let envelope = envelope()?;
        let error =
            validate_lbfv_key_envelope(&envelope, [0x55; 32], BfvPreset::InsecureThresholdLbfv)
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
    fn envelope_rejects_an_unsupported_version() -> Result<()> {
        for version in [0_u16, SCHEMA_VERSION + 1] {
            let mut envelope = envelope()?;
            envelope[8..10].copy_from_slice(&version.to_be_bytes());
            let error = decode_lbfv_key_envelope(&envelope)
                .expect_err("an envelope of another schema version must be rejected");
            assert!(error
                .to_string()
                .contains(&format!("unsupported l-BFV key envelope version {version}")));
        }
        Ok(())
    }

    #[test]
    fn envelope_rejects_a_malformed_header_or_length() -> Result<()> {
        let envelope = envelope()?;

        let error = decode_lbfv_key_envelope(&envelope[..HEADER_LEN - 1])
            .expect_err("a truncated header must be rejected");
        assert!(error.to_string().contains("truncated"));

        let error = decode_lbfv_key_envelope(&envelope[..envelope.len() - 1])
            .expect_err("a truncated payload must be rejected");
        assert!(error.to_string().contains("does not match its header"));

        let mut trailing = envelope.clone();
        trailing.push(0);
        let error =
            decode_lbfv_key_envelope(&trailing).expect_err("trailing bytes must be rejected");
        assert!(error.to_string().contains("does not match its header"));

        let mut public_key_len = envelope;
        public_key_len[10..14].copy_from_slice(&1_u32.to_be_bytes());
        let error = decode_lbfv_key_envelope(&public_key_len)
            .expect_err("a nonzero public-key length must be rejected");
        assert!(error
            .to_string()
            .contains("must reconstruct its public key"));
        Ok(())
    }

    /// A key whose `d1` or `a` rows are not the preset's URS or CRS cannot be bound to the proofs.
    #[test]
    fn envelope_rejects_rows_that_differ_from_the_preset_reference_strings() -> Result<()> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let (params, _) = build_pair_for_preset(preset)?;
        let crs = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_crs_seed(preset).expect("the insecure preset has an l-BFV CRS"),
        )?;
        let urs = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_urs_seed(preset).expect("the insecure preset has an l-BFV URS"),
        )?;
        let foreign = CommonRandomPolyVec::new(&params, &mut rand::rng())?;

        for (foreign_urs, foreign_crs, expected) in [
            (&foreign, &crs, "l-BFV d1 differs at row 0"),
            (&urs, &foreign, "l-BFV a differs at row 0"),
        ] {
            let (_, _, _, public_key, rlk) =
                operational_key_material_on(preset, foreign_urs, foreign_crs)?;
            let encoded =
                encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), preset)?;
            let error = inspect_lbfv_key_envelope(&encoded, preset)
                .expect_err("a key on another reference string must be rejected");
            assert!(error.to_string().contains(expected), "{error}");
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
}
