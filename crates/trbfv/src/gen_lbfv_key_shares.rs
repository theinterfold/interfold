// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use derivative::Derivative;
use e3_crypto::{Cipher, SensitiveBytes};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_utils::ArcBytes;
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare, RlkWitness};
use fhe_math::rq::{NttShoup, Poly, PowerBasis};
use fhe_traits::Serialize as FheSerialize;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::helpers::{serialize_secret_key, try_poly_pb_from_bytes};
use crate::lbfv_operation::{LbfvOperationId, LbfvOperationKind};

/// Generate one l-BFV public-key share and one relinearization-key share.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct GenLbfvKeySharesRequest {
    pub operation_id: LbfvOperationId,
    /// Canonical l-BFV proof-session identifier.
    pub session_id: [u8; 32],
    /// Zero-based party ID in the finalized committee.
    pub party_id: u32,
    /// The encrypted level-0 secret-key polynomial used by the legacy C1 request.
    #[derivative(Debug = "ignore")]
    pub secret_key_bytes: SensitiveBytes,
    /// The encrypted 32-byte seed for deterministic generation retries.
    #[derivative(Debug = "ignore")]
    pub generation_seed: SensitiveBytes,
    pub params_preset: BfvPreset,
    pub ciphertext_level: u32,
    pub key_level: u32,
}

impl GenLbfvKeySharesRequest {
    /// Recompute the operation identity from request semantics.
    pub fn expected_operation_id(&self) -> LbfvOperationId {
        LbfvOperationId::new(
            self.session_id,
            self.party_id,
            LbfvOperationKind::GenKeyShares,
            None,
            None,
            None,
        )
    }

    /// Recompute and validate the operation identity from request semantics.
    pub fn validate_operation_id(&self) -> Result<()> {
        ensure!(
            self.params_preset == BfvPreset::SecureThreshold16384,
            "l-BFV key-share generation requires SecureThreshold16384"
        );
        ensure!(
            self.ciphertext_level == 0 && self.key_level == 0,
            "l-BFV key-share generation supports only ciphertext level 0 and key level 0"
        );
        ensure!(
            self.operation_id == self.expected_operation_id(),
            "l-BFV key-share operation ID does not match the request semantics"
        );
        Ok(())
    }
}

/// The encrypted private values required to prove each RLK row.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct EncryptedRlkWitness {
    #[derivative(Debug = "ignore")]
    pub r_bytes: SensitiveBytes,
    #[derivative(Debug = "ignore")]
    pub errors_d0_bytes: Vec<SensitiveBytes>,
    #[derivative(Debug = "ignore")]
    pub errors_d2_bytes: Vec<SensitiveBytes>,
}

/// Public l-BFV shares and the encrypted local RLK proof witness.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct GenLbfvKeySharesResponse {
    pub operation_id: LbfvOperationId,
    pub public_key_share_bytes: ArcBytes,
    pub rlk_share_bytes: ArcBytes,
    #[derivative(Debug = "ignore")]
    pub witness: EncryptedRlkWitness,
}

struct RlkWitnessGuard(RlkWitness);

impl Drop for RlkWitnessGuard {
    fn drop(&mut self) {
        self.0.errors_d0.zeroize();
        self.0.errors_d2.zeroize();
    }
}

fn encrypt_plaintext(mut bytes: Vec<u8>, cipher: &Cipher) -> Result<SensitiveBytes> {
    let encrypted = cipher.encrypt_data(&mut bytes);
    bytes.zeroize();
    Ok(SensitiveBytes::from_encrypted(&encrypted?))
}

fn encrypt_error_rows(rows: &[Poly<NttShoup>], cipher: &Cipher) -> Result<Vec<SensitiveBytes>> {
    rows.iter()
        .map(|row| encrypt_plaintext(row.to_bytes(), cipher))
        .collect()
}

/// Reconstruct the ternary BFV secret key from the level-0 RNS polynomial used by C1.
pub fn deserialize_c1_secret_key(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<SecretKey> {
    let poly: Zeroizing<Poly<PowerBasis>> = Zeroizing::new(try_poly_pb_from_bytes(bytes, params)?);
    let coefficients = poly.coefficients();
    ensure!(
        coefficients.nrows() == params.moduli().len() && coefficients.ncols() == params.degree(),
        "C1 secret-key polynomial has an invalid shape"
    );

    let first_modulus = params.moduli()[0];
    let mut secret_coefficients = Zeroizing::new(Vec::with_capacity(params.degree()));
    for coefficient_index in 0..params.degree() {
        let residue = coefficients[(0, coefficient_index)];
        let centered = if residue <= first_modulus / 2 {
            i64::try_from(residue).context("C1 secret-key coefficient does not fit i64")?
        } else {
            -i64::try_from(first_modulus - residue)
                .context("C1 secret-key coefficient does not fit i64")?
        };
        ensure!(
            (-1..=1).contains(&centered),
            "C1 secret-key polynomial contains a non-ternary coefficient"
        );

        for (row_index, modulus) in params.moduli().iter().copied().enumerate() {
            let expected = match centered {
                -1 => modulus - 1,
                0 => 0,
                1 => 1,
                _ => unreachable!("the ternary range was checked"),
            };
            ensure!(
                coefficients[(row_index, coefficient_index)] == expected,
                "C1 secret-key polynomial has inconsistent RNS limbs"
            );
        }
        secret_coefficients.push(centered);
    }

    Ok(SecretKey::new(secret_coefficients.to_vec(), params))
}

/// Generate secure-16384 l-BFV key shares from the secret contribution used by C1.
pub fn gen_lbfv_key_shares<R: RngCore + CryptoRng>(
    rng: &mut R,
    cipher: &Cipher,
    request: GenLbfvKeySharesRequest,
) -> Result<GenLbfvKeySharesResponse> {
    request.validate_operation_id()?;

    let (params, _) = build_pair_for_preset(request.params_preset)?;
    let crs_seed = lbfv_crs_seed(request.params_preset)
        .context("the l-BFV CRS seed is unavailable for the preset")?;
    let urs_seed = lbfv_urs_seed(request.params_preset)
        .context("the l-BFV URS seed is unavailable for the preset")?;
    generate_with_params(
        rng,
        cipher,
        request.operation_id,
        &request.secret_key_bytes,
        &params,
        crs_seed,
        urs_seed,
        request.ciphertext_level as usize,
        request.key_level as usize,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_with_params<R: RngCore + CryptoRng>(
    rng: &mut R,
    cipher: &Cipher,
    operation_id: LbfvOperationId,
    encrypted_secret_key: &SensitiveBytes,
    params: &Arc<BfvParameters>,
    crs_seed: [u8; 32],
    urs_seed: [u8; 32],
    ciphertext_level: usize,
    key_level: usize,
) -> Result<GenLbfvKeySharesResponse> {
    let crs = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
    let urs = CommonRandomPolyVec::from_seed(&params, urs_seed)?;

    let secret_key_bytes = encrypted_secret_key.access(cipher)?;
    let secret_key = Zeroizing::new(deserialize_c1_secret_key(&secret_key_bytes, &params)?);
    let public_key_share = PublicKeyShare::contribute_with_crp(&secret_key, &crs, rng)?;
    let (rlk_share, witness) = RelinKeyShare::contribution_with_crp_extended(
        &secret_key,
        &urs,
        &crs,
        ciphertext_level,
        key_level,
        rng,
    )?;
    let witness = RlkWitnessGuard(witness);

    let row_count = params.moduli().len();
    ensure!(
        public_key_share.a_components()?.len() == row_count
            && public_key_share.b_components()?.len() == row_count,
        "l-BFV public-key share row count does not match the preset"
    );
    ensure!(
        rlk_share.d0_components().len() == row_count
            && rlk_share.d2_components().len() == row_count
            && witness.0.errors_d0.len() == row_count
            && witness.0.errors_d2.len() == row_count,
        "l-BFV RLK share and witness row counts do not match the preset"
    );
    ensure!(
        rlk_share.ciphertext_level() == 0 && rlk_share.key_level() == 0,
        "l-BFV RLK share has unsupported levels"
    );

    let encrypted_witness = EncryptedRlkWitness {
        r_bytes: encrypt_plaintext(serialize_secret_key(&witness.0.r)?, cipher)?,
        errors_d0_bytes: encrypt_error_rows(&witness.0.errors_d0, cipher)?,
        errors_d2_bytes: encrypt_error_rows(&witness.0.errors_d2, cipher)?,
    };

    Ok(GenLbfvKeySharesResponse {
        operation_id,
        public_key_share_bytes: ArcBytes::from_bytes(&public_key_share.to_bytes()),
        rlk_share_bytes: ArcBytes::from_bytes(&rlk_share.to_bytes()),
        witness: encrypted_witness,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::deserialize_secret_key;
    use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed};
    use e3_polynomial::CrtPolynomial;
    use e3_zk_helpers::circuits::commitments::compute_sc_sk_secret_root_commitment;
    use e3_zk_helpers::threshold::pk_generation::{Bits, Bounds, LbfvPkGenerationAdapter};
    use e3_zk_helpers::threshold::rlk_generation::RlkGenerationAdapter;
    use e3_zk_helpers::{CiphernodesCommitteeSize, Computation};
    use fhe_math::rq::traits::TryConvertFrom;
    use fhe_traits::{DeserializeParametrized, DeserializeWithContext};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn operation_id(session_id: [u8; 32], party_id: u32) -> LbfvOperationId {
        LbfvOperationId::new(
            session_id,
            party_id,
            LbfvOperationKind::GenKeyShares,
            None,
            None,
            None,
        )
    }

    fn decrypt_witness(
        encrypted: &EncryptedRlkWitness,
        cipher: &Cipher,
        params: &Arc<BfvParameters>,
    ) -> Result<RlkWitness> {
        let context = params.context_at_level(0)?;
        let decrypt_rows = |rows: &[SensitiveBytes]| -> Result<Vec<Poly<NttShoup>>> {
            rows.iter()
                .map(|row| Ok(Poly::<NttShoup>::from_bytes(&row.access(cipher)?, context)?))
                .collect()
        };
        Ok(RlkWitness {
            r: Zeroizing::new(deserialize_secret_key(
                &encrypted.r_bytes.access(cipher)?,
                params,
            )?),
            errors_d0: decrypt_rows(&encrypted.errors_d0_bytes)?,
            errors_d2: decrypt_rows(&encrypted.errors_d2_bytes)?,
        })
    }

    #[tokio::test]
    #[ignore = "secure-16384 key-share generation is a slow cryptographic test"]
    async fn generated_shares_use_the_c1_secret_and_build_all_five_rows() -> Result<()> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let (params, _) = build_pair_for_preset(preset)?;
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&params, &mut rng);
        let c1_secret_poly = Poly::<PowerBasis>::try_convert_from(
            secret_key.coeffs.as_ref(),
            params.context_at_level(0)?,
            false,
        )?;
        let cipher = Cipher::from_password("lbfv-key-share-test").await?;
        let session_id = [7; 32];
        let request = GenLbfvKeySharesRequest {
            operation_id: operation_id(session_id, 0),
            session_id,
            party_id: 0,
            secret_key_bytes: SensitiveBytes::new(c1_secret_poly.to_bytes(), &cipher)?,
            generation_seed: SensitiveBytes::new([8; 32], &cipher)?,
            params_preset: preset,
            ciphertext_level: 0,
            key_level: 0,
        };

        let response = gen_lbfv_key_shares(&mut rng, &cipher, request)?;
        let public_key_share =
            PublicKeyShare::from_bytes(&response.public_key_share_bytes, &params)?;
        let rlk_share = RelinKeyShare::from_bytes(&response.rlk_share_bytes, &params)?;
        assert_eq!(
            PublicKeyShare::from_bytes(&public_key_share.to_bytes(), &params)?,
            public_key_share
        );
        assert_eq!(
            RelinKeyShare::from_bytes(&rlk_share.to_bytes(), &params)?,
            rlk_share
        );

        let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(preset).unwrap())?;
        let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(preset).unwrap())?;
        assert_eq!(public_key_share.a_components()?, crs.to_polys());
        assert_ne!(crs.to_polys(), urs.to_polys());
        assert_eq!(params.moduli().len(), 5);
        assert_eq!(response.witness.errors_d0_bytes.len(), 5);
        assert_eq!(response.witness.errors_d2_bytes.len(), 5);

        let pk_adapter = LbfvPkGenerationAdapter::new(preset)?;
        let reconstructed = deserialize_c1_secret_key(&c1_secret_poly.to_bytes(), &params)?;
        assert_eq!(reconstructed.coeffs, secret_key.coeffs);
        let mut c1_secret = CrtPolynomial::from_fhe_polynomial(&c1_secret_poly).limbs[0].clone();
        c1_secret.reverse();
        c1_secret.center(&params.moduli()[0].into());
        let bounds = Bounds::compute(preset, &committee)?;
        let bits = Bits::compute(preset, &bounds)?;
        let c1_commitment = compute_sc_sk_secret_root_commitment(&c1_secret, bits.sk_bit, 512);
        for row_index in 0..5 {
            let row = pk_adapter.row_data(
                committee.clone(),
                e3_zk_helpers::threshold::lbfv_proof_domain::sample_lbfv_proof_domain(),
                0,
                row_index,
                &reconstructed,
                &public_key_share,
            )?;
            assert_eq!(
                compute_sc_sk_secret_root_commitment(&row.sk, bits.sk_bit, 512),
                c1_commitment
            );
        }

        let witness = decrypt_witness(&response.witness, &cipher, &params)?;
        let rlk_rows = RlkGenerationAdapter::new(preset)?.all_rows_data(
            committee,
            e3_zk_helpers::threshold::lbfv_proof_domain::sample_lbfv_proof_domain(),
            0,
            &reconstructed,
            &rlk_share,
            witness,
        )?;
        assert_eq!(rlk_rows.len(), 5);
        assert_eq!(
            rlk_rows.iter().map(|row| row.row_index).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        for row in &rlk_rows {
            assert_eq!(row.sk, c1_secret);
            assert_eq!(
                compute_sc_sk_secret_root_commitment(&row.sk, bits.sk_bit, 512),
                c1_commitment
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn fixed_seeds_generate_five_serializable_rows_and_encrypted_witnesses() -> Result<()> {
        let params = fhe::bfv::BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[50; 5])
            .build_arc()?;
        let crs_seed = lbfv_crs_seed(BfvPreset::SecureThreshold16384).unwrap();
        let urs_seed = lbfv_urs_seed(BfvPreset::SecureThreshold16384).unwrap();
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&params, &mut rng);
        let c1_secret_poly = Poly::<PowerBasis>::try_convert_from(
            secret_key.coeffs.as_ref(),
            params.context_at_level(0)?,
            false,
        )?;
        let cipher = Cipher::from_password("lbfv-five-row-test").await?;
        let encrypted_secret_key = SensitiveBytes::new(c1_secret_poly.to_bytes(), &cipher)?;

        let generation_seed = [42; 32];
        let mut generation_rng = ChaCha20Rng::from_seed(generation_seed);
        let response = generate_with_params(
            &mut generation_rng,
            &cipher,
            LbfvOperationId([7; 32]),
            &encrypted_secret_key,
            &params,
            crs_seed,
            urs_seed,
            0,
            0,
        )?;
        let mut retry_rng = ChaCha20Rng::from_seed(generation_seed);
        let retry = generate_with_params(
            &mut retry_rng,
            &cipher,
            LbfvOperationId([7; 32]),
            &encrypted_secret_key,
            &params,
            crs_seed,
            urs_seed,
            0,
            0,
        )?;
        assert_eq!(response.operation_id, retry.operation_id);
        assert_eq!(
            response.public_key_share_bytes,
            retry.public_key_share_bytes
        );
        assert_eq!(response.rlk_share_bytes, retry.rlk_share_bytes);
        assert_eq!(
            response.witness.r_bytes.access(&cipher)?,
            retry.witness.r_bytes.access(&cipher)?
        );
        for (first, second) in response
            .witness
            .errors_d0_bytes
            .iter()
            .zip(&retry.witness.errors_d0_bytes)
            .chain(
                response
                    .witness
                    .errors_d2_bytes
                    .iter()
                    .zip(&retry.witness.errors_d2_bytes),
            )
        {
            assert_eq!(first.access(&cipher)?, second.access(&cipher)?);
        }
        let public_key_share =
            PublicKeyShare::from_bytes(&response.public_key_share_bytes, &params)?;
        let rlk_share = RelinKeyShare::from_bytes(&response.rlk_share_bytes, &params)?;
        let crs = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
        let urs = CommonRandomPolyVec::from_seed(&params, urs_seed)?;

        assert_eq!(public_key_share.a_components()?, crs.to_polys());
        assert_ne!(crs.to_polys(), urs.to_polys());
        assert_eq!(public_key_share.b_components()?.len(), 5);
        assert_eq!(rlk_share.d0_components().len(), 5);
        assert_eq!(rlk_share.d2_components().len(), 5);
        assert_eq!(response.witness.errors_d0_bytes.len(), 5);
        assert_eq!(response.witness.errors_d2_bytes.len(), 5);
        assert_eq!(
            PublicKeyShare::from_bytes(&public_key_share.to_bytes(), &params)?,
            public_key_share
        );
        assert_eq!(
            RelinKeyShare::from_bytes(&rlk_share.to_bytes(), &params)?,
            rlk_share
        );
        assert_eq!(
            deserialize_c1_secret_key(&c1_secret_poly.to_bytes(), &params)?.coeffs,
            secret_key.coeffs
        );

        let witness = decrypt_witness(&response.witness, &cipher, &params)?;
        assert_eq!(witness.errors_d0.len(), 5);
        assert_eq!(witness.errors_d2.len(), 5);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_other_presets_and_nonzero_levels_before_decryption() -> Result<()> {
        let cipher = Cipher::from_password("lbfv-key-share-errors").await?;
        let mut rng = rand::rng();
        for request in [
            GenLbfvKeySharesRequest {
                operation_id: operation_id([7; 32], 0),
                session_id: [7; 32],
                party_id: 0,
                secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
                generation_seed: SensitiveBytes::from_encrypted(&[]),
                params_preset: BfvPreset::SecureThreshold8192,
                ciphertext_level: 0,
                key_level: 0,
            },
            GenLbfvKeySharesRequest {
                operation_id: operation_id([7; 32], 0),
                session_id: [7; 32],
                party_id: 0,
                secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
                generation_seed: SensitiveBytes::from_encrypted(&[]),
                params_preset: BfvPreset::SecureThreshold16384,
                ciphertext_level: 1,
                key_level: 0,
            },
            GenLbfvKeySharesRequest {
                operation_id: operation_id([7; 32], 0),
                session_id: [7; 32],
                party_id: 0,
                secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
                generation_seed: SensitiveBytes::from_encrypted(&[]),
                params_preset: BfvPreset::SecureThreshold16384,
                ciphertext_level: 0,
                key_level: 1,
            },
        ] {
            assert!(gen_lbfv_key_shares(&mut rng, &cipher, request).is_err());
        }
        Ok(())
    }

    #[test]
    fn operation_id_binds_session_and_party() {
        let session_id = [7; 32];
        let mut request = GenLbfvKeySharesRequest {
            operation_id: operation_id(session_id, 1),
            session_id,
            party_id: 1,
            secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
            generation_seed: SensitiveBytes::from_encrypted(&[]),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        };

        request.validate_operation_id().unwrap();
        request.party_id = 2;
        assert!(request.validate_operation_id().is_err());
    }

    #[test]
    fn debug_omits_the_encrypted_witness_fields() {
        let response = GenLbfvKeySharesResponse {
            operation_id: LbfvOperationId([7; 32]),
            public_key_share_bytes: ArcBytes::from_bytes(&[]),
            rlk_share_bytes: ArcBytes::from_bytes(&[]),
            witness: EncryptedRlkWitness {
                r_bytes: SensitiveBytes::from_encrypted(b"r-secret"),
                errors_d0_bytes: vec![SensitiveBytes::from_encrypted(b"d0-secret")],
                errors_d2_bytes: vec![SensitiveBytes::from_encrypted(b"d2-secret")],
            },
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("witness"));
        assert!(!debug.contains("r_bytes"));
        assert!(!debug.contains("errors_d0_bytes"));
        assert!(!debug.contains("errors_d2_bytes"));
        assert!(!debug.contains("secret"));
    }
}
