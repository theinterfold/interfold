// SPDX-License-Identifier: LGPL-3.0-only

//! Typed native execution without event envelopes, resource scheduling or retry policy.

use crate::{
    calculate_decryption_key::calculate_decryption_key,
    calculate_decryption_share::calculate_decryption_share,
    calculate_threshold_decryption::calculate_threshold_decryption, gen_esi_sss::gen_esi_sss,
    gen_lbfv_key_shares::gen_lbfv_key_shares, gen_pk_share_and_sk_sss::gen_pk_share_and_sk_sss,
    TrBFVError, TrBFVFailure, TrBFVRequest, TrBFVResponse,
};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_utils::SharedRng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing::{error, warn};
use zeroize::Zeroize;

/// Build the per-job generator of an l-BFV key-share request from its encrypted 32-byte seed.
///
/// The seed makes the request's output a function of the request, so a retried or recovered job
/// returns the same shares and does not touch the shared generator.
fn lbfv_generation_rng(
    cipher: &Cipher,
    encrypted_seed: &SensitiveBytes,
) -> anyhow::Result<ChaCha20Rng> {
    let seed_bytes = encrypted_seed.access(cipher)?;
    anyhow::ensure!(
        seed_bytes.len() == 32,
        "l-BFV generation seed must contain exactly 32 bytes"
    );
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(rng)
}

impl TrBFVRequest {
    /// Stable diagnostic operation label, independent of transport or worker implementation.
    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::GenPkShareAndSkSss(_) => "gen_pk_share_and_sk_sss",
            Self::GenEsiSss(_) => "gen_esi_sss",
            Self::CalculateDecryptionKey(_) => "calculate_decryption_key",
            Self::CalculateDecryptionShare(_) => "calculate_decryption_share",
            Self::CalculateThresholdDecryption(_) => "calculate_threshold_decryption",
            Self::GenLbfvKeyShares(_) => "gen_lbfv_key_shares",
        }
    }

    /// Attach a calculation or local worker failure to this request's typed operation.
    /// Structured threshold/party attribution is retained in the supplied failure payload.
    pub fn failure(&self, failure: TrBFVFailure) -> TrBFVError {
        match self {
            Self::GenPkShareAndSkSss(_) => TrBFVError::GenPkShareAndSkSss(failure),
            Self::GenEsiSss(_) => TrBFVError::GenEsiSss(failure),
            Self::CalculateDecryptionKey(_) => TrBFVError::CalculateDecryptionKey(failure),
            Self::CalculateDecryptionShare(_) => TrBFVError::CalculateDecryptionShare(failure),
            Self::CalculateThresholdDecryption(_) => {
                TrBFVError::CalculateThresholdDecryption(failure)
            }
            Self::GenLbfvKeyShares(_) => TrBFVError::GenLbfvKeyShares(failure),
        }
    }

    /// Execute synchronously using caller-owned randomness and local secret encryption.
    /// Only randomized operations lock the RNG. The caller must provide bounded execution,
    /// admission and recovery, and reuse successful randomized outputs rather than rerun them.
    pub fn execute(&self, rng: &SharedRng, cipher: &Cipher) -> Result<TrBFVResponse, TrBFVError> {
        let lock_rng = || {
            rng.lock().unwrap_or_else(|poisoned| {
                warn!("Recovering the shared random generator after a TrBFV worker panic");
                poisoned.into_inner()
            })
        };
        let result = match self {
            Self::GenPkShareAndSkSss(req) => {
                let mut rng = lock_rng();
                gen_pk_share_and_sk_sss(&mut *rng, cipher, req.clone())
                    .map(TrBFVResponse::GenPkShareAndSkSss)
            }
            Self::GenEsiSss(req) => {
                let mut rng = lock_rng();
                gen_esi_sss(&mut *rng, cipher, req.clone()).map(TrBFVResponse::GenEsiSss)
            }
            Self::CalculateDecryptionKey(req) => calculate_decryption_key(cipher, req.clone())
                .inspect_err(|error| error!("Error calculating decryption key: {}", error))
                .map(TrBFVResponse::CalculateDecryptionKey),
            Self::CalculateDecryptionShare(req) => calculate_decryption_share(cipher, req.clone())
                .map(TrBFVResponse::CalculateDecryptionShare),
            Self::CalculateThresholdDecryption(req) => calculate_threshold_decryption(req.clone())
                .map(TrBFVResponse::CalculateThresholdDecryption),
            Self::GenLbfvKeyShares(req) => req
                .validate_operation_id()
                .and_then(|()| lbfv_generation_rng(cipher, &req.generation_seed))
                .and_then(|mut job_rng| gen_lbfv_key_shares(&mut job_rng, cipher, req.clone()))
                .map(TrBFVResponse::GenLbfvKeyShares),
        };
        result.map_err(|error| self.failure(TrBFVFailure::from_error(&error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gen_esi_sss::GenEsiSssRequest, gen_pk_share_and_sk_sss::GenPkShareAndSkSssRequest,
        TrBFVConfig,
    };
    use e3_crypto::SensitiveBytes;
    use e3_fhe_params::{
        create_deterministic_crp_from_default_seed, encode_bfv_params, BfvParamSet, BfvPreset,
    };
    use e3_utils::ArcBytes;
    use fhe_traits::Serialize;
    use rand::SeedableRng;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn typed_generation_recovers_a_poisoned_rng_and_keeps_secrets_encrypted() {
        let cipher = Cipher::from_password("native-execution-test")
            .await
            .unwrap();
        let preset = BfvPreset::InsecureThreshold64;
        let params = BfvParamSet::from(preset).build_arc();
        let crp = create_deterministic_crp_from_default_seed(&params);
        let config = TrBFVConfig::new(ArcBytes::from_bytes(&encode_bfv_params(&params)), 3, 1);
        let rng: SharedRng = Arc::new(Mutex::new(rand_chacha::ChaCha20Rng::seed_from_u64(7)));
        let poison = rng.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("planned worker panic");
        })
        .join()
        .is_err());
        let request = TrBFVRequest::GenPkShareAndSkSss(GenPkShareAndSkSssRequest {
            trbfv_config: config.clone(),
            crp: ArcBytes::from_bytes(&crp.to_bytes()),
            lambda: preset.lambda_config(),
            num_ciphertexts: 1,
            mult_depth: preset.search_defaults().unwrap().mult_depth,
        });
        let TrBFVResponse::GenPkShareAndSkSss(material) = request.execute(&rng, &cipher).unwrap()
        else {
            panic!("wrong response variant")
        };
        assert!(!material.sk_raw.access(&cipher).unwrap().is_empty());
        assert!(!material.eek_raw.access(&cipher).unwrap().is_empty());
        let request = TrBFVRequest::GenEsiSss(GenEsiSssRequest {
            trbfv_config: config,
            e_sm_raw: material.e_sm_raw,
        });
        let TrBFVResponse::GenEsiSss(material) = request.execute(&rng, &cipher).unwrap() else {
            panic!("wrong response variant")
        };
        assert_eq!(material.esi_sss.len(), 1);
        let shares = material
            .esi_sss
            .into_iter()
            .next()
            .unwrap()
            .decrypt(&cipher)
            .unwrap();
        assert_eq!(shares.moduli_data().len(), params.moduli().len());
    }

    #[tokio::test]
    async fn lbfv_generation_rng_uses_the_encrypted_request_seed() {
        let cipher = Cipher::from_password("lbfv-generation-seed-test")
            .await
            .unwrap();
        let seed = SensitiveBytes::new([42; 32], &cipher).unwrap();
        let mut first = lbfv_generation_rng(&cipher, &seed).unwrap();
        let mut second = lbfv_generation_rng(&cipher, &seed).unwrap();
        let first_bytes: [u8; 64] = rand::Rng::random(&mut first);
        let second_bytes: [u8; 64] = rand::Rng::random(&mut second);

        assert_eq!(first_bytes, second_bytes);
        assert!(
            lbfv_generation_rng(&cipher, &SensitiveBytes::new([1; 31], &cipher).unwrap()).is_err()
        );
    }

    #[test]
    fn request_failure_preserves_structured_party_attribution() {
        let request = TrBFVRequest::GenEsiSss(GenEsiSssRequest {
            trbfv_config: TrBFVConfig::new(ArcBytes::default(), 3, 1),
            e_sm_raw: SensitiveBytes::from_encrypted(&[]),
        });
        let cause = anyhow::Error::new(fhe::Error::malformed_shares(2, "bad shape".to_owned()))
            .context("worker calculation failed");
        let error = request.failure(TrBFVFailure::from_error(&cause));
        assert!(matches!(error, TrBFVError::GenEsiSss(_)));
        let failure = error.failure().threshold.as_ref().unwrap();
        assert_eq!(failure.kind, crate::ThresholdFailureKind::MalformedShares);
        assert_eq!(failure.party_id, Some(2));
    }
}
