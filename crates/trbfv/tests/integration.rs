// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use e3_bfv_client::decode_bytes_to_vec_u64;
use e3_crypto::Cipher;
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::DEFAULT_BFV_PRESET;
use e3_fhe_params::{encode_bfv_params, BfvParamSet};
use e3_test_helpers::{create_shared_rng_from_u64, usecase_helpers};
use e3_trbfv::{
    calculate_decryption_share::{
        calculate_decryption_share, CalculateDecryptionShareRequest,
        CalculateDecryptionShareResponse,
    },
    calculate_threshold_decryption::{
        calculate_threshold_decryption, CalculateThresholdDecryptionRequest,
        CalculateThresholdDecryptionResponse,
    },
    TrBFVConfig,
};
use e3_utils::{to_ordered_vec, ArcBytes};
use fhe_traits::Serialize;

#[tokio::test]
async fn test_trbfv_isolation() -> Result<()> {
    use tracing_subscriber::{fmt, EnvFilter};

    let subscriber = fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_test_writer()
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);
    let rng = create_shared_rng_from_u64(42);

    let params_raw = BfvParamSet::from(DEFAULT_BFV_PRESET).build_arc();
    let params = ArcBytes::from_bytes(&encode_bfv_params(&params_raw.clone()));

    // E3Parameters
    let threshold_m = 2;
    let threshold_n = 5;

    let cipher = Arc::new(Cipher::from_password("I am the music man.").await?);

    let trbfv_config = TrBFVConfig::new(params, threshold_n as u64, threshold_m as u64);
    let crp_raw = create_deterministic_crp_from_default_seed(&trbfv_config.params());

    // let crp = ArcBytes::from_bytes(crp_raw.to_bytes());
    let generated =
        usecase_helpers::generate_shares_hash_map(&trbfv_config, &crp_raw, &rng, &cipher)?;

    let pubkey =
        usecase_helpers::get_public_key(&generated.shares, trbfv_config.params(), &crp_raw)?;
    let shares = to_ordered_vec(generated.shares);
    let decryption_keys = usecase_helpers::get_decryption_keys(
        shares,
        &generated.bfv_secret_keys,
        &cipher,
        &trbfv_config,
        &generated.bfv_params,
    )?;
    // Create the inputs
    let num_votes_per_voter = 3;
    let num_voters = 30;
    let (inputs, numbers) = e3_test_helpers::application::generate_ciphertexts(
        &pubkey,
        num_voters,
        num_votes_per_voter,
    );

    let outputs =
        e3_test_helpers::application::run_application(&inputs, &pubkey, num_votes_per_voter);

    // Encrypt the plaintext
    let ciphertexts = outputs
        .into_iter()
        .map(|ct| ArcBytes::from_bytes(&(*ct).clone().to_bytes()))
        .collect::<Vec<ArcBytes>>();

    let mut decryption_shares = HashMap::new();
    // for party_id in 0..=threshold_m as usize {
    for party_id in [1, 4, 2] {
        let (es_poly_sum, sk_poly_sum) = decryption_keys.get(&party_id).unwrap();
        println!("calculate_decryption_share for party_id={}", party_id);
        let CalculateDecryptionShareResponse { d_share_poly } = calculate_decryption_share(
            &cipher,
            CalculateDecryptionShareRequest {
                name: format!("party_id({})", party_id),
                sk_poly_sum: sk_poly_sum.clone(),
                trbfv_config: trbfv_config.clone(),
                es_poly_sum: es_poly_sum.clone(),
                ciphertexts: ciphertexts.clone(),
            },
        )?;

        // store the decryption shares in a hash map indexed by party_id
        decryption_shares.insert(party_id as u64, d_share_poly);
    }

    // Get a vector of the shares
    let d_share_polys: Vec<(u64, Vec<ArcBytes>)> = decryption_shares.into_iter().collect();

    let CalculateThresholdDecryptionResponse { plaintext } =
        // NOTE: data prep in this function will sort the decryption shares by party_id
        calculate_threshold_decryption(CalculateThresholdDecryptionRequest {
            ciphertexts,
            trbfv_config: trbfv_config.clone(),
            d_share_polys,
        })?;

    let results = plaintext
        .into_iter()
        .map(|a| decode_bytes_to_vec_u64(&a.extract_bytes()).unwrap())
        .collect::<Vec<Vec<u64>>>();

    let results: Vec<u64> = results.into_iter().map(|r| *r.first().unwrap()).collect();

    // Show summation result
    let plaintext_modulus = params_raw.clone().plaintext();

    let mut expected_result = [0u64; 3];
    for vals in &numbers {
        for j in 0..num_votes_per_voter {
            expected_result[j] = (expected_result[j] + vals[j]) % plaintext_modulus;
        }
    }

    for (i, (res, exp)) in results.iter().zip(expected_result.iter()).enumerate() {
        println!("Tally {i} result = {res} / {exp}");
        assert_eq!(res, exp);
    }
    Ok(())
}
