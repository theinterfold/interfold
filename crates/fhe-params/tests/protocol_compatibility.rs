// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "abi-encoding")]

use alloy_primitives::hex;
use e3_fhe_params::{
    bfv_crypto_config_id, bfv_encryption_scheme_id, bfv_parameter_hash,
    current_bfv_crypto_config_id, decode_bfv_params, encode_bfv_params, BfvParamSet, BfvPreset,
    INTERFOLD_BFV_VERSION,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/bfv_protocol.json")).unwrap()
}

#[test]
fn selected_parameters_preserve_frozen_abi_bytes() {
    for vector in vectors()["vectors"].as_array().unwrap() {
        let Some(name) = vector["preset"].as_str() else {
            continue;
        };
        let preset = BfvPreset::from_name(name).unwrap();
        let expected = hex::decode(vector["encodedParameters"].as_str().unwrap()).unwrap();
        assert_eq!(
            encode_bfv_params(&BfvParamSet::from(preset).build()),
            expected,
            "{name}"
        );
    }
}

#[test]
fn protocol_domains_preserve_frozen_values() {
    let fixture = vectors();
    assert_eq!(
        bfv_encryption_scheme_id().to_string(),
        fixture["encryptionSchemeId"].as_str().unwrap()
    );
    assert_eq!(INTERFOLD_BFV_VERSION, fixture["currentCircuitVersion"]);
}

#[test]
fn configuration_identities_preserve_current_and_historical_vectors() {
    for vector in vectors()["vectors"].as_array().unwrap() {
        let params = hex::decode(vector["encodedParameters"].as_str().unwrap()).unwrap();
        let version = vector["circuitVersion"].as_str().unwrap();
        let expected_id = vector["cryptoConfigId"].as_str().unwrap();
        assert_eq!(
            bfv_parameter_hash(&params).to_string(),
            vector["parameterHash"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
        assert_eq!(
            bfv_crypto_config_id(&params, version).to_string(),
            expected_id
        );
        if vector["preset"].is_string() {
            assert_eq!(
                current_bfv_crypto_config_id(&params).to_string(),
                expected_id
            );
        } else {
            assert_ne!(
                current_bfv_crypto_config_id(&params).to_string(),
                expected_id
            );
        }
    }
}

#[test]
fn registry_identity_binds_original_bytes_not_decoded_parameters() {
    let fixture = vectors();
    let vector = &fixture["vectors"][2];
    let params = hex::decode(vector["encodedParameters"].as_str().unwrap()).unwrap();
    let mut extended = params.clone();
    extended.extend_from_slice(&[0; 32]);
    let decoded = decode_bfv_params(&extended).unwrap();
    assert_eq!(encode_bfv_params(&decoded), params);
    let version = vector["circuitVersion"].as_str().unwrap();
    assert_ne!(bfv_parameter_hash(&extended), bfv_parameter_hash(&params));
    assert_ne!(
        bfv_crypto_config_id(&extended, version),
        bfv_crypto_config_id(&params, version)
    );
}
