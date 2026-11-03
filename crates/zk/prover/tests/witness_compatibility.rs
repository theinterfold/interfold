// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_config::threshold::{decrypted_shares_aggregation as c7, share_decryption as c6};
use e3_zk_prover::{inputs_json_to_input_map, CompiledCircuit, WitnessGenerator};
use e3_zk_witness::threshold::{decrypted_shares_aggregation as w7, share_decryption as w6};

use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::BigInt;

#[test]
#[ignore = "requires prepared insecure/minimum C6/C7 artifacts"]
fn c6_c7_zero_products_execute_and_nondefault_widths_reject_fixed_abi() {
    let root = e3_zk_prover::test_utils::workspace_root().join("circuits/bin");
    let active: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".active-preset.json")).unwrap())
            .unwrap();
    assert_eq!(active["preset"], "insecure");
    assert_eq!(active["committee"], "minimum");
    let mut config7 = c7::Configs::for_preset(
        BfvPreset::InsecureThreshold,
        CiphernodesCommitteeSize::Minimum,
    )
    .unwrap();
    let mut config6 = c6::Configs::new(&config7.params).unwrap();
    let poly = Poly::<PowerBasis>::zero(config7.params.context_at_level(0).unwrap());
    let crt = CrtPolynomial::new(vec![
        Polynomial::new(vec![
            BigInt::from(0);
            config6.params.degree()
        ]);
        config6.params.moduli().len()
    ]);
    let data6 = w6::ShareDecryptionCircuitData {
        ciphertext: Ciphertext::new(
            vec![poly.clone().into_ntt(), poly.clone().into_ntt()],
            &config6.params,
        )
        .unwrap(),
        s: crt.clone(),
        e: crt.clone(),
        d_share: crt,
        domain_hi: 0,
        domain_lo: 0,
    };
    let count = config7.committee.values().threshold + 1;
    let data7 = w7::DecryptedSharesAggregationCircuitData {
        d_share_polys: vec![poly; count],
        reconstructing_parties: (1..=count).collect(),
        message_vec: vec![0],
    };
    let compiled6 =
        CompiledCircuit::from_file(&root.join("threshold/target/share_decryption.json")).unwrap();
    let compiled7 = CompiledCircuit::from_file(
        &root.join("threshold/target/decrypted_shares_aggregation.json"),
    )
    .unwrap();
    let generator = WitnessGenerator::new();
    let json6 = w6::Inputs::compute(&config6, &data6).unwrap().to_json();
    let json7 = w7::Inputs::compute(&config7, &data7).unwrap().to_json();
    generator
        .generate_witness(&compiled6, inputs_json_to_input_map(&json6).unwrap())
        .unwrap();
    generator
        .generate_witness(&compiled7, inputs_json_to_input_map(&json7).unwrap())
        .unwrap();
    let mut wrong_quotient = json6;
    wrong_quotient["r"][0]["coefficients"][0] = serde_json::json!(1);
    assert!(generator
        .generate_witness(
            &compiled6,
            inputs_json_to_input_map(&wrong_quotient).unwrap()
        )
        .is_err());
    let mut wrong_message = json7;
    wrong_message["message"]["coefficients"][0] = serde_json::json!(1);
    assert!(generator
        .generate_witness(
            &compiled7,
            inputs_json_to_input_map(&wrong_message).unwrap()
        )
        .is_err());
    config6.max_msg_non_zero_coeffs = 7;
    config7.max_msg_non_zero_coeffs = 7;
    for (compiled, json) in [
        (
            &compiled6,
            w6::Inputs::compute(&config6, &data6).unwrap().to_json(),
        ),
        (
            &compiled7,
            w7::Inputs::compute(&config7, &data7).unwrap().to_json(),
        ),
    ] {
        let error = generator
            .generate_witness(compiled, inputs_json_to_input_map(&json).unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("ABI encode"), "{error}");
    }
}
