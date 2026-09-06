// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Credit-scoring v2 app (ParamSet 4) tooling:
//!
//! - `configs`: emit `circuits/lib/src/configs/ckks_ps4.nr` (Greco legs)
//!   and `ckks_credit_ps4.nr` (credit leg) from codegen.
//! - `prover <out-dir> [pubkey.bin]`: generate real FIVE-leg witnesses
//!   (Greco ct0/ct1 for the logit ciphertext, Greco ct0/ct1 for the mask
//!   ciphertext, the credit validity leg) from TWO encryptions, plus a
//!   `meta.json` the fixture builder reads (ciphertext hexes, expected
//!   commitments, public inputs). Prover.toml files land in the matching
//!   `circuits/bin/threshold/<pkg>/` directories; the Greco packages get
//!   the LOGIT witness (the mask witness is written next to it as
//!   `Prover_mask.toml` for the fixture script to swap in).
//! - `prover-bad <out-dir>`: same, but with a feature ABOVE the cap and a
//!   leaf that attests it — the native pre-check is bypassed so the
//!   circuit's own range check is what rejects it (proving-failure
//!   fixture).
//!
//! Usage: cargo run --release -p e3-zk-helpers --example gen_ckks_credit_prover -- <configs|prover|prover-bad> ...

use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::threshold::ckks_app_validity::{address_to_biguint, field_word_hex};
use e3_zk_helpers::threshold::ckks_credit_validity::{
    build_credit_submission, compute_m_commitment, credit_greco_inputs, credit_preset,
    generate_credit_configs, mask_value, public_input_words, CreditConfigs, CreditInputs,
    CreditModel, FeatureTree, CREDIT_CIRCUIT_PACKAGE, CREDIT_PARAM_SET, FEATURES,
};
use e3_zk_helpers::threshold::user_data_encryption_ckks::{
    generate_configs as generate_greco_configs, generate_toml, Configs as GrecoConfigs,
};
use fhe::ckks::{CkksPublicKey, CkksSecretKey};
use fhe_traits::DeserializeParametrized;

/// Alice (hardhat account #0) and Bob (account #1): the demo issuer snapshot.
const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const BOB: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const DEMO_FEATURES: [u32; FEATURES] = [520, 130, 350, 999, 0, 1, 777, 42];
const BOB_FEATURES: [u32; FEATURES] = [1, 2, 3, 4, 5, 6, 7, 8];
const DEMO_CAP: u32 = 1000;
/// The demo model: weights [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2], bias -0.8.
const DEMO_WEIGHTS: [f64; FEATURES] = [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2];
const DEMO_BIAS: f64 = -0.8;
/// Output-mask numerator (`m = 529664 / 2^10 = 517.25`).
const DEMO_MASK: u32 = 529_664;
/// Alice's applicant slot index in the fixture round.
const DEMO_INDEX: u32 = 0;

fn write_configs() {
    let preset = credit_preset().unwrap();
    let greco = GrecoConfigs::compute(preset.clone(), &()).unwrap();
    let path = format!("circuits/lib/src/configs/ckks_ps{CREDIT_PARAM_SET}.nr");
    std::fs::write(&path, generate_greco_configs(&preset, &greco)).unwrap();
    println!("written {path}");
    let credit = CreditConfigs::compute(&preset).unwrap();
    let path = format!("circuits/lib/src/configs/ckks_credit_ps{CREDIT_PARAM_SET}.nr");
    std::fs::write(&path, generate_credit_configs(&credit)).unwrap();
    println!("written {path}");
}

fn load_or_generate_pk(path: Option<&String>) -> CkksPublicKey {
    let preset = credit_preset().unwrap();
    match path {
        Some(path) => {
            let bytes = std::fs::read(path).unwrap();
            CkksPublicKey::from_bytes(&bytes, &preset.params).unwrap()
        }
        None => {
            let mut rng = rand::rng();
            let sk = CkksSecretKey::random(&preset.params, &mut rng);
            CkksPublicKey::new(&sk, &mut rng).unwrap()
        }
    }
}

struct Legs<'a> {
    logit_toml: &'a str,
    logit_ct: &'a [u8],
    mask_toml: &'a str,
    mask_ct: &'a [u8],
    credit_inputs: &'a CreditInputs,
}

fn write_legs(out_dir: &std::path::Path, legs: Legs<'_>) {
    let configs = CreditConfigs::compute(&credit_preset().unwrap()).unwrap();
    let inputs = legs.credit_inputs;
    let m_c_z = compute_m_commitment(&inputs.m_z, configs.m_bit);
    let m_c_m = compute_m_commitment(&inputs.m_m, configs.m_bit);
    let suffix = format!("_ps{CREDIT_PARAM_SET}");
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/bin/threshold");
    for leg in ["ct0", "ct1"] {
        let dir = format!("{root}/user_data_encryption_ckks_{leg}{suffix}");
        std::fs::write(format!("{dir}/Prover.toml"), legs.logit_toml).unwrap();
        std::fs::write(format!("{dir}/Prover_mask.toml"), legs.mask_toml).unwrap();
    }
    let app_dir = format!("{root}/{CREDIT_CIRCUIT_PACKAGE}");
    std::fs::write(format!("{app_dir}/Prover.toml"), inputs.to_toml().unwrap()).unwrap();

    std::fs::create_dir_all(out_dir).unwrap();
    std::fs::write(out_dir.join("ciphertext_z.bin"), legs.logit_ct).unwrap();
    std::fs::write(out_dir.join("ciphertext_m.bin"), legs.mask_ct).unwrap();
    let proof = &inputs.feature_proof;
    let words = public_input_words(inputs, configs.m_bit);
    let meta = serde_json::json!({
        "app": CREDIT_CIRCUIT_PACKAGE,
        "paramSet": CREDIT_PARAM_SET,
        "cap": inputs.cap,
        "index": inputs.index,
        "mask": inputs.mask,
        "maskValue": mask_value(inputs.mask),
        "logit": inputs.model.logit(&proof.features, inputs.cap),
        "model": { "weights": inputs.model.weights, "bias": inputs.model.bias },
        "modelWords": words[4..13].to_vec(),
        "features": proof.features,
        "ciphertextZHex": format!("0x{}", hex::encode(legs.logit_ct)),
        "ciphertextMHex": format!("0x{}", hex::encode(legs.mask_ct)),
        "mCommitmentZ": field_word_hex(&m_c_z),
        "mCommitmentM": field_word_hex(&m_c_m),
        "appPublicInputs": words,
        "extra": {
            "address": ALICE,
            "addressWord": words[1],
            "merkleRoot": words[2],
            "indexWord": words[3],
            "bobFeatures": BOB_FEATURES,
        },
    });
    std::fs::write(
        out_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    println!(
        "{CREDIT_CIRCUIT_PACKAGE}: Prover.toml (logit) + Prover_mask.toml written for ct0/ct1{suffix}; credit leg Prover.toml; meta at {}",
        out_dir.join("meta.json").display()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let model = CreditModel::from_f64(&DEMO_WEIGHTS, DEMO_BIAS);
    match args.get(1).map(String::as_str) {
        Some("configs") => write_configs(),
        Some("prover") => {
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            let pk = load_or_generate_pk(args.get(3));
            let alice = address_to_biguint(ALICE).unwrap();
            let bob = address_to_biguint(BOB).unwrap();
            let tree =
                FeatureTree::new(&[(alice.clone(), DEMO_FEATURES), (bob, BOB_FEATURES)]).unwrap();
            let proof = tree.proof(0, &alice, DEMO_FEATURES);
            let sub =
                build_credit_submission(pk, proof, DEMO_CAP, model, DEMO_INDEX, DEMO_MASK).unwrap();
            write_legs(
                &out_dir,
                Legs {
                    logit_toml: &sub.logit.greco_toml,
                    logit_ct: &sub.logit.ciphertext,
                    mask_toml: &sub.mask.greco_toml,
                    mask_ct: &sub.mask.ciphertext,
                    credit_inputs: &sub.credit_inputs,
                },
            );
        }
        Some("prover-bad") => {
            // Feature 3 = cap + 1, attested by the issuer leaf: the ONLY
            // thing rejecting it is the circuit's `x_j <= cap` check.
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            let pk = load_or_generate_pk(args.get(3));
            let mut features = DEMO_FEATURES;
            features[3] = DEMO_CAP + 1;
            let alice = address_to_biguint(ALICE).unwrap();
            let tree = FeatureTree::new(&[(alice.clone(), features)]).unwrap();
            let proof = tree.proof(0, &alice, features);
            let z = model.logit(&features, DEMO_CAP);
            let greco_z = credit_greco_inputs(&pk, z, DEMO_INDEX as usize).unwrap();
            let greco_m =
                credit_greco_inputs(&pk, mask_value(DEMO_MASK), DEMO_INDEX as usize).unwrap();
            let credit_inputs = CreditInputs {
                m_z: greco_z.m.clone(),
                m_m: greco_m.m.clone(),
                cap: DEMO_CAP,
                index: DEMO_INDEX,
                model,
                mask: DEMO_MASK,
                feature_proof: proof,
            };
            let logit_ct = greco_z.ciphertext.clone();
            let mask_ct = greco_m.ciphertext.clone();
            let logit_toml = generate_toml(greco_z).unwrap();
            let mask_toml = generate_toml(greco_m).unwrap();
            write_legs(
                &out_dir,
                Legs {
                    logit_toml: &logit_toml,
                    logit_ct: &logit_ct,
                    mask_toml: &mask_toml,
                    mask_ct: &mask_ct,
                    credit_inputs: &credit_inputs,
                },
            );
        }
        _ => panic!(
            "usage: gen_ckks_credit_prover <configs|prover|prover-bad> [out-dir] [pubkey.bin]"
        ),
    }
}
