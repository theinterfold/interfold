// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generate real three-leg witnesses (Greco ct0/ct1 + app leg) for the CKKS
//! app circuits from ONE encryption each, plus a `meta.json` the fixture
//! builder reads (ciphertext hex, expected m_commitment, public inputs).
//!
//! Usage:
//!   cargo run --release -p e3-zk-helpers --example gen_ckks_app_prover -- \
//!       <salary|auction> <out-dir> [pubkey.bin]
//!
//! Without a pubkey a fresh keypair is generated (fixture/test flows). The
//! Prover.toml files land in the matching `circuits/bin/threshold/<pkg>/`
//! directories so `nargo execute --package <pkg>` picks them up.

use e3_zk_helpers::threshold::ckks_app_validity::{
    address_to_biguint, build_app_submission, compute_m_commitment, field_word_hex, AppConfigs,
    BalanceTree, CkksApp,
};
use e3_zk_helpers::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
use fhe::ckks::{CkksPublicKey, CkksSecretKey};
use fhe_traits::DeserializeParametrized;
use num_bigint::BigInt;

/// Alice (hardhat account #0) and Bob (account #1): the demo balance tree.
const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const BOB: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let app = match args.get(1).map(String::as_str) {
        Some("salary") => CkksApp::SalarySurvey,
        Some("auction") => CkksApp::Auction,
        _ => panic!("usage: gen_ckks_app_prover <salary|auction> <out-dir> [pubkey.bin]"),
    };
    let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
    std::fs::create_dir_all(&out_dir).unwrap();
    let preset = ckks_preset_for_param_set(app.param_set()).unwrap();
    let pk = match args.get(3) {
        Some(path) => {
            let bytes = std::fs::read(path).unwrap();
            CkksPublicKey::from_bytes(&bytes, &preset.params).unwrap()
        }
        None => {
            let mut rng = rand::rng();
            let sk = CkksSecretKey::random(&preset.params, &mut rng);
            CkksPublicKey::new(&sk, &mut rng).unwrap()
        }
    };

    // Demo values: salary 52000 over cap 100000; bid 700 (cap 1) with an
    // 800-token balance for Alice, 300 for Bob.
    let (value, cap, balance_proof, extra_public) = match app {
        CkksApp::SalarySurvey => (52_000u64, 100_000u64, None, serde_json::json!({})),
        CkksApp::Auction => {
            let alice = address_to_biguint(ALICE).unwrap();
            let bob = address_to_biguint(BOB).unwrap();
            let tree = BalanceTree::new(&[(alice.clone(), 800), (bob, 300)]).unwrap();
            let proof = tree.proof(0, &alice, 800);
            let root_hex = field_word_hex(&BigInt::from(proof.merkle_root.clone()));
            let addr_hex = field_word_hex(&BigInt::from(alice.clone()));
            (
                700u64,
                1u64,
                Some(proof),
                serde_json::json!({
                    "address": ALICE,
                    "addressWord": addr_hex,
                    "balance": 800,
                    "merkleRoot": root_hex,
                }),
            )
        }
    };

    let sub = build_app_submission(app, pk, value, cap, balance_proof).unwrap();
    let configs = AppConfigs::compute(&preset).unwrap();
    let m_commitment = compute_m_commitment(&sub.app_inputs.m, configs.m_bit);

    let suffix = format!("_ps{}", app.param_set());
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/bin/threshold");
    for leg in ["ct0", "ct1"] {
        let dir = format!("{root}/user_data_encryption_ckks_{leg}{suffix}");
        std::fs::write(format!("{dir}/Prover.toml"), &sub.greco_toml).unwrap();
    }
    let app_dir = format!("{root}/{}", app.circuit_package());
    std::fs::write(format!("{app_dir}/Prover.toml"), &sub.app_toml).unwrap();

    std::fs::write(out_dir.join("ciphertext.bin"), &sub.ciphertext).unwrap();
    let meta = serde_json::json!({
        "app": app.circuit_package(),
        "paramSet": app.param_set(),
        "value": value,
        "cap": cap,
        "capWord": field_word_hex(&BigInt::from(cap)),
        "ciphertextHex": format!("0x{}", hex::encode(&sub.ciphertext)),
        "mCommitment": field_word_hex(&m_commitment),
        "extra": extra_public,
    });
    std::fs::write(
        out_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    println!(
        "{}: Prover.toml written for ct0/ct1{suffix} + {}; meta at {}",
        app.circuit_package(),
        app.circuit_package(),
        out_dir.join("meta.json").display()
    );
}
