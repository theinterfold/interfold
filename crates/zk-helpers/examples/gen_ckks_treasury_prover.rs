// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Treasury-risk app (ParamSet 5) tooling:
//!
//! - `configs`: emit `circuits/lib/src/configs/ckks_treasury_ps5.nr`
//!   (treasury leg) from codegen. (The Greco `ckks_ps5.nr` is owned by
//!   `gen_ckks_configs_ps`.)
//! - `prover <out-dir> [pubkey.bin]`: generate real SEVEN-leg witnesses
//!   (Greco ct0/ct1 for the forward, reversed and mask ciphertexts, the
//!   treasury validity leg) from THREE encryptions, plus a `meta.json`
//!   the fixture builder reads (ciphertext hexes, expected commitments,
//!   public inputs). Prover.toml files land in the matching
//!   `circuits/bin/threshold/<pkg>/` directories; the Greco packages get
//!   the FORWARD witness as `Prover.toml` (the reversed and mask
//!   witnesses are written next to it as `Prover_rev.toml` /
//!   `Prover_mask.toml` for the fixture script to swap in).
//! - `prover-bad <out-dir>`: same, but with an exposure ABOVE 1 — the
//!   native pre-check is bypassed so the circuit's own range check is what
//!   rejects it (proving-failure fixture).
//!
//! Usage: cargo run --release -p e3-zk-helpers --example gen_ckks_treasury_prover -- <configs|prover|prover-bad> ...

use e3_zk_helpers::threshold::ckks_app_validity::{address_to_biguint, field_word_hex};
use e3_zk_helpers::threshold::ckks_treasury_validity::{
    build_treasury_submission, compute_m_commitment, expected_risk, generate_treasury_configs,
    layout_vectors, public_input_words, treasury_greco_inputs_with_rng, treasury_preset, Exposures,
    TreasuryConfigs, TreasuryInputs, Weights, MASK_WIDTH, TREASURY_CIRCUIT_PACKAGE,
    TREASURY_PARAM_SET, WORD_ADDRESS, WORD_INDEX, WORD_M_FWD, WORD_M_MASK, WORD_M_REV,
    WORD_WEIGHTS,
};
use e3_zk_helpers::threshold::user_data_encryption_ckks::generate_toml;
use fhe::ckks::{CkksPublicKey, CkksSecretKey};
use fhe_traits::DeserializeParametrized;

/// Alice (hardhat account #0): the fixture DAO.
const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
/// The demo book: exposures [0.30, 0.10, 0.45, 0.15] of the cap.
const DEMO_X: [f64; 4] = [0.30, 0.10, 0.45, 0.15];
/// The round's public risk weights: [0.5, -0.25, 1.0, 0.125].
const DEMO_W: [f64; 4] = [0.5, -0.25, 1.0, 0.125];
/// Alice's slot in the fixture round.
const DEMO_INDEX: u32 = 0;

fn demo_mask() -> Vec<u32> {
    (0..MASK_WIDTH as u32)
        .map(|j| (j * 37 + 11) % 1024)
        .collect()
}

fn write_configs() {
    let preset = treasury_preset().unwrap();
    let treasury = TreasuryConfigs::compute(&preset).unwrap();
    let path = format!("circuits/lib/src/configs/ckks_treasury_ps{TREASURY_PARAM_SET}.nr");
    std::fs::write(&path, generate_treasury_configs(&treasury)).unwrap();
    println!("written {path}");
}

fn load_or_generate_pk(path: Option<&String>) -> CkksPublicKey {
    let preset = treasury_preset().unwrap();
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
    fwd_toml: &'a str,
    fwd_ct: &'a [u8],
    rev_toml: &'a str,
    rev_ct: &'a [u8],
    mask_toml: &'a str,
    mask_ct: &'a [u8],
    inputs: &'a TreasuryInputs,
}

fn write_legs(out_dir: &std::path::Path, legs: Legs<'_>) {
    let configs = TreasuryConfigs::compute(&treasury_preset().unwrap()).unwrap();
    let inputs = legs.inputs;
    let suffix = format!("_ps{TREASURY_PARAM_SET}");
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/bin/threshold");
    for leg in ["ct0", "ct1"] {
        let dir = format!("{root}/user_data_encryption_ckks_{leg}{suffix}");
        std::fs::write(format!("{dir}/Prover.toml"), legs.fwd_toml).unwrap();
        std::fs::write(format!("{dir}/Prover_rev.toml"), legs.rev_toml).unwrap();
        std::fs::write(format!("{dir}/Prover_mask.toml"), legs.mask_toml).unwrap();
    }
    let app_dir = format!("{root}/{TREASURY_CIRCUIT_PACKAGE}");
    std::fs::write(format!("{app_dir}/Prover.toml"), inputs.to_toml().unwrap()).unwrap();

    std::fs::create_dir_all(out_dir).unwrap();
    std::fs::write(out_dir.join("ciphertext_fwd.bin"), legs.fwd_ct).unwrap();
    std::fs::write(out_dir.join("ciphertext_rev.bin"), legs.rev_ct).unwrap();
    std::fs::write(out_dir.join("ciphertext_mask.bin"), legs.mask_ct).unwrap();
    let words = public_input_words(inputs, configs.m_bit);
    let risk = expected_risk(&[inputs.x], &inputs.weights);
    let meta = serde_json::json!({
        "app": TREASURY_CIRCUIT_PACKAGE,
        "paramSet": TREASURY_PARAM_SET,
        "index": inputs.index,
        "exposures": inputs.x.0,
        "exposuresF64": inputs.x.to_f64(),
        "weights": inputs.weights.0,
        "weightsF64": inputs.weights.to_f64(),
        "weightWords": words[WORD_WEIGHTS..WORD_WEIGHTS + 4].to_vec(),
        "mask": inputs.mask,
        "singleDaoRisk": risk,
        "ciphertextFwdHex": format!("0x{}", hex::encode(legs.fwd_ct)),
        "ciphertextRevHex": format!("0x{}", hex::encode(legs.rev_ct)),
        "ciphertextMaskHex": format!("0x{}", hex::encode(legs.mask_ct)),
        "mCommitmentFwd": field_word_hex(&compute_m_commitment(&inputs.m_fwd, configs.m_bit)),
        "mCommitmentRev": field_word_hex(&compute_m_commitment(&inputs.m_rev, configs.m_bit)),
        "mCommitmentMask": field_word_hex(&compute_m_commitment(&inputs.m_mask, configs.m_bit)),
        "appPublicInputs": words,
        "wordIndex": {
            "weights": WORD_WEIGHTS, "address": WORD_ADDRESS, "index": WORD_INDEX,
            "mFwd": WORD_M_FWD, "mRev": WORD_M_REV, "mMask": WORD_M_MASK,
        },
        "extra": {
            "address": ALICE,
            "addressWord": words[WORD_ADDRESS],
            "indexWord": words[WORD_INDEX],
        },
    });
    std::fs::write(
        out_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    println!(
        "{TREASURY_CIRCUIT_PACKAGE}: Prover.toml (forward) + Prover_rev.toml + Prover_mask.toml written for ct0/ct1{suffix}; treasury leg Prover.toml; meta at {}",
        out_dir.join("meta.json").display()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let weights = Weights::from_f64(&DEMO_W).unwrap();
    match args.get(1).map(String::as_str) {
        Some("configs") => write_configs(),
        Some("prover") => {
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            let pk = load_or_generate_pk(args.get(3));
            let alice = address_to_biguint(ALICE).unwrap();
            let x = Exposures::from_f64(&DEMO_X).unwrap();
            let sub =
                build_treasury_submission(pk, alice, DEMO_INDEX, x, weights, demo_mask()).unwrap();
            write_legs(
                &out_dir,
                Legs {
                    fwd_toml: &sub.forward.greco_toml,
                    fwd_ct: &sub.forward.ciphertext,
                    rev_toml: &sub.reversed.greco_toml,
                    rev_ct: &sub.reversed.ciphertext,
                    mask_toml: &sub.mask.greco_toml,
                    mask_ct: &sub.mask.ciphertext,
                    inputs: &sub.treasury_inputs,
                },
            );
        }
        Some("prover-bad") => {
            // Exposure 2 = 1 + 2^-16 (over the cap): the ONLY thing
            // rejecting it is the circuit's `X_a <= 2^16` range check.
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            let pk = load_or_generate_pk(args.get(3));
            let alice = address_to_biguint(ALICE).unwrap();
            let x = Exposures([19661, 6554, 65537, 9830]);
            let mask = demo_mask();
            let n = treasury_preset().unwrap().params.degree();
            let (fwd, rev, msk) = layout_vectors(n, &x, &weights, &mask);
            let mut rng = rand::rng();
            let greco_f = treasury_greco_inputs_with_rng(&pk, &fwd, &mut rng).unwrap();
            let greco_r = treasury_greco_inputs_with_rng(&pk, &rev, &mut rng).unwrap();
            let greco_m = treasury_greco_inputs_with_rng(&pk, &msk, &mut rng).unwrap();
            let inputs = TreasuryInputs {
                m_fwd: greco_f.m.clone(),
                m_rev: greco_r.m.clone(),
                m_mask: greco_m.m.clone(),
                x,
                mask,
                weights,
                address: alice,
                index: DEMO_INDEX,
            };
            let fwd_ct = greco_f.ciphertext.clone();
            let rev_ct = greco_r.ciphertext.clone();
            let mask_ct = greco_m.ciphertext.clone();
            let fwd_toml = generate_toml(greco_f).unwrap();
            let rev_toml = generate_toml(greco_r).unwrap();
            let mask_toml = generate_toml(greco_m).unwrap();
            write_legs(
                &out_dir,
                Legs {
                    fwd_toml: &fwd_toml,
                    fwd_ct: &fwd_ct,
                    rev_toml: &rev_toml,
                    rev_ct: &rev_ct,
                    mask_toml: &mask_toml,
                    mask_ct: &mask_ct,
                    inputs: &inputs,
                },
            );
        }
        _ => panic!(
            "usage: gen_ckks_treasury_prover <configs|prover|prover-bad> [out-dir] [pubkey.bin]"
        ),
    }
}
