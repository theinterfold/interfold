// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Private-matching app (ParamSet 5) tooling:
//!
//! - `configs`: emit `circuits/lib/src/configs/ckks_matching_ps5.nr`
//!   (matching leg) from codegen. (The Greco `ckks_ps5.nr` is owned by
//!   the committee tooling and already checked in.)
//! - `prover <out-dir> [pubkey.bin]`: generate real FIVE-leg witnesses
//!   (Greco ct0/ct1 for the vector ciphertext, Greco ct0/ct1 for the mask
//!   ciphertext, the matching validity leg) from TWO encryptions for party
//!   A (role 0, `forward`), plus a `meta.json` the fixture builder reads
//!   (ciphertext hexes, expected commitments, public inputs). Prover.toml
//!   files land in the matching `circuits/bin/threshold/<pkg>/`
//!   directories; the Greco packages get the VECTOR witness (the mask
//!   witness is written next to it as `Prover_mask.toml` for the fixture
//!   script to swap in). The matching leg's Prover.toml uses the SAME
//!   `m` polynomials as the Greco legs (one encryption per ciphertext).
//! - `prover-b <out-dir> [pubkey.bin]`: the same for party B (role 1,
//!   `reversed`), Prover files suffixed `_b` (used to prove the B legs so
//!   the spec can exercise both roles).
//! - `prover-bad <out-dir>`: party A with an entry ABOVE 1 — the native
//!   pre-check is bypassed so the circuit's own range check is what
//!   rejects it (proving-failure fixture).
//!
//! Usage: cargo run --release -p e3-zk-helpers --example gen_ckks_matching_prover -- <configs|prover|prover-b|prover-bad> ...

use e3_zk_helpers::threshold::ckks_app_validity::{address_to_biguint, field_word_hex};
use e3_zk_helpers::threshold::ckks_matching_validity::{
    build_matching_submission, compute_m_commitment, generate_matching_configs, layout_vectors,
    matching_greco_inputs_with_rng, matching_preset, public_input_words, MatchingConfigs,
    MatchingInputs, Role, Vector, K, MASK_WIDTH, MATCHING_CIRCUIT_PACKAGE, MATCHING_PARAM_SET,
};
use e3_zk_helpers::threshold::user_data_encryption_ckks::generate_toml;
use fhe::ckks::{CkksPublicKey, CkksSecretKey};
use fhe_traits::DeserializeParametrized;

/// Alice (hardhat account #0) = party A, Bob (account #1) = party B.
const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const BOB: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
/// Demo profile vectors (cap-normalised, `|v| ≤ 1`).
const DEMO_A: [f64; K] = [
    0.5, -0.25, 1.0, -1.0, 0.125, 0.0, 0.75, -0.5, 0.3, -0.7, 0.9, -0.1, 0.6, 0.2, -0.4, 0.05,
];
const DEMO_B: [f64; K] = [
    0.4, 0.3, -0.2, 0.9, -1.0, 1.0, 0.1, 0.5, -0.6, 0.8, 0.25, 0.75, -0.35, 0.15, 0.95, -0.05,
];

/// Deterministic demo mask (`(37 j + 11) mod 1024`, offset per role).
fn demo_mask(role: Role) -> Vec<u32> {
    (0..MASK_WIDTH as u32)
        .map(|j| (j * 37 + 11 + 500 * role.bit()) % 1024)
        .collect()
}

fn write_configs() {
    let preset = matching_preset().unwrap();
    let configs = MatchingConfigs::compute(&preset).unwrap();
    let path = format!("circuits/lib/src/configs/ckks_matching_ps{MATCHING_PARAM_SET}.nr");
    std::fs::write(&path, generate_matching_configs(&configs)).unwrap();
    println!("written {path}");
}

fn load_or_generate_pk(path: Option<&String>) -> CkksPublicKey {
    let preset = matching_preset().unwrap();
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
    vector_toml: &'a str,
    vector_ct: &'a [u8],
    mask_toml: &'a str,
    mask_ct: &'a [u8],
    inputs: &'a MatchingInputs,
    /// Suffix of the Prover files (`""` for A, `"_b"` for B).
    suffix: &'a str,
    address: &'a str,
}

fn write_legs(out_dir: &std::path::Path, legs: Legs<'_>) {
    let configs = MatchingConfigs::compute(&matching_preset().unwrap()).unwrap();
    let inputs = legs.inputs;
    let m_c_vec = compute_m_commitment(&inputs.m_vec, configs.m_bit);
    let m_c_mask = compute_m_commitment(&inputs.m_mask, configs.m_bit);
    let ps = format!("_ps{MATCHING_PARAM_SET}");
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/bin/threshold");
    let sfx = legs.suffix;
    for leg in ["ct0", "ct1"] {
        let dir = format!("{root}/user_data_encryption_ckks_{leg}{ps}");
        std::fs::write(format!("{dir}/Prover{sfx}.toml"), legs.vector_toml).unwrap();
        std::fs::write(format!("{dir}/Prover_mask{sfx}.toml"), legs.mask_toml).unwrap();
    }
    let app_dir = format!("{root}/{MATCHING_CIRCUIT_PACKAGE}");
    std::fs::write(
        format!("{app_dir}/Prover{sfx}.toml"),
        inputs.to_toml().unwrap(),
    )
    .unwrap();

    std::fs::create_dir_all(out_dir).unwrap();
    std::fs::write(out_dir.join("ciphertext_vec.bin"), legs.vector_ct).unwrap();
    std::fs::write(out_dir.join("ciphertext_mask.bin"), legs.mask_ct).unwrap();
    let words = public_input_words(inputs, configs.m_bit);
    let meta = serde_json::json!({
        "app": MATCHING_CIRCUIT_PACKAGE,
        "paramSet": MATCHING_PARAM_SET,
        "role": inputs.role.bit(),
        "index": inputs.index,
        "values": inputs.values.0,
        "valuesF64": inputs.values.to_f64(),
        "mask": inputs.mask,
        "ciphertextVecHex": format!("0x{}", hex::encode(legs.vector_ct)),
        "ciphertextMaskHex": format!("0x{}", hex::encode(legs.mask_ct)),
        "mCommitmentVec": field_word_hex(&m_c_vec),
        "mCommitmentMask": field_word_hex(&m_c_mask),
        "appPublicInputs": words,
        "extra": {
            "address": legs.address,
            "addressWord": words[1],
            "roleWord": words[0],
            "indexWord": words[2],
        },
    });
    std::fs::write(
        out_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    println!(
        "{MATCHING_CIRCUIT_PACKAGE}: Prover{sfx}.toml (vector) + Prover_mask{sfx}.toml written for ct0/ct1{ps}; matching leg Prover{sfx}.toml; meta at {}",
        out_dir.join("meta.json").display()
    );
}

fn build_party(out_dir: &std::path::Path, pk: CkksPublicKey, role: Role, suffix: &str) {
    let (addr, values) = match role {
        Role::A => (ALICE, DEMO_A),
        Role::B => (BOB, DEMO_B),
    };
    let sub = build_matching_submission(
        pk,
        address_to_biguint(addr).unwrap(),
        role,
        Vector::from_f64(&values).unwrap(),
        demo_mask(role),
    )
    .unwrap();
    write_legs(
        out_dir,
        Legs {
            vector_toml: &sub.vector.greco_toml,
            vector_ct: &sub.vector.ciphertext,
            mask_toml: &sub.mask.greco_toml,
            mask_ct: &sub.mask.ciphertext,
            inputs: &sub.matching_inputs,
            suffix,
            address: addr,
        },
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("configs") => write_configs(),
        Some("prover") => {
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            build_party(&out_dir, load_or_generate_pk(args.get(3)), Role::A, "");
        }
        Some("prover-b") => {
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            build_party(&out_dir, load_or_generate_pk(args.get(3)), Role::B, "_b");
        }
        Some("prover-bad") => {
            // Entry 0 = 1.5 (> 1): the ONLY thing rejecting it is the
            // circuit's `|V_j| <= 2^16` check (the Greco input bound of
            // 1024 admits it).
            let out_dir = std::path::PathBuf::from(args.get(2).expect("out-dir"));
            let pk = load_or_generate_pk(args.get(3));
            let preset = matching_preset().unwrap();
            let n = preset.params.degree();
            let mut values = Vector::from_f64(&DEMO_A).unwrap();
            values.0[0] = 98304; // 1.5 * 2^16
            let mask = demo_mask(Role::A);
            let (vec, msk) = layout_vectors(n, Role::A, &values, &mask);
            let mut rng = rand::rng();
            let greco_v = matching_greco_inputs_with_rng(&pk, &vec, &mut rng).unwrap();
            let greco_m = matching_greco_inputs_with_rng(&pk, &msk, &mut rng).unwrap();
            let inputs = MatchingInputs {
                m_vec: greco_v.m.clone(),
                m_mask: greco_m.m.clone(),
                values,
                mask,
                role: Role::A,
                address: address_to_biguint(ALICE).unwrap(),
                index: 0,
            };
            let vector_ct = greco_v.ciphertext.clone();
            let mask_ct = greco_m.ciphertext.clone();
            let vector_toml = generate_toml(greco_v).unwrap();
            let mask_toml = generate_toml(greco_m).unwrap();
            write_legs(
                &out_dir,
                Legs {
                    vector_toml: &vector_toml,
                    vector_ct: &vector_ct,
                    mask_toml: &mask_toml,
                    mask_ct: &mask_ct,
                    inputs: &inputs,
                    suffix: "",
                    address: ALICE,
                },
            );
        }
        _ => panic!(
            "usage: gen_ckks_matching_prover <configs|prover|prover-b|prover-bad> [out-dir] [pubkey.bin]"
        ),
    }
}
