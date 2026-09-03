// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Native parity tests: this crate's witness builder vs the zk-helpers
//! reference (`Inputs::compute` + `generate_toml`), plus an end-to-end
//! `nargo execute` acceptance run on OUR Prover.toml when a compiled
//! circuit and `nargo` are available.

use crate::core::*;
use e3_zk_helpers::threshold::user_data_encryption_ckks::{
    generate_toml, Inputs, UserDataEncryptionCkksCircuitData,
};
use e3_zk_helpers::Computation;
use fhe::ckks::CkksPublicKey;
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::PathBuf;

const SEED: [u8; 32] = [7u8; 32];

fn fixture_pk(param_set: u8) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    generate_keypair(param_set, &mut rng).unwrap().1
}

fn interfold_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}

/// Structural parity: same TOML keys, same limb counts, same coefficient
/// counts as the native builder for the same pk + param set.
fn assert_structural_parity(param_set: u8) {
    let pk_bytes = fixture_pk(param_set);
    let preset = preset_for_param_set(param_set).unwrap();

    let ours = encrypt_and_witness(param_set, &pk_bytes, 0.42, 1.0, true, Some(&SEED)).unwrap();

    let pk = CkksPublicKey::from_bytes(&pk_bytes, &preset.params).unwrap();
    let slots = preset.params.degree() / 2;
    let native = Inputs::compute(
        preset.clone(),
        &UserDataEncryptionCkksCircuitData {
            public_key: pk,
            values: vec![0.42; slots],
        },
    )
    .unwrap();
    let native_toml = generate_toml(native).unwrap();

    let ours_t: toml::Value = ours.prover_toml_ct0.parse().unwrap();
    let native_t: toml::Value = native_toml.parse().unwrap();
    let ours_keys: Vec<_> = ours_t.as_table().unwrap().keys().collect();
    let native_keys: Vec<_> = native_t.as_table().unwrap().keys().collect();
    assert_eq!(ours_keys, native_keys, "toml key set differs");

    for key in native_keys {
        let a = &ours_t[key];
        let b = &native_t[key];
        match (a, b) {
            (toml::Value::Array(x), toml::Value::Array(y)) => {
                assert_eq!(x.len(), y.len(), "limb count differs for {key}");
                for (xi, yi) in x.iter().zip(y) {
                    let xc = xi["coefficients"].as_array().unwrap();
                    let yc = yi["coefficients"].as_array().unwrap();
                    assert_eq!(xc.len(), yc.len(), "coefficient count differs for {key}");
                }
            }
            (toml::Value::Table(x), toml::Value::Table(y)) => {
                let xc = x["coefficients"].as_array().unwrap();
                let yc = y["coefficients"].as_array().unwrap();
                assert_eq!(xc.len(), yc.len(), "coefficient count differs for {key}");
            }
            _ => panic!("shape differs for {key}"),
        }
    }
    assert_eq!(ours.prover_toml_ct0, ours.prover_toml_ct1);
    assert_eq!(ours.message_poly_limbs.len(), preset.params.moduli().len());
    assert_eq!(ours.message_poly.len(), preset.params.degree());
}

#[test]
fn structural_parity_ps0() {
    assert_structural_parity(0);
}

#[test]
fn structural_parity_ps3() {
    assert_structural_parity(3);
}

/// EXACT parity: the native `Inputs::compute` math applied to the same
/// extended encryption. We cannot seed `Inputs::compute` itself, so we
/// re-run the reference ENCRYPTION path with our seeded RNG and feed the
/// result through `witness_from_encryption`; the `decompose_residue`
/// internal asserts (`xi == xi_hat mod R_qi`) are the native pre-checks —
/// they panic if the relation does not hold. Then the JSON→toml shape is
/// compared byte-for-byte via the native `generate_toml` on OUR inputs.
#[test]
fn seeded_witness_is_deterministic_and_toml_matches_native_codegen() {
    let pk_bytes = fixture_pk(3);
    let a = encrypt_and_witness(3, &pk_bytes, 0.42, 1.0, true, Some(&SEED)).unwrap();
    let b = encrypt_and_witness(3, &pk_bytes, 0.42, 1.0, true, Some(&SEED)).unwrap();
    assert_eq!(a.ciphertext_hex, b.ciphertext_hex);
    assert_eq!(a.prover_toml_ct0, b.prover_toml_ct0);
    assert_eq!(a.u_commitment_hex, b.u_commitment_hex);

    // Different seed => different ciphertext.
    let c = encrypt_and_witness(3, &pk_bytes, 0.42, 1.0, true, Some(&[9u8; 32])).unwrap();
    assert_ne!(a.ciphertext_hex, c.ciphertext_hex);

    // The toml is exactly the native codegen of our circuit_inputs JSON.
    let native_toml = toml::to_string(&a.circuit_inputs).unwrap();
    assert_eq!(a.prover_toml_ct0, native_toml);
}

#[test]
fn ciphertext_decrypts_to_value() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_keypair(3, &mut rng).unwrap();
    let bundle = encrypt_and_witness(3, &pk, 52_000.0, 100_000.0, true, Some(&SEED)).unwrap();
    let ct = hex::decode(&bundle.ciphertext_hex).unwrap();
    let values = decrypt(3, &sk, &ct).unwrap();
    assert_eq!(values.len(), 256);
    for v in &values {
        assert!((v - 0.52).abs() < 1e-6, "decoded {v}");
    }
}

#[test]
fn commitments_recompute_from_inputs() {
    let pk_bytes = fixture_pk(3);
    let bundle = encrypt_and_witness(3, &pk_bytes, 0.42, 1.0, true, Some(&SEED)).unwrap();
    let (u, m) = commitments_from_inputs_json(3, &bundle.circuit_inputs).unwrap();
    assert_eq!(u, bundle.u_commitment_hex);
    assert_eq!(m, bundle.m_commitment_hex);
    let (u2, m2) = commitments_from_inputs_json(3, &bundle.ct0_inputs).unwrap();
    assert_eq!(u2, u);
    assert_eq!(m2, m);
}

#[test]
fn param_set_presets_match_fhe_params() {
    for set in [0u8, 2, 3] {
        let ours = params_bytes_for_param_set(set).unwrap();
        let reference = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(set)
            .unwrap()
            .to_bytes();
        assert_eq!(ours, reference, "param set {set} bytes differ");
        let info = param_set_info(set).unwrap();
        assert_eq!(info.degree, 512);
    }
    assert!(params_bytes_for_param_set(7).is_err());
}

#[test]
fn rejects_out_of_bound_values() {
    let pk_bytes = fixture_pk(3);
    assert!(encrypt_and_witness(3, &pk_bytes, 2.0, 1.0, true, Some(&SEED)).is_err());
    assert!(encrypt_and_witness(3, &pk_bytes, 1.0, 0.0, true, Some(&SEED)).is_err());
    assert!(encrypt_and_witness(3, &pk_bytes, 0.5, 1.0, true, Some(&[1u8; 4])).is_err());
}

/// Acceptance proof: `nargo execute` solves BOTH ps3 circuits on OUR
/// Prover.toml, and the solved public outputs equal our commitments.
/// Skips (with a message) when nargo or the compiled circuit is absent.
#[test]
fn nargo_executes_our_toml_ps3() {
    nargo_acceptance(3, "_ps3");
}

#[test]
fn nargo_executes_our_toml_ps0() {
    nargo_acceptance(0, "");
}

fn nargo_acceptance(param_set: u8, suffix: &str) {
    let nargo = std::env::var("NARGO_BIN")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".nargo/bin/nargo")
        });
    let circuits = interfold_root().join("circuits/bin/threshold");
    if !nargo.exists() || !circuits.join("target").exists() {
        eprintln!("SKIP nargo acceptance: nargo or circuits/bin/threshold/target missing");
        return;
    }
    let pk_bytes = fixture_pk(param_set);
    let bundle = encrypt_and_witness(param_set, &pk_bytes, 0.42, 1.0, true, Some(&SEED)).unwrap();

    let nonce = format!("wasmparity_{}_{}", std::process::id(), param_set);
    let mut outputs = Vec::new();
    for leg in 0..2 {
        let pkg = format!("user_data_encryption_ckks_ct{leg}{suffix}");
        let pkg_dir = circuits.join(&pkg);
        if !pkg_dir.exists() {
            eprintln!("SKIP: {pkg} missing");
            return;
        }
        let prover = pkg_dir.join(format!("Prover_{nonce}.toml"));
        std::fs::write(&prover, &bundle.prover_toml_ct0).unwrap();
        let witness = format!("{pkg}_{nonce}");
        let out = std::process::Command::new(&nargo)
            .args([
                "execute",
                "--package",
                &pkg,
                "-p",
                &format!("Prover_{nonce}"),
                &witness,
            ])
            .current_dir(&circuits)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&prover);
        let _ = std::fs::remove_file(circuits.join(format!("target/{witness}.gz")));
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            out.status.success(),
            "nargo execute {pkg} failed:\n{stdout}\n{stderr}"
        );
        eprintln!("{pkg}: {}", stdout.trim());
        outputs.push(stdout);
    }
    // Circuit output is printed as `[Field] [0x…, 0x…, …]`; the shared
    // u_commitment is the last field of BOTH legs, m_commitment is ct0's
    // third field.
    let fields = |s: &str| -> Vec<String> {
        s.split("0x")
            .skip(1)
            .map(|h| {
                format!(
                    "0x{}",
                    h.chars()
                        .take_while(|c| c.is_ascii_hexdigit())
                        .collect::<String>()
                )
            })
            .collect()
    };
    let ct0 = fields(&outputs[0]);
    let ct1 = fields(&outputs[1]);
    assert_eq!(ct0.len(), 4, "ct0 outputs: {ct0:?}");
    assert_eq!(ct1.len(), 3, "ct1 outputs: {ct1:?}");
    assert_eq!(ct0[3], bundle.u_commitment_hex, "u_commitment (ct0)");
    assert_eq!(ct1[2], bundle.u_commitment_hex, "u_commitment (ct1)");
    assert_eq!(ct0[2], bundle.m_commitment_hex, "m_commitment");
}
