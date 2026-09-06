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

/// ParamSet 5 (coefficient inner products): the coefficient-encoded
/// bundle decrypts to EXACTLY the coefficients the app laid out (a forward
/// vector, a reversed vector, a mask), the placement matches
/// `e3_trckks::policy::coefficient_layout` by construction (same helpers),
/// and the ct0/ct1 commitments recompute — so the Greco path is unchanged
/// for coefficient-encoded messages.
#[test]
fn coefficient_bundle_decrypts_to_layout_and_commits() {
    use e3_trckks::policy::coefficient_layout;
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (sk, pk) = generate_keypair(5, &mut rng).unwrap();
    let n = 512usize;
    let a: Vec<f64> = (0..16).map(|j| (j as f64 - 8.0) / 8.0).collect();
    let fwd = coefficient_layout::forward(&a, n);
    let rev = coefficient_layout::reversed(&a, n);
    let mask: Vec<f64> = (0..128).map(|j| (j * 7 % 1024) as f64).collect();
    let msk = coefficient_layout::mask(&mask, n);

    let mut rng2 = ChaCha20Rng::seed_from_u64(8);
    for (coeffs, what) in [(&fwd, "forward"), (&rev, "reversed"), (&msk, "mask")] {
        let bundle = encrypt_coefficients_and_witness(5, &pk, coeffs, &mut rng2).unwrap();
        let ct = hex::decode(&bundle.ciphertext_hex).unwrap();
        let got = decrypt_coefficients(5, &sk, &ct, n).unwrap();
        for k in 0..n {
            assert!(
                (got[k] - coeffs[k]).abs() < 1e-5,
                "{what}: coefficient {k} decoded {} vs laid out {}",
                got[k],
                coeffs[k]
            );
        }
        let (u, m) = commitments_from_inputs_json(5, &bundle.circuit_inputs).unwrap();
        assert_eq!(u, bundle.u_commitment_hex, "{what}: u commitment");
        assert_eq!(m, bundle.m_commitment_hex, "{what}: m commitment");
    }
    // Wrong length and over-bound entries are rejected before encryption.
    assert!(encrypt_coefficients_and_witness(5, &pk, &fwd[..100], &mut rng2).is_err());
    let mut too_big = fwd.clone();
    too_big[3] = 1025.0;
    assert!(encrypt_coefficients_and_witness(5, &pk, &too_big, &mut rng2).is_err());
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

// ---------------------------------------------------------------------
// Credit scoring v2 (ParamSet 4, slot encoding, logit + output mask)
// ---------------------------------------------------------------------

const CREDIT_FEATURES_VEC: [u32; 8] = [520, 130, 350, 999, 0, 1, 777, 42];
const CREDIT_BOB_FEATURES: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const CREDIT_CAP: u32 = 1000;
const CREDIT_MASK: u32 = 529_664; // 517.25
const CREDIT_INDEX: u32 = 2;
const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const BOB: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

fn credit_model() -> CreditModel {
    CreditModel::from_f64(&[1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2], -0.8)
}

fn credit_proof() -> CreditFeatureProof {
    use e3_zk_helpers::threshold::ckks_app_validity::address_to_biguint;
    use e3_zk_helpers::threshold::ckks_credit_validity::FeatureTree;
    let alice = address_to_biguint(ALICE).unwrap();
    let bob = address_to_biguint(BOB).unwrap();
    let tree = FeatureTree::new(&[
        (alice.clone(), CREDIT_FEATURES_VEC),
        (bob, CREDIT_BOB_FEATURES),
    ])
    .unwrap();
    tree.proof(0, &alice, CREDIT_FEATURES_VEC)
}

/// Same seeded RNG → the WASM path and the zk-helpers reference
/// (`build_credit_submission`) produce BYTE-IDENTICAL ciphertexts,
/// Prover.tomls and credit-leg inputs for BOTH encryptions.
#[test]
fn credit_bundle_matches_native_builder() {
    use e3_zk_helpers::threshold::ckks_credit_validity::{
        build_credit_submission_with_rng, credit_preset,
    };
    let pk_bytes = fixture_pk(4);
    let preset = credit_preset().unwrap();
    let pk = CkksPublicKey::from_bytes(&pk_bytes, &preset.params).unwrap();

    let mut rng_a = ChaCha20Rng::from_seed(SEED);
    let (logit, mask, credit_inputs) = encrypt_credit_and_witness(
        &pk_bytes,
        credit_proof(),
        CREDIT_CAP,
        credit_model(),
        CREDIT_INDEX,
        CREDIT_MASK,
        &mut rng_a,
    )
    .unwrap();

    let mut rng_b = ChaCha20Rng::from_seed(SEED);
    let native = build_credit_submission_with_rng(
        pk,
        credit_proof(),
        CREDIT_CAP,
        credit_model(),
        CREDIT_INDEX,
        CREDIT_MASK,
        &mut rng_b,
    )
    .unwrap();
    assert_eq!(hex::encode(&native.logit.ciphertext), logit.ciphertext_hex);
    assert_eq!(hex::encode(&native.mask.ciphertext), mask.ciphertext_hex);
    assert_eq!(native.logit.greco_toml, logit.prover_toml_ct0);
    assert_eq!(native.mask.greco_toml, mask.prover_toml_ct0);
    assert_eq!(native.credit_inputs.to_json(), credit_inputs);
    assert_eq!(
        toml::to_string(&credit_inputs).unwrap(),
        native.credit_toml,
        "credit Prover.toml bytes"
    );
    assert_ne!(logit.ciphertext_hex, mask.ciphertext_hex);
    assert_eq!(credit_inputs["index"], "2");
    assert_eq!(credit_inputs["cap"], "1000");
    assert_eq!(credit_inputs["mask"], CREDIT_MASK.to_string());
    // Same `m` as the Greco ct0 legs (the JSON carries small coefficients
    // as numbers, the noir_js maps as strings — compare the values).
    let stringy = |v: &serde_json::Value| -> Vec<String> {
        v["coefficients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| match c {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                other => panic!("{other}"),
            })
            .collect()
    };
    assert_eq!(
        stringy(&credit_inputs["m_z"]),
        stringy(&logit.ct0_inputs["m"])
    );
    assert_eq!(
        stringy(&credit_inputs["m_m"]),
        stringy(&mask.ct0_inputs["m"])
    );
    assert_eq!(logit.encoded_values, vec![credit_model().logit(&CREDIT_FEATURES_VEC, CREDIT_CAP)]);
    assert_eq!(mask.encoded_values, vec![517.25]);
}

/// Both ciphertexts decrypt to the declared slot values at slot `index`
/// and to 0 everywhere else.
#[test]
fn credit_ciphertexts_decrypt_to_the_slot_values() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_keypair(4, &mut rng).unwrap();
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let (logit, mask, _) = encrypt_credit_and_witness(
        &pk,
        credit_proof(),
        CREDIT_CAP,
        credit_model(),
        CREDIT_INDEX,
        CREDIT_MASK,
        &mut rng,
    )
    .unwrap();
    let z = credit_model().logit(&CREDIT_FEATURES_VEC, CREDIT_CAP);
    let slots_z = decrypt(4, &sk, &hex::decode(&logit.ciphertext_hex).unwrap()).unwrap();
    let slots_m = decrypt(4, &sk, &hex::decode(&mask.ciphertext_hex).unwrap()).unwrap();
    assert!((slots_z[CREDIT_INDEX as usize] - z).abs() < 1e-6, "{}", slots_z[2]);
    assert!((slots_m[CREDIT_INDEX as usize] - 517.25).abs() < 1e-6);
    for (i, (a, b)) in slots_z.iter().zip(&slots_m).enumerate() {
        if i != CREDIT_INDEX as usize {
            assert!(a.abs() < 1e-6 && b.abs() < 1e-6, "slot {i} not empty");
        }
    }
}

#[test]
fn credit_rejects_bad_inputs() {
    let pk = fixture_pk(4);
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let mut over = credit_proof();
    over.features[3] = CREDIT_CAP + 1;
    let model = credit_model();
    assert!(
        encrypt_credit_and_witness(&pk, over, CREDIT_CAP, model, CREDIT_INDEX, CREDIT_MASK, &mut rng)
            .is_err()
    );
    assert!(encrypt_credit_and_witness(
        &pk,
        credit_proof(),
        CREDIT_CAP,
        model,
        CREDIT_INDEX,
        1 << 20,
        &mut rng
    )
    .is_err());
    assert!(
        encrypt_credit_and_witness(&pk, credit_proof(), 0, model, CREDIT_INDEX, CREDIT_MASK, &mut rng)
            .is_err()
    );
    assert!(encrypt_credit_and_witness(
        &pk,
        credit_proof(),
        CREDIT_CAP,
        model,
        256,
        CREDIT_MASK,
        &mut rng
    )
    .is_err());
    let big = CreditModel::from_f64(&[8.5; 8], 0.0);
    assert!(
        encrypt_credit_and_witness(&pk, credit_proof(), CREDIT_CAP, big, CREDIT_INDEX, CREDIT_MASK, &mut rng)
            .is_err()
    );
    // A leaf that does not open under its root fails the pre-check.
    let mut bad_root = credit_proof();
    bad_root.merkle_root += 1u32;
    let err = encrypt_credit_and_witness(
        &pk,
        bad_root,
        CREDIT_CAP,
        model,
        CREDIT_INDEX,
        CREDIT_MASK,
        &mut rng,
    )
    .unwrap_err();
    assert!(err.to_string().contains("root"), "{err}");
}

/// The local sigmoid mirror equals the policy's constants.
#[test]
fn sigmoid_cubic_matches_policy_constants() {
    for z in [-4.0, -1.5, 0.0, 0.164, 2.0, 5.0] {
        let want = 0.5 + 0.197 * z - 0.004 * z * z * z;
        assert!((sigmoid_cubic(z) - want).abs() < 1e-15);
    }
    assert!((sigmoid_cubic(0.0) - 0.5).abs() < 1e-15);
}

/// Acceptance: `nargo execute` solves ALL FIVE ps4 legs on OUR inputs
/// (Greco ct0/ct1 for both ciphertexts + the credit leg), with the
/// commitments matching across legs.
#[test]
fn credit_bundle_solves_all_five_ps4_legs() {
    let nargo = std::env::var("NARGO_BIN")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".nargo/bin/nargo")
        });
    let circuits = interfold_root().join("circuits/bin/threshold");
    if !nargo.exists()
        || !circuits
            .join("target/ckks_credit_validity_ps4.json")
            .exists()
    {
        eprintln!("SKIP nargo credit acceptance: nargo or compiled ps4 circuits missing");
        return;
    }
    let pk = fixture_pk(4);
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let (logit, mask, credit_inputs) = encrypt_credit_and_witness(
        &pk,
        credit_proof(),
        CREDIT_CAP,
        credit_model(),
        CREDIT_INDEX,
        CREDIT_MASK,
        &mut rng,
    )
    .unwrap();
    let credit_toml = toml::to_string(&credit_inputs).unwrap();

    let nonce = format!("wasmcredit_{}", std::process::id());
    let run = |pkg: &str, toml_body: &str| -> String {
        let prover = circuits.join(pkg).join(format!("Prover_{nonce}.toml"));
        std::fs::write(&prover, toml_body).unwrap();
        let witness = format!("{pkg}_{nonce}");
        let out = std::process::Command::new(&nargo)
            .args([
                "execute",
                "--package",
                pkg,
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
        stdout
    };
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
    for (which, bundle) in [("logit", &logit), ("mask", &mask)] {
        let ct0 = fields(&run(
            "user_data_encryption_ckks_ct0_ps4",
            &bundle.prover_toml_ct0,
        ));
        let ct1 = fields(&run(
            "user_data_encryption_ckks_ct1_ps4",
            &bundle.prover_toml_ct1,
        ));
        assert_eq!(ct0[3], bundle.u_commitment_hex, "{which} u (ct0)");
        assert_eq!(ct1[2], bundle.u_commitment_hex, "{which} u (ct1)");
        assert_eq!(ct0[2], bundle.m_commitment_hex, "{which} m");
    }
    let app = fields(&run("ckks_credit_validity_ps4", &credit_toml));
    // The credit leg prints its public inputs then `(m_commitment_z, m_commitment_m)`.
    let n = app.len();
    assert_eq!(app[n - 2], logit.m_commitment_hex, "credit leg m_z: {app:?}");
    assert_eq!(app[n - 1], mask.m_commitment_hex, "credit leg m_m: {app:?}");
}
