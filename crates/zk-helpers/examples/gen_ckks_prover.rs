// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// One-off: generate Prover.toml for the ckks ct0 AND ct1 bin circuits from
// real witnesses (the codegen toml carries both legs' keys; nargo ignores
// keys a circuit does not declare).
fn main() {
    let mut rng = rand::rng();
    let preset = e3_zk_helpers::threshold::user_data_encryption_ckks::insecure_512_ckks().unwrap();
    let sk = fhe::ckks::CkksSecretKey::random(&preset.params, &mut rng);
    let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng).unwrap();
    let data =
        e3_zk_helpers::threshold::user_data_encryption_ckks::UserDataEncryptionCkksCircuitData {
            public_key: pk,
            values: vec![42.5, -17.25, 99.99, 0.001, std::f64::consts::PI],
        };
    // ONE compute: encryption randomness must match between the witness
    // toml and the persisted ciphertext (a second compute re-encrypts).
    use e3_zk_helpers::circuits::computation::Computation;
    let inputs =
        e3_zk_helpers::threshold::user_data_encryption_ckks::Inputs::compute(preset, &data)
            .unwrap();
    std::fs::write("/tmp/greco-ciphertext-v2.bin", &inputs.ciphertext).unwrap();
    let toml = e3_zk_helpers::threshold::user_data_encryption_ckks::generate_toml(inputs).unwrap();
    let artifacts = e3_zk_helpers::circuits::codegen::Artifacts {
        toml,
        configs: String::new(),
    };
    std::fs::write(
        "circuits/bin/threshold/user_data_encryption_ckks_ct0/Prover.toml",
        &artifacts.toml,
    )
    .unwrap();
    std::fs::write(
        "circuits/bin/threshold/user_data_encryption_ckks_ct1/Prover.toml",
        &artifacts.toml,
    )
    .unwrap();
    println!(
        "Prover.toml written for ct0 + ct1 ({} bytes each)",
        artifacts.toml.len()
    );
}
