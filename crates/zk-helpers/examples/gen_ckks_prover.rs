// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// One-off: generate Prover.toml for the ckks ct0 bin circuit from real witnesses.
fn main() {
    use e3_zk_helpers::circuits::codegen::CircuitCodegen;
    let mut rng = rand::rng();
    let preset = e3_zk_helpers::threshold::user_data_encryption_ckks::insecure_512_ckks().unwrap();
    let sk = fhe::ckks::CkksSecretKey::random(&preset.params, &mut rng);
    let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng).unwrap();
    let data =
        e3_zk_helpers::threshold::user_data_encryption_ckks::UserDataEncryptionCkksCircuitData {
            public_key: pk,
            values: vec![42.5, -17.25, 99.99, 0.001, std::f64::consts::PI],
        };
    let artifacts =
        e3_zk_helpers::threshold::user_data_encryption_ckks::UserDataEncryptionCkksCircuit
            .codegen(preset, &data)
            .unwrap();
    std::fs::write(
        "circuits/bin/threshold/user_data_encryption_ckks_ct0/Prover.toml",
        &artifacts.toml,
    )
    .unwrap();
    println!("Prover.toml written ({} bytes)", artifacts.toml.len());
}
