// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// One-off: generate a throwaway CKKS keypair for a Greco param set and
// write the serialized public key — fixture input for the
// `ckks_participant` CLI and the `CkksE3ProgramGrecoPs3` hardhat spec.
// Usage: cargo run --example gen_ckks_test_pubkey -- <param_set> <out_file>
use fhe_traits::Serialize as FheSerialize;

fn main() {
    let param_set: u8 = std::env::args()
        .nth(1)
        .expect("pass the on-chain ParamSet value")
        .parse()
        .expect("param set must be a u8");
    let out = std::env::args().nth(2).expect("pass the output path");
    let preset =
        e3_zk_helpers::threshold::user_data_encryption_ckks::ckks_preset_for_param_set(param_set)
            .unwrap();
    let mut rng = rand::rng();
    let sk = fhe::ckks::CkksSecretKey::random(&preset.params, &mut rng);
    let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng).unwrap();
    std::fs::write(&out, pk.to_bytes()).unwrap();
    println!("written {out}");
}
