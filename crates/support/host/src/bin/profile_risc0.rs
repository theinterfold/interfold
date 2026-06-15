// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_compute_provider::FHEInputs;
use e3_fhe_params::{build_bfv_params_from_set_arc, encode_bfv_params, BfvPreset};
use e3_support_host::run_risc0_compute;
use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use rand::rng;

fn main() {
    println!("Starting RISC0 profiling with mock ciphertexts...");

    // BFV preset is configurable via env var, defaulting to insecure threshold
    // for fast profiling. Set BFV_PRESET to one of:
    //   INSECURE_THRESHOLD_BFV_512 | INSECURE_DKG_BFV_512 |
    //   SECURE_THRESHOLD_BFV_8192  | SECURE_DKG_BFV_8192
    let param_set: BfvPreset = match std::env::var("BFV_PRESET").ok().as_deref() {
        Some("INSECURE_DKG_512") => BfvPreset::InsecureDkg512,
        Some("SECURE_THRESHOLD_BFV_8192") => BfvPreset::SecureThreshold8192,
        Some("SECURE_DKG_8192") => BfvPreset::SecureDkg8192,
        Some(other) => {
            eprintln!(
                "Warning: unknown BFV_PRESET={}, using default InsecureThreshold512",
                other
            );
            BfvPreset::InsecureThreshold512
        }
        None => BfvPreset::InsecureThreshold512,
    };
    println!("Using BFV preset: {:?}", param_set);

    let params = build_bfv_params_from_set_arc(param_set.into());

    println!(
        "Generated BFV parameters: degree={}, plaintext_modulus={}",
        params.degree(),
        params.plaintext()
    );

    // Generate keys
    let mut rng = rng();
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng);

    println!("Generated secret and public keys");

    // Encrypt values 1, 2, 3
    let values = vec![1u64, 2u64, 3u64];
    let mut ciphertexts = Vec::new();

    for (idx, value) in values.iter().enumerate() {
        let plaintext = Plaintext::try_encode(&[*value], Encoding::poly(), &params)
            .expect("Failed to encode plaintext");
        let ciphertext = public_key
            .try_encrypt(&plaintext, &mut rng)
            .expect("Failed to encrypt");

        ciphertexts.push((ciphertext.to_bytes(), idx as u64));
        println!("Encrypted value {} as ciphertext {}", value, idx);
    }

    // Encode params to bytes
    let params_bytes = encode_bfv_params(&params);
    println!("Encoded params to {} bytes", params_bytes.len());

    // Create FHEInputs
    let fhe_inputs = FHEInputs {
        ciphertexts,
        params: params_bytes,
    };

    println!("Calling run_risc0_compute...");

    // Call run_risc0_compute
    match run_risc0_compute(fhe_inputs) {
        Ok((output, ciphertext)) => {
            println!("Success! RISC0 computation completed");
            println!("Output result: {:?}", output.result);
            println!("Output bytes length: {}", output.bytes.len());
            println!("Seal length: {}", output.seal.len());
            println!("Processed ciphertext length: {}", ciphertext.len());
        }
        Err(e) => {
            eprintln!("Error during RISC0 computation: {:?}", e);
            std::process::exit(1);
        }
    }
}
