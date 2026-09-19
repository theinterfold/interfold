// SPDX-License-Identifier: LGPL-3.0-only

//! Generate fresh encrypted test ballots. This tool does not produce ballot or committee proofs.

use anyhow::{ensure, Context, Result};
use e3_bfv_client::client::{compute_ct_commitment_with_params, compute_pk_commitment};
use e3_compute_provider::{ComputeInput, FHEInputs, PublishedData};
use e3_fhe_params::{build_pair_for_preset, encode_bfv_params, BfvPreset};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{fs, path::PathBuf};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let count: usize = args.next().context("Expected a vote count")?.parse()?;
    let output = PathBuf::from(args.next().context("Expected a new output directory")?);
    ensure!(args.next().is_none(), "Unexpected arguments");
    ensure!(
        (1..=1024).contains(&count),
        "Vote count must be between 1 and 1024"
    );
    let (params, _) = build_pair_for_preset(BfvPreset::SecureThreshold8192)?;
    let mut rng = rand::rng();
    let key = SecretKey::random(&params, &mut rng);
    let public_key = PublicKey::new(&key, &mut rng);
    let public_key_bytes = public_key.to_bytes();
    let public_key_commitment = compute_pk_commitment(
        public_key_bytes.clone(),
        params.degree(),
        params.plaintext(),
        params.moduli().to_vec(),
    )?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&output).context("The fixture directory must not already exist")?;
    fs::create_dir(output.join("inputs"))?;
    let mut ciphertexts = Vec::with_capacity(count);
    let mut published = Vec::with_capacity(count);
    let mut entries = Vec::with_capacity(count);
    let mut expected_tally = [0u64; 2];
    for index in 0..count {
        let weight = (index % 3 + 1) as u64;
        let option = index % 2;
        let mut coefficients = vec![0u64; params.degree()];
        for bit in 0..50 {
            coefficients[option * 50 + bit] = (weight >> (49 - bit)) & 1;
        }
        let plaintext = Plaintext::try_encode(&coefficients, Encoding::poly(), &params)?;
        let ciphertext = public_key.try_encrypt(&plaintext, &mut rng)?.to_bytes();
        let commitment = compute_ct_commitment_with_params(&ciphertext, &params)?;
        let mut metadata = vec![0u8; 25];
        metadata[12..20].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        entries.push(json!({
            "index": index,
            "file": format!("inputs/{index}.bin"),
            "content_hash": format!("0x{}", hex::encode(Keccak256::digest(&ciphertext))),
            "commitment": format!("0x{}", hex::encode(commitment)),
            "slot": format!("0x{}", hex::encode(&metadata[..20])),
            "parent_index_plus_one": 0,
        }));
        fs::write(output.join(format!("inputs/{index}.bin")), &ciphertext)?;
        ciphertexts.push((ciphertext, index as u64));
        published.push(PublishedData {
            commitment: Some(commitment),
            metadata,
        });
        expected_tally[option] += weight;
    }
    let params_bytes = encode_bfv_params(&params);
    let input = ComputeInput {
        fhe_inputs: FHEInputs {
            ciphertexts,
            params: params_bytes.clone(),
        },
        published,
    };
    let (result, ciphertext) = input
        .run(e3_user_program::fhe_processor, e3_user_program::policy())
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let decrypted = key.try_decrypt(&Ciphertext::from_bytes(&ciphertext, &params)?)?;
    let coefficients: Vec<u64> = Vec::try_decode(&decrypted, Encoding::poly())?;
    let decode = |offset: usize| {
        coefficients[offset..offset + 50]
            .iter()
            .fold(0u64, |value, bit| value * 2 + bit)
    };
    ensure!(
        [decode(0), decode(50)] == expected_tally,
        "Native tally differs from the ballots"
    );
    ensure!(
        coefficients[100..]
            .iter()
            .all(|coefficient| *coefficient == 0),
        "Unexpected coefficients outside the tally"
    );
    fs::write(output.join("public-key.bin"), &public_key_bytes)?;
    fs::write(output.join("ciphertext.bin"), &ciphertext)?;
    fs::write(
        output.join("plaintext.bin"),
        coefficients
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>(),
    )?;
    let context = json!({
        "preset": "secure-8192", "param_set": 1, "inputs": entries,
        "params": format!("0x{}", hex::encode(params_bytes)),
        "public_key_commitment": format!("0x{}", hex::encode(public_key_commitment)),
        "input_root": format!("0x{}", hex::encode(result.merkle_root)),
        "ciphertext_hash": format!("0x{}", hex::encode(result.ciphertext_hash)),
        "ciphertext_commitment": format!("0x{}", hex::encode(result.ciphertext_commitment)),
        "expected_tally": expected_tally, "native_tally_checked": true,
        "ballot_proofs_generated": false, "threshold_decryption_proof_generated": false,
    });
    fs::write(
        output.join("fixture.json"),
        serde_json::to_vec_pretty(&context)?,
    )?;
    println!(
        "Generated {count} fresh secure-8192 test ballots in {}",
        output.display()
    );
    Ok(())
}
