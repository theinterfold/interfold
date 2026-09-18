// SPDX-License-Identifier: LGPL-3.0-only

use alloy_primitives::{Bytes, B256};
use alloy_sol_types::SolValue;
use anyhow::{ensure, Context, Result};
use e3_compute_provider::{ComputeInput, FHEInputs, PublishedData};
use e3_support_types::{ComputeDomain, ComputeGuestInput, ComputeJournal};
use std::{env, fs, path::PathBuf, process::Command};

pub struct OpenVmOutput {
    pub result: ComputeJournal,
    pub seal: Vec<u8>,
}

/// Reject missing prover configuration before the service accepts work.
pub fn check_configuration() -> Result<()> {
    for name in ["OPENVM_PROVER_BIN", "OPENVM_PROVER_CONFIG"] {
        let path = PathBuf::from(env::var(name).with_context(|| format!("Set {name}"))?);
        ensure!(
            path.is_absolute() && path.is_file(),
            "{name} must name an existing absolute file path"
        );
    }
    let status = Command::new(env::var("OPENVM_PROVER_BIN")?)
        .arg("check")
        .arg(env::var("OPENVM_PROVER_CONFIG")?)
        .status()?;
    ensure!(status.success(), "OpenVM configuration validation failed");
    Ok(())
}

pub fn run_compute(
    params: FHEInputs,
    domain: ComputeDomain,
    published: Vec<PublishedData>,
) -> Result<(OpenVmOutput, Vec<u8>)> {
    ensure!(
        params.ciphertexts.len() <= 1024,
        "The input count exceeds the guest limit"
    );
    let input = ComputeGuestInput {
        domain: domain.clone(),
        input: ComputeInput {
            fhe_inputs: params,
            published,
        },
    };
    let (result, ciphertext) = input
        .input
        .run(e3_user_program::fhe_processor, e3_user_program::policy())
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let journal = ComputeJournal::new(domain, result).map_err(anyhow::Error::msg)?;
    let journal_bytes = journal.abi_bytes().map_err(anyhow::Error::msg)?;
    let input_bytes = bincode::serialize(&input)?;
    ensure!(
        input_bytes.len() <= 512 * 1024 * 1024 - 16,
        "The input exceeds the guest byte limit"
    );
    let job = tempfile::Builder::new()
        .prefix("interfold-openvm-")
        .tempdir()?;
    let input_path = job.path().join("input.bin");
    let journal_path = job.path().join("journal.bin");
    let seal_path = job.path().join("seal.bin");
    fs::write(&input_path, input_bytes)?;
    fs::write(&journal_path, journal_bytes)?;
    let status = Command::new(env::var("OPENVM_PROVER_BIN").context("Set OPENVM_PROVER_BIN")?)
        .arg("prove")
        .arg(env::var("OPENVM_PROVER_CONFIG").context("Set OPENVM_PROVER_CONFIG")?)
        .arg(&input_path)
        .arg(&journal_path)
        .arg(&seal_path)
        .status()
        .context("Cannot start the OpenVM prover")?;
    ensure!(
        status.success(),
        "OpenVM proof generation or verification failed"
    );
    let seal = fs::read(seal_path).context("The OpenVM prover did not return a verified seal")?;
    ensure!(seal.len() == 2144, "The OpenVM seal has an invalid length");
    Ok((
        OpenVmOutput {
            result: journal,
            seal,
        },
        ciphertext,
    ))
}

pub fn encode_compute_proof(seal: &[u8], result: &ComputeJournal) -> Result<Vec<u8>> {
    result.abi_bytes().map_err(anyhow::Error::msg)?;
    ensure!(seal.len() == 2144, "The OpenVM seal has an invalid length");
    Ok((
        Bytes::copy_from_slice(seal),
        B256::from_slice(&result.params_hash),
        B256::from_slice(&result.merkle_root),
    )
        .abi_encode_params())
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_compute_provider::ComputeResult;

    #[test]
    fn journal_and_envelope_preserve_all_fields() {
        let domain = ComputeDomain {
            chain_id: 1,
            verifying_contract: [2; 20],
            e3_id: [3; 32],
            encryption_scheme_id: [4; 32],
            committee_public_key_hash: [5; 32],
        };
        let mut journal = ComputeJournal::new(
            domain,
            ComputeResult {
                ciphertext_hash: vec![6; 32],
                ciphertext_commitment: vec![7; 32],
                params_hash: vec![8; 32],
                merkle_root: vec![9; 32],
            },
        )
        .unwrap();
        let bytes = journal.abi_bytes().unwrap();
        assert_eq!(bytes.len(), 288);
        assert_eq!(&bytes[..24], &[0; 24]);
        assert_eq!(&bytes[32..44], &[0; 12]);
        for (i, field) in bytes[64..].chunks_exact(32).enumerate() {
            assert_eq!(field, &[i as u8 + 3; 32]);
        }
        let envelope = encode_compute_proof(&vec![0; 2144], &journal).unwrap();
        assert_eq!(envelope.len(), 2272);
        assert_eq!(&envelope[32..64], &[8; 32]);
        assert_eq!(&envelope[64..96], &[9; 32]);
        assert!(encode_compute_proof(&[], &journal).is_err());
        journal.e3_id.pop();
        assert!(encode_compute_proof(&vec![0; 2144], &journal).is_err());
    }

    #[test]
    #[ignore = "Requires OPENVM_TEST_INPUT and OPENVM_TEST_JOURNAL"]
    fn native_result_matches_external_guest_journal() -> Result<()> {
        let input: ComputeGuestInput =
            bincode::deserialize(&fs::read(env::var("OPENVM_TEST_INPUT")?)?)?;
        let (result, _) = input
            .input
            .run(e3_user_program::fhe_processor, e3_user_program::policy())
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let journal = ComputeJournal::new(input.domain, result).map_err(anyhow::Error::msg)?;
        assert_eq!(
            journal.abi_bytes().map_err(anyhow::Error::msg)?,
            fs::read(env::var("OPENVM_TEST_JOURNAL")?)?
        );
        Ok(())
    }
}
