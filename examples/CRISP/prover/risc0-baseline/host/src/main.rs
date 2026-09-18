// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use crisp_risc0_baseline_methods::{selected_guest, COMPUTE_PROVIDER_REVISION};
use risc0_zkvm::{
    default_executor, ExecutorEnv, ExitCode, ExternalProver, InnerReceipt, Journal, Prover,
    ProverOpts, Receipt, VerifierContext,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::Instant,
};

fn read_bounded(path: &PathBuf, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "The input file exceeds the byte limit"
    );
    Ok(bytes)
}

fn journal_words(journal: &Journal) -> Result<Vec<u8>> {
    let decoded: e3_support_types::ComputeJournal = journal.decode()?;
    let words = [
        decoded.chain_id,
        decoded.verifying_contract,
        decoded.e3_id,
        decoded.encryption_scheme_id,
        decoded.committee_public_key_hash,
        decoded.ciphertext_hash,
        decoded.ciphertext_commitment,
        decoded.params_hash,
        decoded.merkle_root,
    ];
    ensure!(
        words.iter().all(|word| word.len() == 32),
        "A production journal field has the wrong length"
    );
    Ok(words.concat())
}

fn verify_receipt(receipt: &Receipt, guest_id: [u32; 8], journal: &[u8]) -> Result<u128> {
    ensure!(
        !matches!(receipt.inner, InnerReceipt::Fake(_)),
        "A fake receipt is not a proof"
    );
    let context = VerifierContext::default().with_dev_mode(false);
    let start = Instant::now();
    receipt.verify_with_context(&context, guest_id)?;
    let verification_ms = start.elapsed().as_millis();
    let actual = journal_words(&receipt.journal)?;
    ensure!(
        actual == journal,
        "The proof journal differs from the fixture"
    );
    let mut wrong_id = guest_id;
    wrong_id[0] ^= 1;
    ensure!(
        receipt.verify_with_context(&context, wrong_id).is_err(),
        "The receipt verifier accepted another program"
    );
    let mut modified = receipt.clone();
    modified.journal.bytes[0] ^= 1;
    ensure!(
        modified.verify_with_context(&context, guest_id).is_err(),
        "The receipt verifier accepted a modified journal"
    );
    for word in 0..9 {
        let mut changed = journal.to_vec();
        changed[word * 32 + 31] ^= 1;
        ensure!(actual != changed, "The journal comparison omitted a field");
    }
    Ok(verification_ms)
}

fn main() -> Result<()> {
    let (guest_elf, guest_id, kernel, optimizations) = selected_guest();
    let args: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(
        args.len() == 3,
        "Usage: pnpm crisp:prover risc0 <input.bincode|receipt.bin> <journal.bin> <report.json>"
    );
    let mode = std::env::var("CRISP_RISC0_MODE").unwrap_or_else(|_| "execute".into());
    ensure!(
        ["execute", "prove", "verify"].contains(&mode.as_str()),
        "CRISP_RISC0_MODE must be execute, prove, or verify"
    );
    let journal = read_bounded(&args[1], 288)?;
    ensure!(
        journal.len() == 288,
        "The expected journal must contain nine words"
    );
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args[2])?;
    if mode == "verify" {
        let receipt_bytes = read_bounded(&args[0], 8 << 30)?;
        let receipt: Receipt = bincode::deserialize(&receipt_bytes)?;
        let start = Instant::now();
        let verify_ms = verify_receipt(&receipt, guest_id, &journal)?;
        let report = json!({
            "backend": "risc0-3.0.3-independent-verifier",
            "proof_verified": true,
            "expected_executable_checked": true,
            "journal_words_checked": 9,
            "wrong_executable_rejected": true,
            "modified_journal_rejected": true,
            "modified_journal_words_rejected": 9,
            "receipt_sha256": hex::encode(Sha256::digest(&receipt_bytes)),
            "journal_sha256": hex::encode(Sha256::digest(&journal)),
            "elf_sha256": hex::encode(Sha256::digest(guest_elf)),
            "image_id_words": guest_id,
            "verify_ms": verify_ms,
            "all_checks_ms": start.elapsed().as_millis(),
        });
        output.write_all(&serde_json::to_vec_pretty(&report)?)?;
        println!("{report}");
        return Ok(());
    }
    let input = read_bounded(&args[0], 512 << 20)?;
    let production_input: e3_support_types::ComputeGuestInput = bincode::deserialize(&input)?;
    ensure!(
        bincode::serialize(&production_input)? == input,
        "The production input encoding differs"
    );
    let segment_po2: u32 = std::env::var("CRISP_RISC0_SEGMENT_PO2")
        .unwrap_or_else(|_| "20".into())
        .parse()?;
    ensure!(
        (20..=22).contains(&segment_po2),
        "The segment exponent must be 20, 21, or 22"
    );
    let env = ExecutorEnv::builder()
        .write_slice(&input)
        .segment_limit_po2(segment_po2)
        .session_limit(Some(1 << 37))
        .build()?;
    if mode == "prove" {
        let server = PathBuf::from(
            std::env::var_os("RISC0_SERVER_PATH")
                .context("Set RISC0_SERVER_PATH to the isolated local r0vm binary")?,
        );
        ensure!(
            server.is_absolute() && server.is_file(),
            "The local r0vm path must name an absolute file"
        );
        let receipt_path = args[2].with_extension("receipt.bin");
        ensure!(!receipt_path.exists(), "The receipt file already exists");
        let context = VerifierContext::default().with_dev_mode(false);
        let opts = ProverOpts::composite().with_dev_mode(false);
        let prover = ExternalProver::new("crisp-local-r0vm", &server);
        let start = Instant::now();
        let info = prover.prove_with_ctx(env, &context, guest_elf, &opts)?;
        let prove_ms = start.elapsed().as_millis();
        let verify_ms = verify_receipt(&info.receipt, guest_id, &journal)?;
        let receipt_bytes = bincode::serialize(&info.receipt)?;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&receipt_path)?
            .write_all(&receipt_bytes)?;
        let report = json!({
            "backend": "risc0-3.0.3-local-composite",
            "proof_verified": true,
            "expected_executable_checked": true,
            "journal_words_checked": 9,
            "wrong_executable_rejected": true,
            "modified_journal_rejected": true,
            "modified_journal_words_rejected": 9,
            "kernel": kernel,
            "compute_provider_revision": COMPUTE_PROVIDER_REVISION,
            "optimizations": optimizations,
            "segment_po2": segment_po2,
            "stats": info.stats,
            "prove_ms": prove_ms,
            "verify_ms": verify_ms,
            "elapsed_ms": start.elapsed().as_millis(),
            "input_sha256": hex::encode(Sha256::digest(&input)),
            "journal_sha256": hex::encode(Sha256::digest(&journal)),
            "production_journal_sha256": hex::encode(Sha256::digest(&info.receipt.journal.bytes)),
            "elf_sha256": hex::encode(Sha256::digest(guest_elf)),
            "image_id_words": guest_id,
            "server_sha256": hex::encode(Sha256::digest(fs::read(server)?)),
            "receipt_sha256": hex::encode(Sha256::digest(&receipt_bytes)),
            "receipt_bytes": receipt_bytes.len(),
        });
        output.write_all(&serde_json::to_vec_pretty(&report)?)?;
        println!("{report}");
        return Ok(());
    }
    let start = Instant::now();
    let session = default_executor()
        .execute(env, guest_elf)
        .context("The RISC Zero baseline failed")?;
    let execute_ms = start.elapsed().as_millis();
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "The RISC Zero guest did not halt successfully"
    );
    ensure!(
        journal_words(&session.journal)? == journal,
        "The RISC Zero journal differs from the native CRISP fixture"
    );
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(args[2].with_extension("journal.bin"))?
        .write_all(&session.journal.bytes)?;
    let report = json!({
        "backend": "risc0-3.0.3-execute-only",
        "production_receipt": false,
        "kernel": kernel,
        "compute_provider_revision": COMPUTE_PROVIDER_REVISION,
        "optimizations": optimizations,
        "production_input_roundtrip": true,
        "production_journal_bytes": session.journal.bytes.len(),
        "production_journal_sha256": hex::encode(Sha256::digest(&session.journal.bytes)),
        "user_cycles": session.cycles(),
        "padded_segment_cycles": session.segments.iter().map(|segment| 1u64 << segment.po2).sum::<u64>(),
        "segments": session.segments.len(),
        "execute_ms": execute_ms,
        "input_sha256": hex::encode(Sha256::digest(&input)),
        "journal_sha256": hex::encode(Sha256::digest(&journal)),
        "elf_sha256": hex::encode(Sha256::digest(guest_elf)),
        "image_id_words": guest_id,
    });
    let bytes = serde_json::to_vec_pretty(&report)?;
    output.write_all(&bytes)?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_zkvm::{FakeReceipt, ReceiptClaim};

    fn fixture() -> e3_support_types::ComputeJournal {
        e3_support_types::ComputeJournal {
            chain_id: vec![1; 32],
            verifying_contract: vec![2; 32],
            e3_id: vec![3; 32],
            encryption_scheme_id: vec![4; 32],
            committee_public_key_hash: vec![5; 32],
            ciphertext_hash: vec![6; 32],
            ciphertext_commitment: vec![7; 32],
            params_hash: vec![8; 32],
            merkle_root: vec![9; 32],
        }
    }

    fn encode(value: &e3_support_types::ComputeJournal) -> Journal {
        Journal::new(
            risc0_zkvm::serde::to_vec(value)
                .unwrap()
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )
    }

    #[test]
    fn journal_preserves_all_nine_words() {
        let words = journal_words(&encode(&fixture())).unwrap();
        for (index, word) in words.chunks_exact(32).enumerate() {
            assert_eq!(word, vec![index as u8 + 1; 32]);
        }
        assert_eq!(words.len(), 288);
    }

    #[test]
    fn journal_rejects_a_short_field() {
        let mut value = fixture();
        value.merkle_root.pop();
        assert!(journal_words(&encode(&value)).is_err());
    }

    #[test]
    fn verification_rejects_fake_receipts() {
        let journal = encode(&fixture());
        let fake = FakeReceipt::new(ReceiptClaim::ok([0u32; 8], journal.bytes.clone()));
        let receipt = Receipt::new(InnerReceipt::Fake(fake), journal.bytes);
        let error = verify_receipt(&receipt, [0; 8], &vec![0; 288]).unwrap_err();
        assert!(error.to_string().contains("fake receipt"));
    }
}
