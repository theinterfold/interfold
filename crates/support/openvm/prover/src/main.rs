// SPDX-License-Identifier: LGPL-3.0-only

use eyre::{ensure, Result};
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::{
    config::AggregationSystemParams,
    fs::{read_halo2_pk_from_file, read_object_from_file, write_object_to_file},
    keygen::{AggProvingKey, AppProvingKey},
    types::{AppExecutionCommit, EvmHalo2Verifier, EvmProof},
    Sdk, StdIn, F,
};
use openvm_sdk_config::SdkVmConfig;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    app_pk: PathBuf,
    executable: PathBuf,
    aggregation_pk: PathBuf,
    halo2_pk: PathBuf,
    halo2_params_dir: PathBuf,
    verifier_artifact: PathBuf,
    verifier_sha256: String,
    app_commit: AppExecutionCommit,
    segment_memory_bytes: usize,
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "The artifact exceeds its size limit");
    Ok(bytes)
}

fn config(path: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&read_limited(path, 64 * 1024)?)?;
    for path in [
        &config.app_pk,
        &config.executable,
        &config.aggregation_pk,
        &config.halo2_pk,
        &config.verifier_artifact,
    ] {
        ensure!(
            path.is_absolute() && path.is_file(),
            "Each artifact path must name an existing absolute file path"
        );
    }
    ensure!(
        config.halo2_params_dir.is_absolute() && config.halo2_params_dir.is_dir(),
        "The Halo2 parameter path must name an existing absolute directory"
    );
    ensure!(
        config.segment_memory_bytes > 0,
        "Set a nonzero segment memory limit"
    );
    Ok(config)
}

fn verifier(config: &Config) -> Result<EvmHalo2Verifier> {
    let bytes = read_limited(&config.verifier_artifact, 256 * 1024)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == config.verifier_sha256,
        "The verifier artifact does not match the configured SHA-256 digest"
    );
    Ok(EvmHalo2Verifier {
        artifact: serde_json::from_slice(&bytes)?,
        halo2_verifier_code: String::new(),
        openvm_verifier_code: String::new(),
        openvm_verifier_interface: String::new(),
    })
}

fn sdk(config: &Config) -> Result<(Sdk, VmExe<F>)> {
    let mut app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&config.app_pk)?;
    std::sync::Arc::get_mut(&mut app_pk.app_vm_pk)
        .unwrap()
        .vm_config
        .system
        .config
        .segmentation_max_memory = config.segment_memory_bytes;
    let exe: VmExe<F> = read_object_from_file(&config.executable)?;
    let aggregation_key: AggProvingKey = read_object_from_file(&config.aggregation_pk)?;
    let derived = Sdk::builder()
        .app_pk(app_pk.clone())
        .agg_params(AggregationSystemParams {
            leaf: aggregation_key.prefix.leaf.params.clone(),
            internal: aggregation_key.prefix.internal_for_leaf.params.clone(),
        })
        .build()?;
    ensure!(
        serde_json::to_value(derived.agg_pk())? == serde_json::to_value(&aggregation_key)?,
        "The aggregation key does not match the application VM"
    );
    drop(derived);
    let sdk = Sdk::builder()
        .app_pk(app_pk)
        .agg_pk(aggregation_key)
        .halo2_params_dir(&config.halo2_params_dir)
        .build()?;
    let prover = sdk.prover(exe.clone())?;
    let baseline = prover.generate_baseline();
    let expected = AppExecutionCommit {
        app_exe_commit: baseline.app_exe_commit.into(),
        app_vm_commit: prover.app_vm_commit().into(),
    };
    ensure!(
        expected == config.app_commit,
        "The executable or VM commitment differs from the configured identity"
    );
    Ok((sdk, exe))
}

fn verify(proof: &EvmProof, config: &Config, journal: &[u8]) -> Result<()> {
    ensure!(proof.version == "v2.0", "Unsupported OpenVM proof version");
    ensure!(journal.len() == 288, "Expected nine journal words");
    ensure!(
        proof.app_commit == config.app_commit,
        "The application commitment differs"
    );
    ensure!(
        proof.user_public_values == Sha256::digest(journal).to_vec(),
        "The proof public values do not match the journal"
    );
    ensure!(
        proof.proof_data.accumulator.len() == 384 && proof.proof_data.proof.len() == 1376,
        "The proof data has an invalid length"
    );
    Sdk::verify_evm_halo2_proof(
        &verifier(config)?,
        proof.clone(),
        Some(config.app_commit.clone()),
    )?;
    Ok(())
}

fn word(value: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(value as u64).to_be_bytes());
    bytes
}

/// Encode a verified receipt as (version, proof data, nine journal words).
fn seal(proof: &EvmProof, journal: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2144);
    bytes.extend_from_slice(&word(1));
    bytes.extend_from_slice(&word(352));
    bytes.extend_from_slice(journal);
    bytes.extend_from_slice(&word(1760));
    bytes.extend_from_slice(&proof.proof_data.accumulator);
    bytes.extend_from_slice(&proof.proof_data.proof);
    bytes
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let action = args
        .next()
        .ok_or_else(|| eyre::eyre!("Expected prepare, check, prove, or verify"))?;
    if action == "prepare" {
        let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
        ensure!(
            paths.len() == 3,
            "Expected app.pk, executable, and a new output directory"
        );
        ensure!(!paths[2].exists(), "The output directory already exists");
        let app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&paths[0])?;
        let exe: VmExe<F> = read_object_from_file(&paths[1])?;
        let sdk = Sdk::builder()
            .app_pk(app_pk)
            .agg_params(AggregationSystemParams::default())
            .build()?;
        let prover = sdk.prover(exe)?;
        let baseline = prover.generate_baseline();
        let commit = AppExecutionCommit {
            app_exe_commit: baseline.app_exe_commit.into(),
            app_vm_commit: prover.app_vm_commit().into(),
        };
        fs::create_dir(&paths[2])?;
        write_object_to_file(paths[2].join("aggregation.pk"), sdk.agg_pk())?;
        let identity = serde_json::json!({ "app_commit": commit });
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(paths[2].join("identity.json"))?;
        serde_json::to_writer_pretty(file, &identity)?;
        return Ok(());
    }
    let config = config(&PathBuf::from(
        args.next()
            .ok_or_else(|| eyre::eyre!("Expected a config path"))?,
    ))?;
    verifier(&config)?;
    if action == "check" {
        ensure!(args.next().is_none(), "Unexpected arguments");
        sdk(&config)?;
        return Ok(());
    }
    ensure!(
        action == "prove" || action == "verify",
        "Expected prepare, check, prove, or verify"
    );
    let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
    ensure!(
        paths.len() == 3,
        "Expected input or proof, journal, and a new seal output path"
    );
    ensure!(!paths[2].exists(), "The seal output already exists");
    let journal = read_limited(&paths[1], 288)?;
    ensure!(journal.len() == 288, "Expected nine journal words");
    let proof: EvmProof = if action == "verify" {
        serde_json::from_slice(&read_limited(&paths[0], 256 * 1024)?)?
    } else {
        let input = read_limited(&paths[0], 512 * 1024 * 1024 - 16)?;
        let (sdk, exe) = sdk(&config)?;
        eprintln!("OpenVM: proving the application");
        let app_proof = sdk
            .app_prover(exe.clone())?
            .prove(StdIn::from_bytes(&input))?;
        drop(input);
        eprintln!("OpenVM: aggregating the application proof");
        let (stark_proof, mut metadata) = sdk.agg_prover().prove_vm(app_proof)?;
        let baseline = sdk.prover(exe.clone())?.generate_baseline();
        Sdk::verify_proof(sdk.agg_vk().as_ref().clone(), baseline, &stark_proof)?;
        let root_proof = sdk
            .evm_prover_without_halo2(exe)?
            .prove_root_from_vm_stark_proof(stark_proof, &mut metadata)?;
        eprintln!("OpenVM: generating the EVM proof");
        let halo2 = Sdk::builder()
            .app_pk(sdk.app_pk().clone())
            .agg_pk(sdk.agg_pk())
            .root_pk(sdk.root_pk())
            .halo2_params_dir(&config.halo2_params_dir)
            .halo2_pk(read_halo2_pk_from_file(&config.halo2_pk)?)
            .build()?;
        halo2.halo2_prover().prove_for_evm(&root_proof)?
    };
    verify(&proof, &config, &journal)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&paths[2])?;
    file.write_all(&seal(&proof, &journal))?;
    file.sync_all()?;
    eprintln!("OpenVM: verified the proof, application identity, and all nine journal words");
    Ok(())
}
