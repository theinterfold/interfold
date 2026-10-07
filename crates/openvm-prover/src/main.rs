// SPDX-License-Identifier: LGPL-3.0-only

//! The OpenVM worker. It proves an E3 program's guest, checks the proof against the journal the
//! host expects, and writes a seal. It runs as its own process so a failed proof cannot take the
//! service down, and so one service can choose between a CPU and a CUDA build of it.
//!
//! - `prepare <app.pk> <guest.vmexe> <new-dir>`: the aggregation key and the receipt identity.
//! - `write-config <out.json> <app.pk> <guest.vmexe> <prepared-dir> <setup-dir> <segment-bytes>`:
//!   the configuration every other action reads.
//! - `probe`: succeeds when this build can use a GPU on this machine.
//! - `check <config.json>`: loads every key and the verifier, before a service accepts work.
//! - `execute <config.json> <input> <journal>`: runs the guest without proving and checks that it
//!   reveals the journal's digest. A cheap check of a round, and of the guest against the host.
//! - `prove <config.json> <input> <journal> <new-seal>`: proves and verifies a round.
//! - `verify <config.json> <proof.json> <journal> <new-seal>`: verifies an existing proof.

use eyre::{ensure, Result};
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::{
    config::AggregationSystemParams,
    fs::{
        read_halo2_pk_from_file, read_object_from_file, write_object_to_file,
        EVM_VERIFIER_ARTIFACT_FILENAME,
    },
    halo2_params::CacheHalo2ParamsReader,
    keygen::{AggProvingKey, AppProvingKey},
    prover::Halo2Prover,
    types::{AppExecutionCommit, EvmHalo2Verifier, EvmProof},
    Sdk, StdIn, F, OPENVM_VERSION,
};
use openvm_sdk_config::SdkVmConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

/// The largest single item the guest reads. Matches `e3_openvm_types::MAX_ITEM_BYTES`.
const MAX_ITEM_BYTES: u64 = 512 * 1024 * 1024 - 16;

#[derive(Deserialize, Serialize)]
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

fn validate(config: &Config) -> Result<()> {
    for path in [
        &config.app_pk,
        &config.executable,
        &config.aggregation_pk,
        &config.halo2_pk,
        &config.verifier_artifact,
    ] {
        ensure!(
            path.is_absolute() && path.is_file(),
            "Each artifact path must name an existing absolute file path: {}",
            path.display()
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
    Ok(())
}

fn config(path: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&read_limited(path, 64 * 1024)?)?;
    validate(&config)?;
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

/// Encode a verified receipt as `abi.encode(uint8 version, bytes proofData)`.
///
/// The proof's only public value is the journal digest, which the contract recomputes from chain
/// state and passes to the Halo2 verifier, so the seal does not repeat the journal.
fn seal(proof: &EvmProof) -> Vec<u8> {
    encode_seal(
        &[
            proof.proof_data.accumulator.as_slice(),
            proof.proof_data.proof.as_slice(),
        ]
        .concat(),
    )
}

/// `abi.encode(uint8(1), proofData)` for the 1,760 bytes of Halo2 proof data. No padding is needed:
/// the length is a multiple of 32.
fn encode_seal(proof_data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96 + proof_data.len());
    bytes.extend_from_slice(&word(1));
    bytes.extend_from_slice(&word(64));
    bytes.extend_from_slice(&word(proof_data.len()));
    bytes.extend_from_slice(proof_data);
    bytes
}

/// Reads the guest's input items, which the host writes with `e3_openvm_types::write_items`: a
/// little-endian `u32` count, then each item as a little-endian `u64` length and its bytes.
///
/// Each item becomes one entry of the guest's input stream, which the guest reads with
/// `openvm::io::read_vec`. Items are converted as they are read, so the raw file is never held
/// whole.
fn read_items(reader: impl Read) -> Result<StdIn> {
    let mut reader = BufReader::new(reader);
    let mut word = [0; 4];
    reader.read_exact(&mut word)?;
    let count = u32::from_le_bytes(word);
    let mut stdin = StdIn::default();
    for _ in 0..count {
        let mut length = [0; 8];
        reader.read_exact(&mut length)?;
        let length = u64::from_le_bytes(length);
        ensure!(
            length <= MAX_ITEM_BYTES,
            "A guest input item exceeds the guest memory limit"
        );
        let mut item = vec![0; length as usize];
        reader.read_exact(&mut item)?;
        stdin.write_bytes(&item);
    }
    ensure!(
        reader.read(&mut [0; 1])? == 0,
        "Unexpected bytes after the last guest input item"
    );
    Ok(stdin)
}

/// Whether this build can use a GPU here. A CUDA build opens the current device; a CPU build
/// always fails, so a service never mistakes it for a GPU worker.
#[cfg(feature = "cuda")]
fn probe() -> Result<()> {
    let device = openvm_cuda_common::common::set_device()
        .map_err(|error| eyre::eyre!("Cannot open a CUDA device: {error}"))?;
    eprintln!("OpenVM: CUDA device {device} is available");
    Ok(())
}

#[cfg(not(feature = "cuda"))]
fn probe() -> Result<()> {
    eyre::bail!("This worker was built without CUDA")
}

/// Runs the guest over `input` without proving it and checks that it reveals the digest of the
/// journal the host expects.
fn execute(config: &Config, input: &Path, journal: &Path) -> Result<()> {
    let journal = read_limited(journal, 288)?;
    ensure!(journal.len() == 288, "Expected nine journal words");
    let app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&config.app_pk)?;
    let exe: VmExe<F> = read_object_from_file(&config.executable)?;
    let sdk = Sdk::builder()
        .app_pk(app_pk)
        .agg_params(AggregationSystemParams::default())
        .build()?;
    let (public_values, segments) =
        sdk.execute_metered(exe, read_items(fs::File::open(input)?)?)?;
    let instructions: u64 = segments.iter().map(|segment| segment.num_insns).sum();
    eprintln!(
        "OpenVM: executed {instructions} instructions in {} segments",
        segments.len()
    );
    ensure!(
        public_values == Sha256::digest(&journal).to_vec(),
        "The guest revealed a digest that differs from the host's journal"
    );
    eprintln!("OpenVM: the guest revealed the digest of the host's journal");
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path)
        .map_err(|error| eyre::eyre!("Cannot resolve {}: {error}", path.display()))
}

/// Writes the configuration for the keys `prepare` made and the artifacts `cargo openvm setup`
/// downloaded.
fn write_config(paths: &[PathBuf]) -> Result<()> {
    ensure!(
        paths.len() == 6,
        "Expected the output path, app.pk, the executable, the prepared directory, the setup \
         directory, and the segment memory limit"
    );
    let prepared = absolute(&paths[3])?;
    let setup = absolute(&paths[4])?;
    let identity: serde_json::Value =
        serde_json::from_slice(&read_limited(&prepared.join("identity.json"), 64 * 1024)?)?;
    let verifier_artifact = setup
        .join("halo2")
        .join("src")
        .join(format!("v{OPENVM_VERSION}-base"))
        .join(EVM_VERIFIER_ARTIFACT_FILENAME);
    let config = Config {
        app_pk: absolute(&paths[1])?,
        executable: absolute(&paths[2])?,
        aggregation_pk: prepared.join("aggregation.pk"),
        halo2_pk: setup.join("halo2.pk"),
        halo2_params_dir: setup.join("params"),
        verifier_sha256: hex::encode(Sha256::digest(read_limited(
            &verifier_artifact,
            256 * 1024,
        )?)),
        verifier_artifact,
        app_commit: serde_json::from_value(identity["app_commit"].clone())?,
        segment_memory_bytes: paths[5]
            .to_str()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| eyre::eyre!("The segment memory limit must be a number of bytes"))?,
    };
    validate(&config)?;

    let output = &paths[0];
    let partial = output.with_extension("json.partial");
    fs::write(&partial, serde_json::to_vec_pretty(&config)?)?;
    fs::rename(&partial, output)?;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let action = args.next().ok_or_else(|| {
        eyre::eyre!("Expected prepare, write-config, probe, check, execute, prove, or verify")
    })?;
    if action == "probe" {
        ensure!(args.next().is_none(), "Unexpected arguments");
        return probe();
    }
    if action == "write-config" {
        return write_config(&args.map(PathBuf::from).collect::<Vec<_>>());
    }
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
        // Load the Halo2 key and both KZG parameter files now. `prove` reads them only after the
        // application proof and aggregation, which can take hours.
        Halo2Prover::new(
            &CacheHalo2ParamsReader::new(&config.halo2_params_dir),
            read_halo2_pk_from_file(&config.halo2_pk)?,
        );
        eprintln!("OpenVM: the keys, parameters, verifier, and identity are consistent");
        return Ok(());
    }
    if action == "execute" {
        let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
        ensure!(paths.len() == 2, "Expected the input and the journal");
        return execute(&config, &paths[0], &paths[1]);
    }
    ensure!(
        action == "prove" || action == "verify",
        "Expected prepare, write-config, probe, check, execute, prove, or verify"
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
        let input = read_items(fs::File::open(&paths[0])?)?;
        let (sdk, exe) = sdk(&config)?;
        eprintln!("OpenVM: proving the application");
        let app_proof = sdk.app_prover(exe.clone())?.prove(input)?;
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
    file.write_all(&seal(&proof))?;
    file.sync_all()?;
    eprintln!("OpenVM: verified the proof, the application identity, and the journal digest");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes `e3_openvm_types::write_items` writes for the items `[1, 2, 3]` and `[]`. The same
    /// vector is pinned on the writer's side, so a format change on either side fails a test.
    const TWO_ITEMS: [u8; 23] = [
        2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn reads_each_item_into_its_own_stream_entry() {
        let mut expected = StdIn::default();
        expected.write_bytes(&[1, 2, 3]);
        expected.write_bytes(&[]);

        let mut stdin = read_items(TWO_ITEMS.as_slice()).unwrap();
        assert_eq!(stdin.read(), expected.read());
        assert_eq!(stdin.read(), expected.read());
        assert!(stdin.read().is_none());
    }

    #[test]
    fn refuses_truncated_and_padded_input() {
        assert!(read_items(&TWO_ITEMS[..TWO_ITEMS.len() - 1]).is_err());
        let mut padded = TWO_ITEMS.to_vec();
        padded.push(0);
        assert!(read_items(padded.as_slice()).is_err());
    }

    #[test]
    fn refuses_an_item_above_the_guest_memory_limit() {
        let mut input = 1u32.to_le_bytes().to_vec();
        input.extend_from_slice(&(MAX_ITEM_BYTES + 1).to_le_bytes());
        assert!(read_items(input.as_slice()).is_err());
    }

    /// The seal is `abi.encode(uint8(1), proofData)`: the layout `OpenVmReceiptVerifier` decodes and
    /// the 1,856 bytes `e3_openvm_host::SEAL_BYTES` expects.
    #[test]
    fn the_seal_is_the_abi_encoding_of_the_version_and_the_proof_data() {
        let proof_data = [0xab; 1760];
        let seal = encode_seal(&proof_data);

        assert_eq!(seal.len(), 1856);
        let mut head = [0u8; 96];
        head[31] = 1;
        head[63] = 0x40;
        head[94..96].copy_from_slice(&[0x06, 0xe0]);
        assert_eq!(&seal[..96], head.as_slice());
        assert_eq!(&seal[96..], proof_data.as_slice());
    }

    #[cfg(not(feature = "cuda"))]
    #[test]
    fn a_cpu_build_never_passes_the_gpu_probe() {
        assert!(probe().is_err());
    }
}
