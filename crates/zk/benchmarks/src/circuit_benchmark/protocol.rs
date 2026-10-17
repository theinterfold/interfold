// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    artifacts,
    records::{calldata_gas, Stage},
    run_logged, write_json,
};
use anyhow::{bail, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

#[derive(Clone, Debug)]
pub(crate) struct Configuration {
    pub mode: String,
    pub preset: String,
    pub committee: CiphernodesCommitteeSize,
    pub jobs: usize,
    pub bb_binary: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Outcome {
    pub measurement: Stage,
    pub error: Option<String>,
}
impl Outcome {
    fn export_failure(&mut self, error: &anyhow::Error) {
        self.measurement.success = Some(false);
        self.error = Some(format!("{error:#}"));
    }
    fn pending() -> Self {
        Self {
            measurement: Stage::unmeasured("external_command_wall"),
            error: None,
        }
    }
    fn execute(&mut self, command: &mut Command, log: &Path) -> Result<()> {
        let start = Instant::now();
        let result = run_logged(command, log);
        self.measurement.finish(start.elapsed(), &result);
        self.error = result.as_ref().err().map(|error| format!("{error:#}"));
        result
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProofArtifact {
    pub proof_hex: String,
    pub public_inputs_hex: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct FoldedArtifacts {
    pub dkg_aggregator: ProofArtifact,
    pub decryption_aggregator: ProofArtifact,
}
#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct VerifyGas {
    pub dkg: Option<u64>,
    pub user: Option<u64>,
    pub dec: Option<u64>,
}
#[derive(Debug, Serialize)]
pub(crate) struct ArtifactMeasures {
    pub proof_size_bytes: usize,
    pub public_inputs_size_bytes: usize,
    pub calldata_gas_proof: u64,
    pub calldata_gas_public_inputs: u64,
    pub calldata_gas_total: u64,
}

pub(crate) fn artifact_measures(artifact: &ProofArtifact) -> Result<ArtifactMeasures> {
    let proof = hex::decode(
        artifact
            .proof_hex
            .strip_prefix("0x")
            .unwrap_or(&artifact.proof_hex),
    )
    .context("Invalid proof hex")?;
    let public = hex::decode(
        artifact
            .public_inputs_hex
            .strip_prefix("0x")
            .unwrap_or(&artifact.public_inputs_hex),
    )
    .context("Invalid public-input hex")?;
    if proof.is_empty() || public.is_empty() || !public.len().is_multiple_of(32) {
        bail!("Folded proof and 32-byte-aligned public inputs must be nonempty");
    }
    Ok(ArtifactMeasures {
        proof_size_bytes: proof.len(),
        public_inputs_size_bytes: public.len(),
        calldata_gas_proof: calldata_gas(&proof),
        calldata_gas_public_inputs: calldata_gas(&public),
        calldata_gas_total: calldata_gas(&proof) + calldata_gas(&public),
    })
}

pub(crate) fn read_json(path: &Path) -> Result<serde_json::Value> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("Read {}", path.display()))?)
        .with_context(|| format!("Parse {}", path.display()))
}
pub(crate) fn summary(document: &serde_json::Value) -> &serde_json::Value {
    if document["integration_summary"].is_object() {
        &document["integration_summary"]
    } else {
        document
    }
}

pub(crate) fn folded(document: &serde_json::Value) -> Result<FoldedArtifacts> {
    let document = summary(document);
    let artifacts: FoldedArtifacts =
        serde_json::from_value(if document["folded_artifacts"].is_object() {
            document["folded_artifacts"].clone()
        } else {
            document.clone()
        })
        .context("Missing folded DKG/decryption artifacts")?;
    artifact_measures(&artifacts.dkg_aggregator)?;
    artifact_measures(&artifacts.decryption_aggregator)?;
    Ok(artifacts)
}

pub(crate) fn configuration(
    document: &serde_json::Value,
    mode: Option<&str>,
    committee: Option<&str>,
    jobs: usize,
) -> Result<Configuration> {
    let cfg = &summary(document)["benchmark_config"];
    let stored_mode = cfg["mode"]
        .as_str()
        .or_else(|| match cfg["bfv_preset_subdir"].as_str() {
            Some("insecure-64") => Some("insecure"),
            Some("secure-8192") => Some("secure"),
            _ => None,
        });
    if let (Some(requested), Some(stored)) = (mode, stored_mode) {
        if requested != stored {
            bail!("Replay mode {requested} disagrees with exported mode {stored}");
        }
    }
    let mode = mode
        .or(stored_mode)
        .context("Specify --mode for an export without preset metadata")?;
    let preset = match mode {
        "insecure" => "insecure-64",
        "secure" => "secure-8192",
        _ => bail!("Mode must be insecure or secure"),
    };
    if cfg["bfv_preset_subdir"]
        .as_str()
        .is_some_and(|stored| stored != preset)
    {
        bail!("Exported preset disagrees with its benchmark mode");
    }
    let stored_committee = if let Some(name) = cfg["committee"].as_str() {
        Some(name.parse::<CiphernodesCommitteeSize>()?)
    } else {
        ["minimum", "micro", "small"]
            .into_iter()
            .map(|name| name.parse::<CiphernodesCommitteeSize>().unwrap())
            .find(|committee| {
                let values = committee.values();
                cfg["committee_n"].as_u64() == Some(values.n as u64)
                    && cfg["committee_t"].as_u64() == Some(values.threshold as u64)
                    && cfg["committee_h"].as_u64() == Some(values.h as u64)
            })
    };
    let requested = committee
        .map(str::parse::<CiphernodesCommitteeSize>)
        .transpose()?;
    if stored_committee.is_none()
        && ["committee_n", "committee_t", "committee_h"]
            .iter()
            .any(|key| !cfg[*key].is_null())
    {
        bail!("Exported committee counts do not identify a supported committee");
    }
    if let (Some(requested), Some(stored)) = (requested, stored_committee) {
        if requested != stored {
            bail!("Replay committee disagrees with exported committee");
        }
    }
    if let Some(stored) = stored_committee {
        let values = stored.values();
        for (key, expected) in [
            ("committee_n", values.n),
            ("committee_t", values.threshold),
            ("committee_h", values.h),
        ] {
            if !cfg[key].is_null() && cfg[key].as_u64() != Some(expected as u64) {
                bail!("Exported {key} disagrees with its named committee");
            }
        }
    }
    let committee = requested
        .or(stored_committee)
        .context("Specify --committee for an export without committee metadata")?;
    Ok(Configuration {
        mode: mode.into(),
        preset: preset.into(),
        committee,
        jobs,
        bb_binary: None,
    })
}

pub(crate) fn validate_active(root: &Path, cfg: &Configuration) -> Result<serde_json::Value> {
    let committee = cfg.committee.to_string();
    let policy = e3_zk_build::build_pairs(root)?;
    if !policy
        .iter()
        .any(|pair| pair[0] == cfg.preset && pair[1] == committee)
    {
        bail!("Unsupported artifact pair: {}/{committee}", cfg.preset);
    }
    let active = read_json(&root.join("circuits/bin/.active-preset.json"))?;
    if active["preset"] != cfg.preset || active["committee"] != committee {
        bail!("Protocol/gas requires active {}/{committee}; select its existing artifacts with pnpm build:circuits --preset {} --committee {committee} --hydrate-bin-only", cfg.preset, cfg.preset);
    }
    let dist = root.join("dist/circuits");
    let stamp = artifacts::validate_pair(&dist, &cfg.preset, &committee)?;
    let manifest = read_json(&dist.join("checksums.json"))?;
    if manifest["algorithm"] != "sha256" {
        bail!("Artifact manifest must use sha256");
    }
    let required: Vec<String> = serde_json::from_slice(&fs::read(
        root.join("crates/zk/prover/required-artifacts.json"),
    )?)?;
    for artifact in required {
        let relative = format!("{}/{committee}/{artifact}", cfg.preset);
        let expected = manifest["files"][&relative]
            .as_str()
            .with_context(|| format!("Manifest does not cover {relative}"))?;
        if artifacts::digest(&dist.join(&relative))? != expected {
            bail!("Artifact checksum mismatch: {relative}");
        }
    }
    Ok(stamp)
}

pub(crate) fn integration_command(
    root: &Path,
    output: &Path,
    cfg: &Configuration,
) -> Result<Command> {
    let bb = cfg
        .bb_binary
        .as_deref()
        .context("Integration requires the runner's validated BB selection")?;
    let mut command = Command::new("cargo");
    command
        .args([
            "test",
            "--locked",
            "--release",
            "-p",
            "e3-tests",
            "--test",
            "integration",
            "test_trbfv_actor",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .env("BENCHMARK_MODE", &cfg.mode)
        .env("E3_CUSTOM_BB", bb)
        .env("CIPHERNODE_SKIP_PROOF_AGGREGATION", "false")
        .env("BENCHMARK_MULTITHREAD_JOBS", cfg.jobs.to_string())
        .env(
            "BENCHMARK_FOLDED_OUTPUT",
            output.join("folded_artifacts.json"),
        )
        .env(
            "BENCHMARK_SUMMARY_OUTPUT",
            output.join("integration_summary.json"),
        );
    Ok(command)
}

pub(crate) fn evm_command(
    root: &Path,
    output: &Path,
    folded_path: &Path,
    cfg: &Configuration,
) -> Command {
    let mut command = Command::new("pnpm");
    command
        .args([
            "hardhat",
            "run",
            "scripts/benchmarkGasFromRaw.ts",
            "--network",
            "hardhat",
        ])
        .current_dir(root.join("packages/interfold-contracts"))
        .env("BENCHMARK_RAW_DIR", output.join("raw"))
        .env("BENCHMARK_GAS_OUTPUT", output.join("evm_verify_gas.json"))
        .env("BENCHMARK_FOLDED_JSON", folded_path)
        .env("BENCHMARK_PRESET", &cfg.preset)
        .env("BENCHMARK_COMMITTEE", cfg.committee.to_string());
    command
}

#[derive(Serialize)]
struct Results {
    schema_version: u32,
    artifact_stamp: serde_json::Value,
    source: &'static str,
    verify_gas: VerifyGas,
    user_preset: Option<String>,
    artifacts: BTreeMap<String, ArtifactMeasures>,
    integration: Outcome,
    crisp_setup: Outcome,
    crisp: Outcome,
    replay: Outcome,
    error: Option<String>,
    complete: bool,
}

pub(crate) fn collect(
    root: &Path,
    output: &Path,
    cfg: &Configuration,
    gas: bool,
    existing: Option<&serde_json::Value>,
    user_gas: Option<&serde_json::Value>,
) -> Result<()> {
    let mut results = Results {
        schema_version: 2,
        artifact_stamp: serde_json::Value::Null,
        source: if existing.is_some() {
            "saved_folded_proof_evm_replay"
        } else {
            "integration_and_evm_measurements"
        },
        verify_gas: VerifyGas::default(),
        user_preset: None,
        artifacts: BTreeMap::new(),
        integration: Outcome::pending(),
        crisp_setup: Outcome::pending(),
        crisp: Outcome::pending(),
        replay: Outcome::pending(),
        error: None,
        complete: false,
    };
    let result = (|| -> Result<()> {
        results.artifact_stamp = validate_active(root, cfg)?;
        if gas && existing.is_none() {
            results.crisp_setup.execute(
                Command::new("pnpm")
                    .arg("bench:crisp:prepare")
                    .current_dir(root),
                &output.join("crisp-setup.log"),
            )?;
            let restored = validate_active(root, cfg);
            if let Err(error) = &restored {
                results.crisp_setup.export_failure(error);
            }
            results.artifact_stamp = restored?;
        }
        let document = if let Some(document) = existing {
            document.clone()
        } else {
            results.integration.execute(
                &mut integration_command(root, output, cfg)?,
                &output.join("integration.log"),
            )?;
            let export = (|| -> Result<serde_json::Value> {
                let document = read_json(&output.join("integration_summary.json"))?;
                configuration(
                    &document,
                    Some(&cfg.mode),
                    Some(&cfg.committee.to_string()),
                    cfg.jobs,
                )?;
                if summary(&document)["benchmark_config"]["proof_aggregation_enabled"] != true {
                    bail!("Integration export has proof aggregation disabled");
                }
                folded(&document)?;
                Ok(document)
            })();
            if let Err(error) = &export {
                results.integration.export_failure(error);
            }
            export?
        };
        let artifacts = folded(&document)?;
        results
            .artifacts
            .insert("dkg".into(), artifact_measures(&artifacts.dkg_aggregator)?);
        results.artifacts.insert(
            "dec".into(),
            artifact_measures(&artifacts.decryption_aggregator)?,
        );
        if existing.is_some() {
            write_json(&output.join("integration_summary.json"), summary(&document))?;
        }
        let folded_path = output.join("folded_artifacts.json");
        write_json(
            &folded_path,
            &serde_json::json!({ "preset": cfg.preset, "committee": cfg.committee.to_string(), "folded_artifacts": artifacts }),
        )?;
        if !gas {
            results.complete = true;
            return Ok(());
        }
        let mut failures = Vec::new();
        if existing.is_none() {
            let mut command = Command::new("pnpm");
            command
                .args([
                    "test:ballots:program",
                    "--grep",
                    "should verify the proof correctly with the crisp verifier",
                ])
                .current_dir(root.join("examples/CRISP/packages/crisp-contracts"))
                .env(
                    "BENCHMARK_CRISP_GAS_OUTPUT",
                    output.join("crisp_user_gas.json"),
                );
            match results
                .crisp
                .execute(&mut command, &output.join("crisp.log"))
            {
                Ok(()) => match read_json(&output.join("crisp_user_gas.json"))
                    .and_then(|doc| apply_user_gas(&mut results, &doc))
                {
                    Ok(()) => {}
                    Err(error) => {
                        results.crisp.export_failure(&error);
                        failures.push(format!("CRISP export: {error:#}"));
                    }
                },
                Err(error) => failures.push(format!("CRISP gas: {error:#}")),
            }
        } else if let Some(document) = user_gas {
            apply_user_gas(&mut results, document)?;
        }
        results.replay.execute(
            &mut evm_command(root, output, &folded_path, cfg),
            &output.join("evm-replay.log"),
        )?;
        let export = (|| -> Result<VerifyGas> {
            let evm = read_json(&output.join("evm_verify_gas.json"))?;
            if evm["bfv_preset"] != cfg.preset || evm["bfv_committee"] != cfg.committee.to_string()
            {
                bail!("EVM replay returned another artifact configuration");
            }
            let gas: VerifyGas = serde_json::from_value(evm["verify_gas"].clone())?;
            if gas.dkg.is_none() || gas.dec.is_none() {
                bail!("EVM replay omitted DKG or decryption verifier gas");
            }
            Ok(gas)
        })();
        if let Err(error) = &export {
            results.replay.export_failure(error);
        }
        let evm = export?;
        results.verify_gas.dkg = evm.dkg;
        results.verify_gas.dec = evm.dec;
        results.complete =
            failures.is_empty() && (existing.is_some() || results.verify_gas.user.is_some());
        if !failures.is_empty() {
            bail!("{}", failures.join("\n"));
        }
        Ok(())
    })();
    if let Err(error) = &result {
        if results.integration.error.is_none()
            && results.crisp_setup.error.is_none()
            && results.replay.error.is_none()
            && results.crisp.error.is_none()
        {
            results.replay.error = Some(format!("{error:#}"));
        }
        results.error = Some(format!("{error:#}"));
        results.complete = false;
    }
    write_json(&output.join("protocol_results.json"), &results)?;
    write_json(&output.join("crisp_verify_gas.json"), &results)?;
    result
}

fn apply_user_gas(results: &mut Results, document: &serde_json::Value) -> Result<()> {
    results.verify_gas.user = document["verify_gas"]["user"].as_u64();
    if results.verify_gas.user.is_none() {
        bail!("CRISP export omitted measured user verifier gas");
    }
    results.user_preset = document["preset"]
        .as_str()
        .or_else(|| document["user_preset"].as_str())
        .map(str::to_owned);
    if document["artifact"].is_object() {
        let artifact: ProofArtifact = serde_json::from_value(document["artifact"].clone())?;
        results
            .artifacts
            .insert("user".into(), artifact_measures(&artifact)?);
    }
    Ok(())
}

pub(crate) fn replay(
    root: &Path,
    output: &Path,
    input: &Path,
    mode: Option<&str>,
    committee: Option<&str>,
    gas_path: Option<&Path>,
) -> Result<()> {
    let result = (|| -> Result<()> {
        let path: PathBuf = if input.is_dir() {
            input.join("integration_summary.json")
        } else {
            input.to_path_buf()
        };
        let document = read_json(&path)?;
        let cfg = configuration(&document, mode, committee, 1)?;
        folded(&document)?;
        let user_gas = gas_path.map(read_json).transpose()?;
        collect(root, output, &cfg, true, Some(&document), user_gas.as_ref())
    })();
    if let Err(error) = &result {
        if !output.join("protocol_results.json").exists() {
            let document = serde_json::json!({"schema_version":2,"complete":false,"source":"saved_folded_proof_evm_replay","verify_gas":{"dkg":null,"user":null,"dec":null},"replay":{"measurement":{"success":false,"time_seconds":null,"metric":"external_command_wall"},"error":format!("{error:#}")}});
            write_json(&output.join("protocol_results.json"), &document)?;
            write_json(&output.join("crisp_verify_gas.json"), &document)?;
        }
    }
    result
}
