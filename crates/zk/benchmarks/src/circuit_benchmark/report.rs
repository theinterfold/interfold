// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    protocol::{self, ProofArtifact},
    records::Record,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, path::Path};

#[derive(Default, Deserialize)]
struct HistoricalStage {
    time_seconds: Option<f64>,
    success: Option<bool>,
    circuit_size_bytes: Option<u64>,
    witness_size_bytes: Option<u64>,
    vk_size_bytes: Option<u64>,
    proof_size_bytes: Option<u64>,
    public_inputs_size_bytes: Option<u64>,
    calldata_gas_total: Option<u64>,
}
#[derive(Deserialize)]
struct Historical {
    circuit_name: String,
    circuit_path: String,
    #[serde(default)]
    compilation: HistoricalStage,
    #[serde(default)]
    execution: HistoricalStage,
    #[serde(default)]
    vk_generation: HistoricalStage,
    #[serde(default)]
    proof_generation: HistoricalStage,
    #[serde(default)]
    verification: HistoricalStage,
    #[serde(default)]
    gates: Value,
    #[serde(default)]
    system_info: Value,
    #[serde(default)]
    error: String,
}

#[derive(Debug)]
pub(crate) struct Leaf {
    pub path: String,
    name: String,
    origin: String,
    preparation: Option<f64>,
    compilation: Option<f64>,
    execution: Option<f64>,
    vk: Option<f64>,
    pub prove: Option<f64>,
    verify: Option<f64>,
    gates: Option<u64>,
    circuit_bytes: Option<u64>,
    witness_bytes: Option<u64>,
    vk_bytes: Option<u64>,
    pub proof_bytes: Option<u64>,
    public_bytes: Option<u64>,
    calldata: Option<u64>,
    status: &'static str,
    error: Option<String>,
    artifact: Value,
    system: Value,
}

fn measured(stage: &HistoricalStage) -> Option<f64> {
    if stage.success == Some(false) {
        None
    } else {
        stage.time_seconds
    }
}
pub(crate) fn parse_leaf(document: Value) -> Result<Leaf> {
    let version = document["schema_version"].as_u64().unwrap_or(1);
    let mut leaf = match version {
        2 => {
            let row: Record =
                serde_json::from_value(document).context("Invalid schema 2 leaf record")?;
            let status = if row.error.is_some()
                || [
                    &row.preparation,
                    &row.execution,
                    &row.proof_generation,
                    &row.verification,
                ]
                .iter()
                .any(|stage| stage.success == Some(false))
            {
                "failed"
            } else if row.verification.success == Some(true) {
                "verified"
            } else if row.execution.success == Some(true) {
                "witness only"
            } else {
                "incomplete"
            };
            Leaf {
                path: row.circuit_path,
                name: row.circuit_name,
                origin: row.metric_kind,
                preparation: row.preparation.time_seconds,
                compilation: row.compilation.time_seconds,
                execution: row.execution.time_seconds,
                vk: row.vk_generation.time_seconds,
                prove: row.proof_generation.time_seconds,
                verify: row.verification.time_seconds,
                gates: row.gates.total_gates,
                circuit_bytes: row.circuit_size_bytes,
                witness_bytes: row.witness_size_bytes,
                vk_bytes: row.vk_size_bytes,
                proof_bytes: row.proof_size_bytes,
                public_bytes: row.public_inputs_size_bytes,
                calldata: row.calldata_gas_total,
                status,
                error: row.error,
                artifact: serde_json::to_value(row.artifact)?,
                system: Value::Null,
            }
        }
        1 => {
            let row: Historical =
                serde_json::from_value(document).context("Invalid historical leaf record")?;
            let status = if !row.error.trim().is_empty()
                || row.execution.success == Some(false)
                || row.proof_generation.success == Some(false)
                || row.verification.success == Some(false)
            {
                "failed"
            } else if row.verification.success == Some(true) {
                "verified"
            } else {
                "incomplete"
            };
            let proof_ok = row.proof_generation.success != Some(false);
            let verify_ok = row.verification.success != Some(false);
            Leaf {
                path: row.circuit_path,
                name: row.circuit_name,
                origin: "isolated_nargo".into(),
                preparation: None,
                compilation: measured(&row.compilation),
                execution: measured(&row.execution),
                vk: measured(&row.vk_generation),
                prove: measured(&row.proof_generation),
                verify: measured(&row.verification),
                gates: row.gates["total_gates"]
                    .as_u64()
                    .filter(|value| *value != 0),
                circuit_bytes: row
                    .compilation
                    .circuit_size_bytes
                    .filter(|value| *value != 0),
                witness_bytes: row.execution.witness_size_bytes.filter(|value| *value != 0),
                vk_bytes: row.vk_generation.vk_size_bytes.filter(|value| *value != 0),
                proof_bytes: proof_ok
                    .then_some(row.proof_generation.proof_size_bytes)
                    .flatten()
                    .filter(|value| *value != 0),
                public_bytes: verify_ok
                    .then_some(row.verification.public_inputs_size_bytes)
                    .flatten()
                    .filter(|value| *value != 0),
                calldata: verify_ok
                    .then_some(row.verification.calldata_gas_total)
                    .flatten()
                    .filter(|value| *value != 0),
                status,
                error: (!row.error.trim().is_empty()).then_some(row.error),
                artifact: Value::Null,
                system: row.system_info,
            }
        }
        _ => bail!("Unsupported leaf record schema: {version}"),
    };
    leaf.path = canonical_path(&leaf.path);
    for value in [
        leaf.preparation,
        leaf.compilation,
        leaf.execution,
        leaf.vk,
        leaf.prove,
        leaf.verify,
    ]
    .into_iter()
    .flatten()
    {
        if !value.is_finite() || value < 0.0 {
            bail!("Invalid phase duration for {}", leaf.path);
        }
    }
    Ok(leaf)
}

fn canonical_path(path: &str) -> String {
    let path = path
        .split_once("/circuits/bin/")
        .map(|(_, suffix)| suffix)
        .unwrap_or(path);
    path.trim_start_matches("circuits/")
        .trim_start_matches("bin/")
        .trim_start_matches("insecure/")
        .trim_start_matches("secure/")
        .trim_end_matches('/')
        .to_string()
}
fn text(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}
fn seconds(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.6}"))
        .unwrap_or_else(|| "N/A".into())
}
fn number(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "N/A".into())
}
fn scalar(value: &Value) -> String {
    if value.is_null() {
        "N/A".into()
    } else if let Some(value) = value.as_str() {
        text(value)
    } else {
        text(&value.to_string())
    }
}
fn optional_json(path: &Path) -> Result<Value> {
    if path.is_file() {
        protocol::read_json(path)
    } else {
        Ok(Value::Null)
    }
}

pub(crate) struct Data {
    pub leaves: Vec<Leaf>,
    pub metadata: Value,
    pub integration: Value,
    pub gas: Value,
    pub files: Vec<String>,
}
pub(crate) fn load(input: &Path, summary: Option<&Path>, gas: Option<&Path>) -> Result<Data> {
    let raw = if input.join("raw").is_dir() {
        input.join("raw")
    } else {
        input.to_path_buf()
    };
    let base = if input.join("raw").is_dir()
        || input.join("benchmark_run_meta.json").exists()
        || input.join("integration_summary.json").exists()
    {
        input
    } else {
        input.parent().context("Raw directory has no parent")?
    };
    let mut leaves = Vec::new();
    let mut files = Vec::new();
    if raw.is_dir() {
        let mut paths = fs::read_dir(&raw)?.collect::<std::io::Result<Vec<_>>>()?;
        paths.sort_by_key(|entry| entry.file_name());
        for path in paths {
            if path
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
                && (raw != input || !path.file_name().to_string_lossy().ends_with("summary.json"))
            {
                let document = protocol::read_json(&path.path())?;
                if document.get("circuit_path").is_none() {
                    continue;
                }
                leaves.push(
                    parse_leaf(document)
                        .with_context(|| format!("Leaf record {}", path.path().display()))?,
                );
                files.push(path.path().display().to_string());
            }
        }
    }
    let metadata = optional_json(&base.join("benchmark_run_meta.json"))?;
    let gas = if let Some(path) = gas {
        protocol::read_json(path)?
    } else {
        optional_json(&base.join("crisp_verify_gas.json"))?
    };
    let mut integration = if let Some(path) = summary {
        protocol::read_json(path)?
    } else {
        optional_json(&base.join("integration_summary.json"))?
    };
    if integration.is_null() && gas["integration_summary"].is_object() {
        integration = gas["integration_summary"].clone();
    }
    integration = protocol::summary(&integration).clone();
    if leaves.is_empty() && metadata.is_null() && integration.is_null() && gas.is_null() {
        bail!("No saved benchmark records in {}", input.display());
    }
    Ok(Data {
        leaves,
        metadata,
        integration,
        gas,
        files,
    })
}

fn settings(out: &mut String, title: &str, values: &Value) {
    if let Some(values) = values.as_object() {
        *out += &format!("\n### {title}\n\n| Setting | Saved value |\n|---|---|\n");
        for (key, value) in values {
            if !value.is_array() && !value.is_object() {
                *out += &format!("| {} | {} |\n", text(key), scalar(value));
            }
        }
    }
}

pub(crate) fn render(data: &Data) -> Result<String> {
    let mut out = String::from("# Circuit and protocol benchmarks\n\n## Run configuration\n");
    settings(&mut out, "Saved benchmark settings", &data.metadata);
    settings(
        &mut out,
        "Observed integration configuration",
        &data.integration["benchmark_config"],
    );
    settings(&mut out, "Thread pool", &data.integration["multithread"]);
    settings(
        &mut out,
        "Artifact source stamp",
        &data.metadata["artifact_stamp"],
    );
    if let Some(first) = data.leaves.iter().find(|leaf| !leaf.system.is_null()) {
        settings(&mut out, "Historical host and tools", &first.system);
    }
    out += "\n## Measurement methodology\n\n| Metric | Meaning |\n|---|---|\n| production_input_preparation_wall | Production computation and ABI input conversion; sample/config setup excluded |\n| production_abi_input_projection_wall | Per-leg ABI projection after shared UDE preparation |\n| production_encryption_and_preparation_wall | One UDE encryption and prepared witness, shared by both legs |\n| production_noir_execution_wall | ABI encoding, ACVM execution, and witness serialization in Rust |\n| production_bb_adapter_wall | Production BB adapter, including process startup and file I/O |\n| external_bb_prove_wall / external_bb_verify_wall | BB process wall time for development circuits without CircuitName |\n| isolated_nargo | Historical isolated shell/Nargo measurements, not in-process Rust execution |\n| wall_clock | Integration event/phase span in the in-process test harness, not WAN latency |\n| tracked_job_wall | Shared Rayon job wall time; overlapping sums are not end-to-end latency |\n\nSample generation, configuration construction, and artifact loading are outside leaf phase timers. Missing measurements are N/A, not false zero. Legacy zero compilation durations can represent reused artifacts. Compare host, build profile, preset, committee, variant, source and tool identities before comparing runs.\n";
    out += "\n## Leaf phases\n\n| Circuit | Prove metric | Preparation (s) | Compile (s) | Noir/execute (s) | VK generation (s) | Prove (s) | Verify (s) | Status |\n|---|---|---:|---:|---:|---:|---:|---:|---|\n";
    for leaf in &data.leaves {
        out += &format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            text(&leaf.path),
            text(&leaf.origin),
            seconds(leaf.preparation),
            seconds(leaf.compilation),
            seconds(leaf.execution),
            seconds(leaf.vk),
            seconds(leaf.prove),
            seconds(leaf.verify),
            leaf.status
        );
        if let Some(error) = &leaf.error {
            out += &format!("\n{}: {}\n\n", text(&leaf.name), text(error));
        }
    }
    if !data.metadata["compilation"].is_null() {
        settings(
            &mut out,
            "Canonical pair build (measured once)",
            &data.metadata["compilation"],
        );
    }
    if let Some(shared) = data.metadata["shared_preparations"].as_array() {
        out += "\n### Shared preparation (count once)\n\n| Group | Metric | Duration (s) | Success |\n|---|---|---:|---|\n";
        for preparation in shared {
            out += &format!(
                "| {} | {} | {} | {} |\n",
                scalar(&preparation["id"]),
                scalar(&preparation["preparation"]["metric"]),
                seconds(preparation["preparation"]["time_seconds"].as_f64()),
                scalar(&preparation["preparation"]["success"])
            );
        }
    }
    out += "\n## Leaf constraints and sizes\n\n| Circuit | Gates | Circuit bytes | Witness bytes | VK bytes | Proof bytes | Public-input bytes | Calldata gas |\n|---|---:|---:|---:|---:|---:|---:|---:|\n";
    for leaf in &data.leaves {
        out += &format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            text(&leaf.path),
            number(leaf.gates),
            number(leaf.circuit_bytes),
            number(leaf.witness_bytes),
            number(leaf.vk_bytes),
            number(leaf.proof_bytes),
            number(leaf.public_bytes),
            number(leaf.calldata)
        );
    }
    ude_totals(&mut out, &data.leaves);
    artifact_table(&mut out, data)?;
    phase_table(&mut out, data);
    integration_tables(&mut out, &data.integration);
    out += "\n## Artifact provenance\n\n| Circuit | Compiled SHA-256 | VK SHA-256 | Artifact source |\n|---|---|---|---|\n";
    for leaf in &data.leaves {
        out += &format!(
            "| {} | {} | {} | {} |\n",
            text(&leaf.path),
            scalar(&leaf.artifact["compiled_sha256"]),
            scalar(&leaf.artifact["vk_sha256"]),
            scalar(&leaf.artifact["source_stamp"]["sourceHash"])
        );
    }
    out += "\n## Saved raw records\n\n";
    for file in &data.files {
        out += &format!("- `{}`\n", text(file));
    }
    if !data.gas.is_null() {
        settings(&mut out, "Gas source", &data.gas);
    }
    Ok(out)
}

fn leaf<'a>(leaves: &'a [Leaf], path: &str) -> Option<&'a Leaf> {
    leaves.iter().find(|leaf| leaf.path == path)
}
fn ude_totals(out: &mut String, leaves: &[Leaf]) {
    if let (Some(ct0), Some(ct1)) = (
        leaf(leaves, "threshold/user_data_encryption_ct0"),
        leaf(leaves, "threshold/user_data_encryption_ct1"),
    ) {
        let sum = |a: Option<u64>, b: Option<u64>| a.zip(b).map(|(a, b)| a + b);
        *out += &format!("\n### UDE two-leg totals\n\nGates: {}; proof bytes: {}; public-input bytes: {}; prove time: {} s; verify time: {} s. Shared encryption/preparation is counted once, not in either proof sum.\n", number(sum(ct0.gates, ct1.gates)), number(sum(ct0.proof_bytes, ct1.proof_bytes)), number(sum(ct0.public_bytes, ct1.public_bytes)), seconds(ct0.prove.zip(ct1.prove).map(|(a,b)| a+b)), seconds(ct0.verify.zip(ct1.verify).map(|(a,b)| a+b)));
    }
}

fn artifact_table(out: &mut String, data: &Data) -> Result<()> {
    *out += "\n## On-chain artifacts\n\n| Artifact | Proof bytes | Public-input bytes | Verifier gas | Calldata gas | Total gas |\n|---|---:|---:|---:|---:|---:|\n";
    let mut missing = 0;
    for (label, key, folded_key) in [
        ("Π_DKG", "dkg", "dkg_aggregator"),
        ("Π_user", "user", ""),
        ("Π_dec", "dec", "decryption_aggregator"),
    ] {
        let verify = data.gas["verify_gas"][key].as_u64();
        let mut sizes = (
            data.gas["artifacts"][key]["proof_size_bytes"]
                .as_u64()
                .or_else(|| data.gas["artifact_sizes_bytes"][key]["proof"].as_u64()),
            data.gas["artifacts"][key]["public_inputs_size_bytes"]
                .as_u64()
                .or_else(|| data.gas["artifact_sizes_bytes"][key]["public_inputs"].as_u64()),
            data.gas["artifacts"][key]["calldata_gas_total"]
                .as_u64()
                .or_else(|| data.gas["calldata_gas"][key]["total"].as_u64()),
        );
        let artifact = &data.integration["folded_artifacts"][folded_key];
        if !folded_key.is_empty() && artifact.is_object() {
            let artifact: ProofArtifact = serde_json::from_value(artifact.clone())?;
            let measured = protocol::artifact_measures(&artifact)?;
            sizes = (
                Some(measured.proof_size_bytes as u64),
                Some(measured.public_inputs_size_bytes as u64),
                Some(measured.calldata_gas_total),
            );
        } else if key == "user" && sizes.0.is_none() {
            // Only the actual historical wrapper is an on-chain artifact. A ct0 leaf is not one.
            if let Some(wrapper) = leaf(&data.leaves, "threshold/user_data_encryption") {
                sizes = (wrapper.proof_bytes, wrapper.public_bytes, wrapper.calldata);
            }
        }
        let total = verify.zip(sizes.2).map(|(a, b)| a + b);
        *out += &format!(
            "| {label} | {} | {} | {} | {} | {} |\n",
            number(sizes.0),
            number(sizes.1),
            number(verify),
            number(sizes.2),
            number(total)
        );
        if verify.is_none() {
            missing += 1;
        }
    }
    *out += &format!(
        "\nVerifier gas: {}. Calldata-only values do not establish measured verifier gas.\n",
        if missing == 0
            && data.gas["complete"] != false
            && !data.gas["test_exit_code"]
                .as_object()
                .is_some_and(|codes| codes
                    .values()
                    .any(|code| code.as_i64().is_some_and(|code| code != 0)))
        {
            "complete".to_string()
        } else {
            format!("incomplete ({missing} missing)")
        }
    );
    if !data.gas["user_preset"].is_null() {
        *out += &format!("\nΠ_user gas uses the exported CRISP preset `{}`, independently of the DKG/decryption preset.\n", scalar(&data.gas["user_preset"]));
    }
    for key in ["integration", "crisp_setup", "crisp", "replay"] {
        if !data.gas[key]["error"].is_null() {
            *out += &format!("\n{key} failed: {}\n", scalar(&data.gas[key]["error"]));
        }
    }
    if !data.gas["error"].is_null() {
        *out += &format!(
            "\nProtocol/gas incomplete: {}\n",
            scalar(&data.gas["error"])
        );
    }
    Ok(())
}

fn timing(integration: &Value, label: &str) -> Option<f64> {
    integration["phase_timings"]
        .as_array()
        .or_else(|| integration["timings_seconds"].as_array())?
        .iter()
        .find(|row| row["label"] == label)?["seconds"]
        .as_f64()
}
fn phase_table(out: &mut String, data: &Data) {
    *out += "\n## Role / phase / activity\n\n| Role | Phase | Activity | Metric | Duration (s) | Proof bytes | Proof + public-input bytes |\n|---|---|---|---|---:|---:|---:|\n";
    for (role, phase, activity, label, key) in [
        (
            "Each ciphernode",
            "P1",
            "DKG participation in the test harness",
            "ThresholdShares -> PublicKeyAggregated",
            "",
        ),
        (
            "Aggregator",
            "P2",
            "C5 and DKG aggregation",
            "Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall)",
            "dkg",
        ),
        (
            "Aggregator",
            "P4",
            "Publish ciphertext through plaintext aggregation",
            "Ciphertext published -> PlaintextAggregated",
            "dec",
        ),
        (
            "Aggregator",
            "P4",
            "C7 and fold after pending aggregation",
            "Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)",
            "dec",
        ),
    ] {
        let proof = data.gas["artifacts"][key]["proof_size_bytes"]
            .as_u64()
            .or_else(|| data.gas["artifact_sizes_bytes"][key]["proof"].as_u64());
        let public = data.gas["artifacts"][key]["public_inputs_size_bytes"]
            .as_u64()
            .or_else(|| data.gas["artifact_sizes_bytes"][key]["public_inputs"].as_u64());
        *out += &format!(
            "| {role} | {phase} | {activity} | wall_clock | {} | {} | {} |\n",
            seconds(timing(&data.integration, label)),
            number(proof),
            number(proof.zip(public).map(|(a, b)| a + b))
        );
    }
    if let (Some(ct0), Some(ct1)) = (
        leaf(&data.leaves, "threshold/user_data_encryption_ct0"),
        leaf(&data.leaves, "threshold/user_data_encryption_ct1"),
    ) {
        let metric = if ct0.origin == ct1.origin {
            ct0.origin.as_str()
        } else {
            "mixed (see leaf rows)"
        };
        let proof = ct0.proof_bytes.zip(ct1.proof_bytes).map(|(a, b)| a + b);
        let public = ct0.public_bytes.zip(ct1.public_bytes).map(|(a, b)| a + b);
        *out += &format!(
            "| User | P3 | Two UDE leaf proofs, shared setup excluded | {} | {} | {} | {} |\n",
            text(metric),
            seconds(ct0.prove.zip(ct1.prove).map(|(a, b)| a + b)),
            number(proof),
            number(proof.zip(public).map(|(a, b)| a + b))
        );
    }
    if let Some(c6) = leaf(&data.leaves, "threshold/share_decryption") {
        *out += &format!("| Each ciphernode | P4 | C6 leaf proof, not a deployment estimate | {} | {} | {} | {} |\n", text(&c6.origin), seconds(c6.prove), number(c6.proof_bytes), number(c6.proof_bytes.zip(c6.public_bytes).map(|(a,b)| a+b)));
    }
}

fn integration_tables(out: &mut String, integration: &Value) {
    if !integration.is_object() {
        *out += "\nIntegration timing: incomplete (no saved summary).\n";
        return;
    }
    *out += "\n## Integration phase timings\n\n| Phase | Metric | Duration (s) |\n|---|---|---:|\n";
    if let Some(phases) = integration["phase_timings"]
        .as_array()
        .or_else(|| integration["timings_seconds"].as_array())
    {
        for phase in phases {
            *out += &format!(
                "| {} | {} | {} |\n",
                scalar(&phase["label"]),
                phase["metric"]
                    .as_str()
                    .map(text)
                    .unwrap_or_else(|| "wall_clock".into()),
                seconds(phase["seconds"].as_f64())
            );
        }
    }
    let jobs = integration["operation_timings"].as_array();
    for (title, filter) in [
        ("Tracked jobs", 0),
        ("NodeDkgFold substeps", 1),
        ("Aggregation jobs", 2),
    ] {
        *out += &format!("\n### {title} (`tracked_job_wall`)\n\n| Job | Average (s) | Runs | Total (s) |\n|---|---:|---:|---:|\n");
        let mut total = None;
        for job in jobs.into_iter().flatten() {
            let name = job["name"].as_str().unwrap_or("unknown");
            let include = match filter {
                1 => name.starts_with("NodeDkgFold/"),
                2 => [
                    "ZkNodeDkgFold",
                    "ZkDkgAggregation",
                    "ZkDecryptionAggregation",
                    "ZkPkAggregation",
                    "ZkDecryptedSharesAggregation",
                    "ZkNodesFold",
                ]
                .contains(&name),
                _ => true,
            };
            if include {
                *out += &format!(
                    "| {} | {} | {} | {} |\n",
                    text(name),
                    seconds(job["avg_seconds"].as_f64()),
                    number(job["runs"].as_u64()),
                    seconds(job["total_seconds"].as_f64())
                );
                if let Some(value) = job["total_seconds"].as_f64() {
                    total = Some(total.unwrap_or(0.0) + value);
                }
            }
        }
        *out += &format!("\nTracked sum: {} s. Jobs can overlap; this sum is not end-to-end wall-clock latency.\n", seconds(total));
    }
    settings(
        out,
        "Harness limits",
        &json!({ "network_model": integration["benchmark_config"]["network_model"], "testmode_harness": integration["benchmark_config"]["testmode_harness"], "nodes_spawned": integration["benchmark_config"]["nodes_spawned"], "proof_aggregation_enabled": integration["benchmark_config"]["proof_aggregation_enabled"], "dkg_fold_attestation_verifier": integration["dkg_fold_attestation_verifier"] }),
    );
}

pub(crate) fn command(
    input: &Path,
    output: Option<&Path>,
    summary: Option<&Path>,
    gas: Option<&Path>,
) -> Result<()> {
    let data = load(input, summary, gas)?;
    let report = render(&data)?;
    if let Some(path) = output {
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("Create new report {}", path.display()))?
            .write_all(report.as_bytes())?;
    } else {
        print!("{report}");
    }
    Ok(())
}
