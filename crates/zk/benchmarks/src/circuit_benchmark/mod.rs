// SPDX-License-Identifier: LGPL-3.0-only

mod artifacts;
mod inputs;
mod leaf;
mod protocol;
pub(crate) mod records;
mod report;
pub(crate) mod selection;

#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use clap::Parser;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use e3_zk_prover::{ZkBackend, ZkProver};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Parser)]
#[command(
    about = "Benchmark production Rust witness preparation, Noir execution, and proof backends."
)]
pub(crate) struct Options {
    /// Operation: run, protocol, gas, replay, report, or list.
    #[arg(default_value = "run")]
    pub command: String,
    /// Saved run directory for report, or saved summary/run directory for replay.
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Separate integration summary for saved-data reporting.
    #[arg(long)]
    pub summary: Option<PathBuf>,
    /// Saved gas document for reporting or preserving user gas during replay.
    #[arg(long)]
    pub gas_json: Option<PathBuf>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub mode: Option<String>,
    #[arg(long)]
    pub committee: Option<String>,
    /// Circuit path. Repeat this option to select several cases.
    #[arg(long)]
    pub circuit: Vec<String>,
    /// Artifact root containing preset/committee/variant directories.
    #[arg(long)]
    pub artifacts: Option<PathBuf>,
    /// New or empty output directory. Existing results are never overwritten.
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long, default_value = "recursive")]
    pub variant: String,
    #[arg(long)]
    pub bb: Option<PathBuf>,
    #[arg(long)]
    pub witness_only: bool,
    #[arg(long)]
    pub leaf_only: bool,
    #[arg(long)]
    pub skip_gates: bool,
    /// Measure the canonical source-build command. This explicitly changes the active selection.
    #[arg(long)]
    pub bench_compile: bool,
    /// Measure selected VK generation in the run's private directory.
    #[arg(long)]
    pub bench_vk: bool,
    /// Export prepared ABI inputs as debug TOML under the run directory.
    #[arg(long)]
    pub export_toml: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, default_value_t = 1)]
    pub multithread_jobs: usize,
    #[arg(long)]
    pub verbose: bool,
}

pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

pub(crate) fn run(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("Start {command:?}"))?;
    if !output.status.success() {
        bail!(
            "{command:?} failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(crate) fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

pub(crate) fn run_logged(command: &mut Command, log: &Path) -> Result<()> {
    let file = fs::File::create(log)?;
    let status = command
        .stdout(file.try_clone()?)
        .stderr(file)
        .status()
        .with_context(|| format!("Start {command:?}"))?;
    if !status.success() {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(log)?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(4096)))?;
        let mut tail = Vec::new();
        file.take(4096).read_to_end(&mut tail)?;
        bail!(
            "{command:?} failed ({status}); log {}:\n{}",
            log.display(),
            String::from_utf8_lossy(&tail)
        );
    }
    Ok(())
}

pub(crate) fn main() -> Result<()> {
    let options = Options::parse();
    execute(&root(), &options)
}

pub(crate) fn execute(root: &Path, options: &Options) -> Result<()> {
    if !matches!(
        options.command.as_str(),
        "run" | "protocol" | "gas" | "replay" | "report" | "list"
    ) {
        bail!("Unknown benchmark operation: {}", options.command);
    }
    if options.multithread_jobs == 0 {
        bail!("--multithread-jobs must be positive");
    }
    if options.bench_compile && options.artifacts.is_some() {
        bail!("--bench-compile writes canonical dist artifacts; omit --artifacts");
    }
    if options.command == "report" {
        let input = resolve(
            root,
            options
                .input
                .as_deref()
                .context("report requires --input <saved-run>")?,
        );
        let output = options.output.as_ref().map(|path| resolve(root, path));
        let summary = options.summary.as_ref().map(|path| resolve(root, path));
        let gas = options.gas_json.as_ref().map(|path| resolve(root, path));
        return report::command(
            &input,
            output.as_deref(),
            summary.as_deref(),
            gas.as_deref(),
        );
    }
    if options.command == "replay" {
        if options.bench_compile || options.artifacts.is_some() {
            bail!("Replay uses selected canonical artifacts; prepare them separately with pnpm build:circuits");
        }
        let input = resolve(
            root,
            options
                .input
                .as_deref()
                .context("replay requires --input <summary-or-run>")?,
        );
        let output = new_output(root, options)?;
        let gas = options.gas_json.as_ref().map(|path| resolve(root, path));
        let result = protocol::replay(
            root,
            &output,
            &input,
            options.mode.as_deref(),
            options.committee.as_deref(),
            gas.as_deref(),
        );
        render_saved(&output)?;
        println!("Replay output: {}", output.display());
        return result;
    }
    let config_path = options
        .config
        .as_ref()
        .map(|path| resolve(root, path))
        .unwrap_or_else(|| root.join("circuits/benchmarks/config.json"));
    let config: selection::Config = serde_json::from_slice(&fs::read(config_path)?)?;
    let mode = options.mode.as_deref().unwrap_or(&config.mode);
    let preset = match mode {
        "insecure" => BfvPreset::InsecureThreshold64,
        "secure" => BfvPreset::SecureThreshold8192,
        _ => bail!("Mode must be insecure or secure"),
    };
    let active_path = root.join("circuits/bin/.active-preset.json");
    let active: serde_json::Value = match fs::read(active_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            serde_json::json!({"committee":"minimum"})
        }
        Err(error) => return Err(error.into()),
    };
    let committee_name = options
        .committee
        .as_deref()
        .or_else(|| active["committee"].as_str())
        .context("Specify --committee or prepare an active artifact stamp")?;
    let committee: CiphernodesCommitteeSize = committee_name.parse()?;
    let preset_name = if mode == "secure" {
        "secure-8192"
    } else {
        "insecure-64"
    };
    let policy = e3_zk_build::build_pairs(root)?;
    if !policy
        .iter()
        .any(|pair| pair[0] == preset_name && pair[1] == committee_name)
    {
        bail!("Unsupported build pair: {preset_name}/{committee_name}");
    }
    let variant = selection::variant(&options.variant)?;
    let cases = if matches!(options.command.as_str(), "run" | "list") {
        config.select(mode, &options.circuit)?
    } else {
        Vec::new()
    };
    if options.command == "list" || options.dry_run {
        for case in cases {
            println!(
                "{} ({preset_name}/{committee_name}, {variant})",
                case.path()
            );
        }
        return Ok(());
    }
    if matches!(options.command.as_str(), "protocol" | "gas") && options.artifacts.is_some() {
        bail!("The integration scenario reads canonical dist artifacts; omit --artifacts");
    }
    let output = new_output(root, options)?;
    let work = tempfile::Builder::new()
        .prefix(".work-")
        .tempdir_in(&output)?;
    let mut compilation = records::Stage::unmeasured("canonical_build_command_wall");
    if options.bench_compile
        && (matches!(options.command.as_str(), "protocol" | "gas")
            || cases.iter().any(|case| *case != selection::Case::Config))
    {
        let start = std::time::Instant::now();
        let build = e3_zk_build::Request {
            operation: e3_zk_build::Operation::Build,
            preset: e3_zk_build::PresetSelection::Single(preset),
            committee: e3_zk_build::CommitteeSelection::Single(committee),
            groups: e3_zk_build::GroupSelection::All,
            circuits: Vec::new(),
            output: None,
            skip_vk: false,
            skip_checksums: false,
            skip_utils_patch: false,
            no_clean: true,
            no_clean_targets: true,
            skip_if_built: false,
            hydrate_bin_only: false,
            dry_run: false,
        };
        let result = e3_zk_build::execute(root, &build);
        compilation.finish(start.elapsed(), &result);
        result?;
    }
    let artifact_root = options
        .artifacts
        .as_ref()
        .map(|path| resolve(root, path))
        .unwrap_or_else(|| root.join("dist/circuits"));
    let explicit_bb = options.bb.as_ref().map(|path| resolve(root, path));
    let bb = artifacts::bb_binary(explicit_bb.as_deref())?;
    let backend = ZkBackend::new(
        e3_config::BBPath::Custom(bb),
        artifact_root.clone(),
        work.path().join("prover"),
    );
    let prover = ZkProver::new(&backend);
    let stamp =
        if options.command == "run" && cases.iter().all(|case| *case == selection::Case::Config) {
            // Config has its own compilation provenance, not a runtime archive identity.
            serde_json::Value::Null
        } else {
            artifacts::validate_pair(&artifact_root, preset_name, committee_name)?
        };
    let noir_pin = e3_zk_build::pinned_noir_version(&fs::read_to_string(
        root.join("crates/zk-prover/Cargo.toml"),
    )?)?;
    let bb_version = run(Command::new(prover.bb_binary()).arg("--version"))?;
    if !e3_zk_build::reports_version(&bb_version, &backend.config.required_bb_version) {
        bail!(
            "bb must be {}, observed {}",
            backend.config.required_bb_version,
            bb_version.trim()
        );
    }
    let pair = format!("{preset_name}/{committee_name}");
    let mut metadata = records::RunMetadata::new(
        root,
        mode,
        preset_name,
        committee,
        variant,
        stamp,
        prover.bb_binary(),
        &bb_version,
        &noir_pin,
        compilation,
        options,
    )?;
    write_json(&output.join("benchmark_run_meta.json"), &metadata)?;
    let protocol_config = protocol::Configuration {
        mode: mode.into(),
        preset: preset_name.into(),
        committee,
        jobs: options.multithread_jobs,
        bb_binary: Some(prover.bb_binary().clone()),
    };
    if matches!(options.command.as_str(), "protocol" | "gas") {
        let result = protocol::collect(
            root,
            &output,
            &protocol_config,
            options.command == "gas",
            None,
            None,
        );
        render_saved(&output)?;
        println!("Protocol output: {}", output.display());
        return result;
    }
    let material = inputs::Material::new(preset, committee)?;
    let mut ude = None;
    let mut failures = Vec::new();
    for case in cases {
        let mut record = records::Record::new(case, mode, variant);
        let result = leaf::benchmark(
            root,
            &output,
            work.path(),
            options,
            &prover,
            &pair,
            &noir_pin,
            &material,
            case,
            &mut ude,
            &mut metadata.shared_preparations,
            &mut record,
        );
        if let Err(error) = result {
            record.error = Some(format!("{error:#}"));
            failures.push(format!("{}: {error:#}", case.path()));
        }
        if options.verbose {
            println!(
                "{}: preparation {:?} s, execution {:?} s, proof {:?} s, verification {:?} s",
                case.path(),
                record.preparation.time_seconds,
                record.execution.time_seconds,
                record.proof_generation.time_seconds,
                record.verification.time_seconds
            );
        }
        write_json(
            &output
                .join("raw")
                .join(format!("{}_default.json", case.path().replace('/', "_"))),
            &record,
        )?;
    }
    write_json(&output.join("benchmark_run_meta.json"), &metadata)?;
    if !options.leaf_only && !options.witness_only && failures.is_empty() {
        if let Err(error) = protocol::collect(root, &output, &protocol_config, true, None, None) {
            failures.push(format!("Protocol/gas stage incomplete: {error:#}"));
        }
    }
    render_saved(&output)?;
    println!("Benchmark output: {}", output.display());
    if !failures.is_empty() {
        bail!("Benchmark incomplete:\n{}", failures.join("\n"));
    }
    Ok(())
}

fn new_output(root: &Path, options: &Options) -> Result<PathBuf> {
    let output = options
        .output
        .as_ref()
        .map(|path| resolve(root, path))
        .unwrap_or_else(|| {
            root.join("circuits/benchmarks/runs")
                .join(chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ").to_string())
        });
    if output.exists() && fs::read_dir(&output)?.next().is_some() {
        bail!("Output directory is not empty: {}", output.display());
    }
    fs::create_dir_all(output.join("raw"))?;
    Ok(output)
}

fn render_saved(output: &Path) -> Result<()> {
    let data = report::load(output, None, None)?;
    fs::write(output.join("report.md"), report::render(&data)?)?;
    Ok(())
}
