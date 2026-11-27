// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    artifacts, leaf, new_output, noir_pin, protocol,
    records::{ArtifactIdentity, Record, RunMetadata, Stage},
    render_saved, resolve, run, run_logged,
    selection::Case,
    write_json, Options,
};
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize::Minimum;
use e3_events::Proof;
use e3_fhe_params::BfvProfile;
use e3_zk_config::{synchronized::Configs, CircuitName, CircuitVariant};
use e3_zk_prover::{
    inputs_json_to_input_map, synchronized::decryption::prepare_decryption, BBPath,
    CompiledCircuit, ZkBackend, ZkProver,
};
use e3_zk_samples::threshold::synchronized::{Sample, OWNERS};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

const ROLES: [CircuitName; 3] = CircuitName::SYNCHRONIZED_DECRYPTION;

/// Stage the exact recorded bytes in a private prover namespace. Never install a disabled pair.
fn stage(root: &Path, export: &Path, dest: &Path, profile: BfvProfile, dkg: bool) -> Result<Value> {
    let (name, record, roles, scope) = if dkg {
        (
            "dkg-candidate",
            "dkg-publication.json",
            &CircuitName::SYNCHRONIZED_DKG[..],
            "dkg-publication",
        )
    } else {
        ("candidate", "manifest.json", &ROLES[..], "decryption-only")
    };
    let source = export.join(name);
    let manifest = protocol::read_json(&source.join("manifest.json"))?;
    let pinned = root
        .join("circuits/qualification")
        .join(profile.name())
        .join("minimum")
        .join(record);
    ensure!(
        manifest == protocol::read_json(&pinned)?,
        "{name} differs from {}",
        pinned.display()
    );
    let circuits = manifest["circuits"]
        .as_array()
        .context("missing candidate circuits")?;
    ensure!(
        manifest["scope"] == scope
            && manifest["formatVersion"] == 1
            && manifest["admissionEnabled"] == false
            && manifest["profile"] == profile.name()
            && manifest["committee"] == Minimum.as_str()
            && manifest["cryptoConfigId"] == profile.crypto_config_id(Minimum)?.to_string()
            && manifest["nargo"] == noir_pin(root)?
            && circuits.len() == roles.len(),
        "wrong candidate identity or role count"
    );
    for (&role, entry) in roles.iter().zip(circuits) {
        let variant = role
            .synchronized_variant()
            .context("not a candidate role")?;
        let relative = format!("{}/{}", variant.as_str(), role.dir_path());
        ensure!(
            entry["role"] == role.as_str()
                && entry["path"] == relative
                && entry["target"] == variant.verifier_target(),
            "wrong candidate role or variant for {role}"
        );
        let directory = dest.join(&relative);
        fs::create_dir_all(&directory)?;
        let copy = |file: &str| -> Result<PathBuf> {
            let output = directory.join(file);
            fs::copy(source.join(&relative).join(file), &output)?;
            Ok(output)
        };
        let compiled = copy(&format!("{}.json", role.as_str()))?;
        let vk = copy(&format!("{}.vk", role.as_str()))?;
        let pin = fs::read(copy(&format!("{}.vk_hash", role.as_str()))?)?;
        ensure!(
            pin.len() == 32
                && entry["vkHash"] == format!("0x{}", hex::encode(&pin))
                && entry["vkSha256"] == artifacts::digest(&vk)?
                && entry["circuitSha256"] == artifacts::digest(&compiled)?,
            "candidate digest or VK pin mismatch: {role}"
        );
        let document = protocol::read_json(&compiled)?;
        ensure!(
            document["noir_version"]
                .as_str()
                .is_some_and(|v| e3_zk_build::reports_version(
                    v,
                    manifest["nargo"].as_str().unwrap()
                )),
            "wrong compiled Noir version: {role}"
        );
        if variant == CircuitVariant::Evm {
            ensure!(
                entry["soliditySha256"] == artifacts::digest(&copy("SynchronizedHonk.sol")?)?,
                "wrong generated Solidity verifier for {role}"
            );
        }
    }
    Ok(manifest)
}

fn validate_variant(options: &Options) -> Result<()> {
    ensure!(
        options.variant == "recursive",
        "synchronized candidates have a fixed variant for each role: recursive leaves and an EVM outer"
    );
    Ok(())
}

fn selected(options: &Options) -> Result<usize> {
    validate_variant(options)?;
    ensure!(
        options.committee.as_deref().unwrap_or("minimum") == "minimum",
        "synchronized benchmarks support Minimum only"
    );
    ensure!(
        options.artifacts.is_none() && !options.bench_compile,
        "use --candidate, not archive or compile options"
    );
    ensure!(
        options.multithread_jobs == 1,
        "--multithread-jobs configures only the SS actor benchmark"
    );
    let last = if options.circuit.is_empty() {
        if options.witness_only {
            0
        } else if options.leaf_only {
            1
        } else {
            2
        }
    } else {
        let mut last = 0;
        for path in &options.circuit {
            let index = ROLES
                .iter()
                .position(|role| role.dir_path() == *path)
                .with_context(|| format!("unsupported synchronized decryption circuit: {path}"))?;
            last = last.max(index);
        }
        last
    };
    ensure!(
        !options.witness_only || last == 0,
        "C7 and the outer require verified child proofs"
    );
    ensure!(
        !options.leaf_only || last < 2,
        "--leaf-only excludes the outer proof"
    );
    Ok(last)
}

struct Runner<'a> {
    root: &'a Path,
    output: &'a Path,
    work: &'a Path,
    options: &'a Options,
    prover: ZkProver,
    pair: String,
    manifest: Value,
}

impl Runner<'_> {
    fn measure(
        &self,
        index: usize,
        owner: Option<u32>,
        prepare: impl FnOnce() -> Result<Value>,
    ) -> Result<Option<Proof>> {
        let role = ROLES[index];
        let variant = role.synchronized_variant().unwrap();
        let entry = &self.manifest["circuits"][index];
        let path = self
            .prover
            .circuits_dir(variant, &self.pair)
            .join(role.dir_path())
            .join(format!("{}.json", role.as_str()));
        let case = Case::Named(role);
        let mut record = Record::new(case, self.manifest["profile"].as_str().unwrap(), variant);
        if let Some(owner) = owner {
            record.circuit_path += &format!("/owner-{owner}");
        }
        let result = (|| {
            let compiled = CompiledCircuit::from_file(&path)?;
            let vk = path.with_extension("vk");
            record.circuit_size_bytes = Some(fs::metadata(&path)?.len());
            record.vk_size_bytes = Some(fs::metadata(&vk)?.len());
            record.artifact = Some(ArtifactIdentity {
                source_stamp: json!({"profile":self.manifest["profile"],"committee":"minimum","sourceHash":self.manifest["sourceHash"],"vkHash":entry["vkHash"]}),
                compiled_path: format!(
                    "{}/{}.json",
                    entry["path"].as_str().unwrap(),
                    role.as_str()
                ),
                compiled_sha256: entry["circuitSha256"].as_str().unwrap().into(),
                vk_sha256: Some(entry["vkSha256"].as_str().unwrap().into()),
                artifact_noir_version: protocol::read_json(&path)?["noir_version"]
                    .as_str()
                    .unwrap()
                    .into(),
            });
            let start = Instant::now();
            let inputs = prepare().and_then(|value| Ok(inputs_json_to_input_map(&value)?));
            record.preparation.finish(start.elapsed(), &inputs);
            leaf::measure(
                self.root,
                self.output,
                self.work,
                self.options,
                &self.prover,
                &self.pair,
                case,
                variant,
                &compiled,
                &path,
                &vk,
                inputs?,
                &mut record,
            )
        })();
        if let Err(error) = &result {
            record.error = Some(format!("{error:#}"));
        }
        write_json(
            &self.output.join("raw").join(format!(
                "{}.json",
                record
                    .circuit_path
                    .trim_start_matches("circuits/bin/")
                    .replace('/', "_")
            )),
            &record,
        )?;
        result
    }

    fn graph(&self, cfg: &Configs, last: usize) -> Result<Option<Value>> {
        let sample = Sample::generate(cfg)?;
        let mut partials = Vec::new();
        for (index, owner) in OWNERS.into_iter().enumerate() {
            if let Some(proof) = self.measure(0, Some(owner), || sample.c6_inputs(cfg, index))? {
                partials.push(proof);
            }
        }
        if last == 0 {
            return Ok(None);
        }
        let rows = partials
            .iter()
            .map(|p| p.public_signals.as_ref())
            .collect::<Vec<_>>();
        let c7 = self
            .measure(1, None, || sample.c7_inputs(cfg, &rows))?
            .context("missing C7 proof")?;
        if last == 1 {
            return Ok(None);
        }
        let outer = self
            .measure(2, None, || {
                prepare_decryption(&self.prover, cfg, &partials, &c7)
            })?
            .context("missing outer proof")?;
        let pins = e3_zk_config::synchronized::verifier::SynchronizedChildPins::for_profile(
            cfg.profile,
            cfg.committee,
        )?;
        ensure!(
            outer.public_signals.get(..32) == Some(pins.c6.as_slice())
                && outer.public_signals.get(32..64) == Some(pins.c7.as_slice())
                && outer.public_signals[64..] == c7.public_signals[..],
            "outer differs from the verified C7 statement or request child pins"
        );
        Ok(Some(json!({
            "benchmark_config":{"mode":cfg.profile.name(),"committee":"minimum","sourceHash":self.manifest["sourceHash"]},
            "folded_artifacts":{"decryption_aggregator":{"proof_hex":format!("0x{}",hex::encode(&outer.data[..])), "public_inputs_hex":format!("0x{}",hex::encode(&outer.public_signals[..]))}},
            "authority":sample.public_authority(),
        })))
    }
}

fn gas(
    root: &Path,
    output: &Path,
    candidate: &Path,
    manifest: &Value,
    summary: &Value,
) -> Result<()> {
    let cfg = &summary["benchmark_config"];
    ensure!(
        cfg["mode"] == manifest["profile"]
            && cfg["committee"] == manifest["committee"]
            && cfg["sourceHash"] == manifest["sourceHash"],
        "saved proof configuration does not match the candidate"
    );
    let proof: protocol::ProofArtifact =
        serde_json::from_value(summary["folded_artifacts"]["decryption_aggregator"].clone())?;
    let measures = protocol::artifact_measures(&proof)?;
    let input = output.join("integration_summary.json");
    write_json(&input, summary)?;
    let result = (|| {
        let path = output.join("evm_verify_gas.json");
        run_logged(
            Command::new("pnpm")
                .args([
                    "exec",
                    "hardhat",
                    "run",
                    "--no-compile",
                    "scripts/benchmarkSynchronizedGas.ts",
                    "--network",
                    "hardhat",
                ])
                .current_dir(root.join("packages/interfold-contracts"))
                .env("BENCHMARK_FOLDED_JSON", &input)
                .env(
                    "BENCHMARK_SYNC_HONK",
                    candidate
                        .join(manifest["circuits"][2]["path"].as_str().unwrap())
                        .join("SynchronizedHonk.sol"),
                )
                .env("BENCHMARK_GAS_OUTPUT", &path),
            &output.join("evm-replay.log"),
        )?;
        let doc = protocol::read_json(&path)?;
        ensure!(
            doc["profile"] == cfg["mode"],
            "wrong EVM verifier configuration"
        );
        doc["verify_gas"]["dec"]
            .as_u64()
            .filter(|&v| v > 0)
            .context("missing decryption verifier gas")
    })();
    write_json(
        &output.join("crisp_verify_gas.json"),
        &json!({"scope":"synchronized-decryption","complete":result.is_ok(),"verify_gas":{"dec":result.as_ref().ok()},"artifacts":{"dec":measures},"error":result.as_ref().err().map(|e| format!("{e:#}"))}),
    )?;
    result.map(|_| ())
}

pub(super) fn replay(root: &Path, output: &Path, input: &Path, options: &Options) -> Result<()> {
    let saved = || -> Result<()> {
        validate_variant(options)?;
        let summary = protocol::read_json(&if input.is_dir() {
            input.join("integration_summary.json")
        } else {
            input.into()
        })?;
        let mode = summary["benchmark_config"]["mode"]
            .as_str()
            .context("missing saved profile")?;
        ensure!(
            options.mode.as_deref().unwrap_or(mode) == mode
                && options.committee.as_deref().unwrap_or("minimum") == "minimum",
            "replay selection differs from saved candidate"
        );
        let profile = mode.parse()?;
        let work = tempfile::tempdir_in(output)?;
        let stamp = stage(
            root,
            &resolve(
                root,
                options
                    .candidate
                    .as_deref()
                    .context("specify --candidate")?,
            ),
            work.path(),
            profile,
            false,
        )?;
        gas(root, output, work.path(), &stamp, &summary)
    };
    let result = saved();
    let path = output.join("crisp_verify_gas.json");
    if let Err(error) = &result {
        if !path.exists() {
            write_json(
                &path,
                &json!({"scope": "synchronized-decryption", "complete": false, "verify_gas": {"dec": null}, "error": format!("{error:#}")}),
            )?;
        }
    }
    result
}

pub(super) fn execute(root: &Path, options: &Options, profile: BfvProfile) -> Result<()> {
    let last = selected(options)?;
    let request = matches!(options.command.as_str(), "protocol" | "request");
    if request {
        ensure!(options.circuit.is_empty() && !options.leaf_only && !options.witness_only
            && !options.bench_vk && !options.export_toml && !options.skip_gates, "request measures the complete signed lifecycle; circuit selection and leaf options apply to run");
    }
    ensure!(
        options.command != "gas" || last == 2,
        "gas requires the complete graph"
    );
    if options.command == "list" || options.dry_run {
        for role in &ROLES[..=last] {
            println!(
                "{} ({profile}/minimum, {})",
                role.dir_path(),
                role.synchronized_variant().unwrap()
            );
        }
        return Ok(());
    }
    let export = resolve(
        root,
        options
            .candidate
            .as_deref()
            .context("specify --candidate <synchronized export directory>")?,
    );
    let output = new_output(root, options)?;
    let work = tempfile::tempdir_in(&output)?;
    let cfg = Configs::for_profile(profile, Minimum)?;
    let pair = profile.artifacts_dir_for_committee(Minimum)?;
    let artifacts = work.path().join("artifacts");
    let dest = artifacts.join(&pair);
    let manifest = stage(root, &export, &dest, profile, false)?;
    let bb = artifacts::bb_binary(options.bb.as_deref().map(|p| resolve(root, p)).as_deref())?;
    let backend = ZkBackend::new(
        BBPath::Custom(bb.clone()),
        artifacts.clone(),
        work.path().join("prover"),
    );
    let version = run(Command::new(&bb).arg("--version"))?;
    ensure!(
        manifest["bb"] == backend.config.required_bb_version
            && e3_zk_build::reports_version(&version, &backend.config.required_bb_version),
        "wrong candidate BB version: {version}"
    );
    let mut meta = RunMetadata::new(
        root,
        profile.name(),
        profile.name(),
        Minimum,
        CircuitVariant::Recursive,
        manifest.clone(),
        &bb,
        &version,
        &noir_pin(root)?,
        Stage::unmeasured("canonical_build_command_wall"),
        options,
    )?;
    meta.proof_aggregation = last == 2;
    if request {
        let dkg = stage(root, &export, &dest, profile, true)?;
        ensure!(
            dkg["bb"] == manifest["bb"],
            "different BB versions for the two proof graphs"
        );
        meta.artifact_stamp = json!({"decryption": manifest, "dkg": dkg});
        write_json(&output.join("benchmark_run_meta.json"), &meta)?;
        write_json(&dest.join("manifest.json"), &manifest)?;
        write_json(&dest.join("dkg-publication.json"), &dkg)?;
        let result = protocol::run_request(
            Command::new("cargo")
                .args([
                    "test",
                    "--locked",
                    "--release",
                    "-p",
                    "e3-keyshare",
                    "--lib",
                    "actors::threshold_keyshare::tests::synchronized::recovery::synchronized_cli_request_to_plaintext",
                    "--",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .current_dir(root)
                .env("E3_CUSTOM_BB", &bb)
                .env("RUST_MIN_STACK", std::env::var_os("RUST_MIN_STACK").unwrap_or_else(|| "16777216".into()))
                .env("E3_BENCHMARK_PROFILE", profile.name())
                .env("E3_BENCHMARK_ARTIFACTS", artifacts)
                .env_remove("E3_SYNC_DECRYPTION_EXPORT")
                .env_remove("E3_SYNC_OTHER_PROFILE_EXPORT"),
            &output,
            |saved| {
                ensure!(
                    saved["profile"] == profile.name()
                        && saved["committee"] == "minimum"
                        && saved["plaintext"] == 37
                        && saved["owners"] == json!(OWNERS),
                    "wrong CLI request outcome"
                );
                Ok(())
            },
        );
        render_saved(&output)?;
        println!("CLI request output: {}", output.display());
        return result;
    }
    write_json(&output.join("benchmark_run_meta.json"), &meta)?;
    let runner = Runner {
        root,
        output: &output,
        work: work.path(),
        options,
        prover: ZkProver::new(&backend),
        pair,
        manifest,
    };
    let result = runner.graph(&cfg, last).and_then(|summary| {
        if let Some(summary) = summary {
            gas(root, &output, &dest, &runner.manifest, &summary)?;
        }
        Ok(())
    });
    render_saved(&output)?;
    println!("Benchmark output: {}", output.display());
    result
}
