// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    configuration, github_output, identity, profile, run, vk_commitments, vk_tree, write_json,
    CommitteeSelection, GroupSelection, Operation, PresetSelection, Request,
};
use anyhow::{bail, Context, Result};
use e3_fhe_params::{BfvDecryptionProtocol, BfvProfile};
use e3_zk_config::CircuitName;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug)]
pub struct Circuit {
    pub name: String,
    pub group: String,
    pub package: String,
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stamp {
    pub preset: String,
    pub committee: String,
    pub source_hash: String,
    pub built_at: String,
}

pub fn discover(root: &Path, request: &Request) -> Result<Vec<Circuit>> {
    let profile = match request.preset {
        PresetSelection::Single(profile) => profile,
        PresetSelection::All => BfvProfile::SsInsecure64,
    };
    if profile.protocol() == BfvDecryptionProtocol::Synchronized {
        let mut circuits = Vec::new();
        for role in CircuitName::SYNCHRONIZED_DKG {
            let name = role.as_str();
            if !request.groups.groups().contains(&role.group())
                || (!request.circuits.is_empty()
                    && !request.circuits.iter().any(|selected| selected == name))
            {
                continue;
            }
            let path = root
                .join("circuits/bin")
                .join(role.source_path(profile).unwrap());
            let manifest = path.join("Nargo.toml");
            let value: toml::Value =
                toml::from_str(&fs::read_to_string(&manifest).with_context(|| {
                    format!("Missing synchronized circuit {}", manifest.display())
                })?)?;
            let package = value
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(toml::Value::as_str)
                .context("Nargo package needs a name")?;
            if package != name {
                bail!("Synchronized package {package} does not match logical role {name}");
            }
            circuits.push(Circuit {
                name: name.into(),
                group: role.group().into(),
                package: package.into(),
                path,
            });
        }
        if !request.circuits.is_empty()
            && request
                .circuits
                .iter()
                .any(|name| !circuits.iter().any(|circuit| &circuit.name == name))
        {
            bail!("Unsupported synchronized DKG definition selection");
        }
        return Ok(circuits);
    }
    fn walk(
        path: &Path,
        group: &str,
        relative: &str,
        filter: &[String],
        circuits: &mut Vec<Circuit>,
    ) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "target" {
                continue;
            }
            let name = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let path = entry.path();
            let manifest = path.join("Nargo.toml");
            if manifest.exists() {
                let value: toml::Value = toml::from_str(&fs::read_to_string(&manifest)?)?;
                if let Some(package) = value.get("package") {
                    if filter.is_empty() || filter.contains(&name) {
                        circuits.push(Circuit {
                            package: package
                                .get("name")
                                .and_then(toml::Value::as_str)
                                .context("Nargo package needs a name")?
                                .to_string(),
                            name,
                            group: group.to_string(),
                            path,
                        });
                    }
                    continue;
                }
            }
            walk(&path, group, &name, filter, circuits)?;
        }
        Ok(())
    }
    let mut circuits = Vec::new();
    for group in request.groups.groups() {
        let start = circuits.len();
        walk(
            &root.join("circuits/bin").join(group),
            group,
            "",
            &request.circuits,
            &mut circuits,
        )?;
        circuits[start..].sort_by(|a, b| a.name.cmp(&b.name));
    }
    Ok(circuits)
}

pub fn target_dir(root: &Path, circuit: &Circuit) -> Result<PathBuf> {
    workspace_target(root, &circuit.path)
}

/// The `target` directory nargo writes the package at `package` to: its workspace's, if it has one.
fn workspace_target(root: &Path, package: &Path) -> Result<PathBuf> {
    let bin = root.join("circuits/bin");
    for directory in package
        .ancestors()
        .take_while(|path| path.starts_with(&bin))
    {
        let manifest = directory.join("Nargo.toml");
        if manifest.exists() {
            let value: toml::Value = toml::from_str(&fs::read_to_string(manifest)?)?;
            if value.get("workspace").is_some() && value.get("package").is_none() {
                return Ok(directory.join("target"));
            }
        }
    }
    Ok(package.join("target"))
}

pub fn copy_tree(source: &Path, target: &Path, excluded: &[&str]) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if excluded.contains(&name.to_string_lossy().as_ref()) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("Refuse symlink {}", entry.path().display());
        }
        if kind.is_dir() {
            copy_tree(&entry.path(), &target.join(name), excluded)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(name))?;
        }
    }
    Ok(())
}

fn remove_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn clean_targets(root: &Path, circuits: &[Circuit]) -> Result<()> {
    let mut paths = BTreeSet::new();
    for circuit in circuits {
        paths.insert(target_dir(root, circuit)?);
        paths.insert(circuit.path.join("target"));
    }
    if circuits.iter().any(|circuit| {
        !circuit
            .path
            .starts_with(root.join("circuits/bin/synchronized"))
    }) {
        paths.insert(root.join("circuits/bin/target"));
    }
    for path in paths {
        remove_dir(&path)?;
    }
    Ok(())
}

/// Every artifact a prover requires of a pair (`crates/zk/prover/required-artifacts.json`), as
/// `<variant>/<group>/<name>/<package>.<extension>`.
fn required_artifacts() -> Vec<&'static str> {
    serde_json::from_str(include_str!("../../prover/required-artifacts.json"))
        .expect("invalid required circuit artifact inventory")
}

/// Where [`hydrate`] copies each published file of a variant in `circuits/bin`, as
/// `(published extension, bin extension)`.
const BIN_EXTENSIONS: [(&str, &[(&str, &str)]); 3] = [
    (
        "default",
        &[
            ("json", "json"),
            ("vk", "vk_recursive"),
            ("vk_hash", "vk_recursive_hash"),
        ],
    ),
    ("evm", &[("vk", "vk"), ("vk_hash", "vk_hash")]),
    (
        "recursive",
        &[("vk", "vk_noir"), ("vk_hash", "vk_noir_hash")],
    ),
];

/// The VK-tree anchors, by the name each is published under. An anchor is placed by this name and
/// not with a circuit [`discover`] lists: the C6 tree anchor keeps the retired `c6_fold` path, which
/// holds no circuit.
const ANCHORS: [&str; 2] = ["nodes_fold", "c6_fold"];

/// Where the anchor `name` is published in `pair`.
fn published_anchor(pair: &Path, name: &str) -> PathBuf {
    pair.join("default/recursive_aggregation")
        .join(name)
        .join(format!("{name}.vk_tree_hash"))
}

/// Where a build or [`hydrate`] leaves the anchor `name` under `bin` (`circuits/bin`).
fn built_anchor(bin: &Path, name: &str) -> PathBuf {
    bin.join("recursive_aggregation")
        .join(name)
        .join("target")
        .join(format!("{name}.vk_tree_hash"))
}

/// The required artifacts of a pair. A pair is complete, current or hydratable only with all of
/// them: a tree built before the inventory gained an artifact must not pass.
pub fn dist_markers(pair: &Path) -> Vec<PathBuf> {
    required_artifacts()
        .iter()
        .map(|path| pair.join(path))
        .collect()
}

/// The required artifacts where [`hydrate`] puts them in `circuits/bin`. Every variant's program
/// is the circuit's one compiled `json`.
pub(crate) fn bin_markers(root: &Path) -> Result<Vec<PathBuf>> {
    required_artifacts()
        .into_iter()
        .map(|required| {
            let parts: Vec<&str> = required.split('/').collect();
            let [variant, group @ .., name, file] = parts.as_slice() else {
                bail!("Malformed required artifact {required}");
            };
            let (package, extension) = file
                .split_once('.')
                .with_context(|| format!("Required artifact {required} has no extension"))?;
            if extension == "vk_tree_hash" {
                return Ok(built_anchor(&root.join("circuits/bin"), name));
            }
            let extension = if extension == "json" {
                "json"
            } else {
                BIN_EXTENSIONS
                    .iter()
                    .find(|(published, _)| published == variant)
                    .and_then(|(_, extensions)| {
                        extensions.iter().find(|(from, _)| *from == extension)
                    })
                    .map(|(_, to)| *to)
                    .with_context(|| format!("Required artifact {required} has no bin location"))?
            };
            let package_dir = root.join("circuits/bin").join(group.join("/")).join(name);
            Ok(workspace_target(root, &package_dir)?.join(format!("{package}.{extension}")))
        })
        .collect()
}

fn read_stamp(path: &Path) -> Result<Option<Stamp>> {
    match fs::read(path) {
        Ok(bytes) => {
            Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                format!("Invalid stamp {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn hydration_stamp(
    pair: &Path,
    preset: &str,
    committee: &str,
    current_hash: &str,
) -> Result<Stamp> {
    if profile(preset)?.protocol() == BfvDecryptionProtocol::Synchronized {
        bail!("Synchronized artifacts are incomplete and cannot be hydrated");
    }
    let stamp =
        read_stamp(&pair.join(".build-stamp.json"))?.context("Artifact pair has no build stamp")?;
    if stamp.preset != preset || stamp.committee != committee || stamp.source_hash.is_empty() {
        bail!("Artifact stamp does not identify {preset}/{committee}");
    }
    for marker in dist_markers(pair) {
        if !marker.is_file() {
            bail!("Cannot hydrate; missing {}", marker.display());
        }
    }
    if stamp.source_hash != current_hash {
        eprintln!("Artifact source hash {} differs from current source hash {current_hash}; hydration preserves artifact provenance.", stamp.source_hash);
    }
    Ok(stamp)
}

/// Whether `pair` holds a complete artifact set stamped for `preset`/`committee`. `hash` is the
/// source hash the stamp must record; `None` accepts any, as for published artifacts.
pub fn dist_current(
    pair: &Path,
    preset: &str,
    committee: &str,
    hash: Option<&str>,
) -> Result<bool> {
    if profile(preset)?.protocol() == BfvDecryptionProtocol::Synchronized {
        return Ok(false);
    }
    Ok(
        read_stamp(&pair.join(".build-stamp.json"))?.is_some_and(|stamp| {
            stamp.preset == preset
                && stamp.committee == committee
                && hash.is_none_or(|hash| stamp.source_hash == hash)
        }) && dist_markers(pair).iter().all(|path| path.is_file()),
    )
}

/// Whether `circuits/bin` holds a complete build stamped for `preset`/`committee`. `hash` is as
/// for [`dist_current`].
pub fn bin_current(root: &Path, preset: &str, committee: &str, hash: Option<&str>) -> Result<bool> {
    if profile(preset)?.protocol() == BfvDecryptionProtocol::Synchronized {
        return Ok(false);
    }
    let stamped = read_active_stamp(root)?.is_some_and(|stamp| {
        stamp.preset == preset
            && stamp.committee == committee
            && hash.is_none_or(|hash| stamp.source_hash == hash)
    });
    Ok(stamped && bin_markers(root)?.iter().all(|path| path.is_file()))
}

/// The stamp of the preset and committee `circuits/bin` was built for, or `None` before any build.
pub fn read_active_stamp(root: &Path) -> Result<Option<Stamp>> {
    read_stamp(&root.join("circuits/bin/.active-preset.json"))
}

fn active_stamp(root: &Path, preset: &str, committee: &str, hash: &str) -> Result<()> {
    write_json(
        &root.join("circuits/bin/.active-preset.json"),
        &Stamp {
            preset: preset.into(),
            committee: committee.into(),
            source_hash: hash.into(),
            built_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        },
    )
}

pub fn hydrate(root: &Path, pair: &Path, request: &Request, stamp: &Stamp) -> Result<()> {
    if request.single_profile()?.protocol() == BfvDecryptionProtocol::Synchronized
        || profile(&stamp.preset)?.protocol() == BfvDecryptionProtocol::Synchronized
    {
        bail!("Synchronized artifacts are incomplete and cannot be hydrated");
    }
    let circuits = discover(root, request)?;
    clean_targets(root, &circuits)?;
    for circuit in circuits {
        let target = target_dir(root, &circuit)?;
        fs::create_dir_all(&target)?;
        for (variant, extensions) in BIN_EXTENSIONS {
            let source = pair.join(variant).join(&circuit.group).join(&circuit.name);
            for (from, to) in extensions {
                let source = source.join(format!("{}.{from}", circuit.package));
                if source.is_file() {
                    fs::copy(source, target.join(format!("{}.{to}", circuit.package)))?;
                }
            }
        }
    }
    // `clean_targets` reaches only the targets of circuits, so an anchor at a path that holds no
    // circuit is replaced here.
    for name in ANCHORS {
        let built = built_anchor(&root.join("circuits/bin"), name);
        if built.exists() {
            fs::remove_file(&built)?;
        }
        let published = published_anchor(pair, name);
        if published.is_file() {
            fs::create_dir_all(built.parent().context("Anchor parent")?)?;
            fs::copy(published, built)?;
        }
    }
    active_stamp(root, &stamp.preset, &stamp.committee, &stamp.source_hash)
}

fn compiled_path(root: &Path, circuit: &Circuit) -> Result<PathBuf> {
    if circuit
        .path
        .starts_with(root.join("circuits/bin/synchronized"))
    {
        let path = target_dir(root, circuit)?.join(format!("{}.json", circuit.package));
        if !path.is_file() {
            bail!(
                "Compiled synchronized artifact not found: {}",
                path.display()
            );
        }
        return Ok(path);
    }
    let group = root.join("circuits/bin").join(&circuit.group);
    let mut current = circuit.path.as_path();
    loop {
        let path = current
            .join("target")
            .join(format!("{}.json", circuit.package));
        if path.is_file() {
            return Ok(path);
        }
        if current == group {
            break;
        }
        current = current
            .parent()
            .context("Circuit path has no group ancestor")?;
    }
    let path = root
        .join("circuits/bin/target")
        .join(format!("{}.json", circuit.package));
    if path.is_file() {
        return Ok(path);
    }
    bail!(
        "Compiled artifact not found for {}/{}",
        circuit.group,
        circuit.name
    )
}

fn sanitize_paths(path: &Path) -> Result<()> {
    #[derive(Deserialize)]
    struct Compiled<'a> {
        #[serde(borrow)]
        file_map: BTreeMap<String, SourceFile<'a>>,
    }
    #[derive(Deserialize)]
    struct SourceFile<'a> {
        #[serde(borrow)]
        path: &'a serde_json::value::RawValue,
    }
    let original = fs::read_to_string(path)?;
    let compiled: Compiled<'_> = serde_json::from_str(&original)?;
    let mut replacements = Vec::new();
    for file in compiled.file_map.values() {
        let decoded: String = serde_json::from_str(file.path.get())?;
        let source = decoded.replace('\\', "/");
        // Repository paths can themselves live under ghq/Go's github.com hierarchy.
        let canonical = if let Some((_, suffix)) = source.rsplit_once("/circuits/") {
            format!("interfold/circuits/{suffix}")
        } else if let Some((_, suffix)) = source.split_once("/github.com/") {
            format!("nargo/github.com/{suffix}")
        } else {
            anyhow::ensure!(
                !source.starts_with('/') && source.as_bytes().get(1) != Some(&b':'),
                "Unrecognized absolute compiler source path: {source}"
            );
            source
        };
        if canonical != decoded {
            // RawValue borrows the original token, so replace only that range, not compiler JSON
            // key order, whitespace, ABI, bytecode, or source text containing similar paths.
            let start = file.path.get().as_ptr() as usize - original.as_ptr() as usize;
            replacements.push((
                start,
                file.path.get().len(),
                serde_json::to_string(&canonical)?,
            ));
        }
    }
    if !replacements.is_empty() {
        replacements.sort_unstable_by_key(|(start, _, _)| std::cmp::Reverse(*start));
        let mut normalized = original.clone();
        for (start, length, replacement) in replacements {
            normalized.replace_range(start..start + length, &replacement);
        }
        fs::write(path, normalized)?;
    }
    Ok(())
}

/// The `write_vk` target of a Chonk stack circuit, which takes `--scheme chonk` in place of `-t`.
const CHONK_TARGET: &str = "chonk";

pub fn variants(circuit: &Circuit) -> Vec<(&'static str, &'static str, &'static str)> {
    if circuit.group == "chonk" {
        return vec![("default", CHONK_TARGET, "vk_recursive")];
    }
    if circuit.group == "recursive_aggregation" {
        // The tube and accumulate proofs carry an IPA claim that a root rollup (`c3ab_fold`,
        // `c6_chonk_root`) closes.
        if matches!(
            circuit.name.as_str(),
            "c3_chonk_tube" | "c3_chonk_accumulate" | "c6_chonk_tube"
        ) {
            return vec![("default", "noir-rollup-no-zk", "vk_recursive")];
        }
        let mut values = vec![("default", "noir-recursive-no-zk", "vk_recursive")];
        if matches!(
            circuit.name.as_str(),
            "dkg_aggregator" | "decryption_aggregator"
        ) {
            values.push(("evm", "evm", "vk"));
        }
        values
    } else if circuit.group == "dkg" && circuit.name.contains("_share_computation_chain") {
        // The C2 chunk circuits are only proven non-ZK and verified inside the final C2 circuit,
        // so their `default` key is the only one anything reads.
        vec![("default", "noir-recursive-no-zk", "vk_recursive")]
    } else {
        vec![
            ("evm", "evm", "vk"),
            ("default", "noir-recursive-no-zk", "vk_recursive"),
            ("recursive", "noir-recursive", "vk_noir"),
        ]
    }
}

fn vk_files(extension: &str) -> [(&'static str, String); 2] {
    [
        ("vk", extension.to_string()),
        ("vk_hash", format!("{extension}_hash")),
    ]
}

/// Writes the compiled `circuits/bin` artifacts into `pair` in the `dist/circuits/{preset}/{committee}`
/// layout, the layout `build` publishes, without compiling. Fails on a missing artifact, so check
/// [`bin_current`] first.
pub fn stage_bin(root: &Path, pair: &Path) -> Result<()> {
    let request = Request {
        operation: Operation::Build,
        preset: PresetSelection::All,
        committee: CommitteeSelection::All,
        groups: GroupSelection::All,
        circuits: Vec::new(),
        output: None,
        skip_vk: false,
        skip_checksums: false,
        skip_utils_patch: false,
        no_clean: false,
        no_clean_targets: false,
        skip_if_built: false,
        hydrate_bin_only: false,
        dry_run: false,
    };
    for circuit in discover(root, &request)? {
        let compiled = compiled_path(root, &circuit)?;
        let target = compiled.parent().context("Compiled artifact parent")?;
        for (variant, _, extension) in variants(&circuit) {
            let dist = pair.join(variant).join(&circuit.group).join(&circuit.name);
            fs::create_dir_all(&dist)?;
            fs::copy(&compiled, dist.join(format!("{}.json", circuit.package)))?;
            for (file, suffix) in vk_files(extension) {
                let source = target.join(format!("{}.{suffix}", circuit.package));
                fs::copy(&source, dist.join(format!("{}.{file}", circuit.package)))
                    .with_context(|| format!("Cannot stage {}", source.display()))?;
            }
        }
    }
    for name in ANCHORS {
        let built = built_anchor(&root.join("circuits/bin"), name);
        if built.is_file() {
            let published = published_anchor(pair, name);
            fs::create_dir_all(published.parent().context("Anchor parent")?)?;
            fs::copy(built, published)?;
        }
    }
    Ok(())
}

fn build_circuit(root: &Path, pair: &Path, circuit: &Circuit, skip_vk: bool) -> Result<()> {
    run(Command::new("nargo")
        .arg("compile")
        .current_dir(&circuit.path))?;
    let compiled = compiled_path(root, circuit)?;
    sanitize_paths(&compiled)?;
    let target = compiled.parent().context("Compiled artifact parent")?;
    let variants = if skip_vk {
        vec![("default", "noir-recursive-no-zk", "vk_recursive")]
    } else {
        variants(circuit)
    };
    for (variant, verifier_target, extension) in variants {
        let dist = pair.join(variant).join(&circuit.group).join(&circuit.name);
        fs::create_dir_all(&dist)?;
        fs::copy(&compiled, dist.join(format!("{}.json", circuit.package)))?;
        if skip_vk {
            continue;
        }
        let job = tempfile::tempdir_in(target)?;
        write_vk(circuit, &compiled, verifier_target, job.path())?;
        for (file, suffix) in vk_files(extension) {
            let source = job.path().join(file);
            if !source.is_file() {
                bail!(
                    "bb write_vk produced no {file} for {} ({verifier_target})",
                    circuit.package
                );
            }
            fs::copy(
                &source,
                target.join(format!("{}.{suffix}", circuit.package)),
            )?;
            fs::copy(source, dist.join(format!("{}.{file}", circuit.package)))?;
        }
    }
    println!("Built {}/{}", circuit.group, circuit.name);
    Ok(())
}

/// Writes `vk` and `vk_hash` for `circuit` into `out` with `bb write_vk`. The build and the
/// qualification share it so both derive a Chonk key the same way.
pub(crate) fn write_vk(
    circuit: &Circuit,
    compiled: &Path,
    verifier_target: &str,
    out: &Path,
) -> Result<()> {
    let mut command = Command::new("bb");
    command
        .args(["write_vk", "-b"])
        .arg(compiled)
        .arg("-o")
        .arg(out);
    if verifier_target == CHONK_TARGET {
        // bb 6 derives each Chonk circuit's key against its own Mega flavor. The hiding kernel
        // ends the stack; its key is the stack's Chonk key.
        let kind = if circuit.name.ends_with("_app") {
            "app"
        } else if circuit.name.ends_with("_hiding_kernel") {
            "hiding"
        } else {
            "kernel"
        };
        command.args(["--scheme", "chonk", "--circuit_kind", kind]);
    } else {
        command.args(["-t", verifier_target]);
    }
    run(&mut command)?;
    if verifier_target == CHONK_TARGET {
        write_chonk_vk_hash(out)?;
    }
    Ok(())
}

/// `write_vk --scheme chonk` writes no hash. The kernels pin each key by Barretenberg's
/// Poseidon2 hash of its fields, so the builder writes that hash beside the key.
fn write_chonk_vk_hash(job: &Path) -> Result<()> {
    use ark_ff::{BigInteger, PrimeField};
    let key = fs::read(job.join("vk"))?;
    if key.len() % 32 != 0 {
        bail!("Chonk verification key is not a whole number of fields");
    }
    let fields: Vec<_> = key
        .chunks(32)
        .map(ark_bn254::Fr::from_be_bytes_mod_order)
        .collect();
    let hash = e3_safe::bb_poseidon2_hash(&fields);
    fs::write(job.join("vk_hash"), hash.into_bigint().to_bytes_be())?;
    Ok(())
}

pub fn refresh_anchors(
    root: &Path,
    pair: &Path,
    complete: bool,
    profile: BfvProfile,
) -> Result<()> {
    let bin = if profile.protocol() == BfvDecryptionProtocol::Synchronized {
        if complete {
            bail!("Synchronized publication/decryption artifacts are incomplete");
        }
        root.join("circuits/bin/synchronized")
    } else {
        root.join("circuits/bin")
    };
    vk_commitments::invalidate(pair)?;
    if profile.protocol() == BfvDecryptionProtocol::Synchronized {
        let stamp = pair.join(".build-stamp.json");
        if stamp.exists() {
            fs::remove_file(stamp)?;
        }
    }
    for name in ANCHORS {
        for path in [published_anchor(pair, name), built_anchor(&bin, name)] {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
    }
    if complete {
        for (name, bytes) in vk_tree::hashes(pair)? {
            for path in [published_anchor(pair, name), built_anchor(&bin, name)] {
                fs::create_dir_all(path.parent().context("Anchor parent")?)?;
                fs::write(path, bytes)?;
            }
        }
    }
    Ok(())
}

pub fn checksums(dir: &Path) -> Result<()> {
    fn files(dir: &Path, base: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "SHA256SUMS" | "checksums.json" | "SOURCE_HASH"
                )
            {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("Artifact symlink: {}", entry.path().display());
            }
            if kind.is_dir() {
                files(&entry.path(), base, out)?;
            } else if kind.is_file() {
                out.insert(
                    entry
                        .path()
                        .strip_prefix(base)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    identity::checksum(&entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut values = BTreeMap::new();
    files(dir, dir, &mut values)?;
    let lines = values
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect::<String>();
    fs::write(dir.join("SHA256SUMS"), lines)?;
    write_json(
        &dir.join("checksums.json"),
        &serde_json::json!({ "algorithm": "sha256", "generated": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true), "files": values }),
    )
}

pub fn build(root: &Path, request: &Request) -> Result<()> {
    // The shared build policy rejects disabled pairs before any tool run or write.
    request.validate(root)?;
    let pairs = request.selected_pairs(root)?;
    let mut selections = Vec::new();
    for selected in pairs {
        let mut selected_request = request.clone();
        selected_request.preset = PresetSelection::Single(profile(&selected[0])?);
        selected_request.committee = CommitteeSelection::Single(selected[1].parse()?);
        let circuits = discover(root, &selected_request)?;
        if circuits.is_empty() {
            bail!(
                "No circuits match the build selection for {}/{}",
                selected[0],
                selected[1]
            );
        }
        selections.push((selected, selected_request, circuits));
    }
    // A dry run only reads the selection; it needs no tools and writes nothing.
    if request.dry_run {
        for (_, _, circuits) in selections {
            for circuit in circuits {
                println!("{}/{}", circuit.group, circuit.name);
            }
        }
        return Ok(());
    }
    let output = request.output_dir(root);
    let mut built = 0;
    let mut errors = Vec::new();
    let mut first_hash = None;
    for (selected, selected_request, circuits) in selections {
        let preset_name = selected[0].as_str();
        let committee = selected[1].as_str();
        let selected_profile = selected_request.single_profile()?;
        let pair = output.join(preset_name).join(committee);
        let mut started = false;
        let result = (|| -> Result<()> {
            let mut selection = configuration::prepare_profile(
                root,
                selected_profile,
                committee.parse()?,
                request.skip_utils_patch,
            )?;
            selection.format(root)?;
            let hash = identity::source_hash_with_updates(
                root,
                &selected_request,
                Some(preset_name),
                Some(committee),
                &selection.noir,
            )?;
            if request.hydrate_bin_only {
                // Hydration copies published artifacts; it runs no compiler and no VK generation.
                let stamp = hydration_stamp(&pair, preset_name, committee, &hash)?;
                selection.publish()?;
                hydrate(root, &pair, &selected_request, &stamp)?;
                first_hash.get_or_insert(stamp.source_hash);
                return Ok(());
            }
            first_hash.get_or_insert(hash.clone());
            if request.skip_if_built && dist_current(&pair, preset_name, committee, Some(&hash))? {
                selection.publish()?;
                if !bin_current(root, preset_name, committee, Some(&hash))? {
                    let stamp = hydration_stamp(&pair, preset_name, committee, &hash)?;
                    hydrate(root, &pair, &selected_request, &stamp)?;
                }
                println!("Reused {preset_name}/{committee} (source_hash={hash})");
                return Ok(());
            }
            // The compilation ahead runs nargo, and bb unless VK generation is skipped. Probe the
            // pinned versions before any destructive build step.
            identity::check_tools(root, true, !request.skip_vk)?;
            started = true;
            vk_commitments::invalidate(&pair)?;
            selection.publish()?;
            if !request.no_clean {
                remove_dir(&pair)?;
            }
            if !request.no_clean_targets {
                clean_targets(root, &circuits)?;
            }
            fs::create_dir_all(&pair)?;
            let mut failures = Vec::new();
            for circuit in &circuits {
                match build_circuit(root, &pair, circuit, request.skip_vk) {
                    Ok(()) => built += 1,
                    Err(error) => {
                        failures.push(format!("{}/{}: {error:#}", circuit.group, circuit.name))
                    }
                }
            }
            let complete = failures.is_empty()
                && !request.skip_vk
                && request.circuits.is_empty()
                && request.groups.is_complete();
            refresh_anchors(root, &pair, complete, selected_profile)?;
            if !failures.is_empty() {
                bail!("{}", failures.join("\n"));
            }
            if selected_profile.protocol() == BfvDecryptionProtocol::Synchronized {
                return Ok(());
            }
            let stamp = Stamp {
                preset: preset_name.into(),
                committee: committee.into(),
                source_hash: hash.clone(),
                built_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            };
            write_json(&pair.join(".build-stamp.json"), &stamp)?;
            if complete {
                let manifest = vk_commitments::collect_pair(&output, preset_name, committee)?;
                vk_commitments::write_pair(&pair, &manifest)?;
            }
            active_stamp(root, preset_name, committee, &hash)
        })();
        if let Err(error) = result {
            if started {
                if let Err(cleanup) = refresh_anchors(root, &pair, false, selected_profile)
                    .and_then(|_| vk_commitments::invalidate(&pair))
                {
                    errors.push(format!("{preset_name}/{committee}: failed to invalidate incomplete outputs: {cleanup:#}"));
                }
            }
            errors.push(format!("{preset_name}/{committee}: {error:#}"));
        }
    }
    if !request.skip_checksums && built > 0 {
        checksums(&output)?;
    }
    github_output(&format!(
        "circuits_built={built}\ncircuits_success={}\nsource_hash={}\nartifacts_dir={}\n",
        errors.is_empty(),
        first_hash.as_deref().unwrap_or("unknown"),
        output.display()
    ))?;
    if !errors.is_empty() {
        bail!("{}", errors.join("\n"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn c2_chunk_circuits_build_only_their_default_key() {
        let circuit = |group: &str, name: &str| Circuit {
            name: name.to_string(),
            group: group.to_string(),
            package: name.to_string(),
            path: PathBuf::new(),
        };
        let names = |circuit: &Circuit| -> Vec<&'static str> {
            variants(circuit)
                .into_iter()
                .map(|(name, ..)| name)
                .collect()
        };
        for chunk in [
            "sk_share_computation_chain",
            "sk_share_computation_chain_last",
            "e_sm_share_computation_chain",
            "e_sm_share_computation_chain_last",
        ] {
            assert_eq!(names(&circuit("dkg", chunk)), ["default"], "{chunk}");
        }
        for final_circuit in ["sk_share_computation", "e_sm_share_computation"] {
            assert_eq!(
                names(&circuit("dkg", final_circuit)),
                ["evm", "default", "recursive"],
                "{final_circuit}"
            );
        }
    }

    #[test]
    fn compiled_artifact_paths_are_portable_idempotent_and_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("compiled.json");
        let artifact = |checkout: &str, cache: &str| {
            serde_json::json!({
                "bytecode": "unchanged", "abi": {"parameters": []},
                "file_map": {
                    "1": {"path": format!("{checkout}/circuits/bin/example/src/main.nr"), "source": "fn main() {}"},
                    "2": {"path": format!("{cache}/github.com/AztecProtocol/aztec-packages/v5.2.0/barretenberg/noir/bb_proof_verification/src/lib.nr")},
                    "3": {"path": "std/field/mod.nr"},
                }
            })
        };
        let mut outputs = Vec::new();
        for (checkout, cache) in [
            ("/Users/alice/worktree", "/Users/alice/nargo"),
            ("/home/runner/work/project", "/home/runner/.nargo"),
            ("C:\\worktree", "C:\\Users\\bob\\nargo"),
            (
                "/home/alice/ghq/github.com/theinterfold/interfold",
                "/home/alice/.nargo",
            ),
            (
                "/home/bob/go/src/github.com/theinterfold/interfold",
                "/home/bob/.nargo",
            ),
        ] {
            fs::write(
                &path,
                serde_json::to_vec(&artifact(checkout, cache)).unwrap(),
            )
            .unwrap();
            sanitize_paths(&path).unwrap();
            let bytes = fs::read(&path).unwrap();
            sanitize_paths(&path).unwrap();
            assert_eq!(fs::read(&path).unwrap(), bytes);
            outputs.push(bytes);
        }
        assert!(outputs.windows(2).all(|pair| pair[0] == pair[1]));
        let mut unknown = artifact("/worktree", "/cache");
        unknown["file_map"]["3"]["path"] = "/unknown/private/library.nr".into();
        let original = serde_json::to_vec(&unknown).unwrap();
        fs::write(&path, &original).unwrap();
        assert!(sanitize_paths(&path)
            .unwrap_err()
            .to_string()
            .contains("Unrecognized absolute"));
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn path_sanitization_preserves_compiler_json_bytes_except_source_paths() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("compiled.json");
        let original = "{\n  \"z\": 1, \"file_map\": {\"1\": {\"source\": \"fn main() {}\", \"path\": \"/checkout/circuits/lib/src/lib.nr\"}},\n  \"abi\": {\"z\": 2, \"a\": 1}\n}\n";
        fs::write(&path, original).unwrap();
        sanitize_paths(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original.replace("/checkout/circuits/", "interfold/circuits/")
        );
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        sanitize_paths(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    }

    fn request() -> Request {
        Request {
            operation: super::super::Operation::Build,
            preset: super::super::PresetSelection::Single(BfvProfile::SsInsecure64),
            committee: super::super::CommitteeSelection::Single(
                e3_committee::CiphernodesCommitteeSize::Minimum,
            ),
            groups: super::super::GroupSelection::All,
            circuits: Vec::new(),
            output: None,
            skip_vk: false,
            skip_checksums: false,
            skip_utils_patch: false,
            no_clean: false,
            no_clean_targets: false,
            skip_if_built: false,
            hydrate_bin_only: false,
            dry_run: false,
        }
    }

    #[test]
    fn synchronized_partial_outputs_never_become_current_or_touch_ss_targets() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        copy_tree(
            &repo.join("circuits/bin/synchronized"),
            &root.join("circuits/bin/synchronized"),
            &["target", "Prover.toml", "Witness.toml"],
        )
        .unwrap();
        let mut selected = request();
        selected.preset = PresetSelection::Single(BfvProfile::SyncDecInsecure64);
        selected.circuits = vec!["pk".into()];
        let circuit = discover(root, &selected).unwrap().remove(0);
        crate::tests::write(
            root,
            "scripts/circuits/build-pairs.json",
            r#"[["sync-insecure-64","minimum"]]"#,
        );
        let before = crate::tests::snapshot(root);
        let mut dry = selected.clone();
        dry.preset = PresetSelection::All;
        dry.committee = CommitteeSelection::All;
        dry.dry_run = true;
        build(root, &dry).unwrap();
        assert_eq!(
            crate::tests::snapshot(root),
            before,
            "wildcard sync dry-run wrote files"
        );
        dry.circuits = vec!["decryption_aggregator".into()];
        assert!(build(root, &dry).is_err());
        assert_eq!(crate::tests::snapshot(root), before);
        let manifest = circuit.path.join("Nargo.toml");
        let original = fs::read(&manifest).unwrap();
        fs::write(&manifest, "[package]\ntype = 'bin'\n").unwrap();
        assert!(
            discover(root, &selected).is_err(),
            "malformed package must not panic"
        );
        fs::write(manifest, original).unwrap();
        for path in [
            "circuits/bin/dkg/target/pk.json",
            "circuits/bin/target/pk.json",
        ] {
            crate::tests::write(root, path, "SS artifact must never be selected or removed");
        }
        assert!(compiled_path(root, &circuit).is_err());
        let target = target_dir(root, &circuit).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("pk.json"), "isolated sync artifact").unwrap();
        assert_eq!(
            compiled_path(root, &circuit).unwrap(),
            target.join("pk.json")
        );
        clean_targets(root, &[circuit]).unwrap();
        assert!(!target.exists());
        assert!(root.join("circuits/bin/dkg/target/pk.json").is_file());
        assert!(root.join("circuits/bin/target/pk.json").is_file());

        let pair = root.join("dist/circuits/sync-insecure-64/minimum");
        let stamp = Stamp {
            preset: "sync-insecure-64".into(),
            committee: "minimum".into(),
            source_hash: "stale".into(),
            built_at: "earlier".into(),
        };
        write_json(&pair.join(".build-stamp.json"), &stamp).unwrap();
        for path in dist_markers(&pair) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "stale SS-shaped marker").unwrap();
        }
        assert!(!dist_current(&pair, "sync-insecure-64", "minimum", None).unwrap());
        assert!(!bin_current(root, "sync-insecure-64", "minimum", None).unwrap());
        assert!(hydration_stamp(&pair, "sync-insecure-64", "minimum", "stale").is_err());
        assert!(hydrate(root, &pair, &selected, &stamp).is_err());
        for name in ["nodes_fold", "c6_fold"] {
            crate::tests::write(
                root,
                &format!("circuits/bin/recursive_aggregation/{name}/target/{name}.vk_tree_hash"),
                "SS anchor",
            );
            crate::tests::write(root, &format!(
                "circuits/bin/synchronized/recursive_aggregation/{name}/target/{name}.vk_tree_hash"), "stale sync anchor");
        }
        crate::tests::write(root, "circuits/bin/.active-preset.json", "SS active stamp");
        let ss = crate::tests::snapshot(&root.join("circuits/bin/recursive_aggregation"));
        refresh_anchors(root, &pair, false, BfvProfile::SyncDecInsecure64).unwrap();
        assert_eq!(
            crate::tests::snapshot(&root.join("circuits/bin/recursive_aggregation")),
            ss
        );
        assert_eq!(
            fs::read(root.join("circuits/bin/.active-preset.json")).unwrap(),
            b"SS active stamp"
        );
        assert!(!pair.join(".build-stamp.json").exists());
        for name in ["nodes_fold", "c6_fold"] {
            assert!(!pair
                .join(format!(
                    "default/recursive_aggregation/{name}/{name}.vk_tree_hash"
                ))
                .exists());
            assert!(!root.join(format!(
                "circuits/bin/synchronized/recursive_aggregation/{name}/target/{name}.vk_tree_hash")).exists());
        }
        assert!(refresh_anchors(root, &pair, true, BfvProfile::SyncDecInsecure64).is_err());
    }

    #[test]
    #[ignore = "requires pinned nargo/bb; builds one tiny isolated sync package and exercises failure cleanup"]
    fn synchronized_partial_build_ignores_stale_stamps_and_cleans_up_on_failure() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        identity::check_tools(&repo, true, true).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        identity::tests::seed_sources(root);
        copy_tree(
            &repo.join("circuits/lib"),
            &root.join("circuits/lib"),
            &["target", "Prover.toml", "Witness.toml"],
        )
        .unwrap();
        let write = |path: &str, content: &str| crate::tests::write(root, path, content);
        write(
            "scripts/circuits/build-pairs.json",
            r#"[["sync-insecure-64","minimum"]]"#,
        );
        write(
            "circuits/bin/synchronized/dkg/Nargo.toml",
            "[workspace]\nmembers = ['pk']\n",
        );
        write(
            "circuits/bin/synchronized/dkg/pk/Nargo.toml",
            "[package]\nname = 'pk'\ntype = 'bin'\nauthors = []\n",
        );
        write(
            "circuits/bin/synchronized/dkg/pk/src/main.nr",
            "fn main(x: Field) -> pub Field { x }\n",
        );
        write("circuits/bin/dkg/target/pk.json", "SS JSON");
        write("circuits/bin/dkg/target/pk.vk_noir", "SS VK");
        write("circuits/bin/.active-preset.json", "SS stamp");
        let ss = crate::tests::snapshot(&root.join("circuits/bin/dkg"));
        let selectors = [
            "circuits/lib/src/configs/default/mod.nr",
            "circuits/lib/src/configs/committee/active.nr",
        ]
        .map(|path| fs::read(root.join(path)).unwrap());
        let mut selected = request();
        selected.preset = PresetSelection::Single(BfvProfile::SyncDecInsecure64);
        selected.circuits = vec!["pk".into()];
        selected.no_clean = true;
        selected.no_clean_targets = true;
        selected.skip_if_built = true;
        let pair = root.join("dist/circuits/sync-insecure-64/minimum");
        let mut projection = configuration::prepare_profile(
            root,
            BfvProfile::SyncDecInsecure64,
            e3_committee::CiphernodesCommitteeSize::Minimum,
            true,
        )
        .unwrap();
        projection.format(root).unwrap();
        let hash =
            identity::source_hash(root, &selected, Some("sync-insecure-64"), Some("minimum"))
                .unwrap();
        assert_eq!(
            hash,
            identity::source_hash_with_updates(
                root,
                &selected,
                Some("sync-insecure-64"),
                Some("minimum"),
                &projection.noir,
            )
            .unwrap(),
            "sync hash and formatted build projection disagree"
        );
        let stale = Stamp {
            preset: "sync-insecure-64".into(),
            committee: "minimum".into(),
            source_hash: hash,
            built_at: "earlier".into(),
        };
        write_json(&pair.join(".build-stamp.json"), &stale).unwrap();
        for path in dist_markers(&pair) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "stale complete marker").unwrap();
        }
        super::super::execute(root, &selected).unwrap();
        assert!(!pair.join(".build-stamp.json").exists());
        assert!(
            pair.join("recursive/dkg/pk/pk.vk").is_file(),
            "cache skipped fresh compilation"
        );
        assert_eq!(crate::tests::snapshot(&root.join("circuits/bin/dkg")), ss);
        assert_eq!(
            fs::read(root.join("circuits/bin/.active-preset.json")).unwrap(),
            b"SS stamp"
        );
        for (path, expected) in [
            "circuits/lib/src/configs/default/mod.nr",
            "circuits/lib/src/configs/committee/active.nr",
        ]
        .into_iter()
        .zip(selectors)
        {
            assert_eq!(fs::read(root.join(path)).unwrap(), expected);
        }
        // Compile failure after a build has started must invalidate both anchors and the stale stamp.
        write_json(&pair.join(".build-stamp.json"), &stale).unwrap();
        for name in ["nodes_fold", "c6_fold"] {
            write(&format!("dist/circuits/sync-insecure-64/minimum/default/recursive_aggregation/{name}/{name}.vk_tree_hash"), "stale");
            write(&format!("circuits/bin/synchronized/recursive_aggregation/{name}/target/{name}.vk_tree_hash"), "stale");
        }
        write(
            "circuits/bin/synchronized/dkg/pk/src/main.nr",
            "fn main(x: Field) -> pub Field { missing(x) }\n",
        );
        assert!(super::super::execute(root, &selected).is_err());
        assert!(!pair.join(".build-stamp.json").exists());
        for name in ["nodes_fold", "c6_fold"] {
            assert!(!pair
                .join(format!(
                    "default/recursive_aggregation/{name}/{name}.vk_tree_hash"
                ))
                .exists());
            assert!(!root.join(format!("circuits/bin/synchronized/recursive_aggregation/{name}/target/{name}.vk_tree_hash")).exists());
        }
        assert_eq!(crate::tests::snapshot(&root.join("circuits/bin/dkg")), ss);
    }

    #[test]
    #[ignore = "requires the pinned nargo and bb binaries; compiles only two tiny temporary circuits"]
    fn selected_generation_and_tool_commands_preserve_repository_contracts() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        identity::check_tools(&repo, true, true).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        identity::tests::seed_sources(root);
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::write(
            root.join("scripts/circuits/build-pairs.json"),
            r#"[["insecure-64","minimum"],["secure-8192","minimum"]]"#,
        )
        .unwrap();
        copy_tree(
            &repo.join("circuits/lib"),
            &root.join("circuits/lib"),
            &["target", "Prover.toml", "Witness.toml"],
        )
        .unwrap();
        let utils = Path::new("packages/interfold-contracts/scripts/utils.ts");
        fs::create_dir_all(root.join(utils).parent().unwrap()).unwrap();
        fs::copy(repo.join(utils), root.join(utils)).unwrap();
        let mut selection = configuration::prepare_selection(
            root,
            e3_fhe_params::BfvPreset::InsecureThreshold64,
            e3_committee::CiphernodesCommitteeSize::Minimum,
            false,
        )
        .unwrap();
        selection.format(root).unwrap();
        selection.publish().unwrap();
        for relative in [
            "circuits/lib/src/configs/committee/active.nr",
            "circuits/lib/src/configs/insecure/dkg.nr",
            "circuits/lib/src/configs/insecure/threshold.nr",
        ] {
            assert_eq!(
                fs::read(root.join(relative)).unwrap(),
                fs::read(repo.join(relative)).unwrap(),
                "generated bytes for {relative}"
            );
        }
        // A repeated sync must not invoke even a version probe, or rewrite formatted files.
        fs::remove_dir_all(root.join("crates/zk/prover")).unwrap();
        let before = crate::tests::snapshot(root);
        let mut selection = configuration::prepare_selection(
            root,
            BfvPreset::InsecureThreshold64,
            e3_committee::CiphernodesCommitteeSize::Minimum,
            false,
        )
        .unwrap();
        selection.format(root).unwrap();
        selection.publish().unwrap();
        assert_eq!(crate::tests::snapshot(root), before);
        crate::tests::write_pins(root);

        let pair = root.join("dist/circuits/insecure-64/minimum");
        for (group, name) in [("dkg", "pk"), ("threshold", "pk_generation")] {
            let path = root.join("circuits/bin").join(group).join(name);
            fs::create_dir_all(path.join("src")).unwrap();
            fs::write(
                path.join("Nargo.toml"),
                format!("[package]\nname = \"{name}\"\ntype = \"bin\"\nauthors = []\n"),
            )
            .unwrap();
            fs::write(
                path.join("src/main.nr"),
                "fn main(x: Field, y: Field) -> pub Field { x + y }\n",
            )
            .unwrap();
            if group == "dkg" {
                fs::write(
                    path.parent().unwrap().join("Nargo.toml"),
                    "[workspace]\nmembers = [\"pk\"]\n",
                )
                .unwrap();
            }
        }
        // A BB pin failure must precede publication of a different generated selection.
        fs::write(
            root.join("crates/zk/prover/versions.json"),
            r#"{"required_bb_version":"0.0.0-preflight-invalid"}"#,
        )
        .unwrap();
        let before = crate::tests::snapshot(root);
        let mut bad_bb = request();
        bad_bb.preset = super::super::PresetSelection::Single(BfvProfile::SsSecure8192);
        let error = super::super::execute(root, &bad_bb).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bb must be pinned version 0.0.0-preflight-invalid"),
            "{error:#}"
        );
        assert_eq!(
            crate::tests::snapshot(root),
            before,
            "BB pin failure published generated files"
        );
        crate::tests::write_pins(root);
        // Complete stale keys can recreate valid anchors unless the actual build treats the
        // duplicate-group selection as partial. Keep both dist and bin targets uncleared.
        crate::tests::seed_anchor_keys(&pair);
        refresh_anchors(root, &pair, true, BfvProfile::SsInsecure64).unwrap();
        let mut partial = request();
        partial.groups = super::super::GroupSelection::Selected(vec![
            super::super::Group::Dkg,
            super::super::Group::Dkg,
            super::super::Group::Threshold,
        ]);
        partial.no_clean = true;
        partial.no_clean_targets = true;
        super::super::execute(root, &partial).unwrap();
        for name in ["nodes_fold", "c6_fold"] {
            assert!(
                !pair
                    .join(format!(
                        "default/recursive_aggregation/{name}/{name}.vk_tree_hash"
                    ))
                    .exists(),
                "partial build retained {name} anchor"
            );
            assert!(!root
                .join(format!(
                    "circuits/bin/recursive_aggregation/{name}/target/{name}.vk_tree_hash"
                ))
                .exists());
        }
        assert_eq!(
            discover(root, &partial).unwrap().len(),
            2,
            "duplicate groups compiled twice"
        );
        let before = crate::tests::snapshot(root);
        vk_commitments::qualify(root, &partial).unwrap();
        assert_eq!(crate::tests::snapshot(root), before);
        let key = pair.join("evm/dkg/pk/pk.vk");
        let original_key = fs::read(&key).unwrap();
        fs::write(&key, "stale key").unwrap();
        assert!(vk_commitments::qualify(root, &partial)
            .unwrap_err()
            .to_string()
            .contains("VK bytes differ"));
        fs::write(&key, original_key).unwrap();
        for circuit in discover(root, &request()).unwrap() {
            let target = target_dir(root, &circuit).unwrap();
            for (variant, _, extension) in variants(&circuit) {
                let dist = pair.join(variant).join(&circuit.group).join(&circuit.name);
                assert_eq!(
                    fs::read(target.join(format!("{}.{extension}", circuit.package))).unwrap(),
                    fs::read(dist.join(format!("{}.vk", circuit.package))).unwrap()
                );
                let key_hash = fs::read(dist.join(format!("{}.vk_hash", circuit.package))).unwrap();
                assert_eq!(key_hash.len(), 32);
                assert!(
                    fs::metadata(dist.join(format!("{}.vk", circuit.package)))
                        .unwrap()
                        .len()
                        > 0
                );
                assert_eq!(
                    fs::read(dist.join(format!("{}.json", circuit.package))).unwrap(),
                    fs::read(target.join(format!("{}.json", circuit.package))).unwrap()
                );
            }
        }
        checksums(&root.join("dist/circuits")).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("dist/circuits/checksums.json")).unwrap())
                .unwrap();
        // The json, vk and vk_hash of pk and pk_generation in three variants (18), plus the 27
        // seeded anchor keys the build does not write.
        assert_eq!(manifest["files"].as_object().unwrap().len(), 45);
        let hash =
            identity::source_hash(root, &request(), Some("insecure-64"), Some("minimum")).unwrap();
        let built_stamp = read_stamp(&pair.join(".build-stamp.json"))
            .unwrap()
            .unwrap();
        assert_eq!(
            built_stamp.source_hash, hash,
            "staged source identity differs from published sources"
        );

        // Cache reuse and non-release hydration need neither compiler nor BB probes. Invalid pins
        // make an accidental probe fail without changing process-wide environment variables.
        fs::write(
            root.join("crates/zk/prover/Cargo.toml"),
            "nargo = { git = \"https://github.com/noir-lang/noir\", tag = \"v0.0.0-invalid\" }\n",
        )
        .unwrap();
        fs::write(
            root.join("crates/zk/prover/versions.json"),
            r#"{"required_bb_version":"0.0.0-invalid"}"#,
        )
        .unwrap();
        // The Chonk workspace exists before the markers are placed, so its markers land in the
        // workspace target, where nargo writes them.
        let chonk = root.join("circuits/bin/chonk");
        fs::create_dir_all(chonk.join("c3_chonk_app/src")).unwrap();
        fs::write(
            chonk.join("Nargo.toml"),
            "[workspace]\nmembers = [\"c3_chonk_app\"]\n",
        )
        .unwrap();
        fs::write(
            chonk.join("c3_chonk_app/Nargo.toml"),
            "[package]\nname = \"c3_chonk_app\"\ntype = \"bin\"\nauthors = []\n",
        )
        .unwrap();
        fs::write(
            chonk.join("c3_chonk_app/src/main.nr"),
            "fn main(x: Field, y: Field) -> pub Field { x + y }\n",
        )
        .unwrap();
        for marker in dist_markers(&pair)
            .into_iter()
            .chain(bin_markers(root).unwrap())
        {
            if !marker.exists() {
                fs::create_dir_all(marker.parent().unwrap()).unwrap();
                fs::write(marker, "published marker").unwrap();
            }
        }
        let hash =
            identity::source_hash(root, &request(), Some("insecure-64"), Some("minimum")).unwrap();
        let mut stamp = Stamp {
            preset: "insecure-64".into(),
            committee: "minimum".into(),
            source_hash: hash.clone(),
            built_at: "published-time".into(),
        };
        write_json(&pair.join(".build-stamp.json"), &stamp).unwrap();
        active_stamp(root, "insecure-64", "minimum", &hash).unwrap();
        let mut reuse = request();
        reuse.skip_if_built = true;
        let before = crate::tests::snapshot(root);
        super::super::execute(root, &reuse).unwrap();
        assert_eq!(
            crate::tests::snapshot(root),
            before,
            "cache reuse wrote current files"
        );

        stamp.source_hash = "published-source".into();
        write_json(&pair.join(".build-stamp.json"), &stamp).unwrap();
        let before = crate::tests::snapshot(root);
        let error = super::super::execute(root, &reuse).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("nargo must be pinned version 0.0.0-invalid"),
            "{error:#}"
        );
        assert_eq!(
            crate::tests::snapshot(root),
            before,
            "source-mismatched cache bypassed preflight"
        );
        let archived = fs::read(pair.join(".build-stamp.json")).unwrap();
        let mut hydration = request();
        hydration.hydrate_bin_only = true;
        super::super::execute(root, &hydration).unwrap();
        assert_eq!(
            read_stamp(&root.join("circuits/bin/.active-preset.json"))
                .unwrap()
                .unwrap()
                .source_hash,
            "published-source"
        );
        assert_eq!(fs::read(pair.join(".build-stamp.json")).unwrap(), archived);

        // A Chonk circuit is built with `write_vk --scheme chonk`, which writes no hash. The
        // qualification must derive its key and hash the way the build does.
        crate::tests::write_pins(root);
        let mut only_chonk = request();
        only_chonk.groups =
            super::super::GroupSelection::Selected(vec![super::super::Group::Chonk]);
        only_chonk.no_clean = true;
        only_chonk.no_clean_targets = true;
        super::super::execute(root, &only_chonk).unwrap();
        let built = pair.join("default/chonk/c3_chonk_app");
        assert_eq!(
            fs::read(built.join("c3_chonk_app.vk_hash")).unwrap().len(),
            32
        );
        vk_commitments::qualify(root, &only_chonk).unwrap();
        let hash = built.join("c3_chonk_app.vk_hash");
        fs::write(&hash, [0; 32]).unwrap();
        assert!(vk_commitments::qualify(root, &only_chonk)
            .unwrap_err()
            .to_string()
            .contains("VK hash differs"));
    }
}
