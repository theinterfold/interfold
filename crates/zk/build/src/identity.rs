// SPDX-License-Identifier: LGPL-3.0-only

use super::{artifacts, configuration, preset, run, tier, Request};
pub use crate::reports_version;
use anyhow::{bail, Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

const SOURCE_DIRS: &[&str] = &[
    "circuits/lib/src/core",
    "circuits/lib/src/math",
    "crates/zk/config/src",
    "crates/zk/build/src",
    "crates/zk/build/templates",
    "crates/zk/witness/src",
    "crates/committee/src",
    "crates/fhe-params/src",
    "crates/fhe/src",
    "crates/polynomial/src",
    "crates/polynomial/fhe-adapter/src",
    "crates/parity-matrix/src",
    "crates/safe/src",
];
const SOURCE_FILES: &[&str] = &[
    "circuits/lib/Nargo.toml",
    "circuits/lib/src/lib.nr",
    "circuits/lib/src/configs/mod.nr",
    "circuits/lib/src/configs/protocol.nr",
    "circuits/lib/src/configs/committee/mod.nr",
    "circuits/lib/src/configs/default/mod.nr",
    "crates/zk/build/Cargo.toml",
    "scripts/circuits/constants.ts",
    "scripts/circuits/build-pairs.json",
    "packages/interfold-contracts/scripts/protocol/constants.ts",
    "packages/interfold-contracts/bfv.ts",
    "packages/interfold-contracts/crypto-config.json",
    "Cargo.lock",
];

pub fn toolchain(root: &Path) -> Result<(String, String)> {
    let manifest_path = root.join("crates/zk/prover/Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("Read pinned prover manifest {}", manifest_path.display()))?;
    let tag = crate::pinned_noir_version(&manifest)?;
    let versions_path = root.join("crates/zk/prover/versions.json");
    let versions: serde_json::Value = serde_json::from_slice(
        &fs::read(&versions_path)
            .with_context(|| format!("Read pinned tool versions {}", versions_path.display()))?,
    )?;
    let bb = versions["required_bb_version"]
        .as_str()
        .context("No pinned bb version")?
        .to_string();
    Ok((tag, bb))
}

/// Verify the pinned tool versions for the tools an operation will actually invoke. Operations
/// that only read or compare files call this with both flags cleared and run no tool.
pub fn check_tools(root: &Path, need_nargo: bool, need_bb: bool) -> Result<()> {
    let (nargo, bb) = toolchain(root)?;
    for (tool, version, needed) in [("nargo", nargo, need_nargo), ("bb", bb, need_bb)] {
        if !needed {
            continue;
        }
        let output = run(Command::new(tool).arg("--version"))?;
        if !reports_version(&output, &version) {
            bail!(
                "{tool} must be pinned version {version}; observed {}",
                output.trim()
            );
        }
    }
    Ok(())
}

pub fn stage_sources(root: &Path, destination: &Path) -> Result<()> {
    for directory in SOURCE_DIRS.iter().copied().chain([
        "circuits/lib",
        "circuits/bin",
        "packages/interfold-contracts/contracts/verifiers/bfv/honk",
    ]) {
        artifacts::copy_tree(
            &root.join(directory),
            &destination.join(directory),
            &["target", "Prover.toml", "Witness.toml"],
        )?;
    }
    for file in SOURCE_FILES.iter().copied().chain([
        "crates/zk/prover/Cargo.toml",
        "crates/zk/prover/versions.json",
        "crates/zk/prover/supported-configurations.json",
        "packages/interfold-contracts/scripts/utils.ts",
    ]) {
        let path = destination.join(file);
        fs::create_dir_all(path.parent().context("Staged source parent")?)?;
        fs::copy(root.join(file), path)?;
    }
    Ok(())
}

pub fn strip_test_modules(source: &str) -> String {
    let lines: Vec<_> = source.split('\n').collect();
    let attribute = Regex::new(r"^(\s*)#\[cfg\(test\)\]\s*$").unwrap();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(capture) = attribute.captures(lines[i]) {
            let indent = &capture[1];
            let external_module = Regex::new(&format!(
                r"^{}(?:pub(?:\([^)]*\))?\s+)?mod \w+;\s*$",
                regex::escape(indent)
            ))
            .unwrap();
            if lines
                .get(i + 1)
                .is_some_and(|line| external_module.is_match(line))
            {
                i += 2;
                continue;
            }
            let module = Regex::new(&format!(
                r"^{}(?:pub(?:\([^)]*\))?\s+)?mod \w+ \{{\s*$",
                regex::escape(indent)
            ))
            .unwrap();
            if lines.get(i + 1).is_some_and(|line| module.is_match(line)) {
                if let Some(end) =
                    (i + 2..lines.len()).find(|&end| lines[end] == format!("{indent}}}"))
                {
                    i = end + 1;
                    continue;
                }
            }
        }
        kept.push(lines[i]);
        i += 1;
    }
    kept.join("\n")
}

pub fn external_pins(source: &str) -> Result<String> {
    let lock: toml::Value = toml::from_str(source)?;
    let mut pins = Vec::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let string = |key: &str| package.get(key).and_then(toml::Value::as_str).unwrap_or("");
        if !string("source").is_empty() {
            pins.push(format!(
                "{} {} {} {}\n",
                string("name"),
                string("version"),
                string("source"),
                string("checksum")
            ));
        }
    }
    pins.sort();
    Ok(pins.concat())
}

// Dependency versions and workspace edges are not generator inputs. Feature selections are.
fn generator_manifest(source: &str) -> Result<String> {
    let manifest: toml::Value = toml::from_str(source)?;
    let mut inputs = std::collections::BTreeMap::new();
    if let Some(features) = manifest.get("features") {
        inputs.insert("features".to_string(), features.clone());
    }
    if let Some(package) = manifest.get("package") {
        for key in ["edition", "rust-version"] {
            if let Some(value) = package.get(key) {
                inputs.insert(format!("package.{key}"), value.clone());
            }
        }
    }
    for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
        for (name, dependency) in manifest
            .get(table)
            .and_then(toml::Value::as_table)
            .into_iter()
            .flatten()
        {
            for option in ["features", "default-features", "optional"] {
                if let Some(value) = dependency.get(option) {
                    inputs.insert(format!("{table}.{name}.{option}"), value.clone());
                }
            }
        }
    }
    Ok(toml::to_string(&inputs)?)
}

/// Frame source records with a one-byte tag and big-endian u64 lengths for the name and content.
fn hash_record(hash: &mut Sha256, tag: u8, name: &str, contents: &[u8]) {
    hash.update([tag]);
    hash.update((name.len() as u64).to_be_bytes());
    hash.update(name.as_bytes());
    hash.update((contents.len() as u64).to_be_bytes());
    hash.update(contents);
}

fn hash_dir(
    root: &Path,
    path: &Path,
    hash: &mut Sha256,
    relative: &str,
    bounds: bool,
    updates: &[(PathBuf, String)],
) -> Result<()> {
    let directory = path
        .strip_prefix(root)?
        .to_str()
        .context("Source directory path must be UTF-8")?;
    hash_record(hash, b'd', directory, b"");
    let mut entries: std::collections::BTreeSet<_> = fs::read_dir(path)
        .with_context(|| format!("Read required source directory {directory}"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?;
    entries.extend(
        updates
            .iter()
            .filter(|(file, _)| file.parent() == Some(path))
            .map(|(file, _)| file.clone()),
    );
    for entry in entries {
        let name = entry
            .file_name()
            .context("Source file name")?
            .to_string_lossy()
            .into_owned();
        // This separate suite is not compiled into the generator example.
        if name.starts_with('.')
            || matches!(name.as_str(), "target" | "Prover.toml" | "Witness.toml")
            || (path.ends_with("crates/zk/build/src") && name == "tests.rs")
        {
            continue;
        }
        let relative = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if entry.is_symlink() {
            bail!(
                "Generator source must not be a symlink: {}",
                entry.display()
            );
        }
        if entry.is_dir() {
            hash_dir(root, &entry, hash, &relative, bounds, updates)?;
        } else if entry.is_file() || updates.iter().any(|(path, _)| path == &entry) {
            let mut bytes = match updates.iter().find(|(path, _)| path == &entry) {
                Some((_, text)) => text.as_bytes().to_vec(),
                None => fs::read(&entry)?,
            };
            if bounds {
                if let Some((_, prefix)) = configuration::BOUND_SOURCES
                    .iter()
                    .find(|(file, _)| *file == relative)
                {
                    let mut text = String::from_utf8(bytes)?;
                    for (name, declaration) in configuration::declarations(&text) {
                        if name.starts_with(prefix) {
                            text = text.replacen(
                                &declaration,
                                &format!("pub global {name}:<generated>;"),
                                1,
                            );
                        }
                    }
                    bytes = text.into_bytes();
                }
            }
            if name.ends_with(".rs") {
                bytes = strip_test_modules(std::str::from_utf8(&bytes)?).into_bytes();
            }
            let file = entry
                .strip_prefix(root)?
                .to_str()
                .context("Source file path must be UTF-8")?;
            hash_record(hash, b'f', file, &bytes);
        }
    }
    Ok(())
}

pub fn source_hash(
    root: &Path,
    request: &Request,
    selected_preset: Option<&str>,
    committee: Option<&str>,
) -> Result<String> {
    source_hash_with_updates(root, request, selected_preset, committee, &[])
}

/// Hash the selected generated sources without publishing them to the live tree.
pub fn source_hash_with_updates(
    root: &Path,
    request: &Request,
    selected_preset: Option<&str>,
    committee: Option<&str>,
    updates: &[(PathBuf, String)],
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"interfold:zk-source:v2\0");
    if let Some(name) = selected_preset {
        let tier = tier(preset(name)?);
        hash_record(&mut hash, b'p', name, tier.as_bytes());
        hash_dir(
            root,
            &root.join("circuits/lib/src/configs").join(tier),
            &mut hash,
            "",
            true,
            updates,
        )?;
    }
    if let Some(name) = committee {
        hash_record(&mut hash, b'c', name, b"");
        hash_dir(
            root,
            &root.join("circuits/lib/src/configs/committee").join(name),
            &mut hash,
            "",
            false,
            updates,
        )?;
    }
    let mut circuits = artifacts::discover(root, request)?;
    circuits.sort_by(|left, right| left.path.cmp(&right.path));
    for circuit in circuits {
        hash_dir(root, &circuit.path, &mut hash, "", false, updates)?;
    }
    for path in SOURCE_DIRS {
        hash_dir(root, &root.join(path), &mut hash, "", false, updates)?;
    }
    let (nargo, bb) = toolchain(root)?;
    hash_record(&mut hash, b't', "nargo", nargo.as_bytes());
    hash_record(&mut hash, b't', "bb", bb.as_bytes());
    for &path in SOURCE_FILES {
        let mut source = match updates.iter().find(|(file, _)| *file == root.join(path)) {
            Some((_, text)) => text.clone(),
            None => fs::read_to_string(root.join(path))
                .with_context(|| format!("Read required source file {path}"))?,
        };
        if path == "circuits/lib/src/configs/default/mod.nr" {
            source = Regex::new(r"preset: (insecure-64|secure-8192)")?
                .replace_all(&source, "preset: <selected>")
                .into_owned();
            source = Regex::new(r"super::(insecure|secure)::")?
                .replace_all(&source, "super::<selected>::")
                .into_owned();
            // Noir sorts imports lexically: `protocol` follows `insecure`, but precedes `secure`.
            // Normalize that incidental order after masking the selected preset name.
            let imports = Regex::new(r"(?m)^pub use [^;\n]+;$")?;
            let mut ordered = imports
                .find_iter(&source)
                .map(|item| item.as_str().to_owned())
                .collect::<Vec<_>>();
            ordered.sort();
            let mut ordered = ordered.into_iter();
            source = imports
                .replace_all(&source, |_: &regex::Captures| ordered.next().unwrap())
                .into_owned();
        }
        if path == "Cargo.lock" {
            source = external_pins(&source)?;
        }
        if path == "crates/zk/build/Cargo.toml" {
            source = generator_manifest(&source)?;
        }
        hash_record(&mut hash, b'f', path, source.as_bytes());
    }
    Ok(hex::encode(hash.finalize())[..16].to_string())
}

/// SHA-256 of one file, read through a fixed buffer. The digest is the artifact checksum that
/// `SHA256SUMS` and `checksums.json` record.
pub fn checksum(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn seed_sources(root: &Path) {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        for path in SOURCE_DIRS.iter().copied().chain([
            "circuits/lib/src/configs/insecure",
            "circuits/lib/src/configs/committee/minimum",
            "circuits/lib/src/configs/committee/micro",
        ]) {
            assert!(
                repo.join(path).is_dir(),
                "Missing repository source directory {path}"
            );
            fs::create_dir_all(root.join(path)).unwrap();
        }
        for path in SOURCE_FILES {
            let dest = root.join(path);
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            if !dest.exists() {
                fs::copy(repo.join(path), dest).unwrap();
            }
        }
        crate::tests::write_pins(root);
    }

    #[test]
    fn source_identity_requires_every_input_and_accepts_projected_generated_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repository");
        seed_sources(&root);
        let request = crate::tests::request();
        let hash = || source_hash(&root, &request, Some("insecure-64"), Some("minimum"));
        hash().unwrap();
        for path in SOURCE_DIRS.iter().chain(SOURCE_FILES).copied().chain([
            "circuits/lib/src/configs/insecure",
            "circuits/lib/src/configs/committee/minimum",
            "crates/zk/prover/Cargo.toml",
            "crates/zk/prover/versions.json",
        ]) {
            let source = root.join(path);
            let absent = temp.path().join("absent");
            fs::rename(&source, &absent).unwrap();
            let result = hash();
            fs::rename(&absent, &source).unwrap();
            let error = result.expect_err(path);
            assert!(format!("{error:#}").contains(path), "{path}: {error:#}");
        }
        for relative in [
            "circuits/lib/src/configs/default/mod.nr",
            crate::bindings::NOIR_PATH,
        ] {
            let path = root.join(relative);
            let contents = fs::read_to_string(&path).unwrap();
            let expected = hash().unwrap();
            fs::remove_file(&path).unwrap();
            assert_eq!(
                source_hash_with_updates(
                    &root,
                    &request,
                    Some("insecure-64"),
                    Some("minimum"),
                    &[(path.clone(), contents.clone())]
                )
                .unwrap(),
                expected
            );
            fs::write(&path, format!("{contents}\n// changed protocol source\n")).unwrap();
            assert_ne!(hash().unwrap(), expected);
            fs::write(path, contents).unwrap();
        }
    }

    #[test]
    fn source_identity_is_independent_of_group_selection_order() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        seed_sources(root);
        for group in ["dkg", "threshold", "recursive_aggregation"] {
            let package = root.join("circuits/bin").join(group).join("example");
            fs::create_dir_all(&package).unwrap();
            fs::write(package.join("Nargo.toml"), "[package]\nname = 'example'\n").unwrap();
        }
        let mut request = crate::tests::request();
        let expected = source_hash(root, &request, Some("insecure-64"), Some("minimum")).unwrap();
        request.groups = crate::GroupSelection::Selected(vec![
            crate::Group::Threshold,
            crate::Group::RecursiveAggregation,
            crate::Group::Dkg,
            crate::Group::Threshold,
        ]);
        assert_eq!(
            source_hash(root, &request, Some("insecure-64"), Some("minimum")).unwrap(),
            expected
        );
    }
}
