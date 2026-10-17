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

pub fn toolchain(root: &Path) -> Result<(String, String)> {
    let manifest_path = root.join("crates/zk-prover/Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("Read pinned prover manifest {}", manifest_path.display()))?;
    let tag = crate::pinned_noir_version(&manifest)?;
    let versions_path = root.join("crates/zk-prover/versions.json");
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

pub fn strip_test_modules(source: &str) -> String {
    let lines: Vec<_> = source.split('\n').collect();
    let attribute = Regex::new(r"^(\s*)#\[cfg\(test\)\]\s*$").unwrap();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(capture) = attribute.captures(lines[i]) {
            let indent = &capture[1];
            let external_module =
                Regex::new(&format!(r"^{}mod \w+;\s*$", regex::escape(indent))).unwrap();
            if lines
                .get(i + 1)
                .is_some_and(|line| external_module.is_match(line))
            {
                i += 2;
                continue;
            }
            let module =
                Regex::new(&format!(r"^{}mod \w+ \{{\s*$", regex::escape(indent))).unwrap();
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

fn hash_dir(
    path: &Path,
    hash: &mut Sha256,
    relative: &str,
    bounds: bool,
    updates: &[(PathBuf, String)],
) -> Result<()> {
    let mut entries: std::collections::BTreeSet<_> = if path.exists() {
        fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()?
    } else {
        Default::default()
    };
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
            hash.update(format!("{relative}/"));
            hash_dir(&entry, hash, &relative, bounds, updates)?;
        } else if entry.is_file() || updates.iter().any(|(path, _)| path == &entry) {
            hash.update(&relative);
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
            hash.update(bytes);
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
    if let Some(name) = selected_preset {
        let tier = tier(preset(name)?);
        hash.update(format!("preset:{name}\nnoir_config:{tier}\n"));
        hash_dir(
            &root.join("circuits/lib/src/configs").join(tier),
            &mut hash,
            "",
            true,
            updates,
        )?;
    }
    if let Some(name) = committee {
        hash.update(format!("committee:{name}\n"));
        hash_dir(
            &root.join("circuits/lib/src/configs/committee").join(name),
            &mut hash,
            "",
            false,
            updates,
        )?;
    }
    for circuit in artifacts::discover(root, request)? {
        hash_dir(&circuit.path, &mut hash, "", false, updates)?;
    }
    for path in [
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
    ] {
        hash_dir(&root.join(path), &mut hash, "", false, updates)?;
    }
    if root.join("crates/zk-prover/Cargo.toml").exists()
        && root.join("crates/zk-prover/versions.json").exists()
    {
        let (nargo, bb) = toolchain(root)?;
        hash.update(format!("toolchain:nargo {nargo} bb {bb}\n"));
    }
    for path in [
        "circuits/lib/Nargo.toml",
        "circuits/lib/src/lib.nr",
        "circuits/lib/src/configs/mod.nr",
        "circuits/lib/src/configs/committee/mod.nr",
        "circuits/lib/src/configs/default/mod.nr",
        "crates/zk/build/Cargo.toml",
        "scripts/circuit-constants.ts",
        "scripts/circuit-build-pairs.json",
        "packages/interfold-contracts/scripts/protocol/constants.ts",
        "Cargo.lock",
    ] {
        if !root.join(path).exists() && !updates.iter().any(|(file, _)| *file == root.join(path)) {
            continue;
        }
        hash.update(path);
        let mut source = match updates.iter().find(|(file, _)| *file == root.join(path)) {
            Some((_, text)) => text.clone(),
            None => fs::read_to_string(root.join(path))?,
        };
        if path == "circuits/lib/src/configs/default/mod.nr" {
            source = Regex::new(r"preset: (insecure-64|secure-8192)")?
                .replace_all(&source, "preset: <selected>")
                .into_owned();
            source = Regex::new(r"super::(insecure|secure)::")?
                .replace_all(&source, "super::<selected>::")
                .into_owned();
        }
        if path == "Cargo.lock" {
            source = external_pins(&source)?;
        }
        if path == "crates/zk/build/Cargo.toml" {
            source = generator_manifest(&source)?;
        }
        hash.update(source);
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
