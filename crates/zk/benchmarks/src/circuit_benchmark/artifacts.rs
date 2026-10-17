// SPDX-License-Identifier: LGPL-3.0-only

use super::{records::ArtifactIdentity, selection::Case};
use anyhow::{bail, Context, Result};
use e3_zk_prover::{CompiledCircuit, ZkProver};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

const CONFIG_STAMP: &str = ".config-benchmark.json";

/// File digest shared with the artifact checksums manifest.
pub(crate) fn digest(path: &Path) -> Result<String> {
    e3_zk_build::checksum(path)
}

fn config_directory(root: &Path) -> PathBuf {
    root.join("circuits/bin/config/target")
}

fn config_package_name(root: &Path) -> Result<String> {
    let manifest: toml::Value = toml::from_str(&fs::read_to_string(
        root.join("circuits/bin/config/Nargo.toml"),
    )?)?;
    Ok(manifest["package"]["name"]
        .as_str()
        .context("Config Nargo manifest has no package name")?
        .to_owned())
}

fn config_sources(root: &Path) -> Result<String> {
    fn walk(root: &Path, directory: &Path, hash: &mut Sha256) -> Result<()> {
        let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.')
                || ["target", "Prover.toml", "Witness.toml"]
                    .contains(&name.to_string_lossy().as_ref())
            {
                continue;
            }
            if entry.file_type()?.is_symlink() {
                bail!(
                    "Config source must not be a symlink: {}",
                    entry.path().display()
                );
            }
            if entry.file_type()?.is_dir() {
                walk(root, &entry.path(), hash)?;
            } else {
                hash.update(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_string_lossy()
                        .as_bytes(),
                );
                hash.update(fs::read(entry.path())?);
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    for path in ["circuits/bin/config", "circuits/lib"] {
        walk(root, &root.join(path), &mut hash)?;
    }
    Ok(hex::encode(hash.finalize()))
}

pub(crate) fn compile_config(root: &Path, pair: &str, noir_pin: &str) -> Result<()> {
    let (preset, committee) = pair.split_once('/').context("Config pair identity")?;
    let active: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("circuits/bin/.active-preset.json"))?)?;
    if active["preset"] != preset || active["committee"] != committee {
        bail!("Select {pair} with pnpm build:circuits --hydrate-bin-only before compiling config");
    }
    let directory = config_directory(root);
    let package_name = config_package_name(root)?;
    let stamp = directory.join(CONFIG_STAMP);
    if stamp.exists() {
        fs::remove_file(&stamp)?;
    }
    let source = config_sources(root)?;
    super::run(
        std::process::Command::new("nargo")
            .arg("compile")
            .current_dir(root.join("circuits/bin/config")),
    )?;
    if config_sources(root)? != source {
        bail!("Config sources changed during compilation");
    }
    let compiled = directory.join(format!("{package_name}.json"));
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&compiled)?)?;
    let version = document["noir_version"]
        .as_str()
        .context("Config compiler version")?;
    if !e3_zk_build::reports_version(version, noir_pin) {
        bail!("Config compiler does not match Rust Noir {noir_pin}");
    }
    super::write_json(
        &stamp,
        &serde_json::json!({"schema_version":1,"preset":preset,"committee":committee,"sourceHash":source,"source_origin":"fresh_local_noir_compile","compiler_version":version,"compiled_sha256":digest(&compiled)?,"vk_sha256":{}}),
    )
}

pub(crate) fn bind_config_vk(
    root: &Path,
    compiled: &Path,
    variant: e3_zk_prover::CircuitVariant,
    generated: &Path,
    cached: &Path,
) -> Result<serde_json::Value> {
    let stamp_path = config_directory(root).join(CONFIG_STAMP);
    let mut stamp: serde_json::Value = serde_json::from_slice(&fs::read(&stamp_path)?)?;
    if stamp["compiled_sha256"] != digest(compiled)? {
        bail!("Config circuit changed before VK generation completed");
    }
    fs::copy(generated, cached)?;
    stamp["vk_sha256"][variant.as_str()] = serde_json::json!(digest(cached)?);
    super::write_json(&stamp_path, &stamp)?;
    Ok(stamp)
}

fn verify_manifest_file(
    prover: &ZkProver,
    variant: e3_zk_prover::CircuitVariant,
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let variant_root = prover.circuits_dir(variant, "");
    let root = variant_root.parent().context("Artifact root")?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("checksums.json"))?)?;
    if manifest["algorithm"] != "sha256" {
        bail!("Artifact manifest must use sha256");
    }
    let relative = path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/");
    let expected = manifest["files"][&relative]
        .as_str()
        .with_context(|| format!("Artifact manifest does not cover {relative}"))?;
    e3_zk_prover::verify_checksum(&relative, bytes, Some(expected))?;
    Ok(())
}

pub(crate) fn bb_binary(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.canonicalize()?);
    }
    if let Some(path) = std::env::var_os("E3_CUSTOM_BB") {
        return Ok(PathBuf::from(path).canonicalize()?);
    }
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let path = dir.join("bb");
        if path.is_file() {
            return Ok(path.canonicalize()?);
        }
    }
    bail!("bb is not installed; specify --bb or install the pinned toolchain")
}

pub(crate) fn validate_pair(
    root: &Path,
    preset: &str,
    committee: &str,
) -> Result<serde_json::Value> {
    let path = root.join(preset).join(committee).join(".build-stamp.json");
    let stamp: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("Read {}", path.display()))?,
    )?;
    if stamp["preset"] != preset
        || stamp["committee"] != committee
        || stamp["sourceHash"].as_str().is_none_or(str::is_empty)
    {
        bail!("Artifact stamp does not identify {preset}/{committee}");
    }
    Ok(stamp)
}

pub(crate) fn load(
    root: &Path,
    prover: &ZkProver,
    pair: &str,
    case: Case,
    variant: e3_zk_prover::CircuitVariant,
    noir_pin: &str,
    need_vk: bool,
) -> Result<(CompiledCircuit, PathBuf, PathBuf, ArtifactIdentity)> {
    let (directory, source_stamp) = if case == Case::Config {
        let directory = config_directory(root);
        let stamp: serde_json::Value = serde_json::from_slice(&fs::read(directory.join(CONFIG_STAMP)).context("Config reuse has no artifact-specific provenance; compile the selected config case explicitly with --bench-compile (and --bench-vk for proofs)")?)?;
        let (preset, committee) = pair.split_once('/').context("Artifact pair identity")?;
        if stamp["schema_version"] != 1
            || stamp["preset"] != preset
            || stamp["committee"] != committee
        {
            bail!(
                "Config artifact provenance does not identify {pair}; explicitly compile this config case with --bench-compile"
            );
        }
        if stamp["source_origin"] != "fresh_local_noir_compile"
            || stamp["sourceHash"].as_str().is_none_or(str::is_empty)
        {
            bail!("Config artifact has no local compilation source identity");
        }
        (directory, stamp)
    } else {
        let variant_root = prover.circuits_dir(variant, "");
        let (preset, committee) = pair.split_once('/').context("Artifact pair identity")?;
        (
            prover.circuits_dir(variant, pair).join(case.path()),
            validate_pair(
                variant_root.parent().context("Artifact root")?,
                preset,
                committee,
            )?,
        )
    };
    let package_name = if case == Case::Config {
        config_package_name(root)?
    } else {
        case.name().to_owned()
    };
    let compiled_path = directory.join(format!("{package_name}.json"));
    let vk_path = directory.join(format!(
        "{}.{}",
        package_name,
        if case == Case::Config {
            match variant {
                e3_zk_prover::CircuitVariant::Default => "vk_recursive",
                e3_zk_prover::CircuitVariant::Recursive => "vk_noir",
                e3_zk_prover::CircuitVariant::Evm => "vk",
            }
        } else {
            "vk"
        }
    ));
    let bytes = fs::read(&compiled_path).with_context(|| {
        format!(
            "Compiled circuit {} is unavailable; build the selected artifact pair explicitly",
            compiled_path.display()
        )
    })?;
    let compiled_sha256 = hex::encode(Sha256::digest(&bytes));
    if case == Case::Config && source_stamp["compiled_sha256"] != compiled_sha256 {
        bail!("Config circuit digest differs from its artifact-specific provenance");
    }
    if case != Case::Config {
        verify_manifest_file(prover, variant, &compiled_path, &bytes)?;
    }
    let document: serde_json::Value = serde_json::from_slice(&bytes)?;
    let version = document["noir_version"]
        .as_str()
        .context("Compiled circuit has no Noir version")?;
    if !e3_zk_build::reports_version(version, noir_pin) {
        bail!("Circuit Noir version {version} does not match Rust Noir {noir_pin}");
    }
    if case == Case::Config && source_stamp["compiler_version"] != version {
        bail!("Config compiler version differs from its artifact provenance");
    }
    if need_vk && !vk_path.is_file() {
        bail!(
            "Missing matching {variant} verification key: {}",
            vk_path.display()
        );
    }
    if case != Case::Config && vk_path.is_file() {
        verify_manifest_file(prover, variant, &vk_path, &fs::read(&vk_path)?)?;
    }
    let vk_sha256 = if vk_path.is_file() && case == Case::Config {
        let actual = digest(&vk_path)?;
        if source_stamp["vk_sha256"][variant.as_str()] == actual {
            Some(actual)
        } else if need_vk {
            bail!("Config VK is not bound to this circuit and variant; use --bench-vk");
        } else {
            None
        }
    } else {
        vk_path.is_file().then(|| digest(&vk_path)).transpose()?
    };
    let identity = ArtifactIdentity {
        source_stamp,
        compiled_path: compiled_path.display().to_string(),
        compiled_sha256,
        vk_sha256,
        artifact_noir_version: version.into(),
    };
    let compiled = CompiledCircuit::from_json(std::str::from_utf8(&bytes)?)?;
    if let Some(quotient) = match case {
        Case::Ct0 => Some("r"),
        Case::Ct1 => Some("r_ct1"),
        _ => None,
    } {
        if !compiled
            .abi
            .parameters
            .iter()
            .any(|parameter| parameter.name == quotient)
        {
            bail!("UDE artifact ABI is missing its canonical quotient {quotient}");
        }
    }
    Ok((compiled, compiled_path, vk_path, identity))
}

pub(crate) fn gate_counts(text: &str) -> Result<(u64, Option<u64>)> {
    let document: serde_json::Value = serde_json::from_str(text.trim())?;
    let row = document
        .get("functions")
        .and_then(serde_json::Value::as_array)
        .and_then(|rows| rows.first())
        .unwrap_or(&document);
    let gates = row["circuit_size"]
        .as_u64()
        .context("bb gates output has no circuit_size")?;
    Ok((gates, row["acir_opcodes"].as_u64()))
}
