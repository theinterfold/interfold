// SPDX-License-Identifier: LGPL-3.0-only

use super::{bindings, preset_name, run, tier, Request};
use alloy_primitives::B256;
use anyhow::{bail, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{
    bfv_parameter_hash, current_bfv_crypto_config_id, encode_bfv_params, BfvPreset,
};
use e3_zk_config::{dkg, threshold};
use fhe::bfv::BfvParameters;
use regex::Regex;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

/// The BFV parameter pair and protocol hashes of one preset, built once per operation.
pub struct PresetMaterial {
    pub threshold: Arc<BfvParameters>,
    pub dkg: Arc<BfvParameters>,
    pub parameter_hash: B256,
    pub config_id: B256,
}

impl PresetMaterial {
    pub fn new(preset: BfvPreset) -> Result<Self> {
        let (threshold, dkg) = preset.build_pair()?;
        let encoded_params = encode_bfv_params(&threshold);
        let parameter_hash = bfv_parameter_hash(&encoded_params);
        let config_id = current_bfv_crypto_config_id(&encoded_params);
        Ok(Self {
            threshold,
            dkg,
            parameter_hash,
            config_id,
        })
    }
}

/// The parameter material for both supported presets of one operation. Every renderer reuses it;
/// nothing rebuilds a preset pair inside an operation.
pub struct OperationParams {
    insecure: PresetMaterial,
    secure: PresetMaterial,
}

impl OperationParams {
    pub fn both() -> Result<Self> {
        Ok(Self {
            insecure: PresetMaterial::new(BfvPreset::InsecureThreshold64)?,
            secure: PresetMaterial::new(BfvPreset::SecureThreshold8192)?,
        })
    }
    pub fn get(&self, preset: BfvPreset) -> &PresetMaterial {
        if preset == BfvPreset::InsecureThreshold64 {
            &self.insecure
        } else {
            &self.secure
        }
    }
}

/// Format generated Noir sources with the pinned nargo. The version probe runs only when a
/// formatter invocation is actually needed.
fn format_noir(root: &Path, directory: &Path) -> Result<()> {
    super::identity::check_tools(root, true, false)?;
    run(Command::new("nargo").arg("fmt").current_dir(directory))?;
    Ok(())
}

/// Format changed generated sources in an isolated package before publishing any live file.
fn formatted_noir_changes(
    root: &Path,
    directory: &Path,
    updates: Vec<(PathBuf, String)>,
) -> Result<Vec<(PathBuf, String)>> {
    let changed: Vec<_> = updates
        .into_iter()
        .filter(|(path, contents)| {
            fs::read_to_string(path).ok().as_deref() != Some(contents.as_str())
        })
        .collect();
    if changed.is_empty() {
        return Ok(changed);
    }
    super::identity::check_tools(root, true, false)?;
    let temp = tempfile::tempdir()?;
    let staged_directory = temp.path().join(directory.strip_prefix(root)?);
    super::artifacts::copy_tree(
        directory,
        &staged_directory,
        &["target", "Prover.toml", "Witness.toml"],
    )?;
    let library = root.join("circuits/lib");
    if directory != library {
        super::artifacts::copy_tree(
            &library,
            &temp.path().join("circuits/lib"),
            &["target", "Prover.toml", "Witness.toml"],
        )?;
    }
    for (path, contents) in &changed {
        let staged = staged_directory.join(path.strip_prefix(directory)?);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(staged, contents)?;
    }
    run(Command::new("nargo")
        .arg("fmt")
        .current_dir(&staged_directory))?;
    changed
        .into_iter()
        .map(|(path, _)| {
            let contents =
                fs::read_to_string(staged_directory.join(path.strip_prefix(directory)?))?;
            Ok((path, contents))
        })
        .collect()
}

pub(crate) fn publish_changes(updates: Vec<(PathBuf, String)>) -> Result<()> {
    for (path, contents) in updates {
        if fs::read_to_string(&path).ok().as_deref() == Some(contents.as_str()) {
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, contents)?;
        println!("Updated {}", path.display());
    }
    Ok(())
}

pub(crate) const HEADER: &str = "// SPDX-License-Identifier: LGPL-3.0-only\n//\n// This file is provided WITHOUT ANY WARRANTY;\n// without even the implied warranty of MERCHANTABILITY\n// or FITNESS FOR A PARTICULAR PURPOSE.\n";
pub const BOUND_SOURCES: &[(&str, &str)] = &[
    ("threshold.nr", "PK_GENERATION_"),
    ("dkg.nr", "SHARE_COMPUTATION_"),
];

/// Find the complete declaration, including arrays and formatted multi-line values.
pub fn declarations(source: &str) -> BTreeMap<String, String> {
    let regex = Regex::new(r"(?m)^pub global ([A-Z0-9_]+):").unwrap();
    let mut out = BTreeMap::new();
    for capture in regex.captures_iter(source) {
        let matched = capture.get(0).unwrap();
        let mut depth = 0_i32;
        for (offset, byte) in source.as_bytes()[matched.end()..].iter().enumerate() {
            match byte {
                b'[' | b'(' => depth += 1,
                b']' | b')' => depth -= 1,
                b';' if depth == 0 => {
                    out.insert(
                        capture[1].to_string(),
                        source[matched.start()..=matched.end() + offset].to_string(),
                    );
                    break;
                }
                _ => {}
            }
        }
    }
    out
}

pub fn compact(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn replace_declarations(
    original: &str,
    generated: &str,
    prefix: &str,
    common: &[&str],
    strict: bool,
) -> Result<String> {
    let old = declarations(original);
    let fresh = declarations(generated);
    let mut updated = original.to_string();
    let mut count = 0;
    for (name, declaration) in &fresh {
        if !name.starts_with(prefix) && !common.contains(&name.as_str()) {
            continue;
        }
        count += 1;
        match old.get(name) {
            Some(current)
                if compact(current) != compact(declaration)
                    && !declaration_tokens(current)
                        .is_some_and(|old| Some(old) == declaration_tokens(declaration)) =>
            {
                updated = updated.replacen(current, declaration, 1)
            }
            None if strict => bail!("Missing {name} in committed circuit configuration"),
            _ => {}
        }
    }
    if strict {
        if count == 0 {
            bail!("No {prefix} constants generated");
        }
        for name in old.keys().filter(|name| name.starts_with(prefix)) {
            if !fresh.contains_key(name) {
                bail!("{name} is not generated; remove it or generate it");
            }
        }
    }
    Ok(updated)
}

#[cfg(test)]
pub fn bound_updates(
    root: &Path,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    material: &PresetMaterial,
) -> Result<Vec<(PathBuf, String)>> {
    let sources = [
        (
            "threshold.nr",
            "PK_GENERATION_",
            threshold::pk_generation::Configs::new(preset, &material.threshold, committee)?
                .render()?,
        ),
        (
            "dkg.nr",
            "SHARE_COMPUTATION_",
            dkg::share_computation::Configs::new(preset, &material.threshold, committee)?
                .render()?,
        ),
    ];
    sources
        .into_iter()
        .map(|(file, prefix, generated)| {
            let path = root
                .join("circuits/lib/src/configs")
                .join(tier(preset))
                .join(file);
            let original = fs::read_to_string(&path)?;
            Ok((
                path,
                replace_declarations(&original, &generated, prefix, &[], true)?,
            ))
        })
        .collect()
}

pub fn sync_preset(
    root: &Path,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
) -> Result<()> {
    let material = PresetMaterial::new(preset)?;
    publish_changes(formatted_noir_changes(
        root,
        &root.join("circuits/lib"),
        preset_updates(root, preset, committee, &material)?,
    )?)
}

pub fn preset_updates(
    root: &Path,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    material: &PresetMaterial,
) -> Result<Vec<(PathBuf, String)>> {
    let search = preset.search_config().context("Preset search recipe")?;
    let sources = [
        (
            "threshold.nr",
            "PARAMS_SEARCH_",
            vec![],
            format!("pub global PARAMS_SEARCH_N: Field = {};\npub global PARAMS_SEARCH_Z: Field = {};\n", search.n, search.z),
        ),
        (
            "dkg.nr",
            "PK_",
            vec![],
            dkg::pk::Configs::new(&material.dkg)?.render()?,
        ),
        (
            "dkg.nr",
            "SHARE_COMPUTATION_",
            vec![],
            dkg::share_computation::Configs::new(preset, &material.threshold, committee)?
                .render()?,
        ),
        (
            "dkg.nr",
            "SHARE_ENCRYPTION_",
            vec![
                "N",
                "L",
                "QIS",
                "PLAINTEXT_MODULUS",
                "Q_MOD_T",
                "Q_MOD_T_CENTERED",
            ],
            dkg::share_encryption::Configs::new(&material.dkg)?.render()?,
        ),
        (
            "dkg.nr",
            "SHARE_DECRYPTION_",
            vec![],
            dkg::share_decryption::Configs::new(&material.threshold, &material.dkg)?.render()?,
        ),
        (
            "threshold.nr",
            "USER_DATA_ENCRYPTION_",
            vec![],
            threshold::user_data_encryption::Configs::new(&material.threshold)?.render()?,
        ),
        (
            "threshold.nr",
            "PK_GENERATION_",
            vec!["N", "L", "QIS", "CRP"],
            threshold::pk_generation::Configs::new(preset, &material.threshold, committee)?
                .render()?,
        ),
        (
            "threshold.nr",
            "PK_AGGREGATION_",
            vec![],
            threshold::pk_aggregation::Configs::new(&material.threshold, committee)?.render()?,
        ),
        (
            "threshold.nr",
            "THRESHOLD_SHARE_DECRYPTION_",
            vec![],
            threshold::share_decryption::Configs::new(&material.threshold)?.render()?,
        ),
        (
            "threshold.nr",
            "DECRYPTED_SHARES_AGGREGATION_",
            vec![
                "PLAINTEXT_MODULUS",
                "Q_MOD_T",
                "Q_MOD_T_CENTERED",
                "Q_INVERSE_MOD_T",
            ],
            threshold::decrypted_shares_aggregation::Configs::new(&material.threshold, committee)?
                .render()?,
        ),
    ];
    let threshold_source = sources
        .iter()
        .find(|(file, prefix, _, _)| {
            *file == "threshold.nr" && *prefix == "THRESHOLD_SHARE_DECRYPTION_"
        })
        .context("Threshold share-decryption declarations")?;
    let aggregate_alias_target =
        declarations(&threshold_source.3)["THRESHOLD_SHARE_DECRYPTION_BIT_SK"].clone();
    let mut pending = BTreeMap::new();
    for (file, prefix, common, mut generated) in sources {
        // Only the secure preset exposes these legacy public search globals.
        if prefix == "PARAMS_SEARCH_" && preset == BfvPreset::InsecureThreshold64 {
            continue;
        }
        let path = root
            .join("circuits/lib/src/configs")
            .join(tier(preset))
            .join(file);
        // Later sources build on the pending text; only the first source reads the file.
        let text = match pending.remove(&path) {
            Some(text) => text,
            None => fs::read_to_string(&path)?,
        };
        if file == "dkg.nr" && prefix == "SHARE_DECRYPTION_" {
            // C4 re-exports C6's aggregate width rather than defining another scalar. Verify the
            // real import and the freshly derived values, then leave that alias intact.
            let import = Regex::new(&format!(
                r"(?s)pub\s+use\s+crate::configs::{}::threshold::\{{([^}}]+)\}};",
                tier(preset)
            ))?;
            let exports = import.captures(&text).context("DKG threshold re-exports")?;
            if !compact(&exports[1])
                .contains("THRESHOLD_SHARE_DECRYPTION_BIT_SKasSHARE_DECRYPTION_BIT_AGG")
            {
                bail!("DKG aggregate width must re-export THRESHOLD_SHARE_DECRYPTION_BIT_SK");
            }
            let alias = declarations(&generated)["SHARE_DECRYPTION_BIT_AGG"].clone();
            if compact(&alias.replace(
                "SHARE_DECRYPTION_BIT_AGG",
                "THRESHOLD_SHARE_DECRYPTION_BIT_SK",
            )) != compact(&aggregate_alias_target)
            {
                bail!("C4 and C6 aggregate widths disagree");
            }
            generated = generated.replacen(&alias, "", 1);
        }
        pending.insert(
            path,
            replace_declarations(&text, &generated, prefix, &common, true)?,
        );
    }
    Ok(pending.into_iter().collect())
}

pub fn parity_files(
    committee: CiphernodesCommitteeSize,
    params: &OperationParams,
) -> Result<Vec<(PathBuf, String)>> {
    let values = committee.values();
    let mut out = Vec::new();
    for preset in BfvPreset::PAIR_PRESETS {
        let material = params.get(preset);
        let suffix = tier(preset);
        let l = material.threshold.moduli().len();
        let matrix = dkg::share_computation::parity::parity_matrix_constant_string(
            &material.threshold,
            values.n,
            values.threshold,
        )?;
        let content = format!("{HEADER}//\n// AUTO-GENERATED by `generate_parity_matrices`. DO NOT EDIT BY HAND.\n// Regenerate with `pnpm build:circuits --committee {committee}`.\n//\n// Reed-Solomon parity matrix for the {committee} committee under the\n// {} (L_THRESHOLD={l}) preset. Dimensions: [L_THRESHOLD][N_PARTIES - T][N_PARTIES + 1].\n\nuse crate::configs::committee::{committee}::{{N_PARTIES, T}};\npub use crate::configs::{suffix}::threshold::L as L_THRESHOLD;\n\n{matrix}\n", preset_name(preset));
        out.push((
            PathBuf::from(format!("{committee}/parity_{suffix}.nr")),
            content,
        ));
    }
    Ok(out)
}

/// Pending generated selection files. Preparation reads sources but does not publish them.
pub struct Selection {
    pub noir: Vec<(PathBuf, String)>,
    protocol: Vec<(PathBuf, String)>,
}

impl Selection {
    pub fn format(&mut self, root: &Path) -> Result<()> {
        self.noir = formatted_noir_changes(
            root,
            &root.join("circuits/lib"),
            std::mem::take(&mut self.noir),
        )?;
        Ok(())
    }

    pub fn publish(self) -> Result<()> {
        publish_changes(self.noir)?;
        publish_changes(self.protocol)
    }
}

/// Ignore optional trailing commas only in generated numeric declarations. Comments, strings,
/// imports, and headers never participate in normalization.
fn declaration_tokens(declaration: &str) -> Option<Vec<String>> {
    if !declaration.chars().all(|c| {
        c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || "_:;=+-*[],()<>".contains(c)
    }) {
        return None;
    }
    let regex = Regex::new(r"[A-Za-z0-9_]+|[^\s]").unwrap();
    let mut tokens: Vec<_> = regex
        .find_iter(declaration)
        .map(|m| m.as_str().to_owned())
        .collect();
    for i in (0..tokens.len().saturating_sub(1)).rev() {
        if tokens[i] == "," && matches!(tokens[i + 1].as_str(), "]" | ")") {
            tokens.remove(i);
        }
    }
    Some(tokens)
}

fn preserve_parity_layout(original: &str, generated: String) -> String {
    let old = declarations(original);
    let fresh = declarations(&generated);
    if let (Some(old), Some(fresh)) = (old.get("PARITY_MATRIX"), fresh.get("PARITY_MATRIX")) {
        if declaration_tokens(old).is_some_and(|old| Some(old) == declaration_tokens(fresh)) {
            return generated.replacen(fresh, old, 1);
        }
    }
    generated
}

pub fn prepare_selection(
    root: &Path,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    skip_utils: bool,
) -> Result<Selection> {
    let params = OperationParams::both()?;
    let name = preset_name(preset);
    let tier = tier(preset);
    let default = format!("{HEADER}//\n// Auto-generated by the Rust circuit builder (`pnpm build:circuits`) for preset: {name}\n\n// Committee size (N_PARTIES / T / H) is routed through `committee::active`,\n// which the Rust circuit builder regenerates atomically with this file.\npub use super::committee::active::{{H, N_PARTIES, T}};\npub use super::{tier}::dkg;\npub use super::{tier}::threshold;\npub use super::protocol::MAX_MSG_NON_ZERO_COEFFS;\n");
    let mut updates = vec![
        (
            root.join("circuits/lib/src/configs/default/mod.nr"),
            default,
        ),
        (
            root.join("circuits/lib/src/configs/committee/active.nr"),
            include_str!("../templates/committee_active.nr.in")
                .replace("@committee@", &committee.to_string()),
        ),
    ];
    updates.extend(bindings::noir_sources(root));
    for (relative, content) in parity_files(committee, &params)? {
        let path = root
            .join("circuits/lib/src/configs/committee")
            .join(relative);
        let content = match fs::read_to_string(&path) {
            Ok(original) => preserve_parity_layout(&original, content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => content,
            Err(error) => return Err(error.into()),
        };
        updates.push((path, content));
    }
    updates.extend(preset_updates(root, preset, committee, params.get(preset))?);
    Ok(Selection {
        noir: updates,
        protocol: protocol_updates(root, preset, committee, skip_utils, &params)?,
    })
}

fn replace_required(text: &str, pattern: &str, replacement: &str) -> Result<String> {
    let regex = Regex::new(pattern)?;
    if !regex.is_match(text) {
        bail!("Missing generated configuration declaration: {pattern}");
    }
    Ok(regex
        .replace(text, regex::NoExpand(replacement))
        .into_owned())
}

pub fn protocol_utils(
    before: &str,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
) -> Result<String> {
    let mut after = before.to_string();
    for (name, ty, value) in [
        (
            "ACTIVE_BFV_PRESET",
            "BfvArtifactPreset",
            preset_name(preset).to_string(),
        ),
        (
            "ACTIVE_BFV_COMMITTEE",
            "BfvCommittee",
            committee.to_string(),
        ),
    ] {
        after = replace_required(
            &after,
            &format!(r#"export const {name}: {ty} = "[^"]+""#),
            &format!("export const {name}: {ty} = \"{value}\""),
        )?;
    }
    Ok(after)
}

pub fn sync_protocol(
    root: &Path,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    skip_utils: bool,
    params: &OperationParams,
) -> Result<()> {
    publish_changes(protocol_updates(
        root, preset, committee, skip_utils, params,
    )?)
}

fn protocol_updates(
    root: &Path,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    skip_utils: bool,
    params: &OperationParams,
) -> Result<Vec<(PathBuf, String)>> {
    let mut updates = Vec::new();
    let path = root.join("packages/interfold-contracts/scripts/utils.ts");
    if !skip_utils && path.exists() {
        let before = fs::read_to_string(&path)?;
        let updated = protocol_utils(&before, preset, committee)?;
        updates.push((path, updated));
    }
    let path = root.join(bindings::SOLIDITY_PATH);
    let contract = bindings::solidity(params)?;
    updates.push((path, contract));
    Ok(updates)
}

fn all_sources(root: &Path) -> Result<Selection> {
    let params = OperationParams::both()?;
    let selection_source =
        fs::read_to_string(root.join("packages/interfold-contracts/scripts/utils.ts"))?;
    let selection_name = |name: &str| -> Result<String> {
        let pattern = Regex::new(&format!(r#"export const {name}: [A-Za-z]+ = "([^"]+)";"#))?;
        Ok(pattern
            .captures(&selection_source)
            .with_context(|| format!("Missing deployment selection {name}"))?[1]
            .to_string())
    };
    let active_preset = super::preset(&selection_name("ACTIVE_BFV_PRESET")?)?;
    let active_committee: CiphernodesCommitteeSize =
        selection_name("ACTIVE_BFV_COMMITTEE")?.parse()?;
    let mut selection = prepare_selection(root, active_preset, active_committee, false)?;
    let mut sources: BTreeMap<_, _> = selection.noir.into_iter().collect();
    // An unselected preset retains its canonical development declarations. Pair-specific checks
    // stage the requested committee instead of comparing all pairs with this one live library.
    for preset in BfvPreset::PAIR_PRESETS {
        let committee = if preset == active_preset {
            active_committee
        } else {
            CiphernodesCommitteeSize::Minimum
        };
        for (path, contents) in preset_updates(root, preset, committee, params.get(preset))? {
            sources.insert(path, contents);
        }
    }
    for committee in CiphernodesCommitteeSize::ALL {
        for (relative, contents) in parity_files(committee, &params)? {
            let path = root
                .join("circuits/lib/src/configs/committee")
                .join(relative);
            let contents = match fs::read_to_string(&path) {
                Ok(old) => preserve_parity_layout(&old, contents),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => contents,
                Err(error) => return Err(error.into()),
            };
            sources.insert(path, contents);
        }
    }
    selection.noir = sources.into_iter().collect();
    Ok(selection)
}

pub fn sync_sources(root: &Path) -> Result<()> {
    let mut sources = all_sources(root)?;
    sources.format(root)?;
    sources.publish()
}

/// Format only an isolated library copy. A check never swaps live generated files.
pub fn check(root: &Path, _options: &Request) -> Result<()> {
    bindings::sync(root, true)?;
    check_ownership(root)?;
    let expected = all_sources(root)?;
    let temp = tempfile::tempdir()?;
    let lib = root.join("circuits/lib");
    super::artifacts::copy_tree(
        &lib,
        temp.path(),
        &["target", "Prover.toml", "Witness.toml"],
    )?;
    let mut paths = Vec::new();
    for (path, contents) in expected.noir {
        let path = path.strip_prefix(&lib)?.to_path_buf();
        fs::write(temp.path().join(&path), contents)?;
        paths.push(path);
    }
    format_noir(root, temp.path())?;
    for path in paths {
        if fs::read(lib.join(&path))? != fs::read(temp.path().join(&path))? {
            bail!(
                "{} differs from generated configuration; run pnpm build:circuits",
                lib.join(path).display()
            );
        }
    }
    for (path, contents) in expected.protocol {
        if fs::read_to_string(&path)? != contents {
            bail!("{} differs from its generated source", path.display());
        }
    }
    println!("Generated preset and committee configuration matches the Rust owners (source-only; no artifact qualification).");
    Ok(())
}

pub fn check_ownership(root: &Path) -> Result<()> {
    let metadata = e3_fhe_params::metadata::BfvMetadata::current()?;
    let mut forbidden = vec![
        metadata.encryption_scheme.to_string(),
        metadata.encryption_scheme_id,
        metadata.circuit_version.to_string(),
    ];
    for preset in metadata.presets {
        forbidden.extend([preset.parameter_hash, preset.crypto_config_id]);
    }
    let width = Regex::new(&format!(
        r"(?i)(?:const|global|let|static)\s+(?:MAX_MSG_NON_ZERO_COEFFS|MESSAGE_COEFFS_COUNT|messageCoeffsCount|message_coeffs_count|plaintextByteLength|plaintextByteLen)(?:\s*:\s*[A-Za-z0-9_<>]+)?\s*=\s*(?:{}|{})\b",
        e3_zk_config::MAX_MSG_NON_ZERO_COEFFS,
        e3_zk_config::metadata::CircuitDimensions::current().plaintext_byte_len
    ))?;
    let reviewed = [
        "crates/fhe-params/src/constants.rs",
        "crates/zk/config/src/constants.rs",
        "packages/interfold-contracts/contracts/lib/BfvProtocol.sol",
        "circuits/lib/src/configs/protocol.nr",
        "crates/indexer/tests/fixtures/fake_interfold.sol",
        "crates/zk/build/src/tests.rs",
        "packages/interfold-contracts/scripts/upgrade/v19Cutover.ts",
        "packages/interfold-contracts/test/Risc0BfvCiphertextVerifier.spec.ts",
        "packages/interfold-contracts/test/MockE3Program.spec.ts",
        "packages/interfold-contracts/test/Deployment/ProtocolDeployment.spec.ts",
    ];
    let comments = Regex::new(r"(?s)/\*.*?\*/|(?m)//[^\n]*")?;
    fn walk(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.')
                || ["node_modules", "target", "dist", "cache", "deployments"]
                    .contains(&name.as_str())
            {
                continue;
            }
            // TypeChain/Hardhat output is owned by the contracts build, not every directory named
            // `types`, `artifacts`, or `build` in a new consumer's maintained source tree.
            if [
                "packages/interfold-contracts/types",
                "packages/interfold-contracts/artifacts",
                "templates/default/types",
                "templates/default/artifacts",
            ]
            .iter()
            .any(|generated| entry.path() == root.join(generated))
            {
                continue;
            }
            if entry.file_type()?.is_symlink() {
                if matches!(
                    entry.path().extension().and_then(|value| value.to_str()),
                    Some("rs" | "ts" | "tsx" | "js" | "mjs" | "cjs" | "sol" | "nr")
                ) {
                    bail!("Unregistered symlinked consumer {}", entry.path().display());
                }
                continue;
            }
            if entry.file_type()?.is_dir() {
                walk(root, &entry.path(), files)?;
            } else if matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("rs" | "ts" | "tsx" | "js" | "mjs" | "cjs" | "sol" | "nr")
            ) {
                files.push(entry.path().strip_prefix(root)?.to_path_buf());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    for directory in ["crates", "packages", "scripts", "templates", "circuits"] {
        let path = root.join(directory);
        if path.is_dir() {
            walk(root, &path, &mut files)?;
        }
    }
    for path in files {
        let relative = path
            .to_str()
            .context("UTF-8 consumer path")?
            .replace('\\', "/");
        if reviewed.contains(&relative.as_str()) {
            continue;
        }
        let source = fs::read_to_string(root.join(&path))?;
        let code = comments.replace_all(&source, "");
        if forbidden.iter().any(|value| {
            if value.starts_with("0x") {
                code.to_ascii_lowercase().contains(value)
            } else {
                ['"', '\'', '`']
                    .into_iter()
                    .any(|quote| code.contains(&format!("{quote}{value}{quote}")))
            }
        }) || width.is_match(&code)
        {
            bail!("Independent current protocol definition in {relative}; import its owning binding (generated headers do not exempt consumers)");
        }
    }
    Ok(())
}
