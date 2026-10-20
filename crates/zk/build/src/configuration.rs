// SPDX-License-Identifier: LGPL-3.0-only

use super::{preset_name, run, tier, Request, COMMITTEES};
use alloy_primitives::{keccak256, B256};
use anyhow::{bail, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{crypto_config_id, encode_bfv_params, BfvPreset, CIRCUIT_VERSION_LABEL};
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
        let parameter_hash = keccak256(encode_bfv_params(&threshold));
        let config_id = crypto_config_id(&encode_bfv_params(&threshold));
        Ok(Self {
            threshold,
            dkg,
            parameter_hash,
            config_id,
        })
    }
}

/// The parameter material for supported presets of one operation. Every renderer reuses it;
/// nothing rebuilds a preset pair inside an operation.
pub struct OperationParams {
    insecure: PresetMaterial,
    secure: PresetMaterial,
    secure16384: PresetMaterial,
}

impl OperationParams {
    pub fn both() -> Result<Self> {
        Ok(Self {
            insecure: PresetMaterial::new(BfvPreset::InsecureThreshold)?,
            secure: PresetMaterial::new(BfvPreset::SecureThreshold8192)?,
            secure16384: PresetMaterial::new(BfvPreset::SecureThreshold16384)?,
        })
    }
    pub fn get(&self, preset: BfvPreset) -> &PresetMaterial {
        match preset {
            BfvPreset::InsecureThreshold | BfvPreset::InsecureThresholdLbfv => &self.insecure,
            BfvPreset::SecureThreshold8192 => &self.secure,
            BfvPreset::SecureThreshold16384 => &self.secure16384,
            _ => unreachable!("build selects threshold presets"),
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

fn publish_changes(updates: Vec<(PathBuf, String)>) -> Result<()> {
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

const HEADER: &str = "// SPDX-License-Identifier: LGPL-3.0-only\n//\n// This file is provided WITHOUT ANY WARRANTY;\n// without even the implied warranty of MERCHANTABILITY\n// or FITNESS FOR A PARTICULAR PURPOSE.\n";
pub const BOUND_SOURCES: &[(&str, &str)] = &[
    ("threshold.nr", "PK_GENERATION_"),
    ("dkg.nr", "SHARE_COMPUTATION_"),
];

// The chunk grid belongs to the module generator, not committee-dependent C2 bounds.
pub const CHUNK_GLOBALS: &[&str] = &[
    "SHARE_COMPUTATION_CHUNK_SIZE",
    "SHARE_COMPUTATION_N_CHUNKS",
    "SHARE_COMPUTATION_CHUNKS_PER_BATCH",
    "SHARE_COMPUTATION_N_BATCHES",
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
        if CHUNK_GLOBALS.contains(&name.as_str()) {
            continue;
        }
        if !name.starts_with(prefix) && !common.contains(&name.as_str()) {
            continue;
        }
        count += 1;
        match old.get(name) {
            Some(current) if compact(current) != compact(declaration) => {
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
            if !CHUNK_GLOBALS.contains(&name.as_str()) && !fresh.contains_key(name) {
                bail!("{name} is not generated; remove it or generate it");
            }
        }
    }
    Ok(updated)
}

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
    let sources = [
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
            "USER_DATA_ENCRYPTION_CHUNKED_",
            vec![],
            threshold::user_data_encryption_chunked::Configs::new(&material.threshold)?.render()?,
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
    let mut pending = BTreeMap::new();
    for (file, prefix, common, generated) in sources {
        let path = root
            .join("circuits/lib/src/configs")
            .join(tier(preset))
            .join(file);
        // Later sources build on the pending text; only the first source reads the file.
        let text = match pending.remove(&path) {
            Some(text) => text,
            None => fs::read_to_string(&path)?,
        };
        pending.insert(
            path,
            replace_declarations(&text, &generated, prefix, &common, false)?,
        );
    }
    let threshold_path = root
        .join("circuits/lib/src/configs")
        .join(tier(preset))
        .join("threshold.nr");
    let additional = super::lbfv::threshold_constants(preset, &material.threshold, committee)?;
    let mut text = pending
        .remove(&threshold_path)
        .context("threshold configuration")?;
    for prefix in ["LBFV_PK_GENERATION_", "RLK_GENERATION_", "RLK_AGGREGATION_"] {
        text = replace_declarations(&text, &additional, prefix, &[], false)?;
    }
    pending.insert(threshold_path, text);
    let dkg_path = root
        .join("circuits/lib/src/configs")
        .join(tier(preset))
        .join("dkg.nr");
    let mut text = pending.remove(&dkg_path).context("DKG configuration")?;
    let old = declarations(&text);
    for (name, generated) in declarations(&super::lbfv::chunk_grid(material.threshold.degree())) {
        let current = old
            .get(&name)
            .with_context(|| format!("Missing chunk-grid declaration {name}"))?;
        if compact(current) != compact(&generated) {
            text = text.replacen(current, &generated, 1);
        }
    }
    pending.insert(dkg_path, text);
    pending.extend(super::lbfv::public_randomness(
        root,
        preset,
        &material.threshold,
    )?);
    publish_changes(formatted_noir_changes(
        root,
        &root.join("circuits/lib"),
        pending.into_iter().collect(),
    )?)
}

pub fn parity_files(
    committee: CiphernodesCommitteeSize,
    params: &OperationParams,
) -> Result<Vec<(PathBuf, String)>> {
    let values = committee.values();
    let mut out = Vec::new();
    for preset in super::ARTIFACT_PRESETS {
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
    let mut smudging = format!("{HEADER}//\n// AUTO-GENERATED by `generate_parity_matrices`. DO NOT EDIT BY HAND.\n// Regenerate with `pnpm build:circuits --committee {committee}`.\n//\n// C1 and C2b must use the same smudging-noise width as Rust witness generation.\n\n");
    for (label, preset) in [
        ("INSECURE", BfvPreset::InsecureThreshold),
        ("SECURE_8192", BfvPreset::SecureThreshold8192),
        ("SECURE_16384", BfvPreset::SecureThreshold16384),
    ] {
        let config = threshold::pk_generation::Configs::new(
            preset,
            &params.get(preset).threshold,
            committee,
        )?;
        smudging.push_str(&format!(
            "pub global {label}_E_SM_BIT: u32 = {};\npub global {label}_E_SM_BOUND: Field = {};\n",
            config.bits.e_sm_bit, config.bounds.e_sm_bound
        ));
    }
    out.push((PathBuf::from(format!("{committee}/smudging.nr")), smudging));
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

/// Keep formatter layout only for the generated numeric parity declaration. Comments, strings,
/// imports, and headers must match exactly; they never participate in whitespace normalization.
fn preserve_parity_layout(original: &str, generated: String) -> String {
    let old = declarations(original);
    let fresh = declarations(&generated);
    let tokens = |declaration: &str| -> Option<Vec<String>> {
        if !declaration.chars().all(|c| {
            c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || "_:;=+-*[],()".contains(c)
        }) {
            return None;
        }
        let regex = Regex::new(r"[A-Za-z0-9_]+|[^\s]").unwrap();
        let mut tokens: Vec<_> = regex
            .find_iter(declaration)
            .map(|m| m.as_str().to_owned())
            .collect();
        for i in (0..tokens.len().saturating_sub(1)).rev() {
            if tokens[i] == "," && tokens[i + 1] == "]" {
                tokens.remove(i);
            }
        }
        Some(tokens)
    };
    if let (Some(old), Some(fresh)) = (old.get("PARITY_MATRIX"), fresh.get("PARITY_MATRIX")) {
        if tokens(old).is_some_and(|old| Some(old) == tokens(fresh)) {
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
    let message_width = e3_zk_config::MAX_MSG_NON_ZERO_COEFFS;
    let default = format!("{HEADER}//\n// Auto-generated by the Rust circuit builder (`pnpm build:circuits`) for preset: {name}\n\n// Committee size (N_PARTIES / T / H) is routed through `committee::active`,\n// which the Rust circuit builder regenerates atomically with this file.\npub use super::committee::active::{{H, N_PARTIES, T}};\npub use super::{tier}::dkg;\npub use super::{tier}::threshold;\n\n/// Max number of non-zero coefficients in the message polynomial.\n/// This is a conservative estimate that should be okay for most use cases.\npub global MAX_MSG_NON_ZERO_COEFFS: u32 = {message_width};\n");
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
    updates.extend(bound_updates(root, preset, committee, params.get(preset))?);
    Ok(Selection {
        noir: updates,
        protocol: protocol_updates(root, preset, committee, skip_utils, &params)?,
    })
}

pub fn protocol_contract(
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    params: &OperationParams,
    pairs: &[[String; 2]],
) -> Result<String> {
    let mut text = include_str!("../templates/active_crypto_config.sol.in")
        .replace(
            "@selection@",
            &format!("{}/{}", preset_name(preset), committee),
        )
        .replace(
            "@CIRCUIT_VERSION@",
            std::str::from_utf8(CIRCUIT_VERSION_LABEL)?,
        );
    for (label, preset, param_set) in [
        ("INSECURE", BfvPreset::InsecureThreshold, 0),
        ("SECURE", BfvPreset::SecureThreshold8192, 2),
        ("SECURE_16384", BfvPreset::SecureThreshold16384, 3),
    ] {
        let material = params.get(preset);
        text = text
            .replace(&format!("@{label}_PARAM_SET@"), &param_set.to_string())
            .replace(
                &format!("@{label}_HASH@"),
                &format!("{:#x}", material.parameter_hash),
            )
            .replace(
                &format!("@{label}_ID@"),
                &format!("{:#x}", material.config_id),
            );
    }
    for (index, name) in COMMITTEES.iter().enumerate() {
        let values = name.parse::<CiphernodesCommitteeSize>()?.values();
        let label = name.to_uppercase();
        for (suffix, value) in [
            ("SIZE", index),
            ("N", values.n),
            ("T", values.threshold),
            ("H", values.h),
        ] {
            text = text.replace(&format!("@{label}_{suffix}@"), &value.to_string());
        }
    }
    let mut admission = String::new();
    for (name, param_sets) in [
        (
            "insecure",
            "paramSet == INSECURE_PARAM_SET || paramSet == INSECURE_LBFV_PARAM_SET",
        ),
        ("secure-8192", "paramSet == SECURE_PARAM_SET"),
        ("secure-16384", "paramSet == SECURE_16384_PARAM_SET"),
    ] {
        let committees = pairs
            .iter()
            .filter(|pair| pair[0] == name)
            .map(|pair| format!("committeeSize == {}_COMMITTEE_SIZE", pair[1].to_uppercase()))
            .collect::<Vec<_>>();
        if !committees.is_empty() {
            admission.push_str(&format!(
                "        if ({param_sets}) {{\n            if (\n                {}\n            ) return;\n        }}\n",
                committees.join(" ||\n                ")
            ));
        }
    }
    Ok(text.replace("@PAIR_ADMISSION@", admission.trim_end()))
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
    params: &OperationParams,
    pairs: &[[String; 2]],
) -> Result<String> {
    let values = committee.values();
    let size = COMMITTEES
        .iter()
        .position(|name| *name == committee.to_string())
        .context("committee index")?;
    let param_set = match preset {
        BfvPreset::InsecureThreshold => 0,
        BfvPreset::InsecureThresholdLbfv => 4,
        BfvPreset::SecureThreshold8192 => 2,
        BfvPreset::SecureThreshold16384 => 3,
        _ => unreachable!("build selects threshold presets"),
    };
    let mut after = before.to_string();
    for (name, value) in [
        ("BFV_DKG_H", values.h),
        ("BFV_THRESHOLD_T", values.threshold),
        ("ACTIVE_BFV_PARAM_SET", param_set),
        ("ACTIVE_BFV_COMMITTEE_SIZE", size),
        ("ACTIVE_BFV_COMMITTEE_N", values.n),
    ] {
        after = replace_required(
            &after,
            &format!(r"export const {name} = \d+"),
            &format!("export const {name} = {value}"),
        )?;
    }
    for (prefix, preset) in [
        ("INSECURE", BfvPreset::InsecureThreshold),
        ("SECURE", BfvPreset::SecureThreshold8192),
        ("SECURE_16384", BfvPreset::SecureThreshold16384),
    ] {
        let material = params.get(preset);
        for (suffix, value) in [
            ("PARAM_SET_HASH", material.parameter_hash),
            ("CONFIG_ID", material.config_id),
        ] {
            let name = format!("{prefix}_{suffix}");
            after = replace_required(
                &after,
                &format!(r#"const {name} =\s*\n\s*"0x[0-9a-fA-F]+""#),
                &format!("const {name} =\n  \"{value:#x}\""),
            )?;
        }
    }
    // Keep installed-package deployment self-contained: render the shared policy rather than
    // importing a repository-relative JSON file from the published package.
    let mut configs = String::from(
        "// Generated from scripts/circuits/build-pairs.json and canonical committee values.\n",
    );
    let mut names = Vec::new();
    let deployment_pairs = pairs
        .iter()
        .filter(|pair| pair[0] == "insecure")
        .map(|pair| (pair, false))
        .chain(
            pairs
                .iter()
                .filter(|pair| pair[0] == "insecure")
                .map(|pair| (pair, true)),
        )
        .chain(
            pairs
                .iter()
                .filter(|pair| pair[0] != "insecure")
                .map(|pair| (pair, false)),
        );
    for (pair, lbfv) in deployment_pairs {
        let prefix = match (pair[0].as_str(), lbfv) {
            ("insecure", false) => "INSECURE",
            ("insecure", true) => "INSECURE_LBFV",
            ("secure-8192", _) => "SECURE",
            ("secure-16384", _) => "SECURE_16384",
            _ => bail!("Unsupported deployment preset: {}", pair[0]),
        };
        let name = format!("{prefix}_{}_BFV_CONFIG", pair[1].to_uppercase());
        let values = pair[1].parse::<CiphernodesCommitteeSize>()?.values();
        let size = COMMITTEES
            .iter()
            .position(|name| *name == pair[1])
            .context("committee index")?;
        configs.push_str(&format!("export const {name}: ActiveBfvConfig = bfvConfig(\n  \"{}\",\n  \"{}\",\n  {{ committeeSize: {size}, h: {}, t: {}, n: {} }},\n{});\n\n", pair[0], pair[1], values.h, values.threshold, values.n, if lbfv { "  true,\n" } else { "" }));
        names.push(name);
    }
    after = replace_required(
        &after,
        r"(?:// Generated from scripts/circuits/build-pairs.json and canonical committee values.\n)?export const INSECURE_MINIMUM_BFV_CONFIG:[\s\S]*?\nexport const PRODUCTION_BFV_CONFIG:",
        &format!("{configs}export const PRODUCTION_BFV_CONFIG:"),
    )?;
    let mut routes =
        String::from("export const TESTNET_BFV_CONFIGS: readonly ActiveBfvConfig[] = [\n");
    for name in names {
        routes.push_str(&format!("  {name},\n"));
    }
    routes.push_str("] as const;");
    after = replace_required(
        &after,
        r"export const TESTNET_BFV_CONFIGS:[\s\S]*?\] as const;",
        &routes,
    )?;
    let name = committee.to_string();
    let capitalized = format!("{}{}", name[..1].to_uppercase(), &name[1..]);
    let doc = format!("/**\n * <generated-committee-doc>\n * Active {} / {committee} committee layout for BFV aggregator verifiers.\n * Must match `lib::configs::default::{{H, T}}` in compiled circuits.\n * {capitalized} committee: N={}, T={}, H={}.\n * </generated-committee-doc>\n */", preset_name(preset), values.n, values.threshold, values.h);
    replace_required(
        &after,
        r"/\*\*\s*\n \* <generated-committee-doc>[\s\S]*?</generated-committee-doc>\s*\n \*/",
        &doc,
    )
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
    let pairs = crate::build_pairs(root)?;
    let mut updates = Vec::new();
    let path = root.join("packages/interfold-contracts/scripts/utils.ts");
    if !skip_utils && path.exists() {
        let before = fs::read_to_string(&path)?;
        let updated = protocol_utils(&before, preset, committee, params, &pairs)?;
        updates.push((path, updated));
    }
    let path = root.join("packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol");
    let contract = protocol_contract(preset, committee, params, &pairs)?;
    updates.push((path, contract));
    Ok(updates)
}

/// Format only an isolated library copy. A check never swaps live generated files.
pub fn check(root: &Path, options: &Request) -> Result<()> {
    let params = OperationParams::both()?;
    let temp = tempfile::tempdir()?;
    let lib = root.join("circuits/lib");
    super::artifacts::copy_tree(
        &lib,
        temp.path(),
        &["target", "Prover.toml", "Witness.toml"],
    )?;
    let mut paths = Vec::new();
    for committee in options.committees() {
        for (relative, contents) in parity_files(committee, &params)? {
            let path = PathBuf::from("src/configs/committee").join(relative);
            fs::write(temp.path().join(&path), contents)?;
            paths.push(path);
        }
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
    println!("Generated committee configuration matches the Rust owner.");
    Ok(())
}
