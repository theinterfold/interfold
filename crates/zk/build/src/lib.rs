// SPDX-License-Identifier: LGPL-3.0-only

mod artifacts;
mod bindings;
mod configuration;
mod identity;
mod layouts;
pub mod metadata;
mod toolchain;
mod vk_tree;

pub use identity::checksum;
pub use toolchain::{pinned_noir_version, reports_version};

use anyhow::{bail, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use std::{
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

const COMMITTEES: &[&str] = &["minimum", "micro", "small"];

pub fn build_pairs(root: &Path) -> Result<Vec<[String; 2]>> {
    let path = root.join("scripts/circuits/build-pairs.json");
    let pairs: Vec<[String; 2]> = serde_json::from_slice(&fs::read(&path)?)
        .with_context(|| format!("Invalid circuit build policy: {}", path.display()))?;
    if pairs.is_empty() {
        bail!("Circuit build policy contains no supported pairs");
    }
    let mut seen = std::collections::BTreeSet::new();
    for pair in &pairs {
        let valid = matches!(
            pair[0].parse::<PresetSelection>(),
            Ok(PresetSelection::Single(_))
        ) && matches!(
            pair[1].parse::<CommitteeSelection>(),
            Ok(CommitteeSelection::Single(_))
        );
        if !valid {
            bail!("Invalid circuit build pair: {pair:?}");
        }
        if !seen.insert(pair) {
            bail!("Duplicate circuit build pair: {pair:?}");
        }
    }
    Ok(pairs)
}

/// One build operation. The names are the command-line strings of `pnpm build:circuits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Build,
    Hash,
    SyncConfig,
    SyncPreset,
    Check,
    ExportConfig,
    SyncBindings,
    CheckBindings,
    CheckLayouts,
}

impl FromStr for Operation {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "build" => Ok(Self::Build),
            "hash" => Ok(Self::Hash),
            "sync-config" => Ok(Self::SyncConfig),
            "sync-preset" => Ok(Self::SyncPreset),
            "check" => Ok(Self::Check),
            "export-config" => Ok(Self::ExportConfig),
            "sync-bindings" => Ok(Self::SyncBindings),
            "check-bindings" => Ok(Self::CheckBindings),
            "check-layouts" => Ok(Self::CheckLayouts),
            other => Err(format!(
                "unknown build operation {other}; expected build, hash, sync-config, sync-preset, check, export-config, sync-bindings, check-bindings, or check-layouts"
            )),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Build => "build",
            Self::Hash => "hash",
            Self::SyncConfig => "sync-config",
            Self::SyncPreset => "sync-preset",
            Self::Check => "check",
            Self::ExportConfig => "export-config",
            Self::SyncBindings => "sync-bindings",
            Self::CheckBindings => "check-bindings",
            Self::CheckLayouts => "check-layouts",
        })
    }
}

/// A preset selection: one supported preset, or every supported preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetSelection {
    Single(BfvPreset),
    All,
}

impl FromStr for PresetSelection {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            other => Ok(Self::Single(
                preset(other).map_err(|error| error.to_string())?,
            )),
        }
    }
}

/// A committee selection: one supported committee, or every supported committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeSelection {
    Single(CiphernodesCommitteeSize),
    All,
}

impl FromStr for CommitteeSelection {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            other => Ok(Self::Single(
                other
                    .parse()
                    .map_err(|_| format!("unknown committee {other}"))?,
            )),
        }
    }
}

/// One circuit group, named as on the command line and in `circuits/bin/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Dkg,
    Threshold,
    RecursiveAggregation,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dkg => "dkg",
            Self::Threshold => "threshold",
            Self::RecursiveAggregation => "recursive_aggregation",
        }
    }
}

impl FromStr for Group {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dkg" => Ok(Self::Dkg),
            "threshold" => Ok(Self::Threshold),
            "recursive_aggregation" => Ok(Self::RecursiveAggregation),
            other => Err(format!(
                "unknown circuit group {other}; expected dkg, threshold, or recursive_aggregation"
            )),
        }
    }
}

/// A group selection: every group, or an explicit list in the requested order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupSelection {
    All,
    Selected(Vec<Group>),
}

impl GroupSelection {
    /// The explicit list of an explicit selection; empty for the complete selection.
    pub fn explicit(&self) -> &[Group] {
        match self {
            Self::All => &[],
            Self::Selected(groups) => groups,
        }
    }
    /// Whether the selection covers every circuit group.
    pub fn is_complete(&self) -> bool {
        let all = [Group::Dkg, Group::Threshold, Group::RecursiveAggregation];
        let groups = self.groups();
        all.iter().all(|group| groups.contains(&group.as_str()))
    }
    pub fn groups(&self) -> Vec<&'static str> {
        match self {
            Self::All => vec!["dkg", "threshold", "recursive_aggregation"],
            Self::Selected(groups) => {
                let mut selected = Vec::new();
                for group in groups {
                    if !selected.contains(&group.as_str()) {
                        selected.push(group.as_str());
                    }
                }
                selected
            }
        }
    }
}

/// A typed build request. The binary in `main.rs` parses command-line arguments into it;
/// Rust callers construct it directly.
#[derive(Clone, Debug)]
pub struct Request {
    pub operation: Operation,
    pub preset: PresetSelection,
    pub committee: CommitteeSelection,
    pub groups: GroupSelection,
    /// Circuit names. An empty list selects every circuit of the selected groups.
    pub circuits: Vec<String>,
    /// Artifact output directory.
    pub output: Option<PathBuf>,
    pub skip_vk: bool,
    pub skip_checksums: bool,
    pub skip_utils_patch: bool,
    pub no_clean: bool,
    pub no_clean_targets: bool,
    pub skip_if_built: bool,
    /// Copy published artifacts without requiring a source-hash match.
    pub hydrate_bin_only: bool,
    /// Show the selected circuits without changing files.
    pub dry_run: bool,
}

impl Request {
    /// Reject requests that name no buildable pair before any tool run or write.
    pub fn validate(&self, root: &Path) -> Result<()> {
        if matches!(&self.groups, GroupSelection::Selected(groups) if groups.is_empty()) {
            bail!("Select at least one circuit group, or use all");
        }
        if self.hydrate_bin_only
            && (self.skip_vk || !self.circuits.is_empty() || !self.groups.explicit().is_empty())
        {
            bail!("Hydration requires a complete artifact pair");
        }
        self.selected_pairs(root)?;
        Ok(())
    }
    pub fn selected_pairs(&self, root: &Path) -> Result<Vec<[String; 2]>> {
        if let PresetSelection::Single(preset) = self.preset {
            if !BfvPreset::PAIR_PRESETS.contains(&preset) {
                bail!("Unsupported build preset: {preset:?}");
            }
        }
        let pairs: Vec<_> = build_pairs(root)?
            .into_iter()
            .filter(|pair| self.preset.matches(&pair[0]) && self.committee.matches(&pair[1]))
            .collect();
        if pairs.is_empty() {
            bail!(
                "Unsupported preset/committee pair: {}/{}",
                self.preset,
                self.committee
            );
        }
        Ok(pairs)
    }
    pub fn committees(&self) -> Vec<CiphernodesCommitteeSize> {
        match self.committee {
            CommitteeSelection::All => COMMITTEES
                .iter()
                .map(|name| name.parse().expect("compiled committee list"))
                .collect(),
            CommitteeSelection::Single(committee) => vec![committee],
        }
    }
    /// The single selected preset, or an error for `all`.
    pub fn single_preset(&self) -> Result<BfvPreset> {
        match self.preset {
            PresetSelection::Single(preset) => Ok(preset),
            PresetSelection::All => bail!("Select one supported preset, not all"),
        }
    }
    /// The single selected committee, or an error for `all`.
    pub fn single_committee(&self) -> Result<CiphernodesCommitteeSize> {
        match self.committee {
            CommitteeSelection::Single(committee) => Ok(committee),
            CommitteeSelection::All => bail!("Select one supported committee, not all"),
        }
    }
    pub fn output_dir(&self, root: &Path) -> PathBuf {
        self.output
            .clone()
            .unwrap_or_else(|| root.join("dist/circuits"))
    }
}

impl PresetSelection {
    fn matches(self, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Single(preset) => preset_name(preset) == name,
        }
    }
    fn single_name(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Single(preset) => Some(preset_name(preset)),
        }
    }
}

impl CommitteeSelection {
    fn matches(self, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Single(committee) => committee.to_string() == name,
        }
    }
    fn single_name(&self) -> Option<String> {
        match self {
            Self::All => None,
            Self::Single(committee) => Some(committee.to_string()),
        }
    }
}

impl fmt::Display for PresetSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::Single(preset) => f.write_str(preset_name(*preset)),
        }
    }
}

impl fmt::Display for CommitteeSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::Single(committee) => write!(f, "{committee}"),
        }
    }
}

fn preset(value: &str) -> Result<BfvPreset> {
    match value {
        "insecure-64" => Ok(BfvPreset::InsecureThreshold64),
        "secure-8192" => Ok(BfvPreset::SecureThreshold8192),
        _ => bail!("Select one supported preset, not {value}"),
    }
}
fn tier(preset: BfvPreset) -> &'static str {
    match preset {
        BfvPreset::InsecureThreshold64 => "insecure",
        BfvPreset::SecureThreshold8192 => "secure",
        _ => unreachable!("build selects threshold presets"),
    }
}
fn preset_name(preset: BfvPreset) -> &'static str {
    match preset {
        BfvPreset::InsecureThreshold64 => "insecure-64",
        BfvPreset::SecureThreshold8192 => "secure-8192",
        _ => unreachable!("build selects threshold presets"),
    }
}

fn run(command: &mut Command) -> Result<String> {
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
fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    fs::write(path, data)?;
    Ok(())
}
fn github_output(text: &str) -> Result<()> {
    if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        fs::OpenOptions::new()
            .append(true)
            .open(path)?
            .write_all(text.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;

pub fn execute(root: &Path, request: &Request) -> Result<()> {
    request.validate(root)?;
    match request.operation {
        Operation::Hash => {
            let preset_label = request.preset.single_name().map(str::to_owned);
            let committee_label = request.committee.single_name();
            let hash = identity::source_hash(
                root,
                request,
                preset_label.as_deref(),
                committee_label.as_deref(),
            )?;
            println!("{hash}");
            github_output(&format!("source_hash={hash}\n"))?;
        }
        Operation::SyncConfig => {
            let params = configuration::OperationParams::both()?;
            configuration::sync_protocol(
                root,
                request.single_preset()?,
                request.single_committee()?,
                request.skip_utils_patch,
                &params,
            )?
        }
        Operation::SyncPreset => {
            configuration::sync_preset(root, request.single_preset()?, request.single_committee()?)?
        }
        Operation::Check => configuration::check(root, request)?,
        Operation::SyncBindings => bindings::sync(root, false)?,
        Operation::CheckBindings => bindings::sync(root, true)?,
        Operation::CheckLayouts => layouts::check(root, request)?,
        Operation::ExportConfig => {
            let metadata = metadata::collect(root)?;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &metadata)?;
            writeln!(stdout)?;
        }
        Operation::Build => artifacts::build(root, request)?,
    }
    Ok(())
}
