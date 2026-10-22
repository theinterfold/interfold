// SPDX-License-Identifier: LGPL-3.0-only

//! Command-line entry for the repository circuit builder. All argument parsing lives here;
//! `e3_zk_build::execute` runs a typed [`Request`](e3_zk_build::Request).

use clap::Parser;
use e3_zk_build::{CommitteeSelection, Group, GroupSelection, Operation, PresetSelection, Request};

#[derive(Parser)]
#[command(about = "Build circuit artifacts or check generated configuration.")]
struct Cli {
    /// Operation: build, hash, sync-config, sync-preset, check, export-config, sync-bindings, or check-bindings.
    #[arg(default_value = "build")]
    command: Operation,
    /// BFV artifact preset, or all.
    #[arg(long, default_value = "insecure-64")]
    preset: PresetSelection,
    /// Committee name, or all.
    #[arg(long, default_value = "minimum")]
    committee: CommitteeSelection,
    /// Circuit groups, separated by commas.
    #[arg(long, value_delimiter = ',')]
    group: Vec<Group>,
    /// Circuit name. Repeat this option to select several circuits.
    #[arg(long)]
    circuit: Vec<String>,
    /// Artifact output directory.
    #[arg(short, long)]
    output: Option<std::path::PathBuf>,
    #[arg(long)]
    skip_vk: bool,
    #[arg(long)]
    skip_checksums: bool,
    #[arg(long)]
    skip_utils_patch: bool,
    #[arg(long)]
    no_clean: bool,
    #[arg(long)]
    no_clean_targets: bool,
    #[arg(long)]
    skip_if_built: bool,
    /// Copy published artifacts without requiring a source-hash match.
    #[arg(long)]
    hydrate_bin_only: bool,
    /// Show the selected circuits without changing files.
    #[arg(long)]
    dry_run: bool,
}

impl From<Cli> for Request {
    fn from(cli: Cli) -> Self {
        Self {
            operation: cli.command,
            preset: cli.preset,
            committee: cli.committee,
            groups: if cli.group.is_empty() {
                GroupSelection::All
            } else {
                GroupSelection::Selected(cli.group)
            },
            circuits: cli.circuit,
            output: cli.output,
            skip_vk: cli.skip_vk,
            skip_checksums: cli.skip_checksums,
            skip_utils_patch: cli.skip_utils_patch,
            no_clean: cli.no_clean,
            no_clean_targets: cli.no_clean_targets,
            skip_if_built: cli.skip_if_built,
            hydrate_bin_only: cli.hydrate_bin_only,
            dry_run: cli.dry_run,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let request = Request::from(Cli::parse());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    e3_zk_build::execute(&root, &request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    use e3_fhe_params::BfvPreset;

    fn parse(args: &[&str]) -> Result<Request, clap::Error> {
        Cli::try_parse_from(std::iter::once("build-circuits").chain(args.iter().copied()))
            .map(Request::from)
    }

    #[test]
    fn cli_defaults_and_flags_map_onto_typed_requests() {
        let request = parse(&[]).unwrap();
        assert_eq!(request.operation, Operation::Build);
        assert_eq!(
            request.preset,
            PresetSelection::Single(BfvPreset::InsecureThreshold64)
        );
        assert_eq!(
            request.committee,
            CommitteeSelection::Single(e3_committee::CiphernodesCommitteeSize::Minimum)
        );
        assert_eq!(request.groups, GroupSelection::All);
        let request = parse(&["sync-preset", "--preset", "all"]).unwrap();
        assert_eq!(request.operation, Operation::SyncPreset);
        assert_eq!(request.preset, PresetSelection::All);
        assert_eq!(
            parse(&["export-config"]).unwrap().operation,
            Operation::ExportConfig
        );
        assert_eq!(
            parse(&["sync-bindings"]).unwrap().operation,
            Operation::SyncBindings
        );
        assert_eq!(
            parse(&["check-bindings"]).unwrap().operation,
            Operation::CheckBindings
        );
        let request = parse(&[
            "build",
            "--committee",
            "small",
            "--group",
            "threshold,dkg",
            "--circuit",
            "pk",
            "--no-clean",
            "--no-clean-targets",
        ])
        .unwrap();
        assert_eq!(
            request.groups,
            GroupSelection::Selected(vec![Group::Threshold, Group::Dkg])
        );
        assert_eq!(request.circuits, ["pk"]);
        assert!(request.no_clean && request.no_clean_targets);
    }

    #[test]
    fn cli_rejects_unknown_operations_presets_committees_and_groups() {
        for args in [
            &["frobnicate"][..],
            &["build", "--preset", "secure-4096"],
            &["build", "--committee", "huge"],
            &["build", "--group", "folding"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
        assert_eq!(
            parse(&["nope"]).unwrap_err().kind(),
            ErrorKind::ValueValidation
        );
    }
}
