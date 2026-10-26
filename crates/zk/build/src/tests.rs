// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{
    artifacts, configuration,
    configuration::{compact, PresetMaterial},
    identity, vk_tree, CommitteeSelection, GroupSelection, Operation, PresetSelection, Request,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_zk_witness::compute_vk_hash;
use std::time::{Duration, SystemTime};

#[test]
fn source_hash_matches_the_formatted_build_projection_for_every_pair() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for preset in BfvPreset::PAIR_PRESETS {
        for committee in CiphernodesCommitteeSize::ALL {
            let mut request = request();
            request.preset = PresetSelection::Single(preset);
            request.committee = CommitteeSelection::Single(committee);
            let mut selection =
                configuration::prepare_selection(&root, preset, committee, true).unwrap();
            selection.format(&root).unwrap();
            let name = preset_name(preset);
            let committee = committee.to_string();
            assert_eq!(
                identity::source_hash(&root, &request, Some(name), Some(&committee)).unwrap(),
                identity::source_hash_with_updates(
                    &root,
                    &request,
                    Some(name),
                    Some(&committee),
                    &selection.noir
                )
                .unwrap(),
                "{name}/{committee}: hash CLI and staged build disagree; projected selector: {}",
                selection
                    .noir
                    .iter()
                    .find(|(path, _)| path.ends_with("configs/default/mod.nr"))
                    .unwrap()
                    .1,
            );
        }
    }
}

pub(crate) fn request() -> Request {
    Request {
        operation: Operation::Build,
        preset: PresetSelection::Single(BfvPreset::InsecureThreshold64),
        committee: CommitteeSelection::Single(CiphernodesCommitteeSize::Minimum),
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
    }
}

fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// Seed the pinned-tool manifests that formatter probes read.
pub(crate) fn write_pins(root: &Path) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    write(
        root,
        "crates/zk/prover/Cargo.toml",
        fs::read_to_string(repo.join("crates/zk/prover/Cargo.toml")).unwrap(),
    );
    write(
        root,
        "crates/zk/prover/versions.json",
        fs::read_to_string(repo.join("crates/zk/prover/versions.json")).unwrap(),
    );
}

/// A build root with one tiny circuit per group, the tracked generated library, and no
/// pinned-tool manifests: any tool probe fails on the missing pin file.
fn circuit_root_without_tools() -> tempfile::TempDir {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write(
        root,
        "scripts/circuits/build-pairs.json",
        r#"[["insecure-64","minimum"]]"#,
    );
    artifacts::copy_tree(
        &repo.join("circuits/lib"),
        &root.join("circuits/lib"),
        &["target", "Prover.toml", "Witness.toml"],
    )
    .unwrap();
    for (group, name, workspace) in [("dkg", "pk", true), ("threshold", "pk_generation", false)] {
        write(
            root,
            &format!("circuits/bin/{group}/{name}/Nargo.toml"),
            format!("[package]\nname = \"{name}\"\ntype = \"bin\"\nauthors = []\n"),
        );
        write(
            root,
            &format!("circuits/bin/{group}/{name}/src/main.nr"),
            "fn main(x: Field) -> pub Field { x }\n",
        );
        if workspace {
            write(
                root,
                &format!("circuits/bin/{group}/Nargo.toml"),
                format!("[workspace]\nmembers = [\"{name}\"]\n"),
            );
        }
    }
    temp
}

#[test]
fn build_policy_rejects_disabled_pairs_before_tools_and_filters_all_selectors() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut pairs = build_pairs(&repo).unwrap();
    let mut all = request();
    all.preset = PresetSelection::All;
    all.committee = CommitteeSelection::All;
    assert_eq!(all.selected_pairs(&repo).unwrap(), pairs);
    let count = pairs.len();
    pairs.retain(|pair| pair != &["secure-8192".to_string(), "micro".to_string()]);
    assert_eq!(pairs.len(), count - 1);
    let temp = tempfile::tempdir().unwrap();
    write(
        temp.path(),
        "scripts/circuits/build-pairs.json",
        serde_json::to_vec(&pairs).unwrap(),
    );
    let mut hydration = request();
    hydration.hydrate_bin_only = true;
    hydration.skip_vk = true;
    hydration.preset = PresetSelection::All;
    assert!(hydration
        .validate(temp.path())
        .unwrap_err()
        .to_string()
        .contains("Hydration requires a complete artifact pair"));
    let mut disabled = request();
    disabled.preset = PresetSelection::Single(BfvPreset::SecureThreshold8192);
    disabled.committee = CommitteeSelection::Single(CiphernodesCommitteeSize::Micro);
    assert!(disabled
        .validate(temp.path())
        .unwrap_err()
        .to_string()
        .contains("Unsupported preset/committee pair"));
    // This build root has no toolchain, tool pins, or circuits. Policy rejection must come first.
    assert!(artifacts::build(temp.path(), &disabled)
        .unwrap_err()
        .to_string()
        .contains("Unsupported preset/committee pair"));
    assert!(!temp.path().join("circuits").exists());
    assert!(!temp.path().join("dist").exists());
    assert_eq!(all.selected_pairs(temp.path()).unwrap(), pairs);
    for preset in [BfvPreset::InsecureDkg64, BfvPreset::SecureDkg8192] {
        let mut invalid = request();
        invalid.preset = PresetSelection::Single(preset);
        assert!(execute(temp.path(), &invalid)
            .unwrap_err()
            .to_string()
            .contains("Unsupported build preset"));
    }
    let mut empty = request();
    empty.groups = GroupSelection::Selected(Vec::new());
    assert!(execute(temp.path(), &empty)
        .unwrap_err()
        .to_string()
        .contains("Select at least one circuit group"));
    for options in [
        {
            let mut r = request();
            r.preset = PresetSelection::Single(BfvPreset::SecureThreshold8192);
            r.committee = CommitteeSelection::All;
            r
        },
        {
            let mut r = request();
            r.preset = PresetSelection::All;
            r.committee = CommitteeSelection::Single(CiphernodesCommitteeSize::Micro);
            r
        },
    ] {
        let selected = options.selected_pairs(temp.path()).unwrap();
        for pair in &selected {
            assert!(pairs.contains(pair));
        }
        assert_eq!(
            selected.len(),
            if matches!(options.preset, PresetSelection::All) {
                1
            } else {
                2
            }
        );
        options.validate(temp.path()).unwrap();
    }
}

#[test]
fn dry_run_lists_selections_without_tools_or_writes() {
    // The root has no pinned-tool manifests: any tool probe fails on the missing file, so this
    // passes only while the dry run runs before every probe.
    let temp = circuit_root_without_tools();
    let root = temp.path();
    let mut dry = request();
    dry.dry_run = true;
    execute(root, &dry).unwrap();
    assert!(!root.join("dist").exists());
    assert!(!root.join("circuits/bin/.active-preset.json").exists());
    let content = fs::read_to_string(root.join("circuits/bin/dkg/pk/src/main.nr")).unwrap();
    assert_eq!(content, "fn main(x: Field) -> pub Field { x }\n");
    dry.groups = GroupSelection::Selected(vec![Group::Threshold, Group::Dkg, Group::Threshold]);
    execute(root, &dry).unwrap();
    let discovered = artifacts::discover(root, &dry).unwrap();
    assert_eq!(
        discovered
            .iter()
            .map(|circuit| circuit.group.as_str())
            .collect::<Vec<_>>(),
        ["threshold", "dkg"]
    );
    assert!(!dry.groups.is_complete());
    dry.groups = GroupSelection::Selected(vec![
        Group::Threshold,
        Group::Dkg,
        Group::Dkg,
        Group::RecursiveAggregation,
    ]);
    assert!(dry.groups.is_complete());
}

#[test]
fn full_build_probes_pinned_tools_before_any_artifact_write() {
    let temp = circuit_root_without_tools();
    let root = temp.path();
    write(
        root,
        "circuits/lib/src/configs/committee/active.nr",
        "// stale selection\n",
    );
    write(root, "circuits/bin/.active-preset.json", "old stamp");
    write(root, "dist/circuits/keep", "old artifact");
    write(root, "circuits/bin/dkg/target/keep", "old target");
    let before = snapshot(root);
    assert!(execute(root, &request())
        .unwrap_err()
        .to_string()
        .contains("crates/zk/prover/Cargo.toml"));
    assert_eq!(snapshot(root), before, "tool failure changed live files");
}

#[test]
fn current_selection_sync_preserves_bytes_and_mtimes_without_tools() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let selector =
        fs::read_to_string(repo.join("circuits/lib/src/configs/default/mod.nr")).unwrap();
    let preset = if selector.contains("super::secure::") {
        BfvPreset::SecureThreshold8192
    } else {
        BfvPreset::InsecureThreshold64
    };
    let active =
        fs::read_to_string(repo.join("circuits/lib/src/configs/committee/active.nr")).unwrap();
    let committee = COMMITTEES
        .iter()
        .find(|name| active.contains(&format!("committee::{name}::N_PARTIES")))
        .unwrap()
        .parse()
        .unwrap();
    artifacts::copy_tree(
        &repo.join("circuits/lib"),
        &root.join("circuits/lib"),
        &["target", "Prover.toml", "Witness.toml"],
    )
    .unwrap();
    for relative in [
        "packages/interfold-contracts/scripts/utils.ts",
        "packages/interfold-contracts/contracts/lib/BfvProtocol.sol",
    ] {
        write(root, relative, fs::read(repo.join(relative)).unwrap());
    }
    let files = snapshot(root);
    let relatives: Vec<_> = files.keys().map(|path| path.to_str().unwrap()).collect();
    age_files(root, &relatives);
    let before = snapshot(root);
    // No pin manifests exist. Both syncs must avoid even a formatter version probe.
    for _ in 0..2 {
        let mut selection =
            configuration::prepare_selection(root, preset, committee, false).unwrap();
        selection.format(root).unwrap();
        selection.publish().unwrap();
        assert_eq!(
            snapshot(root),
            before,
            "current generated selection was rewritten"
        );
    }
}

pub(crate) fn snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, (Vec<u8>, SystemTime)> {
    fn walk(
        root: &Path,
        directory: &Path,
        out: &mut std::collections::BTreeMap<PathBuf, (Vec<u8>, SystemTime)>,
    ) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    (
                        fs::read(&path).unwrap(),
                        fs::metadata(path).unwrap().modified().unwrap(),
                    ),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Move file modification times into the past so rewrites are observable.
fn age_files(root: &Path, relatives: &[&str]) {
    let past = SystemTime::now() - Duration::from_secs(3600);
    for relative in relatives {
        let file = fs::File::options()
            .write(true)
            .open(root.join(relative))
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(past))
            .unwrap();
    }
}

#[test]
fn source_identity_tracks_inputs_not_generated_selections_or_tests() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    identity::tests::seed_sources(root);
    let opts = request();
    let hash = || identity::source_hash(root, &opts, Some("insecure-64"), Some("micro")).unwrap();
    let config = "circuits/lib/src/configs/insecure/threshold.nr";
    write(root, config, "pub global PK_GENERATION_E_SM_BOUND: Field = 10;\npub global PK_GENERATION_E_SM_QUOTIENT_BOUNDS: [Field; L] =\n    [1, 2];\npub global L: u32 = 2;\n");
    let before = hash();
    write(root, config, "pub global PK_GENERATION_E_SM_BOUND: Field = 20;\npub global PK_GENERATION_E_SM_QUOTIENT_BOUNDS: [Field; L] =\n    [3, 4];\npub global L: u32 = 2;\n");
    assert_eq!(hash(), before);
    write(root, "crates/zk/build/src/tests.rs", "test-only source");
    assert_eq!(hash(), before);
    write(root, config, "pub global PK_GENERATION_E_SM_BOUND: Field = 20;\npub global PK_GENERATION_E_SM_QUOTIENT_BOUNDS: [Field; L] =\n    [3, 4];\npub global L: u32 = 3;\n");
    assert_ne!(hash(), before);
    for path in [
        "crates/zk/build/src/main.rs",
        "crates/zk/build/src/configuration.rs",
        "crates/zk/config/src/threshold/pk_generation.rs",
        "crates/zk/witness/src/commitments.rs",
        "crates/committee/src/lib.rs",
        "crates/fhe-params/src/presets.rs",
        "crates/polynomial/src/lib.rs",
        "crates/polynomial/fhe-adapter/src/lib.rs",
    ] {
        write(
            root,
            path,
            "pub fn bound() -> u64 { 7 }\n#[cfg(test)]\nmod tests {\n    fn sample() {}\n}\n",
        );
        let before = hash();
        for visibility in ["", "pub ", "pub(crate) ", "pub(super) "] {
            write(root, path, format!("pub fn bound() -> u64 {{ 7 }}\n#[cfg(test)]\n{visibility}mod tests {{\n    fn another_sample() {{}}\n}}\n"));
            assert_eq!(hash(), before, "test-only edit of {path} ({visibility})");
        }
        write(root, path, "pub fn bound() -> u64 { 8 }\n#[cfg(test)]\nmod tests {\n    fn another_sample() {}\n}\n");
        assert_ne!(hash(), before, "generator edit of {path}");
    }
    let selector = "circuits/lib/src/configs/default/mod.nr";
    write(root, selector, "// preset: insecure-64\npub use super::insecure::threshold;\npub global MAX_MSG_NON_ZERO_COEFFS: u32 = 50;\n");
    let before = hash();
    write(root, selector, "// preset: secure-8192\npub use super::secure::threshold;\npub global MAX_MSG_NON_ZERO_COEFFS: u32 = 50;\n");
    assert_eq!(hash(), before);
    write(root, selector, "// preset: secure-8192\npub use super::secure::threshold;\npub global MAX_MSG_NON_ZERO_COEFFS: u32 = 51;\n");
    assert_ne!(hash(), before);
    for path in [
        "circuits/lib/src/core/dkg/pk.nr",
        "circuits/lib/src/math/commitments.nr",
        "circuits/lib/Nargo.toml",
        "circuits/lib/src/configs/committee/micro/mod.nr",
        "scripts/circuits/build-pairs.json",
        "crates/zk/build/templates/active_crypto_config.sol.in",
        "crates/zk/build/templates/committee_active.nr.in",
    ] {
        write(root, path, "original");
        let before = hash();
        write(root, path, "changed");
        assert_ne!(hash(), before, "{path}");
    }
    let parity = root.join("circuits/lib/src/configs/committee/micro/parity_insecure.nr");
    let updates = vec![(parity.clone(), "generated parity\n".to_owned())];
    let projected = identity::source_hash_with_updates(
        root,
        &opts,
        Some("insecure-64"),
        Some("micro"),
        &updates,
    )
    .unwrap();
    assert!(
        !parity.exists(),
        "projected identity published a missing source"
    );
    fs::write(&parity, &updates[0].1).unwrap();
    assert_eq!(
        hash(),
        projected,
        "projected identity does not match published sources"
    );
}

#[test]
fn source_identity_frames_file_boundaries_and_source_roots() {
    let cases = [
        (
            "directory file boundaries",
            vec![
                ("crates/zk/config/src/a.rs", "// first"),
                ("crates/zk/config/src/b.rs", "// secondc.rs// third"),
            ],
            vec![
                ("crates/zk/config/src/a.rs", "// firstb.rs// second"),
                ("crates/zk/config/src/c.rs", "// third"),
            ],
        ),
        (
            "source root identity",
            vec![("crates/zk/config/src/lib.rs", "// source")],
            vec![("crates/zk/witness/src/lib.rs", "// source")],
        ),
        (
            "top-level file boundaries",
            vec![
                ("circuits/lib/Nargo.toml", "# first"),
                (
                    "circuits/lib/src/lib.nr",
                    "// secondcircuits/lib/src/configs/mod.nr// third",
                ),
            ],
            vec![
                (
                    "circuits/lib/Nargo.toml",
                    "# firstcircuits/lib/src/lib.nr// second",
                ),
                ("circuits/lib/src/configs/mod.nr", "// third"),
            ],
        ),
    ];
    for (case, left, right) in cases {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for (root, files) in [(first.path(), left), (second.path(), right)] {
            identity::tests::seed_sources(root);
            for (path, contents) in files {
                write(root, path, contents);
            }
        }
        let hash = |root| {
            identity::source_hash(root, &request(), Some("insecure-64"), Some("minimum")).unwrap()
        };
        assert_ne!(hash(first.path()), hash(second.path()), "{case}");
    }
}

#[test]
fn source_identity_tracks_external_pins_and_pinned_tools() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    identity::tests::seed_sources(root);
    let opts = request();
    let lock = "version = 3\n[[package]]\nname = \"e3-example\"\nversion = \"0.14.0\"\ndependencies = [\"external\"]\n[[package]]\nname = \"external\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"1111\"\n";
    write(root, "Cargo.lock", lock);
    let manifest = "[package]\nedition = \"2021\"\nversion = \"0.19.0\"\n[dependencies]\ne3-polynomial = { workspace = true, features = [\"serde\"] }\n[dev-dependencies]\ne3-zk-witness = { workspace = true }\n";
    write(root, "crates/zk/build/Cargo.toml", manifest);
    write(
        root,
        "crates/zk/prover/Cargo.toml",
        "nargo = { git = \"https://github.com/noir-lang/noir\", tag = \"v1.0.0-beta.26\" }\n",
    );
    write(
        root,
        "crates/zk/prover/versions.json",
        r#"{"required_bb_version":"5.2.0","required_circuits_version":"0.19.0"}"#,
    );
    let hash = || identity::source_hash(root, &opts, Some("insecure-64"), Some("minimum")).unwrap();
    let before = hash();
    write(
        root,
        "crates/zk/build/Cargo.toml",
        manifest.replace("0.19.0", "0.20.0").replace(
            "e3-zk-witness = { workspace = true }",
            "e3-other = { workspace = true }",
        ),
    );
    assert_eq!(hash(), before);
    write(
        root,
        "crates/zk/build/Cargo.toml",
        manifest.replace("features = [\"serde\"]", "features = []"),
    );
    assert_ne!(hash(), before);
    write(root, "crates/zk/build/Cargo.toml", manifest);
    write(
        root,
        "Cargo.lock",
        lock.replace("0.14.0", "0.15.0")
            .replace("[\"external\"]", "[]"),
    );
    assert_eq!(hash(), before);
    write(root, "Cargo.lock", lock.replace("1111", "2222"));
    assert_ne!(hash(), before);
    write(root, "Cargo.lock", lock);
    write(
        root,
        "crates/zk/prover/versions.json",
        r#"{"required_bb_version":"5.2.0","required_circuits_version":"9.9.9"}"#,
    );
    assert_eq!(hash(), before);
    write(
        root,
        "crates/zk/prover/versions.json",
        r#"{"required_bb_version":"5.2.1"}"#,
    );
    assert_ne!(hash(), before);
    write(
        root,
        "crates/zk/prover/versions.json",
        r#"{"required_bb_version":"5.2.0"}"#,
    );
    write(
        root,
        "crates/zk/prover/Cargo.toml",
        "nargo = { git = \"https://github.com/noir-lang/noir\", tag = \"v1.0.0-beta.27\" }\n",
    );
    assert_ne!(hash(), before);
}

#[test]
fn exact_tool_versions_accept_build_metadata_not_other_releases() {
    for (text, version, accepted) in [
        (
            "nargo version = 1.0.0-beta.26+abcdef\n",
            "1.0.0-beta.26",
            true,
        ),
        ("v5.2.0\r\n", "5.2.0", true),
        ("5.2.01\n", "5.2.0", false),
        ("15.2.0\n", "5.2.0", false),
        ("5.2.0-nightly\n", "5.2.0", false),
        (
            "nargo version = 1.0.0-beta.26-dev\n",
            "1.0.0-beta.26",
            false,
        ),
    ] {
        assert_eq!(identity::reports_version(text, version), accepted, "{text}");
    }
}

#[test]
fn checksum_streams_files_of_any_size_to_the_same_digest() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("artifact");
    // 20_000 bytes cross several read buffers. The expected digests are SHA-256 of this exact
    // content, computed independently of the implementation.
    let bytes = vec![0xAB_u8; 20_000];
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        checksum(&path).unwrap(),
        "1b53c5e8138cf85261885e5efbd49452254ad6ad365603d05fc7776d5eee93c0"
    );
    let bytes = vec![0x01_u8; 8191];
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        checksum(&path).unwrap(),
        "4a9cdd5a3aae2fb93eef060ff6c7903abf74021ed059ad34d4de45d47d12bd57"
    );
    let bytes = vec![0x00_u8; 8192];
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        checksum(&path).unwrap(),
        "9f1dcbc35c350d6027f98be0f5c8b43b42ca52b7604459c0c42be3aa88913d47"
    );
}

#[test]
fn protocol_generation_preserves_deployed_parameter_hashes() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fhe-params/tests/fixtures/bfv_protocol.json"
    ))
    .unwrap();
    for vector in fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|vector| vector["preset"].is_string())
    {
        let preset = BfvPreset::from_name(vector["preset"].as_str().unwrap()).unwrap();
        let material = PresetMaterial::new(preset).unwrap();
        assert_eq!(
            material.parameter_hash.to_string(),
            vector["parameterHash"].as_str().unwrap()
        );
        assert_eq!(
            material.config_id.to_string(),
            vector["cryptoConfigId"].as_str().unwrap()
        );
    }
}

#[test]
fn shared_operation_material_serves_parity_bounds_and_protocol_renderers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    artifacts::copy_tree(
        &repo.join("circuits/lib"),
        &root.join("circuits/lib"),
        &["target", "Prover.toml", "Witness.toml"],
    )
    .unwrap();
    let params = configuration::OperationParams::both().unwrap();
    // The same material renders parity files, bound updates, the TypeScript constants, and the
    // Solidity contract with the deployed hashes.
    for committee in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
        CiphernodesCommitteeSize::Small,
    ] {
        let parity = configuration::parity_files(committee, &params).unwrap();
        assert_eq!(parity.len(), 2);
    }
    let material = params.get(BfvPreset::InsecureThreshold64);
    let bounds = configuration::bound_updates(
        root,
        BfvPreset::InsecureThreshold64,
        CiphernodesCommitteeSize::Minimum,
        material,
    )
    .unwrap();
    assert_eq!(bounds.len(), 2);
    let contract = crate::bindings::solidity(&params).unwrap();
    assert!(contract.contains(&format!(
        "{:#x}",
        params.get(BfvPreset::SecureThreshold8192).config_id
    )));
    let selection = configuration::prepare_selection(
        root,
        BfvPreset::InsecureThreshold64,
        CiphernodesCommitteeSize::Minimum,
        true,
    )
    .unwrap();
    let protocol = &selection
        .noir
        .iter()
        .find(|(path, _)| path.ends_with("configs/protocol.nr"))
        .unwrap()
        .1;
    let declarations = configuration::declarations(protocol);
    let width = declarations["MAX_MSG_NON_ZERO_COEFFS"]
        .split('=')
        .nth(1)
        .unwrap()
        .trim()
        .trim_end_matches(';')
        .parse::<usize>()
        .unwrap();
    assert_eq!(width, e3_zk_config::MAX_MSG_NON_ZERO_COEFFS);
    let width = regex::Regex::new(r"\bMESSAGE_COEFFS_COUNT\s*=\s*(\d+)\s*;")
        .unwrap()
        .captures(&contract)
        .unwrap()[1]
        .parse::<usize>()
        .unwrap();
    assert_eq!(width, e3_zk_config::MAX_MSG_NON_ZERO_COEFFS);
}

#[test]
fn every_pair_replaces_whole_scalar_and_array_bound_declarations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let params = configuration::OperationParams::both().unwrap();
    for preset in BfvPreset::PAIR_PRESETS {
        for name in COMMITTEES {
            let committee = name.parse().unwrap();
            let material = params.get(preset);
            for (path, updated) in
                configuration::bound_updates(&root, preset, committee, material).unwrap()
            {
                let fresh = if path.ends_with("threshold.nr") {
                    e3_zk_config::threshold::pk_generation::Configs::new(
                        preset,
                        &material.threshold,
                        committee,
                    )
                    .unwrap()
                    .render()
                    .unwrap()
                } else {
                    e3_zk_config::dkg::share_computation::Configs::new(
                        preset,
                        &material.threshold,
                        committee,
                    )
                    .unwrap()
                    .render()
                    .unwrap()
                };
                let declarations = configuration::declarations(&updated);
                for (name, declaration) in configuration::declarations(&fresh) {
                    if name.starts_with("PK_GENERATION_") || name.starts_with("SHARE_COMPUTATION_")
                    {
                        assert_eq!(
                            compact(declarations.get(&name).unwrap()),
                            compact(&declaration),
                            "{name}"
                        );
                    }
                }
            }
        }
    }
    assert!(configuration::replace_declarations(
        "pub global A: [Field; 2] =\n [1, 2];\n",
        "pub global A: [Field; 2] = [3, 4];\n",
        "A",
        &[],
        true
    )
    .unwrap()
    .contains("[3, 4]"));
    assert!(configuration::replace_declarations(
        "pub global A: u32 = 1;\npub global AB: u32 = 2;",
        "pub global A: u32 = 3;",
        "A",
        &[],
        true
    )
    .is_err());
}

#[test]
fn hydration_accepts_other_source_but_records_actual_artifact_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let opts = request();
    let pair = root.join("dist/circuits/insecure-64/minimum");
    for marker in artifacts::dist_markers(&pair) {
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(marker, b"marker").unwrap();
    }
    let stamp = artifacts::Stamp {
        preset: "insecure-64".into(),
        committee: "minimum".into(),
        source_hash: "published-source".into(),
        built_at: "published-time".into(),
    };
    write_json(&pair.join(".build-stamp.json"), &stamp).unwrap();
    for (group, name, workspace) in [
        ("dkg", "pk", true),
        ("recursive_aggregation", "nodes_fold", false),
    ] {
        write(
            root,
            &format!("circuits/bin/{group}/{name}/Nargo.toml"),
            format!("[package]\nname = \"{name}\"\ntype = \"bin\"\n"),
        );
        if workspace {
            write(
                root,
                &format!("circuits/bin/{group}/Nargo.toml"),
                format!("[workspace]\nmembers = [\"{name}\"]\n"),
            );
        }
        write(
            root,
            &format!("circuits/bin/{group}/{name}/target/stale.json"),
            "stale",
        );
        for variant in ["default", "recursive", "evm"] {
            for extension in ["json", "vk", "vk_hash"] {
                write(
                    &pair,
                    &format!("{variant}/{group}/{name}/{name}.{extension}"),
                    format!("{variant}-{extension}"),
                );
            }
        }
    }
    let accepted =
        artifacts::hydration_stamp(&pair, "insecure-64", "minimum", "current-source").unwrap();
    artifacts::hydrate(root, &pair, &opts, &accepted).unwrap();
    assert_eq!(
        fs::read_to_string(root.join("circuits/bin/dkg/target/pk.json")).unwrap(),
        "default-json"
    );
    for (suffix, value) in [
        ("vk", "evm-vk"),
        ("vk_recursive", "default-vk"),
        ("vk_noir", "recursive-vk"),
    ] {
        assert_eq!(
            fs::read_to_string(root.join(format!("circuits/bin/dkg/target/pk.{suffix}"))).unwrap(),
            value
        );
    }
    assert!(!root.join("circuits/bin/dkg/pk/target/stale.json").exists());
    assert!(!root
        .join("circuits/bin/recursive_aggregation/nodes_fold/target/stale.json")
        .exists());
    let active: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("circuits/bin/.active-preset.json")).unwrap())
            .unwrap();
    assert_eq!(active["sourceHash"], "published-source");
    assert_eq!(
        fs::read_to_string(pair.join(".build-stamp.json")).unwrap(),
        serde_json::to_string_pretty(&stamp).unwrap() + "\n"
    );
    assert!(artifacts::hydration_stamp(&pair, "secure-8192", "minimum", "current-source").is_err());
    fs::remove_file(pair.join("default/recursive_aggregation/c6_fold/c6_fold.vk_tree_hash"))
        .unwrap();
    assert!(artifacts::hydration_stamp(&pair, "insecure-64", "minimum", "current-source").is_err());
}

const VK_PATHS: &[(&str, &str, &str)] = &[
    ("recursive", "dkg", "sk_share_computation"),
    ("recursive", "dkg", "e_sm_share_computation"),
    ("default", "recursive_aggregation", "c3_fold"),
    ("default", "recursive_aggregation", "c3_fold_kernel"),
    ("recursive", "dkg", "share_encryption"),
    ("recursive", "dkg", "share_decryption"),
    ("recursive", "dkg", "pk"),
    ("recursive", "threshold", "pk_generation"),
    ("default", "recursive_aggregation", "c2ab_fold"),
    ("default", "recursive_aggregation", "c3ab_fold"),
    ("default", "recursive_aggregation", "c4ab_fold"),
    ("default", "recursive_aggregation", "nodes_fold"),
    ("default", "recursive_aggregation", "nodes_fold_kernel"),
    ("default", "recursive_aggregation", "node_fold"),
    ("default", "recursive_aggregation", "c6_fold"),
    ("default", "recursive_aggregation", "c6_fold_kernel"),
    ("recursive", "threshold", "share_decryption"),
];
pub(crate) fn seed_anchor_keys(pair: &Path) {
    for i in 0..VK_PATHS.len() {
        write(pair, &key_path(i), field_bytes(Fr::from((i + 1) as u64)));
    }
}
fn key_path(index: usize) -> String {
    let (variant, group, name) = VK_PATHS[index];
    format!("{variant}/{group}/{name}/{name}.vk_hash")
}
fn field_bytes(value: Fr) -> [u8; 32] {
    let repr = value.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - repr.len()..].copy_from_slice(&repr);
    out
}

#[test]
fn anchors_bind_all_descendants_in_circuit_order_and_reject_noncanonical_keys() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let keys: Vec<_> = (1..=VK_PATHS.len()).map(|i| Fr::from(i as u64)).collect();
    for (i, key) in keys.iter().enumerate() {
        write(root, &key_path(i), field_bytes(*key));
    }
    let c2 = compute_vk_hash(vec![keys[0], keys[1]]);
    let c3_chain = compute_vk_hash(vec![keys[2], keys[3], keys[4]]);
    let node = compute_vk_hash(vec![
        keys[6],
        keys[7],
        keys[8],
        c2,
        keys[9],
        compute_vk_hash(vec![c3_chain, c3_chain]),
        keys[10],
        compute_vk_hash(vec![keys[5], keys[5]]),
    ]);
    let expected = [
        (
            "nodes_fold",
            field_bytes(compute_vk_hash(vec![keys[11], keys[12], keys[13], node])),
        ),
        (
            "c6_fold",
            field_bytes(compute_vk_hash(vec![keys[14], keys[15], keys[16]])),
        ),
    ];
    assert_eq!(vk_tree::hashes(root).unwrap(), expected);
    for (i, key) in keys.iter().enumerate() {
        write(root, &key_path(i), field_bytes(Fr::from(99_u64)));
        let changed = vk_tree::hashes(root).unwrap();
        assert_ne!(
            changed[usize::from(i >= 14)].1,
            expected[usize::from(i >= 14)].1,
            "{}",
            key_path(i)
        );
        assert_eq!(
            changed[usize::from(i < 14)].1,
            expected[usize::from(i < 14)].1
        );
        write(root, &key_path(i), field_bytes(*key));
    }
    write(root, &key_path(0), [0xff; 32]);
    assert!(vk_tree::hashes(root)
        .unwrap_err()
        .to_string()
        .contains("canonical range"));
    write(root, &key_path(0), [0; 31]);
    assert!(vk_tree::hashes(root)
        .unwrap_err()
        .to_string()
        .contains("expected 32 bytes"));
    fs::remove_file(root.join(key_path(0))).unwrap();
    assert!(vk_tree::hashes(root).is_err());
}

#[test]
fn partial_build_removes_anchors_and_manifests_cover_complete_anchors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let pair = root.join("dist/circuits/insecure-64/minimum");
    seed_anchor_keys(&pair);
    artifacts::refresh_anchors(root, &pair, true).unwrap();
    artifacts::checksums(&root.join("dist/circuits")).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("dist/circuits/checksums.json")).unwrap())
            .unwrap();
    for name in ["nodes_fold", "c6_fold"] {
        let relative =
            format!("insecure-64/minimum/default/recursive_aggregation/{name}/{name}.vk_tree_hash");
        let digest = checksum(&root.join("dist/circuits").join(&relative)).unwrap();
        assert_eq!(manifest["files"][&relative], digest);
    }
    artifacts::refresh_anchors(root, &pair, false).unwrap();
    for name in ["nodes_fold", "c6_fold"] {
        assert!(!pair
            .join(format!(
                "default/recursive_aggregation/{name}/{name}.vk_tree_hash"
            ))
            .exists());
        assert!(!root
            .join(format!(
                "circuits/bin/recursive_aggregation/{name}/target/{name}.vk_tree_hash"
            ))
            .exists());
    }
}
