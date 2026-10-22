// SPDX-License-Identifier: LGPL-3.0-only

use crate::{artifacts, configuration, identity, vk_tree, Request};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub const PAIR_FILE: &str = "identities.json";
pub const MANIFEST: &str = "circuits/identities.json";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashKind {
    BbVkHash,
    SolidityVkHash,
    RecursiveTreeCommitment,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Key {
    pub preset: String,
    pub committee: String,
    pub circuit: String,
    pub proof_variant: String,
    pub hash_kind: HashKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub key: Key,
    pub value: String,
    pub compiled_artifact: Option<Artifact>,
    pub verification_key: Option<Artifact>,
    pub dependencies: Vec<Key>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pair {
    pub preset: String,
    pub committee: String,
    pub source_hash: String,
    pub nargo_version: String,
    pub bb_version: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub pairs: Vec<Pair>,
}

fn artifact(base: &Path, path: &Path) -> Result<Artifact> {
    ensure!(
        path.is_file() && !path.is_symlink(),
        "Missing or symlinked artifact {}",
        path.display()
    );
    Ok(Artifact {
        path: path
            .strip_prefix(base)?
            .to_str()
            .context("UTF-8 artifact path")?
            .replace('\\', "/"),
        sha256: identity::checksum(path)?,
    })
}

fn hash_file(path: &Path, canonical_field: bool) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Read {}", path.display()))?;
    ensure!(
        bytes.len() == 32,
        "{}: expected a 32-byte identity",
        path.display()
    );
    if canonical_field {
        vk_tree::validate_field(&bytes)?;
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn solidity_hash(source: &str) -> Result<String> {
    let regex = regex::Regex::new(r"(?m)^uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});$")?;
    let values: Vec<_> = regex.captures_iter(source).collect();
    ensure!(values.len() == 1, "Expected one generated Solidity VK_HASH");
    Ok(values[0][1].to_lowercase())
}

pub fn verifier_path(root: &Path, preset: &str, committee: &str, name: &str) -> PathBuf {
    let base = root.join("packages/interfold-contracts/contracts/verifiers/bfv/honk");
    let directory = if preset == "insecure-64" && committee == "minimum" {
        base
    } else {
        base.join(preset).join(committee)
    };
    directory.join(if name == "dkg_aggregator" {
        "DkgAggregatorVerifier.sol"
    } else {
        "DecryptionAggregatorVerifier.sol"
    })
}

pub fn collect_pair(root: &Path, output: &Path, preset: &str, committee: &str) -> Result<Pair> {
    let pair = output.join(preset).join(committee);
    let stamp: artifacts::Stamp = serde_json::from_slice(&fs::read(pair.join(".build-stamp.json")).with_context(|| format!("Missing build stamp for {preset}/{committee}; prepare this pair with pnpm build:circuits"))?)?;
    let mut request = crate::default_request();
    request.preset = crate::PresetSelection::Single(crate::preset(preset)?);
    request.committee = crate::CommitteeSelection::Single(committee.parse()?);
    let mut selection =
        configuration::prepare_selection(root, crate::preset(preset)?, committee.parse()?, true)?;
    selection.format(root)?;
    let source_hash = identity::source_hash_with_updates(
        root,
        &request,
        Some(preset),
        Some(committee),
        &selection.noir,
    )?;
    ensure!(stamp.preset == preset && stamp.committee == committee && stamp.source_hash == source_hash,
        "Stale artifacts for {preset}/{committee}: stamp={}, current={source_hash}; rebuild, do not restamp", stamp.source_hash);
    let (nargo_version, bb_version) = identity::toolchain(root)?;
    let key = |circuit: String, variant: &str, kind| Key {
        preset: preset.into(),
        committee: committee.into(),
        circuit,
        proof_variant: variant.into(),
        hash_kind: kind,
    };
    let mut entries = Vec::new();
    for circuit in artifacts::discover(root, &request)? {
        for (variant, _, _) in artifacts::variants(&circuit) {
            let directory = pair.join(variant).join(&circuit.group).join(&circuit.name);
            let compiled = artifact(output, &directory.join(format!("{}.json", circuit.package)))?;
            let vk = artifact(output, &directory.join(format!("{}.vk", circuit.package)))?;
            let value = hash_file(
                &directory.join(format!("{}.vk_hash", circuit.package)),
                variant != "evm",
            )?;
            let circuit_name = format!("{}/{}", circuit.group, circuit.name);
            entries.push(Entry {
                key: key(circuit_name.clone(), variant, HashKind::BbVkHash),
                value,
                compiled_artifact: Some(compiled.clone()),
                verification_key: Some(vk.clone()),
                dependencies: vec![],
            });
            if variant == "evm" && circuit.group == "recursive_aggregation" {
                let source = verifier_path(root, preset, committee, &circuit.name);
                entries.push(Entry {
                    key: key(circuit_name, variant, HashKind::SolidityVkHash),
                    value: solidity_hash(
                        &fs::read_to_string(&source)
                            .with_context(|| format!("Read {}", source.display()))?,
                    )?,
                    compiled_artifact: Some(compiled),
                    verification_key: Some(vk),
                    dependencies: vec![],
                });
            }
        }
    }
    for tree in vk_tree::commitments(&pair)? {
        let value = format!("0x{}", hex::encode(tree.value));
        if matches!(tree.name, "nodes_fold" | "c6_fold") {
            let path = pair
                .join("default/recursive_aggregation")
                .join(tree.name)
                .join(format!("{}.vk_tree_hash", tree.name));
            ensure!(
                hash_file(&path, true)? == value,
                "Stale ordered tree anchor {}",
                path.display()
            );
        }
        let dependencies = tree
            .dependencies
            .into_iter()
            .map(|dependency| match dependency {
                vk_tree::Component::Vk(variant, group, name) => {
                    key(format!("{group}/{name}"), variant, HashKind::BbVkHash)
                }
                vk_tree::Component::Tree(name) => key(
                    format!("recursive_aggregation/{name}"),
                    "default",
                    HashKind::RecursiveTreeCommitment,
                ),
            })
            .collect();
        entries.push(Entry {
            key: key(
                format!("recursive_aggregation/{}", tree.name),
                "default",
                HashKind::RecursiveTreeCommitment,
            ),
            value,
            compiled_artifact: None,
            verification_key: None,
            dependencies,
        });
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    validate_entries(&entries)?;
    Ok(Pair {
        preset: preset.into(),
        committee: committee.into(),
        source_hash,
        nargo_version,
        bb_version,
        entries,
    })
}

fn validate_entries(entries: &[Entry]) -> Result<()> {
    let keys: BTreeSet<_> = entries.iter().map(|entry| &entry.key).collect();
    ensure!(
        keys.len() == entries.len(),
        "Duplicate circuit identity key"
    );
    for entry in entries {
        ensure!(
            ["default", "recursive", "evm"].contains(&entry.key.proof_variant.as_str()),
            "Unknown proof variant"
        );
        ensure!(
            entry.value.len() == 66
                && entry.value.starts_with("0x")
                && hex::decode(&entry.value[2..])?.len() == 32,
            "Invalid 32-byte circuit identity"
        );
        if entry.key.hash_kind == HashKind::RecursiveTreeCommitment {
            ensure!(
                entry.key.proof_variant == "default"
                    && entry.compiled_artifact.is_none()
                    && entry.verification_key.is_none()
                    && !entry.dependencies.is_empty(),
                "Invalid composite identity shape"
            );
            vk_tree::validate_field(&hex::decode(&entry.value[2..])?)?;
        } else {
            ensure!(
                entry.compiled_artifact.is_some()
                    && entry.verification_key.is_some()
                    && entry.dependencies.is_empty(),
                "Key identities require their compiled artifact and VK digests"
            );
            if entry.key.hash_kind == HashKind::SolidityVkHash {
                ensure!(
                    entry.key.proof_variant == "evm",
                    "Solidity identities must use EVM keys"
                );
            }
            if entry.key.proof_variant != "evm" {
                vk_tree::validate_field(&hex::decode(&entry.value[2..])?)?;
            }
        }
        for dependency in &entry.dependencies {
            ensure!(
                *dependency != entry.key && keys.contains(dependency),
                "Missing or self-dependent circuit identity {dependency:?}"
            );
        }
    }
    fn visit<'a>(
        key: &'a Key,
        entries: &'a [Entry],
        visiting: &mut BTreeSet<&'a Key>,
        done: &mut BTreeSet<&'a Key>,
    ) -> Result<()> {
        if done.contains(key) {
            return Ok(());
        }
        ensure!(visiting.insert(key), "Cyclic circuit identity {key:?}");
        for child in &entries
            .iter()
            .find(|entry| entry.key == *key)
            .context("Missing identity")?
            .dependencies
        {
            visit(child, entries, visiting, done)?;
        }
        visiting.remove(key);
        done.insert(key);
        Ok(())
    }
    let (mut visiting, mut done) = (BTreeSet::new(), BTreeSet::new());
    for entry in entries {
        visit(&entry.key, entries, &mut visiting, &mut done)?;
    }
    Ok(())
}

pub fn collect(root: &Path, output: &Path) -> Result<Manifest> {
    let mut pairs = Vec::new();
    let policy = crate::build_pairs(root)?;
    let required: Vec<[String; 2]> = serde_json::from_slice(&fs::read(
        root.join("crates/zk/prover/supported-configurations.json"),
    )?)?;
    for pair in &required {
        ensure!(
            policy.contains(pair),
            "Release-required pair {pair:?} is disabled by build policy"
        );
    }
    for [preset, committee] in policy {
        pairs.push(collect_pair(root, output, &preset, &committee)?);
    }
    Ok(Manifest {
        format_version: 1,
        pairs,
    })
}

fn write_changed(path: &Path, value: &impl Serialize) -> Result<bool> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if fs::read(path).ok().as_deref() != Some(bytes.as_slice()) {
        fs::create_dir_all(path.parent().context("Identity parent")?)?;
        fs::write(path, bytes)?;
        return Ok(true);
    }
    Ok(false)
}

pub fn generate(root: &Path, output: &Path) -> Result<()> {
    let manifest = collect(root, output)?;
    let mut changed = false;
    for pair in &manifest.pairs {
        changed |= write_changed(
            &output
                .join(&pair.preset)
                .join(&pair.committee)
                .join(PAIR_FILE),
            pair,
        )?;
    }
    changed |= write_changed(&root.join(MANIFEST), &manifest)?;
    changed |= write_changed(&output.join(PAIR_FILE), &manifest)?;
    if changed || !output.join("checksums.json").is_file() {
        artifacts::checksums(output)?;
    }
    Ok(())
}

pub fn write_pair(directory: &Path, pair: &Pair) -> Result<()> {
    write_changed(&directory.join(PAIR_FILE), pair).map(|_| ())
}

pub fn invalidate(root: &Path, pair: &Path) -> Result<()> {
    for path in [
        root.join(MANIFEST),
        pair.join(PAIR_FILE),
        pair.parent()
            .and_then(Path::parent)
            .context("Artifact output parent")?
            .join(PAIR_FILE),
    ] {
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub fn check(root: &Path, request: &Request) -> Result<()> {
    identity::check_tools(root, true, true)?;
    let output = request.output_dir(root);
    let selected = request.selected_pairs(root)?;
    let complete = selected == crate::build_pairs(root)?;
    let expected = if complete {
        collect(root, &output)?
    } else {
        Manifest {
            format_version: 1,
            pairs: selected
                .iter()
                .map(|[preset, committee]| collect_pair(root, &output, preset, committee))
                .collect::<Result<Vec<_>>>()?,
        }
    };
    if complete {
        let path = root.join(MANIFEST);
        let actual: Manifest = serde_json::from_slice(&fs::read(&path).with_context(|| {
            format!(
                "Read {}; generate identities after preparing the complete matrix",
                path.display()
            )
        })?)?;
        validate_manifest(&actual, &expected)?;
        let published: Manifest = serde_json::from_slice(&fs::read(output.join(PAIR_FILE))?)?;
        validate_manifest(&published, &expected)?;
    }
    for pair in &expected.pairs {
        let stored: Pair = serde_json::from_slice(&fs::read(
            output
                .join(&pair.preset)
                .join(&pair.committee)
                .join(PAIR_FILE),
        )?)?;
        ensure!(
            &stored == pair,
            "Stale pair identity slice {}/{}",
            pair.preset,
            pair.committee
        );
        let mut verified = BTreeSet::new();
        for entry in &pair.entries {
            let (Some(compiled), Some(vk)) = (&entry.compiled_artifact, &entry.verification_key)
            else {
                continue;
            };
            if !verified.insert(vk.path.clone()) {
                continue;
            }
            let job = tempfile::tempdir()?;
            let target = match entry.key.proof_variant.as_str() {
                "default" => "noir-recursive-no-zk",
                "recursive" => "noir-recursive",
                "evm" => "evm",
                other => bail!("Unknown proof variant {other}"),
            };
            crate::run(
                Command::new("bb")
                    .args(["write_vk", "-b"])
                    .arg(output.join(&compiled.path))
                    .arg("-o")
                    .arg(job.path())
                    .args(["-t", target]),
            )?;
            ensure!(
                fs::read(job.path().join("vk"))? == fs::read(output.join(&vk.path))?,
                "Backend VK bytes differ: {}",
                vk.path
            );
            let key_hash = hash_file(&job.path().join("vk_hash"), target != "evm")?;
            let bb_key = Key {
                hash_kind: HashKind::BbVkHash,
                ..entry.key.clone()
            };
            ensure!(
                pair.entries
                    .iter()
                    .find(|item| item.key == bb_key)
                    .context("Missing BB identity")?
                    .value
                    == key_hash,
                "Backend VK hash differs: {}",
                vk.path
            );
            if target == "evm" && entry.key.circuit.starts_with("recursive_aggregation/") {
                let name = entry
                    .key
                    .circuit
                    .split('/')
                    .last()
                    .context("Circuit name")?;
                let source = verifier_path(root, &pair.preset, &pair.committee, name);
                let rendered = crate::run(Command::new("pnpm").args(["exec", "tsx", "-e", "const {renderSolidityVerifier}=require(process.argv[1]); process.stdout.write(renderSolidityVerifier(process.argv[2],process.argv[3],process.argv[4],process.argv[5]));"]).arg(root.join("scripts/circuits/verifiers.ts")).arg(root).arg(job.path().join("vk")).arg(name).arg(&source).current_dir(root))?;
                ensure!(
                    rendered == fs::read_to_string(&source)?,
                    "Complete generated verifier differs: {}",
                    source.display()
                );
                let sol_key = Key {
                    hash_kind: HashKind::SolidityVkHash,
                    ..entry.key.clone()
                };
                ensure!(
                    pair.entries
                        .iter()
                        .find(|item| item.key == sol_key)
                        .context("Missing Solidity identity")?
                        .value
                        == solidity_hash(&rendered)?,
                    "Solidity VK hash differs"
                );
            }
        }
        println!(
            "Verified {}/{}: {} backend keys and ordered recursive dependencies",
            pair.preset,
            pair.committee,
            verified.len()
        );
    }
    if !complete {
        println!(
            "Checked {} selected pair(s); this is not complete-matrix acceptance.",
            expected.pairs.len()
        );
    }
    Ok(())
}

fn validate_manifest(actual: &Manifest, expected: &Manifest) -> Result<()> {
    ensure!(
        actual.format_version == 1,
        "Unsupported circuit identity format"
    );
    for pair in &actual.pairs {
        validate_entries(&pair.entries)?;
    }
    ensure!(
        actual == expected,
        "Missing, unknown, or stale circuit identities; regenerate from source-matched artifacts"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Manifest {
        let leaf = |name: &str| Entry {
            key: Key {
                preset: "insecure-64".into(),
                committee: "minimum".into(),
                circuit: format!("threshold/{name}"),
                proof_variant: "recursive".into(),
                hash_kind: HashKind::BbVkHash,
            },
            value: format!("0x{:064x}", 1),
            compiled_artifact: Some(Artifact {
                path: format!("{name}.json"),
                sha256: "a".repeat(64),
            }),
            verification_key: Some(Artifact {
                path: format!("{name}.vk"),
                sha256: "b".repeat(64),
            }),
            dependencies: vec![],
        };
        let a = leaf("a");
        let b = leaf("b");
        let tree = Entry {
            key: Key {
                circuit: "recursive_aggregation/tree".into(),
                proof_variant: "default".into(),
                hash_kind: HashKind::RecursiveTreeCommitment,
                ..a.key.clone()
            },
            value: format!("0x{:064x}", 2),
            compiled_artifact: None,
            verification_key: None,
            dependencies: vec![a.key.clone(), b.key.clone()],
        };
        Manifest {
            format_version: 1,
            pairs: vec![Pair {
                preset: "insecure-64".into(),
                committee: "minimum".into(),
                source_hash: "source".into(),
                nargo_version: "noir".into(),
                bb_version: "bb".into(),
                entries: vec![a, b, tree],
            }],
        }
    }

    fn copy(value: &Manifest) -> Manifest {
        serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap()
    }

    #[test]
    fn identity_inventory_rejects_missing_unknown_duplicate_wrong_pair_and_reordered_dependencies()
    {
        let expected = fixture();
        validate_manifest(&expected, &expected).unwrap();
        let mut wrong = copy(&expected);
        wrong.pairs[0].entries.pop();
        assert!(validate_manifest(&wrong, &expected).is_err());
        let mut wrong = copy(&expected);
        let duplicate = wrong.pairs[0].entries[0].clone();
        wrong.pairs[0].entries.push(duplicate);
        assert!(validate_manifest(&wrong, &expected).is_err());
        let mut wrong = copy(&expected);
        wrong.pairs[0].entries[0].key.committee = "micro".into();
        assert!(validate_manifest(&wrong, &expected).is_err());
        let mut wrong = copy(&expected);
        wrong.pairs[0].entries[0].key.proof_variant = "evm".into();
        assert!(validate_manifest(&wrong, &expected).is_err());
        let mut wrong = copy(&expected);
        wrong.pairs[0].entries[2].dependencies.reverse();
        assert!(validate_manifest(&wrong, &expected).is_err());
        let mut wrong = copy(&expected);
        wrong.pairs[0].entries[2].value = format!("0x{}", "ff".repeat(32));
        assert!(validate_manifest(&wrong, &expected).is_err());
    }

    #[test]
    fn metadata_has_no_timestamps_and_noop_generation_preserves_bytes_and_mtime() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("manifest.json");
        let value = fixture();
        assert!(write_changed(&path, &value).unwrap());
        let before = crate::tests::snapshot(temp.path());
        assert!(!write_changed(&path, &value).unwrap());
        assert_eq!(crate::tests::snapshot(temp.path()), before);
        let serialized = fs::read_to_string(path).unwrap();
        assert!(!serialized.contains("builtAt"));
        assert!(!serialized.contains(temp.path().to_str().unwrap()));
    }
}
