// SPDX-License-Identifier: LGPL-3.0-only

use crate::{artifacts, identity, vk_tree, Request};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

pub const PAIR_FILE: &str = "identities.json";
pub const MANIFEST: &str = "circuits/identities.json";

// The deployment wrappers and CRISP are the consumers of this catalogue. Other keys remain in
// their existing artifact files; the catalogue is not another artifact inventory or trust graph.
const LEAVES: &[&str] = &[
    "threshold/pk_aggregation",
    "threshold/decrypted_shares_aggregation",
    "threshold/user_data_encryption",
    "threshold/user_data_encryption_ct0",
    "threshold/user_data_encryption_ct1",
];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pair {
    pub preset: String,
    pub committee: String,
    pub identities: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub pairs: Vec<Pair>,
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Read {}", path.display()))?;
    vk_tree::validate_field(&bytes)?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

pub fn collect_pair(output: &Path, preset: &str, committee: &str) -> Result<Pair> {
    let pair = output.join(preset).join(committee);
    let stamp: artifacts::Stamp =
        serde_json::from_slice(&fs::read(pair.join(".build-stamp.json"))?)?;
    ensure!(
        stamp.preset == preset && stamp.committee == committee && !stamp.source_hash.is_empty(),
        "Artifact stamp does not identify {preset}/{committee}"
    );
    let mut identities = BTreeMap::new();
    for circuit in LEAVES {
        let name = circuit.rsplit('/').next().unwrap();
        let path = pair
            .join("default")
            .join(circuit)
            .join(format!("{name}.vk_hash"));
        identities.insert(format!("bb-vk-hash/default/{circuit}"), hash_file(&path)?);
    }
    // Use the existing ordered SAFE implementation, including repeated descendants.
    for (name, value) in vk_tree::hashes(&pair)? {
        let path = pair
            .join("default/recursive_aggregation")
            .join(name)
            .join(format!("{name}.vk_tree_hash"));
        let expected = format!("0x{}", hex::encode(value));
        ensure!(
            hash_file(&path)? == expected,
            "Stale ordered tree anchor {}",
            path.display()
        );
        identities.insert(
            format!("recursive-tree-commitment/default/recursive_aggregation/{name}"),
            expected,
        );
    }
    Ok(Pair {
        preset: preset.into(),
        committee: committee.into(),
        identities,
    })
}

fn write_changed(path: &Path, value: &impl Serialize) -> Result<bool> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if fs::read(path).ok().as_deref() == Some(bytes.as_slice()) {
        return Ok(false);
    }
    fs::create_dir_all(path.parent().context("Identity parent")?)?;
    fs::write(path, bytes)?;
    Ok(true)
}

pub fn write_pair(directory: &Path, pair: &Pair) -> Result<()> {
    write_changed(&directory.join(PAIR_FILE), pair).map(|_| ())
}

pub fn generate(root: &Path, output: &Path) -> Result<()> {
    sync(root, output, true)
}

/// Prepare older archives for named consumers without changing the committed expectations.
pub fn prepare(root: &Path, output: &Path) -> Result<()> {
    sync(root, output, false)
}

fn sync(root: &Path, output: &Path, update_expected: bool) -> Result<()> {
    let pairs = crate::build_pairs(root)?
        .into_iter()
        .map(|[preset, committee]| collect_pair(output, &preset, &committee))
        .collect::<Result<Vec<_>>>()?;
    let manifest = Manifest {
        format_version: 1,
        pairs,
    };
    if !update_expected {
        let expected: Manifest = serde_json::from_slice(&fs::read(root.join(MANIFEST))?)?;
        ensure!(
            manifest == expected,
            "Prepared circuit identities differ from the committed catalogue; use matching artifacts"
        );
    }
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
    if update_expected {
        changed |= write_changed(&root.join(MANIFEST), &manifest)?;
    }
    changed |= write_changed(&output.join(PAIR_FILE), &manifest)?;
    if changed || !output.join("checksums.json").is_file() {
        artifacts::checksums(output)?;
    }
    Ok(())
}

pub fn invalidate(pair: &Path) -> Result<()> {
    for path in [
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
    let output = request.output_dir(root);
    let selected = request.selected_pairs(root)?;
    let mut pairs = Vec::new();
    for [preset, committee] in &selected {
        let expected = collect_pair(&output, preset, committee)?;
        let stored: Pair = serde_json::from_slice(&fs::read(
            output.join(preset).join(committee).join(PAIR_FILE),
        )?)?;
        ensure!(
            stored == expected,
            "Stale named identities for {preset}/{committee}"
        );
        pairs.push(expected);
    }
    if selected == crate::build_pairs(root)? {
        let expected = Manifest {
            format_version: 1,
            pairs,
        };
        for path in [root.join(MANIFEST), output.join(PAIR_FILE)] {
            let stored: Manifest = serde_json::from_slice(&fs::read(&path)?)?;
            ensure!(
                stored == expected,
                "Stale named identity catalogue {}",
                path.display()
            );
        }
    }
    println!("Checked {} named identity pair(s). Use the existing artifact validator for source/inventory checks; keys were not rederived.", selected.len());
    Ok(())
}

/// Explicit qualification, not part of ordinary pre-push checks. Artifact inventory/source
/// validation and compiled layout checks are composed by `qualify:crypto-config`.
pub fn qualify(root: &Path, request: &Request) -> Result<()> {
    identity::check_tools(root, true, true)?;
    let output = request.output_dir(root);
    for [preset, committee] in request.selected_pairs(root)? {
        let pair = output.join(&preset).join(&committee);
        let mut count = 0;
        for circuit in artifacts::discover(root, request)? {
            for (variant, target, _) in artifacts::variants(&circuit) {
                let directory = pair.join(variant).join(&circuit.group).join(&circuit.name);
                let compiled = directory.join(format!("{}.json", circuit.package));
                let vk = directory.join(format!("{}.vk", circuit.package));
                let hash = directory.join(format!("{}.vk_hash", circuit.package));
                let job = tempfile::tempdir()?;
                crate::run(
                    Command::new("bb")
                        .args(["write_vk", "-b"])
                        .arg(&compiled)
                        .arg("-o")
                        .arg(job.path())
                        .args(["-t", target]),
                )?;
                ensure!(
                    fs::read(job.path().join("vk"))? == fs::read(&vk)?,
                    "Backend VK bytes differ: {}",
                    vk.display()
                );
                ensure!(
                    fs::read(job.path().join("vk_hash"))? == fs::read(&hash)?,
                    "Backend VK hash differs: {}",
                    hash.display()
                );
                if variant == "evm" && circuit.group == "recursive_aggregation" {
                    let base =
                        root.join("packages/interfold-contracts/contracts/verifiers/bfv/honk");
                    let base = if preset == "insecure-64" && committee == "minimum" {
                        base
                    } else {
                        base.join(&preset).join(&committee)
                    };
                    let filename = if circuit.name == "dkg_aggregator" {
                        "DkgAggregatorVerifier.sol"
                    } else {
                        "DecryptionAggregatorVerifier.sol"
                    };
                    let source = base.join(filename);
                    let rendered = crate::run(Command::new("pnpm").args(["exec", "tsx", "-e", "const {renderSolidityVerifier}=require(process.argv[1]); process.stdout.write(renderSolidityVerifier(process.argv[2],process.argv[3],process.argv[4],process.argv[5]));"]).arg(root.join("scripts/circuits/verifiers.ts")).arg(root).arg(&vk).arg(&circuit.name).arg(&source).current_dir(root))?;
                    ensure!(
                        rendered == fs::read_to_string(&source)?,
                        "Generated verifier differs: {}",
                        source.display()
                    );
                }
                count += 1;
            }
        }
        println!(
            "Qualified {preset}/{committee}: {count} backend keys and generated Solidity verifiers"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(root: &Path, output: &Path) -> std::path::PathBuf {
        let pair = output.join("insecure-64/minimum");
        crate::tests::seed_anchor_keys(&pair);
        artifacts::refresh_anchors(root, &pair, true).unwrap();
        for circuit in LEAVES {
            let name = circuit.rsplit('/').next().unwrap();
            let path = pair
                .join("default")
                .join(circuit)
                .join(format!("{name}.vk_hash"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, [0; 32]).unwrap();
        }
        fs::write(pair.join(".build-stamp.json"), r#"{"preset":"insecure-64","committee":"minimum","sourceHash":"preserved-source","builtAt":"original"}"#).unwrap();
        pair
    }

    #[test]
    fn catalogue_contains_only_consumer_identities_and_preserves_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let output = root.join("dist/circuits");
        let pair = seed(root, &output);
        let stamp = fs::read(pair.join(".build-stamp.json")).unwrap();
        let catalogue = collect_pair(&output, "insecure-64", "minimum").unwrap();
        assert_eq!(catalogue.identities.len(), 7);
        assert_eq!(fs::read(pair.join(".build-stamp.json")).unwrap(), stamp);
        write_pair(&pair, &catalogue).unwrap();
        let before = crate::tests::snapshot(root);
        write_pair(&pair, &catalogue).unwrap();
        assert_eq!(crate::tests::snapshot(root), before);
        fs::remove_file(
            pair.join("default/threshold/user_data_encryption/user_data_encryption.vk_hash"),
        )
        .unwrap();
        assert!(collect_pair(&output, "insecure-64", "minimum").is_err());
    }

    #[test]
    fn catalogue_check_rejects_stale_values_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let output = root.join("dist/circuits");
        seed(root, &output);
        fs::create_dir_all(root.join("scripts/circuits")).unwrap();
        fs::write(
            root.join("scripts/circuits/build-pairs.json"),
            r#"[["insecure-64","minimum"]]"#,
        )
        .unwrap();
        generate(root, &output).unwrap();
        check(root, &crate::tests::request()).unwrap();
        let path = output.join("insecure-64/minimum/identities.json");
        let mut stored: Pair = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored.identities.clear();
        write_changed(&path, &stored).unwrap();
        let before = crate::tests::snapshot(root);
        assert!(check(root, &crate::tests::request()).is_err());
        assert_eq!(crate::tests::snapshot(root), before);
        let source = fs::read(root.join(MANIFEST)).unwrap();
        invalidate(&output.join("insecure-64/minimum")).unwrap();
        assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), source);
        assert!(!path.exists());
        assert!(!output.join(PAIR_FILE).exists());
    }

    #[test]
    fn prepare_legacy_archive_metadata_preserves_expectations_and_rejects_drift_before_writes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let output = root.join("dist/circuits");
        let pair = seed(root, &output);
        fs::create_dir_all(root.join("scripts/circuits")).unwrap();
        fs::write(
            root.join("scripts/circuits/build-pairs.json"),
            r#"[["insecure-64","minimum"]]"#,
        )
        .unwrap();
        generate(root, &output).unwrap();
        fs::remove_file(pair.join(PAIR_FILE)).unwrap();
        fs::remove_file(output.join(PAIR_FILE)).unwrap();
        artifacts::checksums(&output).unwrap();

        let before = crate::tests::snapshot(root);
        let mut request = crate::tests::request();
        request.operation = "prepare-identities".parse().unwrap();
        crate::execute(root, &request).unwrap();
        let after = crate::tests::snapshot(root);
        for (path, original) in &before {
            if !["SHA256SUMS", "checksums.json"]
                .contains(&path.file_name().unwrap().to_str().unwrap())
            {
                assert_eq!(&after[path], original, "{} changed", path.display());
            }
        }
        check(root, &request).unwrap();
        assert!(pair.join(PAIR_FILE).is_file());
        crate::execute(root, &request).unwrap();
        assert_eq!(crate::tests::snapshot(root), after);

        let mut hash = [0; 32];
        hash[31] = 1;
        fs::write(
            pair.join("default/threshold/user_data_encryption/user_data_encryption.vk_hash"),
            hash,
        )
        .unwrap();
        fs::remove_file(pair.join(PAIR_FILE)).unwrap();
        let before = crate::tests::snapshot(root);
        assert!(crate::execute(root, &request)
            .unwrap_err()
            .to_string()
            .contains("differ from the committed catalogue"));
        assert_eq!(crate::tests::snapshot(root), before);
    }
}
