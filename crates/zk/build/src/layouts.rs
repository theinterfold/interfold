// SPDX-License-Identifier: LGPL-3.0-only

use crate::Request;
use anyhow::{bail, ensure, Context, Result};
use e3_zk_config::{output_layout::DecryptionAggregatorLayout, MAX_MSG_NON_ZERO_COEFFS};
use serde_json::Value;
use std::{fs, path::Path};

// bb 5.2.0's EVM verifier counts the pairing-point accumulator in its VK metadata, but callers
// supply only the Noir application fields. This is not part of the circuit's public ABI.
const HONK_PAIRING_POINT_FIELDS: usize = 8;

fn flattened_fields(typ: &Value) -> Result<usize> {
    match typ["kind"].as_str() {
        Some("field") => Ok(1),
        Some("array") => {
            let len = usize::try_from(typ["length"].as_u64().context("ABI array length")?)?;
            len.checked_mul(flattened_fields(&typ["type"])?)
                .context("ABI field count overflow")
        }
        Some("tuple") => typ["fields"]
            .as_array()
            .context("ABI tuple fields")?
            .iter()
            .try_fold(0usize, |count, field| {
                count
                    .checked_add(flattened_fields(field)?)
                    .context("ABI field count overflow")
            }),
        other => bail!("Unsupported decryption ABI type: {other:?}"),
    }
}

fn field_array(typ: &Value, length: usize) -> bool {
    typ["kind"] == "array"
        && typ["length"].as_u64() == Some(length as u64)
        && typ["type"]["kind"] == "field"
}

fn validate_abi(abi: &Value, threshold: usize) -> Result<usize> {
    let layout = DecryptionAggregatorLayout::current();
    let public: Vec<_> = abi["parameters"]
        .as_array()
        .context("ABI parameters")?
        .iter()
        .filter(|parameter| parameter["visibility"] == "public")
        .collect();
    ensure!(
        public.len() == layout.public_inputs.len(),
        "Decryption public parameter count differs"
    );
    for (parameter, expected) in public.iter().zip(layout.public_inputs) {
        ensure!(
            parameter["name"] == expected.name && parameter["type"]["kind"] == "field",
            "Decryption public parameter must be scalar Field {} in canonical order",
            expected.name
        );
    }
    let result = &abi["return_type"];
    ensure!(
        result["visibility"] == "public" && result["abi_type"]["kind"] == "tuple",
        "Decryption return must be a public tuple"
    );
    let fields = result["abi_type"]["fields"]
        .as_array()
        .context("Decryption return fields")?;
    ensure!(
        fields.len() == layout.return_prefix.len() + layout.columns.len() + 1,
        "Decryption return tuple shape differs"
    );
    for (index, field) in fields.iter().enumerate() {
        let matches = if index < layout.return_prefix.len() {
            field["kind"] == "field"
        } else if index < layout.return_prefix.len() + layout.columns.len() {
            field_array(field, DecryptionAggregatorLayout::share_count(threshold))
        } else {
            field_array(field, MAX_MSG_NON_ZERO_COEFFS)
        };
        ensure!(
            matches,
            "Decryption return field {index} has the wrong type or dimension"
        );
    }
    // Flatten the compiled ABI independently of the layout helper, including its anonymous return.
    let count = public
        .iter()
        .try_fold(0usize, |count, parameter| -> Result<usize> {
            Ok(count + flattened_fields(&parameter["type"])?)
        })?
        + flattened_fields(&result["abi_type"])?;
    ensure!(
        count == layout.public_inputs_length(threshold),
        "Decryption application input count differs"
    );
    Ok(count)
}

fn validate_honk_count(source: &str, application_count: usize) -> Result<()> {
    let pattern = regex::Regex::new(r"(?m)^uint256 constant NUMBER_OF_PUBLIC_INPUTS = ([0-9]+);$")?;
    let matches: Vec<_> = pattern.captures_iter(source).collect();
    ensure!(
        matches.len() == 1,
        "Expected one generated Honk public-input count"
    );
    let count: usize = matches[0][1].parse()?;
    ensure!(count == application_count + HONK_PAIRING_POINT_FIELDS,
        "Honk declares {count} inputs; expected {application_count} application fields + {HONK_PAIRING_POINT_FIELDS} pairing-point fields");
    Ok(())
}

pub fn check(root: &Path, request: &Request) -> Result<()> {
    let pairs = request.selected_pairs(root)?;
    for [preset, committee] in &pairs {
        let threshold = committee
            .parse::<e3_committee::CiphernodesCommitteeSize>()?
            .values()
            .threshold;
        let path = request
            .output_dir(root)
            .join(preset)
            .join(committee)
            .join("evm/recursive_aggregation/decryption_aggregator/decryption_aggregator.json");
        let artifact: Value = serde_json::from_slice(&fs::read(&path).with_context(|| format!("Read {}; prepare this pair with pnpm build:circuits --preset {preset} --committee {committee}", path.display()))?)?;
        let count = validate_abi(&artifact["abi"], threshold)
            .with_context(|| format!("{preset}/{committee} compiled decryption ABI"))?;
        // The development/CI pair occupies honk/ itself; other pairs coexist below it.
        let base = root.join("packages/interfold-contracts/contracts/verifiers/bfv/honk");
        let directory = if preset == "insecure-64" && committee == "minimum" {
            base
        } else {
            base.join(preset).join(committee)
        };
        let source = directory.join("DecryptionAggregatorVerifier.sol");
        validate_honk_count(
            &fs::read_to_string(&source).with_context(|| format!("Read {}", source.display()))?,
            count,
        )
        .with_context(|| format!("{}", source.display()))?;
        println!(
            "{preset}/{committee}: {count} application fields, {} Honk fields",
            count + HONK_PAIRING_POINT_FIELDS
        );
    }
    println!("Checked {} decryption layouts. Artifact provenance, key derivation, and proof acceptance are not qualified by this check.", pairs.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Public ABI excerpt of the independently compiled insecure/minimum decryption aggregator.
    fn compiled_abi() -> Value {
        serde_json::from_str(
            r#"{
          "parameters": [
            {"name":"c6_fold_key_hash","type":{"kind":"field"},"visibility":"public"},
            {"name":"c7_key_hash","type":{"kind":"field"},"visibility":"public"},
            {"name":"committee_hash_hi","type":{"kind":"field"},"visibility":"public"},
            {"name":"committee_hash_lo","type":{"kind":"field"},"visibility":"public"},
            {"name":"domain_hi","type":{"kind":"field"},"visibility":"public"},
            {"name":"domain_lo","type":{"kind":"field"},"visibility":"public"},
            {"name":"ciphertext_commitment","type":{"kind":"field"},"visibility":"public"}
          ],
          "return_type":{"visibility":"public","abi_type":{"kind":"tuple","fields":[
            {"kind":"field"},
            {"kind":"array","length":2,"type":{"kind":"field"}},
            {"kind":"array","length":2,"type":{"kind":"field"}},
            {"kind":"array","length":2,"type":{"kind":"field"}},
            {"kind":"array","length":50,"type":{"kind":"field"}}
          ]}}
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn compiled_abi_and_honk_metadata_count_different_inputs() {
        let count = validate_abi(&compiled_abi(), 1).unwrap();
        assert_eq!(count, 64);
        validate_honk_count("uint256 constant NUMBER_OF_PUBLIC_INPUTS = 72;", count).unwrap();
        assert!(
            validate_honk_count("uint256 constant NUMBER_OF_PUBLIC_INPUTS = 64;", count).is_err()
        );
    }

    #[test]
    fn abi_validation_rejects_reordering_types_widths_and_extra_inputs() {
        let mut abi = compiled_abi();
        abi["parameters"].as_array_mut().unwrap().swap(2, 3);
        assert!(validate_abi(&abi, 1).is_err());
        let mut abi = compiled_abi();
        abi["parameters"][0]["type"] = json!({"kind":"integer", "width":254, "sign":"unsigned"});
        assert!(validate_abi(&abi, 1).is_err());
        let mut abi = compiled_abi();
        abi["parameters"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"extra","type":{"kind":"field"},"visibility":"public"}));
        assert!(validate_abi(&abi, 1).is_err());
        for index in 1..=4 {
            let mut abi = compiled_abi();
            abi["return_type"]["abi_type"]["fields"][index]["length"] = json!(3);
            assert!(validate_abi(&abi, 1).is_err());
        }
        let mut abi = compiled_abi();
        abi["return_type"]["abi_type"]["fields"][1] =
            json!({"kind":"tuple","fields":[{"kind":"field"},{"kind":"field"}]});
        assert!(
            validate_abi(&abi, 1).is_err(),
            "equal flattened counts do not establish ABI shape"
        );
    }

    #[test]
    fn missing_compiled_artifacts_fail_without_writing_or_building() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("scripts/circuits")).unwrap();
        fs::write(
            temp.path().join("scripts/circuits/build-pairs.json"),
            r#"[["insecure-64","minimum"]]"#,
        )
        .unwrap();
        let before = crate::tests::snapshot(temp.path());
        assert!(check(temp.path(), &crate::tests::request()).is_err());
        assert_eq!(crate::tests::snapshot(temp.path()), before);
    }

    #[test]
    fn checking_prepared_layouts_is_read_only_and_does_not_repair_honk_counts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let files = [
            ("scripts/circuits/build-pairs.json", r#"[["insecure-64","minimum"]]"#.to_string()),
            ("dist/circuits/insecure-64/minimum/evm/recursive_aggregation/decryption_aggregator/decryption_aggregator.json", json!({"abi": compiled_abi()}).to_string()),
            ("packages/interfold-contracts/contracts/verifiers/bfv/honk/DecryptionAggregatorVerifier.sol", "uint256 constant NUMBER_OF_PUBLIC_INPUTS = 72;".to_string()),
        ];
        for (path, contents) in &files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let before = crate::tests::snapshot(root);
        check(root, &crate::tests::request()).unwrap();
        assert_eq!(crate::tests::snapshot(root), before);
        fs::write(
            root.join(files[2].0),
            "uint256 constant NUMBER_OF_PUBLIC_INPUTS = 64;",
        )
        .unwrap();
        let before = crate::tests::snapshot(root);
        assert!(check(root, &crate::tests::request()).is_err());
        assert_eq!(crate::tests::snapshot(root), before);
    }
}
