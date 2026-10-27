// SPDX-License-Identifier: LGPL-3.0-only

use crate::{
    IBondingRegistry, ICiphernodeRegistry, IInterfold, INodeReleaseRegistry, IRandomnessProvider,
    ISlashingManager,
};
use alloy_json_abi::JsonAbi;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packages/interfold-contracts/artifacts")
}

fn artifact(contract: &str) -> Vec<Value> {
    let path = artifacts_dir().join("contracts").join(contract);
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}; run pnpm evm:build", path.display()));
    serde_json::from_str::<Value>(&contents).unwrap()["abi"]
        .as_array()
        .expect("contract ABI")
        .clone()
}

#[test]
fn typed_views_and_embedded_tuple_match_compiled_solidity() {
    use crate::{CommitteeSize, E3Stage, FailureReason};
    use alloy_sol_types::{SolEnum, SolStruct};

    // ABI JSON erases enum members. Read the compiler AST, not a second numeric Rust table.
    let implementation: Value = serde_json::from_str(
        &fs::read_to_string(artifacts_dir().join("contracts/Interfold.sol/Interfold.json"))
            .unwrap(),
    )
    .unwrap();
    let id = implementation["buildInfoId"].as_str().unwrap();
    let output: Value = serde_json::from_str(
        &fs::read_to_string(artifacts_dir().join(format!("build-info/{id}.output.json")))
            .expect("Solidity build info; run pnpm evm:build"),
    )
    .unwrap();
    let ast = &output["output"]["sources"]["project/contracts/interfaces/IInterfold.sol"]["ast"];
    let contract = ast["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["nodeType"] == "ContractDefinition" && node["name"] == "IInterfold")
        .unwrap();
    let members = |name: &str| {
        contract["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["nodeType"] == "EnumDefinition" && node["name"] == name)
            .unwrap()["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["name"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        (0..CommitteeSize::COUNT as u8)
            .map(|value| format!("{:?}", CommitteeSize::try_from(value).unwrap()))
            .collect::<Vec<_>>(),
        members("CommitteeSize")
    );
    assert_eq!(
        (0..E3Stage::COUNT as u8)
            .map(|value| format!("{:?}", E3Stage::try_from(value).unwrap()))
            .collect::<Vec<_>>(),
        members("E3Stage")
    );
    let mut reasons = members("FailureReason");
    assert_eq!(reasons.pop().as_deref(), Some("_MAX_FAILURE_REASON"));
    assert_eq!(
        (0..FailureReason::COUNT as u8)
            .map(|value| format!("{:?}", FailureReason::try_from(value).unwrap()))
            .collect::<Vec<_>>(),
        reasons
    );
    assert!(FailureReason::try_from(FailureReason::COUNT as u8).is_err());
    assert!(E3Stage::try_from(255).is_err());
    assert!(CommitteeSize::try_from(255).is_err());

    // This tuple is ABI-encoded inside a bytes argument, so it is absent from the public JSON ABI.
    let reference = contract["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| {
            node["nodeType"] == "StructDefinition" && node["name"] == "CiphertextOutputReference"
        })
        .unwrap();
    let fields = reference["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| {
            format!(
                "{} {}",
                member["typeDescriptions"]["typeString"].as_str().unwrap(),
                member["name"].as_str().unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        IInterfold::CiphertextOutputReference::eip712_encode_type(),
        format!("CiphertextOutputReference({fields})")
    );
}

// Names and Solidity internal types do not affect the ABI. Preserve order, widths, array suffixes,
// tuple nesting and topic placement; comparing selectors alone misses all return-layout drift.
fn param(value: &Value) -> Value {
    let mut result = json!({"type": value["type"]});
    if let Some(components) = value["components"].as_array() {
        result["components"] = components.iter().map(param).collect();
    }
    if let Some(indexed) = value["indexed"].as_bool() {
        result["indexed"] = indexed.into();
    }
    result
}

fn shape(value: &Value) -> Value {
    let mut result = json!({
        "type": value["type"],
        "name": value["name"],
        "inputs": value["inputs"].as_array().unwrap().iter().map(param).collect::<Vec<_>>(),
    });
    match value["type"].as_str().unwrap() {
        "function" => {
            result["outputs"] = value["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(param)
                .collect();
            result["stateMutability"] = value["stateMutability"].clone();
        }
        "event" => result["anonymous"] = value["anonymous"].as_bool().unwrap_or(false).into(),
        "error" => {}
        other => panic!("unexpected minimal ABI item: {other}"),
    }
    result
}

fn assert_subset(bindings: JsonAbi, contract: &str, forwarded: &[(&str, &str)]) {
    let built = artifact(contract);
    let bindings = serde_json::to_value(bindings).unwrap();
    for entry in bindings.as_array().unwrap() {
        let expected = shape(entry);
        let source = forwarded
            .iter()
            .find(|(name, _)| entry["type"] == "error" && entry["name"].as_str() == Some(*name));
        let forwarded_abi;
        let candidates = if let Some((_, source)) = source {
            forwarded_abi = artifact(source);
            &forwarded_abi
        } else {
            &built
        };
        assert!(
            candidates.iter().any(|candidate| {
                candidate["type"] == entry["type"]
                    && candidate["name"] == entry["name"]
                    && shape(candidate) == expected
            }),
            "binding differs from {contract}: {expected}"
        );
    }
}

#[test]
fn declared_bindings_match_solidity() {
    assert_subset(
        IInterfold::abi::contract(),
        "Interfold.sol/Interfold.json",
        &[(
            "SettlementBlocked",
            "interfaces/IE3RefundManager.sol/IE3RefundManager.json",
        )],
    );
    // publishCommittee forwards failures from IPkVerifier unchanged.
    assert_subset(
        ICiphernodeRegistry::abi::contract(),
        "registry/CiphernodeRegistryOwnable.sol/CiphernodeRegistryOwnable.json",
        &[
            (
                "DomainBindingMismatch",
                "interfaces/IPkVerifier.sol/IPkVerifier.json",
            ),
            (
                "InvalidPublicInputsLength",
                "interfaces/IPkVerifier.sol/IPkVerifier.json",
            ),
            (
                "PkCommitmentMismatch",
                "interfaces/IPkVerifier.sol/IPkVerifier.json",
            ),
            (
                "VkHashMismatch",
                "interfaces/IPkVerifier.sol/IPkVerifier.json",
            ),
        ],
    );
    for (bindings, contract) in [
        (
            IBondingRegistry::abi::contract(),
            "registry/BondingRegistry.sol/BondingRegistry.json",
        ),
        (
            ISlashingManager::abi::contract(),
            "slashing/SlashingManager.sol/SlashingManager.json",
        ),
        (
            INodeReleaseRegistry::abi::contract(),
            "registry/NodeReleaseRegistry.sol/NodeReleaseRegistry.json",
        ),
        (
            IRandomnessProvider::abi::contract(),
            "interfaces/IRandomnessProvider.sol/IRandomnessProvider.json",
        ),
    ] {
        assert_subset(bindings, contract, &[]);
    }
}

#[test]
fn comparison_retains_outputs_and_indexing() {
    let function = json!({
        "type": "function", "name": "read", "inputs": [], "stateMutability": "view",
        "outputs": [{"type": "tuple", "components": [{"type": "uint32"}]}],
    });
    let mut changed = function.clone();
    changed["outputs"][0]["components"][0]["type"] = "uint64".into();
    assert_ne!(shape(&function), shape(&changed));

    let event = json!({
        "type": "event", "name": "Observed", "anonymous": false,
        "inputs": [{"name": "id", "type": "uint256", "indexed": true}],
    });
    let mut changed = event.clone();
    changed["inputs"][0]["indexed"] = false.into();
    assert_ne!(shape(&event), shape(&changed));
}
