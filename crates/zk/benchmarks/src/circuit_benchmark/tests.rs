// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused_imports)]

use super::*;
use records::{Record, Stage};
use selection::{Case, Config};

#[test]
fn configured_leaf_selection_rejects_unknown_or_restricted_cases() {
    let config: Config = serde_json::from_str(include_str!(
        "../../../../../circuits/benchmarks/config.json"
    ))
    .unwrap();
    assert_eq!(config.select("secure", &[]).unwrap().len(), 12);
    assert_eq!(config.select("insecure", &[]).unwrap().len(), 11);
    assert!(config.select("insecure", &["config".into()]).is_err());
    assert!(config
        .select("secure", &["threshold/missing".into()])
        .is_err());
    assert_eq!(
        config
            .select(
                "secure",
                &[
                    "threshold/user_data_encryption_ct0".into(),
                    "threshold/user_data_encryption_ct1".into()
                ]
            )
            .unwrap(),
        [Case::Ct0, Case::Ct1]
    );
}

#[test]
fn unmeasured_and_failed_stages_are_distinct_and_calldata_uses_actual_bytes() {
    let mut record = Record::new(Case::Ct1, "secure", e3_zk_prover::CircuitVariant::Recursive);
    let before = serde_json::to_value(&record).unwrap();
    assert!(before["execution"]["time_seconds"].is_null());
    assert!(before["proof_size_bytes"].is_null());
    let failure: anyhow::Result<()> = Err(anyhow::anyhow!("execution failed"));
    record
        .execution
        .finish(std::time::Duration::from_millis(25), &failure);
    assert_eq!(record.execution.success, Some(false));
    assert_eq!(record.execution.time_seconds, Some(0.025));
    record.proof_bytes(&[0, 1, 0xff], &[0]);
    assert_eq!(record.proof_size_bytes, Some(3));
    assert_eq!(record.public_inputs_size_bytes, Some(1));
    assert_eq!(record.calldata_gas_total, Some(40));
    let mut unmeasured = Stage::unmeasured("optional_vk");
    let success: anyhow::Result<()> = Ok(());
    unmeasured.finish(std::time::Duration::ZERO, &success);
    assert_eq!(unmeasured.time_seconds, Some(0.0));
    assert_eq!(unmeasured.success, Some(true));
}

#[test]
fn ude_projection_preserves_ct1_quotient_name_and_rejects_missing_material() {
    let mut document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../crates/zk-prover/tests/fixtures/dummy.json"
    ))
    .unwrap();
    document["abi"]["parameters"] = serde_json::json!([{ "name": "r_ct1", "type": { "kind": "field" }, "visibility": "private" }]);
    let compiled = e3_zk_prover::CompiledCircuit::from_json(&document.to_string()).unwrap();
    let inputs =
        inputs::project_ude(&serde_json::json!({ "r": 7, "r_ct1": 19 }), &compiled).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(
        inputs["r_ct1"],
        noirc_abi::input_parser::InputValue::Field(acir::FieldElement::from(19_u128))
    );
    assert!(
        inputs::project_ude(&serde_json::json!({ "r": 7 }), &compiled)
            .unwrap_err()
            .to_string()
            .contains("r_ct1")
    );
}

#[test]
fn artifact_pair_validation_rejects_wrong_dimensions_and_gate_parsing_rejects_missing_counts() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("secure-8192/micro");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(".build-stamp.json"),
        r#"{"preset":"secure-8192","committee":"minimum","sourceHash":"published"}"#,
    )
    .unwrap();
    assert!(artifacts::validate_pair(temp.path(), "secure-8192", "micro").is_err());
    fs::write(
        dir.join(".build-stamp.json"),
        r#"{"preset":"secure-8192","committee":"micro","sourceHash":"older-source"}"#,
    )
    .unwrap();
    assert_eq!(
        artifacts::validate_pair(temp.path(), "secure-8192", "micro").unwrap()["sourceHash"],
        "older-source"
    );
    assert_eq!(
        artifacts::gate_counts(r#"{"functions":[{"circuit_size":1024,"acir_opcodes":17}]}"#)
            .unwrap(),
        (1024, Some(17))
    );
    assert!(artifacts::gate_counts(r#"{"functions":[{}]}"#).is_err());
}

#[test]
fn failed_external_command_preserves_logs_and_is_not_a_successful_measurement() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("job.log");
    let result = run_logged(
        Command::new("/bin/sh").args(["-c", "echo 'stage failed' >&2; exit 17"]),
        &log,
    );
    assert!(result.unwrap_err().to_string().contains("stage failed"));
    assert!(fs::read_to_string(log).unwrap().contains("stage failed"));
}

#[test]
fn report_reads_both_schemas_without_relabeling_metrics_or_confusing_ude_wrapper() {
    let mut current = Record::new(
        Case::Ct0,
        "insecure",
        e3_zk_prover::CircuitVariant::Recursive,
    );
    current.proof_generation.time_seconds = Some(0.0);
    current.proof_generation.success = Some(true);
    current.proof_bytes(&[1, 2, 3], &[0; 32]);
    let historical = serde_json::json!({"circuit_name":"user_data_encryption_ct1","circuit_path":"circuits/bin/threshold/user_data_encryption_ct1","execution":{"success":true,"time_seconds":2.0},"proof_generation":{"success":true,"time_seconds":7.5,"proof_size_bytes":11},"verification":{"success":true,"time_seconds":0.125,"public_inputs_size_bytes":32}});
    let leaves = vec![
        report::parse_leaf(serde_json::to_value(current).unwrap()).unwrap(),
        report::parse_leaf(historical).unwrap(),
    ];
    let data = report::Data {
        leaves,
        metadata: serde_json::json!({"shared_preparations":[{"id":"ude","preparation":{"metric":"production_encryption_and_preparation_wall","time_seconds":0.25,"success":true}}]}),
        integration: serde_json::Value::Null,
        gas: serde_json::json!({"verify_gas":{"user":123}}),
        files: vec![],
    };
    let rendered = report::render(&data).unwrap();
    assert!(rendered.contains("production_bb_adapter_wall") && rendered.contains("isolated_nargo"));
    assert!(rendered.contains("proof bytes: 14") && rendered.contains("prove time: 7.500000"));
    assert!(rendered.contains("| Π_user | N/A | N/A | 123 | N/A | N/A |"));
    assert_eq!(
        rendered
            .matches("| ude | production_encryption_and_preparation_wall | 0.250000 | true |")
            .count(),
        1
    );
}

#[test]
fn report_only_uses_saved_data_and_does_not_overwrite_its_input() {
    let temp = tempfile::tempdir().unwrap();
    let saved = temp.path().join("saved");
    fs::create_dir_all(saved.join("raw")).unwrap();
    let record = Record::new(
        Case::Ct1,
        "insecure",
        e3_zk_prover::CircuitVariant::Recursive,
    );
    write_json(&saved.join("raw/ct1.json"), &record).unwrap();
    let output = temp.path().join("report.md");
    let options = clap::Parser::parse_from([
        "benchmark",
        "report",
        "--input",
        saved.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    // The supplied repository has no tools, stamps, policy, or Cargo manifest.
    execute(&temp.path().join("absent-repository"), &options).unwrap();
    assert!(fs::read_to_string(&output)
        .unwrap()
        .contains("external_bb_prove_wall"));
    assert!(execute(&temp.path().join("absent-repository"), &options).is_err());
    assert_eq!(report::load(&saved, None, None).unwrap().leaves.len(), 1);
}

#[test]
fn replay_rejects_bad_proofs_and_wrong_configuration_before_evm_execution() {
    let doc = serde_json::json!({"benchmark_config":{"mode":"insecure","bfv_preset_subdir":"insecure-64","committee_n":3,"committee_h":2,"committee_t":1},"folded_artifacts":{"dkg_aggregator":{"proof_hex":"0x01","public_inputs_hex":"0x00"},"decryption_aggregator":{"proof_hex":"0x01","public_inputs_hex":"0x00"}}});
    assert!(protocol::configuration(&doc, Some("secure"), None, 1).is_err());
    assert!(protocol::configuration(&doc, None, Some("micro"), 1).is_err());
    assert!(protocol::folded(&doc).is_err());
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("summary.json");
    write_json(&input, &doc).unwrap();
    let output = temp.path().join("replay");
    fs::create_dir_all(output.join("raw")).unwrap();
    assert!(protocol::replay(
        &temp.path().join("absent-repository"),
        &output,
        &input,
        None,
        None,
        None
    )
    .is_err());
    let result = protocol::read_json(&output.join("protocol_results.json")).unwrap();
    assert_eq!(result["complete"], false);
    assert!(result["verify_gas"]["dkg"].is_null());
    assert!(!output.join("evm-replay.log").exists());
}

#[test]
fn integration_launcher_delivers_full_proof_controls_and_structured_export_paths() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let executable = bin.join("cargo");
    fs::write(&executable, "#!/bin/sh\n[ \"$1\" = test ] || exit 1\n[ \"$CIPHERNODE_SKIP_PROOF_AGGREGATION\" = false ] || exit 2\n[ \"$BENCHMARK_MODE\" = secure ] || exit 3\n[ \"$BENCHMARK_MULTITHREAD_JOBS\" = 3 ] || exit 4\ncase \" $* \" in *' --release '*test_trbfv_actor*) ;; *) exit 5 ;; esac\nprintf '{\"synthetic_transport_fixture\":true}' > \"$BENCHMARK_SUMMARY_OUTPUT\"\nprintf '{\"synthetic_transport_fixture\":true}' > \"$BENCHMARK_FOLDED_OUTPUT\"\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let output = temp.path().join("outputs with spaces");
    fs::create_dir_all(&output).unwrap();
    let cfg = protocol::Configuration {
        mode: "secure".into(),
        preset: "secure-8192".into(),
        committee: e3_committee::CiphernodesCommitteeSize::Micro,
        jobs: 3,
        bb_binary: Some(PathBuf::from("/validated/bb")),
    };
    let mut command = protocol::integration_command(temp.path(), &output, &cfg).unwrap();
    command.env("PATH", bin);
    run_logged(&mut command, &output.join("launch.log")).unwrap();
    assert_eq!(
        protocol::read_json(&output.join("integration_summary.json")).unwrap()
            ["synthetic_transport_fixture"],
        true
    );
    assert!(output.join("folded_artifacts.json").is_file());
}

#[test]
fn config_loader_binds_the_compiled_digest_and_pair_not_the_active_stamp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let directory = root.join("circuits/bin/config/target");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.parent().unwrap().join("Nargo.toml"),
        "[package]\nname = \"validate_secure_configs\"\ntype = \"bin\"\nauthors = []\n",
    )
    .unwrap();
    let compiled = directory.join("validate_secure_configs.json");
    fs::write(
        &compiled,
        include_str!("../../../../../crates/zk-prover/tests/fixtures/dummy.json"),
    )
    .unwrap();
    let stale = directory.join("config.json");
    fs::write(&stale, b"unrelated stale config artifact").unwrap();
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../crates/zk-prover/tests/fixtures/dummy.json"
    ))
    .unwrap();
    let stamp = serde_json::json!({"schema_version":1,"preset":"secure-8192","committee":"minimum","compiled_sha256":artifacts::digest(&compiled).unwrap(),"compiler_version":document["noir_version"],"sourceHash":"original-config-sources","source_origin":"fresh_local_noir_compile","vk_sha256":{}});
    write_json(&directory.join(".config-benchmark.json"), &stamp).unwrap();
    write_json(&root.join("circuits/bin/.active-preset.json"), &serde_json::json!({"preset":"secure-8192","committee":"micro","sourceHash":"different-hydrated-build"})).unwrap();
    let backend = e3_zk_prover::ZkBackend::new(
        e3_config::BBPath::Custom(root.join("bb")),
        root.join("dist/circuits"),
        root.join("work"),
    );
    let prover = e3_zk_prover::ZkProver::new(&backend);
    let load = |pair, need_vk| {
        artifacts::load(
            root,
            &prover,
            pair,
            Case::Config,
            e3_zk_prover::CircuitVariant::Recursive,
            "1.0.0-beta.26",
            need_vk,
        )
    };
    assert!(load("secure-8192/micro", false)
        .unwrap_err()
        .to_string()
        .contains("does not identify"));
    let (_, loaded, vk, identity) = load("secure-8192/minimum", false).unwrap();
    assert_eq!(loaded, compiled);
    assert_eq!(vk, directory.join("validate_secure_configs.vk_noir"));
    assert_eq!(
        fs::read(&stale).unwrap(),
        b"unrelated stale config artifact"
    );
    assert_eq!(
        identity.source_stamp["sourceHash"],
        "original-config-sources"
    );
    fs::write(&vk, b"unbound-old-key").unwrap();
    assert!(load("secure-8192/minimum", true)
        .unwrap_err()
        .to_string()
        .contains("not bound"));
    let generated = root.join("generated-vk");
    fs::write(&generated, b"fresh-key").unwrap();
    artifacts::bind_config_vk(
        root,
        &compiled,
        e3_zk_prover::CircuitVariant::Recursive,
        &generated,
        &vk,
    )
    .unwrap();
    assert!(load("secure-8192/minimum", true).is_ok());
    fs::write(
        &compiled,
        include_str!("../../../../../crates/zk-prover/tests/fixtures/dummy.json")
            .replace("2159294962516643373", "2159294962516643374"),
    )
    .unwrap();
    assert!(load("secure-8192/minimum", false)
        .unwrap_err()
        .to_string()
        .contains("digest differs"));
}

#[test]
#[ignore = "requires pinned nargo; compiles one tiny temporary config package, not the circuit matrix"]
fn fresh_config_compilation_records_local_sources_not_hydrated_source_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let package = root.join("circuits/bin/config");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::create_dir_all(root.join("circuits/lib")).unwrap();
    fs::write(
        root.join("circuits/lib/Nargo.toml"),
        "[package]\nname = \"lib\"\ntype = \"lib\"\nauthors = []\n",
    )
    .unwrap();
    fs::write(
        package.join("Nargo.toml"),
        "[package]\nname = \"validate_secure_configs\"\ntype = \"bin\"\nauthors = []\n",
    )
    .unwrap();
    fs::write(package.join("src/main.nr"), "fn main() {}\n").unwrap();
    fs::create_dir_all(package.join("target")).unwrap();
    let stale = package.join("target/config.json");
    fs::write(&stale, b"unrelated stale config artifact").unwrap();
    write_json(&root.join("circuits/bin/.active-preset.json"), &serde_json::json!({"preset":"secure-8192","committee":"minimum","sourceHash":"old-archived-source"})).unwrap();
    artifacts::compile_config(root, "secure-8192/minimum", "1.0.0-beta.26").unwrap();
    let stamp = protocol::read_json(&package.join("target/.config-benchmark.json")).unwrap();
    assert_eq!(stamp["source_origin"], "fresh_local_noir_compile");
    assert_ne!(stamp["sourceHash"], "old-archived-source");
    assert_eq!(stamp["sourceHash"].as_str().unwrap().len(), 64);
    assert_eq!(
        stamp["compiled_sha256"],
        artifacts::digest(&package.join("target/validate_secure_configs.json")).unwrap()
    );
    let backend = e3_zk_prover::ZkBackend::new(
        e3_config::BBPath::Custom(root.join("bb")),
        root.join("dist/circuits"),
        root.join("work"),
    );
    let prover = e3_zk_prover::ZkProver::new(&backend);
    let (_, compiled, vk, identity) = artifacts::load(
        root,
        &prover,
        "secure-8192/minimum",
        Case::Config,
        e3_zk_prover::CircuitVariant::Recursive,
        "1.0.0-beta.26",
        false,
    )
    .unwrap();
    assert_eq!(
        compiled,
        package.join("target/validate_secure_configs.json")
    );
    assert_eq!(vk, package.join("target/validate_secure_configs.vk_noir"));
    assert_eq!(identity.source_stamp, stamp);
    assert_eq!(
        fs::read(&stale).unwrap(),
        b"unrelated stale config artifact"
    );
}

#[test]
fn integration_child_uses_validated_bb_even_when_path_selects_another_binary() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let selected = root.join("selected bb");
    for (path, script) in [(&selected, "#!/bin/sh\nprintf '5.2.0\\n'\n"), (&bin.join("bb"), "#!/bin/sh\nprintf 'wrong-version\\n'\n"), (&bin.join("cargo"), "#!/bin/sh\nversion=$(\"${E3_CUSTOM_BB:-bb}\" --version)\n[ \"$version\" = 5.2.0 ] || exit 7\nprintf '%s' \"$E3_CUSTOM_BB\" > \"$BENCHMARK_SUMMARY_OUTPUT\"\n")] {
        fs::write(path, script).unwrap(); fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let selected = artifacts::bb_binary(Some(&selected)).unwrap();
    let observed = run(Command::new(&selected).arg("--version")).unwrap();
    assert!(e3_zk_build::reports_version(&observed, "5.2.0"));
    let cfg = protocol::Configuration {
        mode: "insecure".into(),
        preset: "insecure-64".into(),
        committee: e3_committee::CiphernodesCommitteeSize::Minimum,
        jobs: 1,
        bb_binary: Some(selected.clone()),
    };
    let mut command = protocol::integration_command(root, root, &cfg).unwrap();
    command.env("PATH", &bin);
    run_logged(&mut command, &root.join("child.log")).unwrap();
    assert_eq!(
        fs::read_to_string(root.join("integration_summary.json")).unwrap(),
        selected.to_string_lossy()
    );
    let mut without_forwarding = protocol::integration_command(root, root, &cfg).unwrap();
    without_forwarding
        .env_remove("E3_CUSTOM_BB")
        .env("PATH", &bin);
    assert!(run_logged(&mut without_forwarding, &root.join("negative-control.log")).is_err());
}
