// SPDX-License-Identifier: LGPL-3.0-only

use e3_fhe_params::{constants::secure_8192, BfvParamSet, BfvPreset};
use e3_zk_build::metadata;
use serde_json::Value;
use std::{fs, path::Path, process::Command};

#[test]
fn export_config_is_deterministic_json_without_compiler_tools_or_output_files() {
    let temp = tempfile::tempdir().unwrap();
    let export = || {
        let output = Command::new(env!("CARGO_BIN_EXE_e3-zk-build"))
            .arg("export-config")
            .env("PATH", "")
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let first = export();
    assert_eq!(first, export());
    let document: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(document["formatVersion"], 1);
    assert!(document["bfv"].get("messageCoeffsCount").is_none());
    assert_eq!(
        document["zk"]["messageCoeffsCount"],
        e3_zk_config::MAX_MSG_NON_ZERO_COEFFS
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn metadata_preserves_frozen_identities_exact_integers_and_owner_dimensions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let metadata = metadata::collect(&root).unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fhe-params/tests/fixtures/bfv_protocol.json"
    ))
    .unwrap();
    let current: Vec<_> = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|vector| vector["preset"].is_string())
        .collect();
    assert_eq!(metadata.bfv.presets.len(), current.len());
    assert_eq!(
        metadata.bfv.encryption_scheme_id,
        fixture["encryptionSchemeId"]
    );
    assert_eq!(
        metadata.bfv.circuit_version,
        fixture["currentCircuitVersion"]
    );
    for vector in current {
        let preset = BfvPreset::from_name(vector["preset"].as_str().unwrap()).unwrap();
        let record = metadata
            .bfv
            .presets
            .iter()
            .find(|record| record.threshold.name == preset.name())
            .unwrap();
        assert_eq!(
            u64::from(record.param_set),
            vector["paramSet"].as_u64().unwrap()
        );
        assert_eq!(record.crypto_config_id, vector["cryptoConfigId"]);
        assert_eq!(record.parameter_hash, vector["parameterHash"]);
        assert_eq!(record.dkg.name, preset.dkg_counterpart().unwrap().name());
        let selected = BfvParamSet::from(preset);
        assert_eq!(
            record.threshold.degree.parse::<usize>().unwrap(),
            selected.degree
        );
        assert_eq!(
            record
                .threshold
                .moduli
                .iter()
                .map(|value| value.parse::<u64>().unwrap())
                .collect::<Vec<_>>(),
            selected.moduli
        );
        assert_eq!(
            record.threshold.error1_variance,
            selected.error1_variance.unwrap()
        );
        let recipe = preset.search_config().unwrap();
        assert_eq!(record.search.n.parse::<u128>().unwrap(), recipe.n);
        assert_eq!(record.search.z.parse::<u128>().unwrap(), recipe.z);
        assert_eq!(record.search.k.parse::<u128>().unwrap(), recipe.k);
        assert_eq!(record.search.lambda, recipe.lambda);
        assert_eq!(record.search.b.parse::<u128>().unwrap(), recipe.b);
        assert_eq!(record.search.b_chi.parse::<u128>().unwrap(), recipe.b_chi);
        assert_eq!(record.search.d, recipe.d.map(|degree| degree.to_string()));
        assert_eq!(record.search.insecure, recipe.insecure);
        assert_eq!(record.search.mult_depth, recipe.mult_depth);
        assert_eq!(record.search.min_prime_bits, recipe.min_prime_bits);
        assert_eq!(record.search.min_margin, recipe.min_margin);
    }
    let document = serde_json::to_value(&metadata).unwrap();
    let secure = document["bfv"]["presets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|preset| preset["preset"] == "secure-8192")
        .unwrap();
    assert_eq!(
        secure["dkg"]["plaintextModulus"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        secure_8192::dkg::PLAINTEXT_MODULUS
    );
    assert_eq!(
        metadata.zk.field_byte_len,
        e3_zk_config::output_layout::FIELD_BYTE_LEN
    );
    assert_eq!(
        metadata.zk.message_coeffs_count,
        e3_zk_config::MAX_MSG_NON_ZERO_COEFFS
    );
    assert_eq!(
        metadata.zk.plaintext_byte_len,
        e3_zk_config::MAX_MSG_NON_ZERO_COEFFS * std::mem::size_of::<u64>()
    );
    assert_eq!(
        metadata.committees.len(),
        e3_committee::CiphernodesCommitteeSize::ALL.len()
    );
    for (index, (record, committee)) in metadata
        .committees
        .iter()
        .zip(e3_committee::CiphernodesCommitteeSize::ALL)
        .enumerate()
    {
        assert_eq!(usize::from(record.committee_size), index);
        let values = committee.values();
        assert_eq!(
            (record.n, record.t, record.h),
            (values.n, values.threshold, values.h)
        );
        assert_eq!(record.name, committee.as_str());
    }
    let policy: Vec<[String; 2]> = serde_json::from_str(
        &fs::read_to_string(root.join("scripts/circuits/build-pairs.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(metadata.build_pairs, policy);
}
