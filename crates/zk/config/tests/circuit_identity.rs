// SPDX-License-Identifier: LGPL-3.0-only

use e3_zk_config::{CircuitName, CircuitVariant};

#[test]
fn baseline_enum_bytes_names_paths_and_layout_selection_are_unchanged() {
    // Frozen from the e3-events definitions at 26023af50, including the shared C4/C6 basename. The
    // chunked C4 also outputs its key tree; the chunk and Chonk circuits are appended after it.
    for (index, (name, path, inputs, outputs)) in [
        ("PkBfv", "dkg/pk", 0, Some(1)),
        ("PkGeneration", "threshold/pk_generation", 0, Some(3)),
        ("SkShareComputation", "dkg/sk_share_computation", 0, None),
        ("ESmShareComputation", "dkg/e_sm_share_computation", 0, None),
        ("ShareEncryption", "dkg/share_encryption", 2, Some(1)),
        ("DkgShareDecryption", "dkg/share_decryption", 0, Some(2)),
        ("PkAggregation", "threshold/pk_aggregation", 0, Some(1)),
        (
            "ThresholdShareDecryption",
            "threshold/share_decryption",
            5,
            Some(1),
        ),
        (
            "DecryptedSharesAggregation",
            "threshold/decrypted_shares_aggregation",
            0,
            Some(0),
        ),
        ("C3Fold", "recursive_aggregation/c3_fold", 0, Some(0)),
        (
            "C3FoldKernel",
            "recursive_aggregation/c3_fold_kernel",
            0,
            Some(0),
        ),
        ("C6Fold", "recursive_aggregation/c6_fold", 0, Some(0)),
        (
            "C6FoldKernel",
            "recursive_aggregation/c6_fold_kernel",
            0,
            Some(0),
        ),
        ("C2abFold", "recursive_aggregation/c2ab_fold", 0, Some(0)),
        ("C3abFold", "recursive_aggregation/c3ab_fold", 0, Some(0)),
        ("C4abFold", "recursive_aggregation/c4ab_fold", 0, Some(0)),
        ("NodeFold", "recursive_aggregation/node_fold", 0, Some(0)),
        ("NodesFold", "recursive_aggregation/nodes_fold", 0, Some(0)),
        (
            "NodesFoldKernel",
            "recursive_aggregation/nodes_fold_kernel",
            0,
            Some(0),
        ),
        (
            "DkgAggregator",
            "recursive_aggregation/dkg_aggregator",
            0,
            Some(0),
        ),
        (
            "DecryptionAggregator",
            "recursive_aggregation/decryption_aggregator",
            0,
            Some(0),
        ),
        (
            "SkShareComputationChain",
            "dkg/sk_share_computation_chain",
            0,
            Some(0),
        ),
        (
            "SkShareComputationChainLast",
            "dkg/sk_share_computation_chain_last",
            0,
            Some(0),
        ),
        (
            "ESmShareComputationChain",
            "dkg/e_sm_share_computation_chain",
            0,
            Some(0),
        ),
        (
            "ESmShareComputationChainLast",
            "dkg/e_sm_share_computation_chain_last",
            0,
            Some(0),
        ),
        (
            "DkgShareDecryptionLimb0",
            "dkg/share_decryption_limb_0",
            0,
            Some(0),
        ),
        (
            "DkgShareDecryptionLimb1",
            "dkg/share_decryption_limb_1",
            0,
            Some(0),
        ),
        (
            "DkgShareDecryptionLimb2",
            "dkg/share_decryption_limb_2",
            0,
            Some(0),
        ),
        ("C3ChonkApp", "chonk/c3_chonk_app", 0, Some(0)),
        (
            "C3ChonkInitKernel",
            "chonk/c3_chonk_init_kernel",
            0,
            Some(0),
        ),
        (
            "C3ChonkTailKernel",
            "chonk/c3_chonk_tail_kernel",
            0,
            Some(0),
        ),
        (
            "C3ChonkHidingKernel",
            "chonk/c3_chonk_hiding_kernel",
            0,
            Some(0),
        ),
        (
            "C3ChonkTube",
            "recursive_aggregation/c3_chonk_tube",
            0,
            Some(0),
        ),
        (
            "C3ChonkAccumulate",
            "recursive_aggregation/c3_chonk_accumulate",
            0,
            Some(0),
        ),
        ("C6ChonkApp", "chonk/c6_chonk_app", 0, Some(0)),
        (
            "C6ChonkInitKernel",
            "chonk/c6_chonk_init_kernel",
            0,
            Some(0),
        ),
        (
            "C6ChonkTailKernel",
            "chonk/c6_chonk_tail_kernel",
            0,
            Some(0),
        ),
        (
            "C6ChonkHidingKernel",
            "chonk/c6_chonk_hiding_kernel",
            0,
            Some(0),
        ),
        (
            "C6ChonkTube",
            "recursive_aggregation/c6_chonk_tube",
            0,
            Some(0),
        ),
        (
            "C6ChonkRoot",
            "recursive_aggregation/c6_chonk_root",
            0,
            Some(0),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let json = serde_json::Value::String(name.to_owned());
        let circuit: CircuitName = serde_json::from_value(json.clone()).unwrap();
        let bytes = (index as u32).to_le_bytes();
        assert_eq!(
            bincode::deserialize::<CircuitName>(&bytes).unwrap(),
            circuit
        );
        assert_eq!(bincode::serialize(&circuit).unwrap(), bytes);
        assert_eq!(serde_json::to_value(circuit).unwrap(), json);
        assert_eq!(circuit.dir_path(), path);
        assert_eq!(circuit.to_string(), path);
        let (group, basename) = path.split_once('/').unwrap();
        assert_eq!((circuit.group(), circuit.as_str()), (group, basename));
        assert_eq!(circuit.input_layout().field_count(), Some(inputs));
        assert_eq!(circuit.output_layout().field_count(), outputs);
    }
    for (index, (name, text, target)) in [
        ("Default", "default", "noir-recursive-no-zk"),
        ("Recursive", "recursive", "noir-recursive"),
        ("Evm", "evm", "evm"),
    ]
    .into_iter()
    .enumerate()
    {
        let json = serde_json::Value::String(name.to_owned());
        let variant: CircuitVariant = serde_json::from_value(json.clone()).unwrap();
        let bytes = (index as u32).to_le_bytes();
        assert_eq!(
            bincode::deserialize::<CircuitVariant>(&bytes).unwrap(),
            variant
        );
        assert_eq!(bincode::serialize(&variant).unwrap(), bytes);
        assert_eq!(serde_json::to_value(variant).unwrap(), json);
        assert_eq!(variant.as_str(), text);
        assert_eq!(variant.to_string(), text);
        assert_eq!(variant.verifier_target(), target);
    }
    assert_eq!(CircuitVariant::default(), CircuitVariant::Default);
}
