// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{
    synchronized::{provenance::verify_recipient, publication::verify_publication},
    ZkBackend,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{Proof, SynchronizedProofContext};
use e3_fhe_params::BfvProfile;
use e3_utils::ArcBytes;
use e3_zk_config::{CircuitName, CircuitVariant};
use fhe::bfv::SecretKey;
use std::time::Duration;

#[test]
fn malformed_generated_signals_are_local_but_standalone_verifiers_reject() {
    let root = tempfile::tempdir().unwrap();
    let prover = ZkProver::new(&ZkBackend {
        base_dir: root.path().to_owned(),
        bb_binary: root.path().join("absent-bb"),
        circuits_dir: root.path().join("circuits"),
        work_dir: root.path().join("work"),
        config: Default::default(),
        using_custom_bb: true,
        bb_timeout: Duration::from_secs(1),
    });
    let config = Configs::for_profile(
        BfvProfile::SyncDecInsecure64,
        CiphernodesCommitteeSize::Minimum,
    )
    .unwrap();
    let namespace = config
        .profile
        .artifacts_dir_for_committee(config.committee)
        .unwrap();
    for (circuit, variant) in [
        (CircuitName::PkBfv, CircuitVariant::Recursive),
        (CircuitName::PkGeneration, CircuitVariant::Recursive),
        (CircuitName::SkShareComputation, CircuitVariant::Recursive),
        (CircuitName::ShareEncryption, CircuitVariant::Recursive),
        (CircuitName::DkgShareDecryption, CircuitVariant::Recursive),
        (CircuitName::NodeFold, CircuitVariant::Default),
        (CircuitName::NodesFold, CircuitVariant::Default),
        (CircuitName::PkAggregation, CircuitVariant::Default),
    ] {
        let dir = prover
            .circuits_dir(variant, &namespace)
            .join(circuit.dir_path());
        std::fs::create_dir_all(&dir).unwrap();
        for suffix in ["vk", "vk_hash"] {
            std::fs::write(dir.join(format!("{}.{suffix}", circuit.as_str())), [0; 32]).unwrap();
        }
    }
    let context = SynchronizedProofContext {
        party_id: 0,
        setup: e3_committee_hash::DkgSetupContext {
            interfold_address: alloy::primitives::Address::repeat_byte(1),
            committee_hash: [2; 32].into(),
            crypto_config_id: config.profile.crypto_config_id(config.committee).unwrap(),
        },
    };
    let id = E3id::new("9", 31337);
    let setup = ExpectedSetup {
        dealers: &[0, 2],
        threshold_keys: &[[0; 32]; 2],
        dealer_batch: [0; 32],
        sk_commitment: [0; 32],
        key_bundle: [0; 32],
    };
    let mut rng = rand::rng();
    let secret = SecretKey::random(&config.threshold, &mut rng);
    let key = PublicKey::new(&secret, &mut rng);
    let publication = ExpectedPublication {
        dealers: setup.dealers,
        threshold_keys: setup.threshold_keys,
        dealer_batch: setup.dealer_batch,
        sk_commitments: &[[0; 32]; 2],
        key_bundles: &[[0; 32]; 2],
        public_key: &key,
    };
    for circuit in [CircuitName::NodesFold, CircuitName::DkgAggregator] {
        let count =
            config.public_inputs(circuit).unwrap() + config.public_outputs(circuit).unwrap();
        for signals in [vec![0; (count - 1) * 32], vec![255; count * 32]] {
            let proof = Proof::new(circuit, ArcBytes::default(), ArcBytes::from_bytes(&signals));
            let rejection = if circuit == CircuitName::NodesFold {
                assert!(verify_recipient(
                    &prover,
                    &config,
                    &context,
                    &id,
                    &setup,
                    &proof,
                    "malformed"
                )
                .unwrap()
                .is_none());
                verify_recipient_result(
                    &prover,
                    &config,
                    &context,
                    &id,
                    &setup,
                    &proof,
                    "malformed",
                )
                .unwrap()
                .err()
                .unwrap()
            } else {
                assert!(verify_publication(
                    &prover,
                    &config,
                    &context,
                    &id,
                    &publication,
                    &proof,
                    "malformed"
                )
                .unwrap()
                .is_none());
                verify_publication_result(
                    &prover,
                    &config,
                    &context,
                    &id,
                    &publication,
                    &proof,
                    "malformed",
                )
                .unwrap()
                .err()
                .unwrap()
            };
            assert!(matches!(
                generated_rejection(rejection, "expectation mismatch"),
                ExecutionError::Local(_)
            ));
        }
    }
    assert!(!prover.work_dir().exists());
}
