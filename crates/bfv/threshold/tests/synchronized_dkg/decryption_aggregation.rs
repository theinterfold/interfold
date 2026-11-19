// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::provenance::{field, reject_join, stage_profile};
use super::*;
use e3_events::Proof;
use e3_zk_prover::{synchronized::decryption::*, BBPath, ZkBackend, ZkProver};

#[allow(clippy::too_many_arguments)]
pub(super) fn qualify(
    root: &Path,
    bb: &Path,
    fixture: &Fixture,
    partials: &[Proof],
    c7: &Proof,
    alternate: Option<&Proof>,
    request: super::threshold_decryption::Request,
    ciphertext: &BigInt,
    message: &[u64],
) -> Result<()> {
    let config = &fixture.config;
    let temp = tempfile::tempdir()?;
    let backend = ZkBackend::new(
        BBPath::Custom(bb.into()),
        temp.path().join("artifacts"),
        temp.path().join("work"),
    );
    let prover = ZkProver::new(&backend);
    let stage = |role| {
        stage_profile(
            &CircuitJob::for_profile(root, role, config.profile)?,
            &prover,
            bb,
            role,
            config.profile,
        )
    };
    for role in [
        CircuitName::ThresholdShareDecryption,
        CircuitName::DecryptedSharesAggregation,
    ] {
        stage(role)?;
    }
    let role = CircuitName::DecryptionAggregator;
    let compiled = stage(role)?;
    let start = std::time::Instant::now();
    let outer = prove_decryption(&prover, config, partials, c7, "sync-final")?;
    eprintln!(
        "{} outer witness + EVM proving: {:.2}s",
        config.profile,
        start.elapsed().as_secs_f64()
    );
    ensure!(outer.public_signals[64..] == c7.public_signals[..]);
    e3_zk_config::synchronized::public_signals::PublicSignals::decode(
        config,
        role,
        &outer.public_signals,
    )?;
    let mut sk = Vec::new();
    let mut bundles = Vec::new();
    for id in DEALERS {
        let leaf = fixture
            .leaves
            .iter()
            .find(|l| l.role == CircuitName::DkgShareDecryption && l.inputs["recipient_id"] == id)
            .context("missing independent C4 anchors")?;
        sk.push(field(&leaf.outputs[0]));
        bundles.push(field(&leaf.outputs[1]));
    }
    let expected = ExpectedDecryption {
        setup: request.setup,
        domain: request.domain,
        roster: &DEALERS,
        ciphertext_commitment: field(ciphertext),
        sk_commitments: &sk,
        key_bundles: &bundles,
        message,
    };
    ensure!(verify_decryption(
        &prover,
        config,
        &expected,
        &outer,
        "sync-final"
    )?);
    // Preserve only the verified public fixture when a separate EVM qualification requests it.
    if let Some(directory) = std::env::var_os("E3_SYNC_DECRYPTION_EXPORT") {
        let directory = PathBuf::from(directory);
        fs::create_dir(&directory)?;
        fs::copy(
            compiled.with_extension("vk"),
            directory.join("decryption_aggregator.vk"),
        )?;
        fs::write(directory.join("proof"), &outer.data[..])?;
        fs::write(directory.join("public_inputs"), &outer.public_signals[..])?;
        let namespace = config
            .profile
            .artifacts_dir_for_committee(config.committee)?;
        let keys = prover.circuits_dir(e3_zk_config::CircuitVariant::Recursive, &namespace);
        let key = |role| e3_zk_prover::test_utils::load_vk_artifacts(&keys, role);
        fs::write(
            directory.join("expected.json"),
            serde_json::to_vec(&json!({
                "pins": [key(CircuitName::ThresholdShareDecryption)?.key_hash,
                         key(CircuitName::DecryptedSharesAggregation)?.key_hash],
                "sk": sk, "bundles": bundles, "ciphertext": expected.ciphertext_commitment,
                "pk": request.pk, "ciphertext_hash": request.ciphertext_hash,
                "plaintext": message.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>()
            }))?,
        )?;
    }
    let other_bundles = [bundles[1], bundles[0]];
    let other_sk = [sk[1], sk[0]];
    let mut other_message = message.to_vec();
    other_message[0] += 1;
    for wrong in [
        ExpectedDecryption {
            setup: [0, 0],
            ..expected
        },
        ExpectedDecryption {
            domain: [0, 0],
            ..expected
        },
        ExpectedDecryption {
            roster: &[1, 2],
            ..expected
        },
        ExpectedDecryption {
            ciphertext_commitment: [0; 32],
            ..expected
        },
        ExpectedDecryption {
            sk_commitments: &other_sk,
            ..expected
        },
        ExpectedDecryption {
            key_bundles: &other_bundles,
            ..expected
        },
        ExpectedDecryption {
            message: &other_message,
            ..expected
        },
    ] {
        ensure!(!verify_decryption(
            &prover,
            config,
            &wrong,
            &outer,
            "wrong-authority"
        )?);
    }
    // Even with matching (changed) expectations the original outer proof must reject.
    let mut changed = outer.public_signals.extract_bytes();
    let message_start = changed.len() - message.len() * 32;
    changed[message_start + 24..message_start + 32]
        .copy_from_slice(&other_message[0].to_be_bytes());
    let other = Proof::new(
        role,
        outer.data.clone(),
        e3_utils::utility_types::ArcBytes::from_bytes(&changed),
    );
    ensure!(!verify_decryption(
        &prover,
        config,
        &ExpectedDecryption {
            message: &other_message,
            ..expected
        },
        &other,
        "modified-public"
    )?);

    ensure!(prepare_decryption(&prover, config, &partials[..1], c7).is_err());
    let mut wrong = partials.to_vec();
    wrong.swap(0, 1);
    ensure!(prepare_decryption(&prover, config, &wrong, c7).is_err());
    wrong.swap(0, 1);
    let Some(alternate) = alternate else {
        return Ok(());
    };
    wrong[1] = alternate.clone();
    ensure!(prepare_decryption(&prover, config, &wrong, c7).is_err());
    // Both child proofs individually verified. Even if the host row precheck is satisfied,
    // the recursive verifier must reject the proof body belonging to the other designated set.
    wrong[1].public_signals = partials[1].public_signals.clone();
    let error = prove_decryption(&prover, config, &wrong, c7, "mixed-c6-proof")
        .expect_err("mixed C6 proof verified");
    ensure!(
        matches!(
            error.downcast_ref::<e3_zk_prover::ZkError>(),
            Some(e3_zk_prover::ZkError::ProofRejected(_))
        ),
        "unexpected failure for mixed C6 proof: {error:#}"
    );
    let input = prepare_decryption(&prover, config, partials, c7)?;
    for name in ["c6", "c7"] {
        let mut wrong_key = input.clone();
        wrong_key[format!("{name}_vk")][0] = json!("0");
        ensure!(wrong_key != input);
        reject_join(&compiled, &wrong_key, "altered child VK with genuine hash")?;
    }
    Ok(())
}
