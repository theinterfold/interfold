// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Isolated final decryption proof. No dispatch or SS fallback. Authority comes from the
//! caller's confirmed setup and ciphertext publication, never the candidate public fields.

use super::provenance::{child, prove};
use crate::{
    circuits::vk::{self, VkArtifacts},
    ZkProver,
};
use anyhow::{ensure, Context, Result};
use e3_events::Proof;
use e3_zk_config::{
    synchronized::{
        public_signals::{Field, PublicSignals},
        Configs,
    },
    CircuitName, CircuitVariant, MAX_MSG_NON_ZERO_COEFFS,
};
use e3_zk_witness::synchronized::{
    decryption_aggregation, provenance::VerificationKey, SetupBinding,
};
use serde_json::Value;

pub struct ExpectedDecryption<'a> {
    pub setup: SetupBinding,
    pub domain: [u128; 2],
    pub ciphertext_commitment: Field,
    /// All three DKG columns are in published H order, not indexed by committee ID.
    pub roster: &'a [u32],
    pub sk_commitments: &'a [Field],
    pub key_bundles: &'a [Field],
    pub message: &'a [u64],
}

fn key(vk: &VkArtifacts) -> VerificationKey<'_> {
    VerificationKey {
        fields: &vk.verification_key_bytes,
        hash: vk.key_hash_bytes,
    }
}

pub(super) fn child_key(
    prover: &ZkProver,
    config: &Configs,
    role: CircuitName,
) -> Result<VkArtifacts> {
    let namespace = config
        .profile
        .artifacts_dir_for_committee(config.committee)?;
    let dir = prover.circuits_dir(CircuitVariant::Recursive, &namespace);
    let artifacts = vk::load_vk_artifacts(&dir, role)?;
    if config.profile == e3_fhe_params::BfvProfile::SyncDecInsecure64
        && config.committee == e3_committee::CiphernodesCommitteeSize::Minimum
    {
        let pins = e3_request::canonical_key::SynchronizedChildPins::insecure_minimum()?;
        let expected = match role {
            CircuitName::ThresholdShareDecryption => pins.c6,
            CircuitName::DecryptedSharesAggregation => pins.c7,
            _ => anyhow::bail!("not a synchronized decryption child: {role}"),
        };
        ensure!(
            artifacts.key_hash_bytes == expected.0,
            e3_zk_witness::WitnessError::VerificationKey(format!(
                "installed {role} VK differs from the qualified request pin {expected}"
            ))
        );
    }
    key(&artifacts)
        .validate_recursive_honk()
        .with_context(|| format!("Invalid local {role} VK in {}", dir.display()))?;
    Ok(artifacts)
}

fn keys(prover: &ZkProver, config: &Configs) -> Result<[VkArtifacts; 2]> {
    Ok([
        child_key(prover, config, CircuitName::ThresholdShareDecryption)?,
        child_key(prover, config, CircuitName::DecryptedSharesAggregation)?,
    ])
}

pub fn prepare_decryption(
    prover: &ZkProver,
    config: &Configs,
    partials: &[Proof],
    aggregation: &Proof,
) -> Result<Value> {
    let [c6, c7] = keys(prover, config)?;
    Ok(decryption_aggregation::prepare(
        config,
        &partials.iter().map(child).collect::<Vec<_>>(),
        child(aggregation),
        key(&c6),
        key(&c7),
    )?)
}

pub fn prove_decryption(
    prover: &ZkProver,
    config: &Configs,
    partials: &[Proof],
    aggregation: &Proof,
    job: &str,
) -> Result<Proof> {
    prove(
        prover,
        config,
        CircuitName::DecryptionAggregator,
        prepare_decryption(prover, config, partials, aggregation)?,
        job,
        CircuitVariant::Evm,
        None,
    )
}

/// Reject a wrong statement or invalid proof; propagate local key, I/O and verifier errors.
pub fn verify_decryption(
    prover: &ZkProver,
    config: &Configs,
    expected: &ExpectedDecryption<'_>,
    proof: &Proof,
    job: &str,
) -> Result<bool> {
    let h = config.committee.values().h;
    ensure!(
        expected.roster.len() == h
            && expected.sk_commitments.len() == h
            && expected.key_bundles.len() == h
            && expected.message.len() == MAX_MSG_NON_ZERO_COEFFS,
        "incomplete independent decryption expectations"
    );
    if proof.circuit != CircuitName::DecryptionAggregator {
        return Ok(false);
    }
    let Some((pins, c7)) = proof.public_signals.split_at_checked(64) else {
        return Ok(false);
    };
    let Ok((rows, message)) = PublicSignals::decode_c7(config, c7) else {
        return Ok(false);
    };
    let [c6_vk, c7_vk] = keys(prover, config)?;
    if pins[..32] != c6_vk.key_hash_bytes
        || pins[32..] != c7_vk.key_hash_bytes
        || message != expected.message
        || rows[0].binding() != Some(expected.setup)
        || rows[0].decryption_domain() != Some(expected.domain)
        || rows[0].dealers().as_deref() != Some(expected.roster)
        || rows[0].ciphertext_commitment() != Some(expected.ciphertext_commitment)
    {
        return Ok(false);
    }
    // decode_c7 has already checked the owner of every row against this exact roster's prefix.
    for (s, row) in rows.iter().enumerate() {
        if row.sk_commitment() != Some(expected.sk_commitments[s])
            || row.key_bundle() != Some(expected.key_bundles[s])
        {
            return Ok(false);
        }
    }
    let namespace = config
        .profile
        .artifacts_dir_for_committee(config.committee)?;
    Ok(prover.verify_proof_with_variant(proof, job, 0, CircuitVariant::Evm, &namespace)?)
}
