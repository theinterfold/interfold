// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Local end-to-end tests that require a local bb binary and pre-compiled circuit artifacts.
//! These tests will be skipped if bb is not found.
//!
//! Circuit artifacts (`.json` + `.vk`) are expected in `circuits/bin/{group}/target/`,
//! produced by `pnpm build:circuits` locally or the `build_circuits` CI job.
//!
//! To add a new circuit: add setup_*_test() and one line in `e2e_proof_tests!`
//! `(name, setup, CircuitVariant::...)` (C5 uses Default / noir-recursive-no-zk; EVM is `DkgAggregator`).
//! A circuit with a commitment check gets one dedicated test instead of a macro row: it proves
//! once, verifies with `assert_proof_verifies`, and then compares the commitments.

mod common;

use e3_polynomial_fhe::FromFhePolynomial as _;
use std::sync::Arc;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use common::{
    extract_field, extract_field_from_end, find_bb, require_minimum_circuits,
    setup_compiled_circuit, setup_test_prover,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{CircuitName, Proof};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_config::DkgInputType;
use e3_zk_prover::{CircuitVariant, Provable, ZkBackend, ZkProver};
use e3_zk_prover::{
    DecryptedSharesAggregationCircuit, DkgShareDecryptionCircuit, PkAggregationCircuit, PkCircuit,
    PkGenerationCircuit, ShareComputationCircuit, ShareEncryptionCircuit,
    ThresholdShareDecryptionCircuit,
};
use e3_zk_witness::commitments::{
    compute_aggregated_shares_commitment, compute_dkg_pk_commitment,
    compute_threshold_decryption_share_commitment,
};
use e3_zk_witness::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_witness::dkg::share_decryption::ShareDecryptionCircuitData as DkgShareDecryptionCircuitData;
use e3_zk_witness::dkg::share_encryption::ShareEncryptionCircuitData;
use e3_zk_witness::threshold::pk_generation::PkGenerationCircuitData;
use e3_zk_witness::threshold::{
    decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData,
    pk_aggregation::PkAggregationCircuitData,
    share_decryption::ShareDecryptionCircuitData as ThresholdShareDecryptionCircuitData,
};
use e3_zk_witness::{
    compute_pk_aggregation_commitment, compute_share_computation_sk_commitment,
    compute_threshold_pk_commitment,
};
use fhe::trbfv::TRBFV;

/// Sum per-modulus decrypted shares across honest parties (matches C4 `compute_aggregated_shares`).
/// Coefficients are summed in the BN254 field, not reduced mod each CRT modulus (see `share_decryption.nr`).
fn aggregate_dkg_decrypted_shares_to_crt(
    decrypted_shares: &[Vec<Vec<num_bigint::BigInt>>],
) -> CrtPolynomial {
    let h = decrypted_shares.len();
    let l = decrypted_shares[0].len();
    let n = decrypted_shares[0][0].len();
    let mut limb_vecs: Vec<Vec<num_bigint::BigInt>> = Vec::with_capacity(l);
    for mod_idx in 0..l {
        let mut coeffs = vec![num_bigint::BigInt::from(0u64); n];
        for coeff_idx in 0..n {
            let mut sum = Fr::zero();
            for share in decrypted_shares.iter().take(h) {
                let bytes = bigint_to_field_bytes32(&share[mod_idx][coeff_idx]);
                sum += Fr::from_be_bytes_mod_order(&bytes);
            }
            coeffs[coeff_idx] = fr_to_bigint(sum);
        }
        limb_vecs.push(coeffs);
    }
    CrtPolynomial::new(limb_vecs.into_iter().map(Polynomial::new).collect())
}

/// Normalize an aggregated DKG CrtPolynomial to match C4's output representation.
///
/// C4 normalizes aggregated shares (which sum to `[0, H*q_l)`) before hashing:
///   1. Reduce each coefficient mod q_l → `[0, q_l)`
///   2. Reverse each limb (high-degree first)
///   3. Center each limb → `[-(q_l-1)/2, (q_l-1)/2]`
///
/// This is the same normalization C6 applies to `s` (already `[0, q_l)`) before
/// calling `compute_aggregated_shares_commitment`, so after this C4 and C6 hash
/// the same representation.
fn normalize_crt_for_commitment(crt: &CrtPolynomial, moduli: &[u64]) -> CrtPolynomial {
    let normalized: Vec<Polynomial> = crt
        .limbs
        .iter()
        .zip(moduli.iter())
        .map(|(limb, &qi)| {
            let q = num_bigint::BigInt::from(qi);
            let mut l = limb.clone();
            l.reduce(&q);
            l.reverse();
            l.center(&q);
            l
        })
        .collect();
    CrtPolynomial::new(normalized)
}

fn bigint_to_field_bytes32(b: &num_bigint::BigInt) -> [u8; 32] {
    let (_, bytes) = b.to_bytes_be();
    let mut out = [0u8; 32];
    let take = bytes.len().min(32);
    out[32 - take..].copy_from_slice(&bytes[bytes.len() - take..]);
    out
}

fn fr_to_bigint(f: Fr) -> num_bigint::BigInt {
    let le = f.into_bigint().to_bytes_le();
    num_bigint::BigInt::from_bytes_le(num_bigint::Sign::Plus, &le)
}

/// Verify `proof` with bb and fail the test if bb rejects it.
fn assert_proof_verifies<C: Provable>(
    circuit: &C,
    prover: &ZkProver,
    proof: &Proof,
    e3_id: &str,
    variant: CircuitVariant,
    artifacts_dir: &str,
) {
    let party_id = 1;
    let verification_result =
        circuit.verify_with_variant(prover, proof, e3_id, party_id, variant, artifacts_dir);
    assert!(
        verification_result.as_ref().is_ok_and(|&v| v),
        "Proof verification failed: {:?}",
        verification_result
    );
}

async fn setup_share_encryption_e_sm_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ShareEncryptionCircuit,
    ShareEncryptionCircuitData,
    BfvPreset,
    &'static str,
)> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    let sd: e3_fhe_params::PresetSearchDefaults =
        BfvPreset::InsecureThreshold64.search_defaults().unwrap();

    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;

    let (threshold_params, dkg_params) = preset.build_pair().ok()?;
    let sample = e3_zk_samples::dkg::share_encryption::generate(
        &threshold_params,
        &dkg_params,
        preset,
        committee,
        DkgInputType::SmudgingNoise,
        sd.z,
    )
    .ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        ShareEncryptionCircuit,
        sample,
        preset,
        "1",
    ))
}

async fn setup_share_computation_sk_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ShareComputationCircuit,
    ShareComputationCircuitData,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "sk_share_computation").await;
    setup_compiled_circuit(&backend, "dkg", "e_sm_share_computation").await;

    let config = e3_zk_config::dkg::share_computation::Configs::for_preset(
        preset,
        CiphernodesCommitteeSize::Minimum,
    )
    .ok()?;
    let sample =
        e3_zk_samples::dkg::share_computation::generate(&config, preset, DkgInputType::SecretKey)
            .ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        ShareComputationCircuit,
        sample,
        preset,
        "1",
    ))
}

async fn setup_share_computation_e_sm_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ShareComputationCircuit,
    ShareComputationCircuitData,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "sk_share_computation").await;
    setup_compiled_circuit(&backend, "dkg", "e_sm_share_computation").await;

    let config = e3_zk_config::dkg::share_computation::Configs::for_preset(
        preset,
        CiphernodesCommitteeSize::Minimum,
    )
    .ok()?;
    let sample = e3_zk_samples::dkg::share_computation::generate(
        &config,
        preset,
        DkgInputType::SmudgingNoise,
    )
    .ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        ShareComputationCircuit,
        sample,
        preset,
        "2",
    ))
}

async fn setup_pk_generation_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    PkGenerationCircuit,
    PkGenerationCircuitData,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "pk_generation").await;

    let config = e3_zk_config::threshold::pk_generation::Configs::for_preset(
        preset,
        CiphernodesCommitteeSize::Minimum,
    )
    .ok()?;
    let sample = e3_zk_samples::threshold::pk_generation::generate(&config).ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        PkGenerationCircuit,
        sample,
        preset,
        "0",
    ))
}

async fn setup_share_decryption_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ThresholdShareDecryptionCircuit,
    ThresholdShareDecryptionCircuitData,
    BfvPreset,
    &'static str,
)> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;

    let (params, _) = preset.build_pair().ok()?;
    let sample =
        e3_zk_samples::threshold::share_decryption::generate(&params, preset, committee).ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        ThresholdShareDecryptionCircuit,
        sample,
        preset,
        "1",
    ))
}

/// Loads C4 (dkg/share_decryption) and C6 (threshold/share_decryption) artifacts for link tests.
async fn setup_c4_c6_e2e_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    DkgShareDecryptionCircuitData,
    ThresholdShareDecryptionCircuitData,
    BfvPreset,
)> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "share_decryption").await;
    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;

    let config = e3_zk_config::dkg::share_decryption::Configs::for_preset(preset).ok()?;
    let dkg_sample = e3_zk_samples::dkg::share_decryption::generate(
        &config,
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )
    .ok()?;
    let c6_sample = e3_zk_samples::threshold::share_decryption::generate(
        &config.threshold_params,
        preset,
        committee,
    )
    .ok()?;
    let prover = ZkProver::new(&backend);

    Some((backend, temp, prover, dkg_sample, c6_sample, preset))
}

async fn setup_pk_aggregation_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    PkAggregationCircuit,
    PkAggregationCircuitData,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "pk_aggregation").await;

    let config = e3_zk_config::threshold::pk_aggregation::Configs::for_preset(
        preset,
        CiphernodesCommitteeSize::Minimum,
    )
    .ok()?;
    let sample = e3_zk_samples::threshold::pk_aggregation::generate(&config).ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        PkAggregationCircuit,
        sample,
        preset,
        "1",
    ))
}

async fn setup_decrypted_shares_aggregation_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    DecryptedSharesAggregationCircuit,
    DecryptedSharesAggregationCircuitData,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "decrypted_shares_aggregation").await;

    let config = e3_zk_config::threshold::decrypted_shares_aggregation::Configs::for_preset(
        preset,
        CiphernodesCommitteeSize::Minimum,
    )
    .ok()?;
    let sample =
        e3_zk_samples::threshold::decrypted_shares_aggregation::generate(&config, preset).ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        DecryptedSharesAggregationCircuit,
        sample,
        preset,
        "1",
    ))
}

async fn setup_pk_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    PkCircuit,
    fhe::bfv::PublicKey,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "pk").await;

    let config = e3_zk_config::dkg::pk::Configs::for_preset(preset).ok()?;
    let sample = e3_zk_samples::dkg::pk::generate(&config.params).ok()?;
    let prover = ZkProver::new(&backend);

    Some((backend, temp, prover, PkCircuit, sample, preset, "0"))
}

macro_rules! e2e_proof_tests {
    ($(($name:ident, $setup:expr, $variant:expr, $config:expr)),* $(,)?) => {
        $(
            paste::paste! {
                #[tokio::test]
                async fn [<test_ $name _proof>]() {
                    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
                        $setup.await
                    else {
                        println!("skipping: bb not found");
                        return;
                    };

                    let artifacts_dir = preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
                    let config = ($config)(preset);
                    let proof = circuit
                        .prove_with_variant(&prover, &config, &sample, e3_id, $variant, &artifacts_dir)
                        .expect("proof generation should succeed");

                    assert!(!proof.data.is_empty(), "proof data should not be empty");
                    assert!(!proof.public_signals.is_empty(), "public signals should not be empty");

                    assert_proof_verifies(&circuit, &prover, &proof, e3_id, $variant, &artifacts_dir);

                    prover.cleanup(e3_id).unwrap();
                }
            }
        )*
    };
}

e2e_proof_tests! {
    (share_computation_sk, setup_share_computation_sk_test(), CircuitVariant::Recursive, |preset| e3_zk_config::dkg::share_computation::Configs::for_preset(preset, CiphernodesCommitteeSize::Minimum).unwrap()),
    (share_computation_e_sm, setup_share_computation_e_sm_test(), CircuitVariant::Recursive, |preset| e3_zk_config::dkg::share_computation::Configs::for_preset(preset, CiphernodesCommitteeSize::Minimum).unwrap()),
    (share_encryption_e_sm, setup_share_encryption_e_sm_test(), CircuitVariant::Recursive, |preset| e3_zk_config::dkg::share_encryption::Configs::for_preset(preset).unwrap()),
}

#[tokio::test]
async fn test_pk_generation_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
        setup_pk_generation_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove(
            &prover,
            &e3_zk_config::threshold::pk_generation::Configs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::Minimum,
            )
            .unwrap(),
            &sample,
            e3_id,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    assert_proof_verifies(
        &circuit,
        &prover,
        &proof,
        e3_id,
        CircuitVariant::Recursive,
        &artifacts_dir,
    );

    let committee = CiphernodesCommitteeSize::Minimum;
    let config =
        e3_zk_config::threshold::pk_generation::Configs::for_preset(preset, committee).unwrap();
    let inputs =
        e3_zk_witness::threshold::pk_generation::Inputs::compute(&config, &sample).unwrap();

    // Each commitment is represented as a single field element (32 bytes), and there are 3 commitments at the end of the public signals
    let sk_commitment_from_proof = extract_field_from_end(&proof.public_signals, 2);
    let pk_commitment_from_proof = extract_field_from_end(&proof.public_signals, 1);

    // Recompute commitments from the witness
    let sk_commitment_expected =
        compute_share_computation_sk_commitment(&inputs.sk, config.bits.sk_bit);
    let pk_commitment_expected = compute_threshold_pk_commitment(&inputs.pk0is, config.bits.pk_bit);

    assert_eq!(
        sk_commitment_from_proof, sk_commitment_expected,
        "sk commitment mismatch"
    );
    assert_eq!(
        pk_commitment_from_proof, pk_commitment_expected,
        "pk commitment mismatch"
    );

    // The correlated node-fold fixture checks the C1/C2 smudging commitment links.

    prover.cleanup(e3_id).unwrap();
}

#[tokio::test]
async fn test_pk_bfv_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) = setup_pk_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove(
            &prover,
            &e3_zk_config::dkg::pk::Configs::for_preset(preset).unwrap(),
            &sample,
            e3_id,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    assert_proof_verifies(
        &circuit,
        &prover,
        &proof,
        e3_id,
        CircuitVariant::Recursive,
        &artifacts_dir,
    );

    // Verify the commitment from the proof is a valid field element
    let commitment_from_proof =
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &proof.public_signals);
    assert!(
        commitment_from_proof > num_bigint::BigInt::from(0),
        "commitment should be positive"
    );

    // Compute the commitment independently to ensure consistency
    let config = e3_zk_config::dkg::pk::Configs::for_preset(preset).unwrap();
    let inputs = e3_zk_witness::dkg::pk::Inputs::compute(&config, &sample).unwrap();
    let commitment_calculated =
        compute_dkg_pk_commitment(&inputs.pk0is, &inputs.pk1is, config.pk_bit);

    assert_eq!(
        commitment_from_proof, commitment_calculated,
        "Commitment from proof must match independently calculated commitment"
    );

    prover.cleanup(e3_id).unwrap();
}

#[tokio::test]
async fn test_pk_aggregation_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
        setup_pk_aggregation_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::pk_aggregation::Configs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::Minimum,
            )
            .unwrap(),
            &sample,
            e3_id,
            CircuitVariant::Default,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    assert_proof_verifies(
        &circuit,
        &prover,
        &proof,
        e3_id,
        CircuitVariant::Default,
        &artifacts_dir,
    );

    let config = e3_zk_config::threshold::pk_aggregation::Configs::for_preset(
        preset,
        e3_committee::CiphernodesCommitteeSize::Minimum,
    )
    .unwrap();
    let inputs =
        e3_zk_witness::threshold::pk_aggregation::Inputs::compute(&config, &sample).unwrap();

    for (i, expected) in inputs.expected_threshold_pk_commitments.iter().enumerate() {
        let commitment_from_proof = extract_field(&proof.public_signals, i);
        assert_eq!(
            commitment_from_proof, *expected,
            "pk_aggregation per-party commitment {} mismatch",
            i
        );
    }

    let expected_final_commitment = compute_pk_aggregation_commitment(
        &inputs.pk0_agg,
        &e3_zk_config::threshold::pk_generation::crp::deterministic_crp_crt_polynomial(
            &config.params,
        )
        .unwrap(),
        config.pk_bit,
    );
    let final_commitment_from_proof = extract_field_from_end(&proof.public_signals, 0);
    assert_eq!(
        final_commitment_from_proof, expected_final_commitment,
        "pk_aggregation final commitment mismatch"
    );

    prover.cleanup(e3_id).unwrap();
}

#[tokio::test]
async fn test_threshold_share_decryption_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
        setup_share_decryption_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap(),
            &sample,
            e3_id,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    assert_proof_verifies(
        &circuit,
        &prover,
        &proof,
        e3_id,
        CircuitVariant::Recursive,
        &artifacts_dir,
    );

    let config = e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap();
    let inputs =
        e3_zk_witness::threshold::share_decryption::Inputs::compute(&config, &sample).unwrap();

    let expected_d_commitment = compute_threshold_decryption_share_commitment(
        &inputs.d_native_trunc,
        config.bits.d_native_bit,
        config.max_msg_non_zero_coeffs,
    );

    let d_commitment_from_proof = extract_field_from_end(&proof.public_signals, 0);
    assert_eq!(
        d_commitment_from_proof, expected_d_commitment,
        "C6 d_commitment must match hash of d_native_trunc (C7-aligned), not centered witness d"
    );

    prover.cleanup(e3_id).unwrap();
}

/// Wires the same aggregated SK (`agg_sk`) into C6: DKG aggregate → `s` + TRBFV `decryption_share` for new `d_share`.
///
/// C4 hashes the aggregate with `SHARE_DECRYPTION_BIT_AGG`; C6 uses the same width for `sk`.
/// Per-share C4 checks still use `SHARE_DECRYPTION_BIT_MSG` (`msg_bit`) vs C2.
#[tokio::test]
async fn test_c4_c6_sk_commitment_aligned_transcript_e2e() {
    let Some((_backend, _temp, prover, dkg_sample, mut c6_sample, preset)) =
        setup_c4_c6_e2e_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let committee = CiphernodesCommitteeSize::Minimum.values();
    let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
    let ctx = threshold_params.context_at_level(0).unwrap();
    let moduli = threshold_params.moduli();

    let dkg_config = e3_zk_config::dkg::share_decryption::Configs::for_preset(preset).unwrap();
    let dkg_inputs =
        e3_zk_witness::dkg::share_decryption::Inputs::compute(&dkg_config, &dkg_sample).unwrap();
    let agg_sk = aggregate_dkg_decrypted_shares_to_crt(&dkg_inputs.decrypted_shares);

    // Rebuild the native FHE inputs for this cross-circuit transcript fixture.
    let to_fhe = |crt: &CrtPolynomial| {
        use fhe_math::rq::{traits::TryConvertFrom, Poly, PowerBasis};
        use num_integer::Integer;
        use num_traits::ToPrimitive;
        let coefficients: Vec<u64> = crt
            .limbs
            .iter()
            .zip(moduli)
            .flat_map(|(limb, &qi)| {
                let qi = num_bigint::BigInt::from(qi);
                limb.coefficients()
                    .iter()
                    .map(move |c| c.mod_floor(&qi).to_u64().unwrap())
            })
            .collect();
        Poly::<PowerBasis>::try_convert_from(coefficients, ctx, false).unwrap()
    };
    let sk_poly = to_fhe(&agg_sk).into_ntt();
    let es_poly = to_fhe(&c6_sample.e);

    let trbfv =
        TRBFV::new(committee.n, committee.threshold, threshold_params.clone()).expect("TRBFV::new");

    let d_share_rns = trbfv
        .decryption_share(Arc::new(c6_sample.ciphertext.clone()), sk_poly, es_poly)
        .expect("decryption_share");

    c6_sample.s = agg_sk.clone();
    c6_sample.d_share = CrtPolynomial::from_fhe_polynomial(&d_share_rns);

    let e3_id_c4 = "c4-align";
    let e3_id_c6 = "c6-align";
    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());

    let c4_proof = DkgShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::dkg::share_decryption::Configs::for_preset(preset).unwrap(),
            &dkg_sample,
            e3_id_c4,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C4 proof generation should succeed");

    let c6_proof = ThresholdShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap(),
            &c6_sample,
            e3_id_c6,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C6 proof generation should succeed");

    let c4_commitment = CircuitName::DkgShareDecryption
        .output_layout()
        .extract_field(&c4_proof.public_signals, "commitment")
        .expect("C4 commitment");

    let c6_expected_sk = CircuitName::ThresholdShareDecryption
        .input_layout()
        .extract_field(&c6_proof.public_signals, "expected_sk_commitment")
        .expect("C6 expected_sk_commitment");

    let c4_big = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, c4_commitment);
    let c6_big = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, c6_expected_sk);

    // C4 normalizes (reduce + reverse + center) before hashing; apply the same here.
    let agg_sk_normalized = normalize_crt_for_commitment(&agg_sk, threshold_params.moduli());
    let expected_c4_hash =
        compute_aggregated_shares_commitment(&agg_sk_normalized, dkg_config.bits.agg_bit);
    assert_eq!(
        c4_big, expected_c4_hash,
        "C4 commitment must match hash(normalized agg_sk) with DKG agg_bit (BIT_AGG)"
    );

    let c6_config =
        e3_zk_config::threshold::share_decryption::Configs::new(&threshold_params).unwrap();
    let c6_inputs =
        e3_zk_witness::threshold::share_decryption::Inputs::compute(&c6_config, &c6_sample)
            .unwrap();
    assert_eq!(
        c6_big, c6_inputs.expected_sk_commitment,
        "C6 expected_sk_commitment must match witness after wiring agg_sk"
    );

    assert_eq!(
        dkg_config.bits.agg_bit,
        c6_config.bits.sk_bit,
        "DKG bits.agg_bit (compute_modulus_bit on threshold) must match C6 bits.sk_bit for aggregate hashing"
    );

    prover.cleanup(e3_id_c4).unwrap();
    prover.cleanup(e3_id_c6).unwrap();
}

#[tokio::test]
async fn test_decrypted_shares_aggregation_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
        setup_decrypted_shares_aggregation_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::decrypted_shares_aggregation::Configs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::Minimum,
            )
            .unwrap(),
            &sample,
            e3_id,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    assert_proof_verifies(
        &circuit,
        &prover,
        &proof,
        e3_id,
        CircuitVariant::Recursive,
        &artifacts_dir,
    );

    let config = e3_zk_config::threshold::decrypted_shares_aggregation::Configs::for_preset(
        preset,
        e3_committee::CiphernodesCommitteeSize::Minimum,
    )
    .unwrap();
    let inputs =
        e3_zk_witness::threshold::decrypted_shares_aggregation::Inputs::compute(&config, &sample)
            .unwrap();

    for (i, expected) in inputs.expected_d_commitments.iter().enumerate() {
        let from_proof = extract_field(&proof.public_signals, i);
        assert_eq!(
            from_proof, *expected,
            "C7 public expected_d_commitments[{}] must match witness-derived commitment",
            i
        );
    }

    prover.cleanup(e3_id).unwrap();
}
