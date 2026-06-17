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
//! Commitment consistency tests are defined separately.

mod common;

use std::sync::Arc;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use common::{
    extract_field, extract_field_from_end, find_bb, require_minimum_circuits,
    setup_compiled_circuit, setup_test_prover,
};
use e3_events::CircuitName;
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_helpers::circuits::dkg::pk::circuit::PkCircuit;
use e3_zk_helpers::circuits::dkg::pk::circuit::PkCircuitData;
use e3_zk_helpers::circuits::{
    commitments::{
        compute_aggregated_shares_commitment, compute_dkg_pk_commitment,
        compute_threshold_decryption_share_commitment,
    },
    threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS,
    CircuitComputation,
};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_computation::{ShareComputationCircuit, ShareComputationCircuitData};
use e3_zk_helpers::dkg::share_decryption::{
    ShareDecryptionCircuit as DkgShareDecryptionCircuit,
    ShareDecryptionCircuitData as DkgShareDecryptionCircuitData,
};
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::pk_generation::{PkGenerationCircuit, PkGenerationCircuitData};
use e3_zk_helpers::threshold::{
    decrypted_shares_aggregation::{
        DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
    },
    pk_aggregation::{PkAggregationCircuit, PkAggregationCircuitData},
    share_decryption::{
        ShareDecryptionCircuit as ThresholdShareDecryptionCircuit,
        ShareDecryptionCircuitData as ThresholdShareDecryptionCircuitData,
    },
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_helpers::{
    compute_pk_aggregation_commitment, compute_share_computation_sk_commitment,
    compute_threshold_pk_commitment,
};
use e3_zk_prover::{CircuitVariant, Provable, ZkBackend, ZkProver};
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
    CrtPolynomial::from_bigint_vectors(limb_vecs)
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

/// Convert raw public signals bytes (32-byte big-endian chunks) to ark_bn254::Fr field elements.
fn public_signals_to_fields(signals: &[u8]) -> Vec<Fr> {
    signals
        .chunks(32)
        .map(Fr::from_be_bytes_mod_order)
        .collect()
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
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    let sd: e3_fhe_params::PresetSearchDefaults =
        BfvPreset::InsecureThreshold512.search_defaults().unwrap();

    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;

    let sample = ShareEncryptionCircuitData::generate_sample(
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

async fn setup_share_encryption_sk_test() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ShareEncryptionCircuit,
    ShareEncryptionCircuitData,
    BfvPreset,
    &'static str,
)> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    let sd: e3_fhe_params::PresetSearchDefaults =
        BfvPreset::InsecureThreshold512.search_defaults().unwrap();

    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;

    let sample = ShareEncryptionCircuitData::generate_sample(
        preset,
        committee,
        DkgInputType::SecretKey,
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
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "sk_share_computation").await;
    setup_compiled_circuit(&backend, "dkg", "e_sm_share_computation").await;

    let sample =
        ShareComputationCircuitData::generate_sample(preset, committee, DkgInputType::SecretKey)
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
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "sk_share_computation").await;
    setup_compiled_circuit(&backend, "dkg", "e_sm_share_computation").await;

    let sample = ShareComputationCircuitData::generate_sample(
        preset,
        committee,
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
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "pk_generation").await;

    let sample = PkGenerationCircuitData::generate_sample(preset, committee).ok()?;
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
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;

    let sample = ThresholdShareDecryptionCircuitData::generate_sample(preset, committee).ok()?;
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
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "share_decryption").await;
    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;

    let dkg_sample = DkgShareDecryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )
    .ok()?;
    let c6_sample = ThresholdShareDecryptionCircuitData::generate_sample(preset, committee).ok()?;
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
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "pk_aggregation").await;

    let sample = PkAggregationCircuitData::generate_sample(preset, committee).ok()?;
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
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    require_minimum_circuits()?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "decrypted_shares_aggregation").await;

    let sample = DecryptedSharesAggregationCircuitData::generate_sample(preset, committee).ok()?;
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
    PkCircuitData,
    BfvPreset,
    &'static str,
)> {
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "dkg", "pk").await;

    let sample = PkCircuitData::generate_sample(preset).ok()?;
    let prover = ZkProver::new(&backend);

    Some((backend, temp, prover, PkCircuit, sample, preset, "0"))
}

macro_rules! e2e_proof_tests {
    ($(($name:ident, $setup:expr, $variant:expr)),* $(,)?) => {
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
                    let proof = circuit
                        .prove_with_variant(&prover, &preset, &sample, e3_id, $variant, &artifacts_dir)
                        .expect("proof generation should succeed");

                    assert!(!proof.data.is_empty(), "proof data should not be empty");
                    assert!(!proof.public_signals.is_empty(), "public signals should not be empty");

                    let party_id = 1;
                    let verification_result =
                        circuit.verify_with_variant(&prover, &proof, e3_id, party_id, $variant, &artifacts_dir);
                    assert!(
                        verification_result.as_ref().is_ok_and(|&v| v),
                        "Proof verification failed: {:?}",
                        verification_result
                    );

                    prover.cleanup(e3_id).unwrap();
                }
            }
        )*
    };
}

e2e_proof_tests! {
    (pk_generation, setup_pk_generation_test(), CircuitVariant::Recursive),
    (pk, setup_pk_test(), CircuitVariant::Recursive),
    (share_computation_sk, setup_share_computation_sk_test(), CircuitVariant::Recursive),
    (share_computation_e_sm, setup_share_computation_e_sm_test(), CircuitVariant::Recursive),
    (share_encryption_sk, setup_share_encryption_sk_test(), CircuitVariant::Recursive),
    (share_encryption_e_sm, setup_share_encryption_e_sm_test(), CircuitVariant::Recursive),
    (share_decryption, setup_share_decryption_test(), CircuitVariant::Recursive),
    (pk_aggregation, setup_pk_aggregation_test(), CircuitVariant::Default),
    (decrypted_shares_aggregation, setup_decrypted_shares_aggregation_test(), CircuitVariant::Recursive),
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
        .prove(&prover, &preset, &sample, e3_id, &artifacts_dir)
        .expect("proof generation should succeed");

    let computation_output = PkGenerationCircuit::compute(preset, &sample).unwrap();

    // Each commitment is represented as a single field element (32 bytes), and there are 3 commitments at the end of the public signals
    let sk_commitment_from_proof = extract_field_from_end(&proof.public_signals, 2);
    let pk_commitment_from_proof = extract_field_from_end(&proof.public_signals, 1);

    // Recompute commitments from the witness
    let sk_commitment_expected = compute_share_computation_sk_commitment(
        &computation_output.inputs.sk,
        computation_output.bits.sk_bit,
    );
    let pk_commitment_expected = compute_threshold_pk_commitment(
        &computation_output.inputs.pk0is,
        computation_output.bits.pk_bit,
    );

    assert_eq!(
        sk_commitment_from_proof, sk_commitment_expected,
        "sk commitment mismatch"
    );
    assert_eq!(
        pk_commitment_from_proof, pk_commitment_expected,
        "pk commitment mismatch"
    );

    // NOTE: e_sm commitment check is skipped because Bounds::compute uses
    // SEARCH_N (100) for the smudging bound while the Noir circuit config
    // uses the committee size (5), producing different bit widths for packing.

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
        .prove(&prover, &preset, &sample, e3_id, &artifacts_dir)
        .expect("proof generation should succeed");

    // Verify the commitment from the proof is a valid field element
    let commitment_from_proof =
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &proof.public_signals);
    assert!(
        commitment_from_proof > num_bigint::BigInt::from(0),
        "commitment should be positive"
    );

    // Compute the commitment independently to ensure consistency
    let computation_output =
        PkCircuit::compute(preset, &sample).expect("computation should succeed");
    let commitment_calculated = compute_dkg_pk_commitment(
        &computation_output.inputs.pk0is,
        &computation_output.inputs.pk1is,
        computation_output.bits.pk_bit,
    );

    assert_eq!(
        commitment_from_proof, commitment_calculated,
        "Commitment from proof must match independently calculated commitment"
    );

    prover.cleanup(e3_id).unwrap();
}

#[tokio::test]
async fn test_share_computation_sk_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
        setup_share_computation_sk_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove(&prover, &preset, &sample, e3_id, &artifacts_dir)
        .expect("inner sk_share_computation proof should succeed");

    assert_eq!(
        proof.circuit,
        CircuitName::SkShareComputation,
        "expected SkShareComputation inner circuit tag"
    );
    assert!(
        !proof.public_signals.is_empty() && proof.public_signals.len() % 32 == 0,
        "inner C2 public signals should be non-empty 32-byte field chunks"
    );

    let fields = public_signals_to_fields(&proof.public_signals);
    assert!(
        fields.iter().any(|f| !f.is_zero()),
        "inner share computation public signals should not all be zero"
    );

    prover.cleanup(e3_id).unwrap();
}

#[tokio::test]
async fn test_share_computation_e_sm_commitment_consistency() {
    let Some((_backend, _temp, prover, circuit, sample, preset, e3_id)) =
        setup_share_computation_e_sm_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let proof = circuit
        .prove(&prover, &preset, &sample, e3_id, &artifacts_dir)
        .expect("inner e_sm_share_computation proof should succeed");

    assert_eq!(
        proof.circuit,
        CircuitName::ESmShareComputation,
        "expected ESmShareComputation inner circuit tag"
    );
    assert!(
        !proof.public_signals.is_empty() && proof.public_signals.len() % 32 == 0,
        "inner C2 public signals should be non-empty 32-byte field chunks"
    );

    let fields = public_signals_to_fields(&proof.public_signals);
    assert!(
        fields.iter().any(|f| !f.is_zero()),
        "inner share computation public signals should not all be zero"
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
            &preset,
            &sample,
            e3_id,
            CircuitVariant::Default,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    let computation_output = PkAggregationCircuit::compute(preset, &sample).unwrap();

    for (i, expected) in computation_output
        .inputs
        .expected_threshold_pk_commitments
        .iter()
        .enumerate()
    {
        let commitment_from_proof = extract_field(&proof.public_signals, i);
        assert_eq!(
            commitment_from_proof, *expected,
            "pk_aggregation per-party commitment {} mismatch",
            i
        );
    }

    let expected_final_commitment = compute_pk_aggregation_commitment(
        &computation_output.inputs.pk0_agg,
        &computation_output.inputs.crp,
        computation_output.bits.pk_bit,
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
            &preset,
            &sample,
            e3_id,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    let computation_output = ThresholdShareDecryptionCircuit::compute(preset, &sample).unwrap();

    let expected_d_commitment = compute_threshold_decryption_share_commitment(
        &computation_output.inputs.d_native_trunc,
        computation_output.bits.d_native_bit,
        MAX_MSG_NON_ZERO_COEFFS,
    );

    let d_commitment_from_proof = extract_field_from_end(&proof.public_signals, 0);
    assert_eq!(
        d_commitment_from_proof, expected_d_commitment,
        "C6 d_commitment must match hash of d_native_trunc (C7-aligned), not centered witness d"
    );

    prover.cleanup(e3_id).unwrap();
}

/// C4a publishes `commitment` (aggregated sk); C6 consumes `expected_sk_commitment` as its first
/// public input — see `commitment_links/c4a_to_c6.rs`. This test checks both proofs expose those
/// values consistently with witness recomputation (same hash as the cross-circuit link).
#[tokio::test]
async fn test_c4_sk_commitment_is_c6_expected_sk_input_e2e() {
    let Some((_backend, _temp, prover, dkg_sample, c6_sample, preset)) =
        setup_c4_c6_e2e_test().await
    else {
        println!("skipping: bb not found");
        return;
    };

    let e3_id_c4 = "c4-e2e";
    let e3_id_c6 = "c6-e2e";
    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());

    let c4_proof = DkgShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &dkg_sample,
            e3_id_c4,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C4 proof generation should succeed");

    let c6_proof = ThresholdShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &c6_sample,
            e3_id_c6,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C6 proof generation should succeed");

    let c4_commitment_bytes = CircuitName::DkgShareDecryption
        .output_layout()
        .extract_field(&c4_proof.public_signals, "commitment")
        .expect("C4 proof must expose commitment output");

    let c6_expected_sk_bytes = CircuitName::ThresholdShareDecryption
        .input_layout()
        .extract_field(&c6_proof.public_signals, "expected_sk_commitment")
        .expect("C6 proof must expose expected_sk_commitment at public inputs");

    let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
    let dkg_out = DkgShareDecryptionCircuit::compute(preset, &dkg_sample).unwrap();
    let aggregated = aggregate_dkg_decrypted_shares_to_crt(&dkg_out.inputs.decrypted_shares);
    // C4 normalizes (reduce + reverse + center) before hashing; apply the same here.
    let aggregated_normalized =
        normalize_crt_for_commitment(&aggregated, threshold_params.moduli());
    let expected_c4 =
        compute_aggregated_shares_commitment(&aggregated_normalized, dkg_out.bits.agg_bit);
    let c4_from_proof =
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, c4_commitment_bytes);
    assert_eq!(
        c4_from_proof, expected_c4,
        "C4 commitment output must match compute_aggregated_shares_commitment on normalized aggregated DKG shares"
    );

    let c6_out = ThresholdShareDecryptionCircuit::compute(preset, &c6_sample).unwrap();
    let expected_c6_sk = c6_out.inputs.expected_sk_commitment.clone();
    let c6_expected_sk_from_proof =
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, c6_expected_sk_bytes);
    assert_eq!(
        c6_expected_sk_from_proof, expected_c6_sk,
        "C6 expected_sk_commitment public input must match witness computation"
    );

    prover.cleanup(e3_id_c4).unwrap();
    prover.cleanup(e3_id_c6).unwrap();
}

/// Wires the same aggregated SK (`agg_sk`) into C6: DKG aggregate → `s` + TRBFV `decryption_share` for new `d_share`.
///
/// C4 hashes the aggregate with `SHARE_DECRYPTION_BIT_AGG` (Rust `dkg_out.bits.agg_bit`); C6 uses the same width for `sk`.
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

    let dkg_out = DkgShareDecryptionCircuit::compute(preset, &dkg_sample).unwrap();
    let agg_sk = aggregate_dkg_decrypted_shares_to_crt(&dkg_out.inputs.decrypted_shares);

    let sk_poly = agg_sk
        .to_fhe_polynomial(ctx, moduli)
        .expect("agg_sk -> Poly")
        .into_ntt();
    let es_poly = c6_sample
        .e
        .to_fhe_polynomial(ctx, moduli)
        .expect("e -> Poly");

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
            &preset,
            &dkg_sample,
            e3_id_c4,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C4 proof generation should succeed");

    let c6_proof = ThresholdShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &preset,
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
        compute_aggregated_shares_commitment(&agg_sk_normalized, dkg_out.bits.agg_bit);
    assert_eq!(
        c4_big, expected_c4_hash,
        "C4 commitment must match hash(normalized agg_sk) with DKG agg_bit (BIT_AGG)"
    );

    let c6_out = ThresholdShareDecryptionCircuit::compute(preset, &c6_sample).unwrap();
    assert_eq!(
        c6_big, c6_out.inputs.expected_sk_commitment,
        "C6 expected_sk_commitment must match witness after wiring agg_sk"
    );

    assert_eq!(
        dkg_out.bits.agg_bit,
        c6_out.bits.sk_bit,
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
            &preset,
            &sample,
            e3_id,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("proof generation should succeed");

    let computation_output = DecryptedSharesAggregationCircuit::compute(preset, &sample).unwrap();

    for (i, expected) in computation_output
        .inputs
        .expected_d_commitments
        .iter()
        .enumerate()
    {
        let from_proof = extract_field(&proof.public_signals, i);
        assert_eq!(
            from_proof, *expected,
            "C7 public expected_d_commitments[{}] must match witness-derived commitment",
            i
        );
    }

    prover.cleanup(e3_id).unwrap();
}
