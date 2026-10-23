// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Synchronous protocol ZK execution, kept independent of actor scheduling and publication.

#![allow(clippy::result_large_err)]

use alloy::primitives::keccak256;
use anyhow::Result;
use e3_crypto::Cipher;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use crate::ZkBackend;
use crate::{
    generate_nodes_fold_step, prove_decryption_aggregation_jobs, prove_dkg_aggregation,
    prove_node_dkg_fold, CircuitVariant, DecryptionAggregationJob, DkgAggregationInput,
    FoldProveStepTiming, NodeDkgFoldInput, NodeDkgFoldProveResult, Provable, ZkError, ZkProver,
};
use crate::{
    DecryptedSharesAggregationCircuit, DkgShareDecryptionCircuit as ShareDecryptionCircuit,
    PkAggregationCircuit, PkCircuit, PkGenerationCircuit, ShareComputationCircuit,
    ShareEncryptionCircuit,
};
use e3_committee::CiphernodesCommitteeSize;
#[cfg(test)]
use e3_events::E3id;
use e3_events::{
    ComputeRequest, ComputeRequestError, ComputeRequestErrorKind, ComputeRequestKind,
    ComputeResponse, DecryptedSharesAggregationProofRequest,
    DecryptedSharesAggregationProofResponse, DecryptionAggregationRequest,
    DecryptionAggregationResponse, DkgAggregationRequest, DkgAggregationResponse,
    DkgShareDecryptionProofRequest, DkgShareDecryptionProofResponse, NodeDkgFoldRequest,
    NodeDkgFoldResponse, NodesFoldStepRequest, NodesFoldStepResponse, PartyVerificationResult,
    PkAggregationProofRequest, PkAggregationProofResponse, PkBfvProofRequest, PkBfvProofResponse,
    PkGenerationProofRequest, PkGenerationProofResponse, Proof, ShareComputationProofRequest,
    ShareComputationProofResponse, ShareEncryptionProofRequest, ShareEncryptionProofResponse,
    ThresholdShareDecryptionProofRequest, ThresholdShareDecryptionProofResponse,
    VerifyShareDecryptionProofsRequest, VerifyShareDecryptionProofsResponse,
    VerifyShareProofsRequest, VerifyShareProofsResponse, ZkError as ZkEventError, ZkRequest,
    ZkResponse,
};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::BfvParamSet;
#[cfg(test)]
use e3_fhe_params::BfvPreset;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_trbfv::helpers::deserialize_secret_key;
use e3_trbfv::helpers::try_poly_from_sensitive_bytes;
use e3_trbfv::helpers::try_poly_ntt_from_bytes;
use e3_trbfv::helpers::try_poly_pb_from_bytes;
use e3_trbfv::shares::SharedSecret;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_witness::dkg::share_decryption::ShareDecryptionCircuitData;
use e3_zk_witness::dkg::share_encryption::ShareEncryptionCircuitData;
use e3_zk_witness::threshold::decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData;
use e3_zk_witness::threshold::pk_aggregation::PkAggregationCircuitData;
use e3_zk_witness::threshold::pk_generation::PkGenerationCircuitData;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey};
use fhe::mbfv::PublicKeyShare;
use fhe_math::rq::PowerBasis;
use fhe_traits::{DeserializeParametrized, FheEncoder};
use ndarray::Array2;
use num_bigint::BigInt;
use tracing::info;

/// Stable diagnostic operation label for a protocol proof request.
pub fn zk_operation_name(request: &ZkRequest) -> &'static str {
    match request {
        ZkRequest::PkBfv(_) => "zk_pk_bfv",
        ZkRequest::PkGeneration(_) => "zk_pk_generation",
        ZkRequest::ShareComputation(_) => "zk_share_computation",
        ZkRequest::ShareEncryption(_) => "zk_share_encryption",
        ZkRequest::DkgShareDecryption(_) => "zk_dkg_share_decryption",
        ZkRequest::VerifyShareProofs(_) => "zk_verify_share_proofs",
        ZkRequest::ReverifyAccusedProof(_) => "zk_reverify_accused_proof",
        ZkRequest::VerifyShareDecryptionProofs(_) => "zk_verify_share_decryption_proofs",
        ZkRequest::PkAggregation(_) => "zk_pk_aggregation",
        ZkRequest::ThresholdShareDecryption(_) => "zk_threshold_share_decryption",
        ZkRequest::DecryptedSharesAggregation(_) => "zk_decrypted_shares_aggregation",
        ZkRequest::NodeDkgFold(_) => "zk_node_dkg_fold",
        ZkRequest::NodesFoldStep(_) => "zk_nodes_fold_step",
        ZkRequest::DkgAggregation(_) => "zk_dkg_aggregation",
        ZkRequest::DecryptionAggregation(_) => "zk_decryption_aggregation",
    }
}

/// Execute a correlated protocol ZK request synchronously, including runtime witness decryption.
/// Call from a bounded worker, not an actor mailbox. The caller owns admission, retries,
/// cancellation and publication; `record_step` receives completed node-fold timing observations.
pub fn execute_zk_request(
    prover: &ZkProver,
    cipher: &Cipher,
    request: ComputeRequest,
    record_step: &mut dyn FnMut(FoldProveStepTiming),
) -> Result<ComputeResponse, ComputeRequestError> {
    let ComputeRequestKind::Zk(kind) = request.request.clone() else {
        return Err(make_zk_error(&request, "expected a ZK request".into()));
    };
    match kind {
        ZkRequest::PkBfv(req) => handle_pk_bfv_proof(prover, req, request),
        ZkRequest::PkGeneration(req) => handle_pk_generation_proof(prover, cipher, req, request),
        ZkRequest::ShareComputation(req) => {
            handle_share_computation_proof(prover, cipher, req, request)
        }
        ZkRequest::ShareEncryption(req) => {
            handle_share_encryption_proof(prover, cipher, req, request)
        }
        ZkRequest::DkgShareDecryption(req) => {
            handle_dkg_share_decryption_proof(prover, cipher, req, request)
        }
        ZkRequest::VerifyShareProofs(req) | ZkRequest::ReverifyAccusedProof(req) => {
            handle_verify_share_proofs(prover, req, request)
        }
        ZkRequest::VerifyShareDecryptionProofs(req) => {
            handle_verify_share_decryption_proofs(prover, req, request)
        }
        ZkRequest::PkAggregation(req) => handle_pk_aggregation_proof(prover, req, request),
        ZkRequest::ThresholdShareDecryption(req) => {
            handle_threshold_share_decryption_proof(prover, cipher, req, request)
        }
        ZkRequest::DecryptedSharesAggregation(req) => {
            handle_decrypted_shares_aggregation_proof(prover, req, request)
        }
        ZkRequest::NodeDkgFold(req) => {
            handle_node_dkg_fold_proof(prover, req, request, record_step)
        }
        ZkRequest::NodesFoldStep(req) => handle_nodes_fold_step_proof(prover, req, request),
        ZkRequest::DkgAggregation(req) => handle_dkg_aggregation_proof(prover, req, request),
        ZkRequest::DecryptionAggregation(req) => {
            handle_decryption_aggregation_proof(prover, req, request)
        }
    }
}

#[cfg(test)]
#[path = "request_execution_tests.rs"]
mod execution_tests;

fn handle_pk_aggregation_proof(
    prover: &ZkProver,
    req: PkAggregationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // 1. Build threshold BFV parameters from preset
    let (threshold_params, _dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    // 2. Create deterministic CRP
    let crp = create_deterministic_crp_from_default_seed(&threshold_params);

    // 3. Validate keyshare count before deserialization
    if req.keyshare_bytes.len() != req.committee_h {
        return Err(make_zk_error(
            &request,
            format!(
                "keyshare_bytes length {} != committee_h {}",
                req.keyshare_bytes.len(),
                req.committee_h
            ),
        ));
    }

    // 4. Deserialize each keyshare as PublicKeyShare and extract pk0
    let mut pk0_shares = Vec::with_capacity(req.keyshare_bytes.len());
    for (i, ks_bytes) in req.keyshare_bytes.iter().enumerate() {
        let pk_share = PublicKeyShare::deserialize(ks_bytes, &threshold_params, crp.clone())
            .map_err(|e| {
                make_zk_error(&request, format!("keyshare[{}] deserialize: {:?}", i, e))
            })?;
        pk0_shares.push(CrtPolynomial::from_fhe_polynomial(&pk_share.p0_share()));
    }

    // 4. Deserialize aggregated PublicKey
    let public_key = PublicKey::from_bytes(&req.aggregated_pk_bytes, &threshold_params)
        .map_err(|e| make_zk_error(&request, format!("aggregated_pk deserialize: {:?}", e)))?;

    // 6. Build committee and circuit data
    let circuit_data = PkAggregationCircuitData {
        public_key,
        pk0_shares,
    };

    // C1 commitment consistency is verified by the PublicKeyAggregator before
    // dispatching this request (pre-aggregation check). By the time we reach
    // the prover, all keyshares are guaranteed to match their C1 proofs.

    // 7. C5 uses noir-recursive-no-zk (non-ZK recursive); it is verified inside `DkgAggregator` via
    // `verify_honk_proof_non_zk`. The EVM-facing proof for on-chain is `CircuitName::DkgAggregator`.
    let circuit = PkAggregationCircuit;
    let bb_work_id = zk_bb_work_id(&request);
    let committee =
        CiphernodesCommitteeSize::from_n_h(req.committee_n, req.committee_h).map_err(|e| {
            make_zk_error(
                &request,
                format!(
                    "unknown committee (n={}, h={}): {e}",
                    req.committee_n, req.committee_h
                ),
            )
        })?;
    if req.committee_threshold != committee.values().threshold {
        return Err(make_zk_error(
            &request,
            "C5 request threshold does not match its configured committee".into(),
        ));
    }
    let config =
        e3_zk_config::threshold::pk_aggregation::Configs::new(&threshold_params, committee)
            .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;
    let artifacts_dir = prover.resolve_artifacts_dir(req.params_preset, committee.as_str());
    let proof = circuit
        .prove_with_variant(
            prover,
            &config,
            &circuit_data,
            &bb_work_id,
            CircuitVariant::Default,
            &artifacts_dir,
        )
        .map_err(|e| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
                request.clone(),
            )
        })?;

    // 8. Return response
    Ok(ComputeResponse::zk(
        ZkResponse::PkAggregation(PkAggregationProofResponse { proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_threshold_share_decryption_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: ThresholdShareDecryptionProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // 1. Build threshold BFV parameters from preset
    let (threshold_params, _dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    let config = e3_zk_config::threshold::share_decryption::Configs::new(&threshold_params)
        .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;

    // Validate the published key at the request boundary, although C6 does not use it.
    PublicKey::from_bytes(&req.aggregated_pk_bytes, &threshold_params)
        .map_err(|e| make_zk_error(&request, format!("aggregated_pk deserialize: {:?}", e)))?;

    // 3. Decrypt sk_poly_sum → Poly → CrtPolynomial (s)
    let sk_poly = try_poly_from_sensitive_bytes(req.sk_poly_sum, threshold_params.clone(), cipher)
        .map_err(|e| make_zk_error(&request, format!("sk_poly_sum decrypt: {}", e)))?;
    let s = CrtPolynomial::from_fhe_polynomial(&sk_poly);

    // 4. For each index, build circuit data and generate proof
    let num_indices = req.ciphertext_bytes.len();
    if req.es_poly_sum.is_empty() {
        return Err(make_zk_error(&request, "empty es_poly_sum".to_string()));
    }
    if req.d_share_bytes.len() < num_indices {
        return Err(make_zk_error(
            &request,
            format!(
                "d_share_bytes too short: {} < {}",
                req.d_share_bytes.len(),
                num_indices
            ),
        ));
    }
    let mut proofs = Vec::with_capacity(num_indices);
    let bb_work_base = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let numeric_e3_id = request.e3_id.clone().try_into().map_err(|e| {
        make_zk_error(
            &request,
            format!("invalid numeric E3 id for decryption domain: {e}"),
        )
    })?;

    for i in 0..num_indices {
        // Deserialize ciphertext
        let ciphertext = Ciphertext::from_bytes(&req.ciphertext_bytes[i], &threshold_params)
            .map_err(|e| {
                make_zk_error(&request, format!("ciphertext[{}] deserialize: {:?}", i, e))
            })?;

        // Decrypt es_poly_sum → Poly → CrtPolynomial (e)
        // Currently there is a single smudging noise polynomial shared across all
        // ciphertexts (see calculate_decryption_share.rs).
        let es_idx = i % req.es_poly_sum.len();
        let e_poly = try_poly_from_sensitive_bytes(
            req.es_poly_sum[es_idx].clone(),
            threshold_params.clone(),
            cipher,
        )
        .map_err(|e| make_zk_error(&request, format!("es_poly_sum[{}] decrypt: {}", i, e)))?;
        let e = CrtPolynomial::from_fhe_polynomial(&e_poly);

        // Deserialize d_share → Poly → CrtPolynomial
        let d_share_poly = try_poly_pb_from_bytes(&req.d_share_bytes[i], &threshold_params)
            .map_err(|e| make_zk_error(&request, format!("d_share[{}] deserialize: {}", i, e)))?;
        let d_share = CrtPolynomial::from_fhe_polynomial(&d_share_poly);
        let domain = e3_committee_hash::decryption_domain_limbs(
            request.e3_id.chain_id(),
            numeric_e3_id,
            req.decryption_domain,
            keccak256(&req.ciphertext_bytes[i][..]),
        );

        // Build circuit data
        let circuit_data = e3_zk_witness::threshold::share_decryption::ShareDecryptionCircuitData {
            ciphertext,
            s: s.clone(),
            e,
            d_share,
            domain_hi: domain.hi,
            domain_lo: domain.lo,
        };

        // Generate proof
        let circuit = crate::ThresholdShareDecryptionCircuit;
        let idx_work_id = format!("{bb_work_base}_c6_{i}");
        let proof = circuit
            .prove(prover, &config, &circuit_data, &idx_work_id, &artifacts_dir)
            .map_err(|e| {
                ComputeRequestError::new(
                    ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(format!(
                        "C6 proof[{}]: {}",
                        i, e
                    ))),
                    request.clone(),
                )
            })?;

        proofs.push(proof);
    }

    Ok(ComputeResponse::zk(
        ZkResponse::ThresholdShareDecryption(ThresholdShareDecryptionProofResponse { proofs }),
        request.correlation_id,
        request.e3_id,
    ))
}

#[cfg(test)]
mod threshold_share_decryption_tests {
    use super::*;
    use e3_crypto::SensitiveBytes;
    use e3_events::CorrelationId;
    use fhe::bfv::SecretKey;
    use fhe_traits::Serialize;

    #[actix::test]
    async fn c6_validates_the_published_key_before_reading_secret_witnesses() {
        let cipher = Cipher::from_password("test-password").await.unwrap();
        let preset = BfvPreset::InsecureThreshold64;
        let (params, _) = preset.build_pair().unwrap();
        let sk = SecretKey::random(&params, &mut rand::rng());
        let valid_pk = PublicKey::new(&sk, &mut rand::rng()).to_bytes();
        // No proof path can be reached: even the valid-key control has an invalid secret polynomial.
        let unused = std::path::PathBuf::from("unused-c6-boundary-test");
        let prover = ZkProver::new(&ZkBackend {
            base_dir: unused.clone(),
            bb_binary: unused.clone(),
            circuits_dir: unused.clone(),
            work_dir: unused,
            config: Default::default(),
            using_custom_bb: true,
            bb_timeout: Duration::from_secs(1),
        });
        for (key, expected_error) in [
            (vec![], "aggregated_pk deserialize"),
            (
                valid_pk[..valid_pk.len() / 2].to_vec(),
                "aggregated_pk deserialize",
            ),
            (valid_pk, "sk_poly_sum decrypt"),
        ] {
            let req = ThresholdShareDecryptionProofRequest {
                ciphertext_bytes: vec![],
                aggregated_pk_bytes: e3_utils::utility_types::ArcBytes::from_bytes(&key),
                sk_poly_sum: SensitiveBytes::new(vec![], &cipher).unwrap(),
                es_poly_sum: vec![],
                d_share_bytes: vec![],
                decryption_domain: e3_committee_hash::DecryptionDomainContext {
                    interfold_address: Default::default(),
                    committee_hash: Default::default(),
                    committee_public_key: Default::default(),
                },
                params_preset: preset,
                committee_size: CiphernodesCommitteeSize::Minimum,
            };
            let request = ComputeRequest::zk(
                ZkRequest::ThresholdShareDecryption(req.clone()),
                CorrelationId::new(),
                E3id::new("7", 1),
            );
            let error =
                execute_zk_request(&prover, &cipher, request.clone(), &mut |_| {}).unwrap_err();
            assert!(
                format!("{:?}", error.get_err()).contains(expected_error),
                "{error:?}"
            );
            assert_eq!(error.request(), &request);
        }
    }
}

fn handle_node_dkg_fold_proof(
    prover: &ZkProver,
    req: NodeDkgFoldRequest,
    request: ComputeRequest,
    record_step: &mut dyn FnMut(FoldProveStepTiming),
) -> Result<ComputeResponse, ComputeRequestError> {
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let job_id = zk_bb_work_id(&request);
    let input = NodeDkgFoldInput {
        c0_proof: &req.c0_proof,
        c1_proof: &req.c1_proof,
        c2a_proof: &req.c2a_proof,
        c2b_proof: &req.c2b_proof,
        c3a_inner_proofs: &req.c3a_inner_proofs,
        c3b_inner_proofs: &req.c3b_inner_proofs,
        c3_slot_indices_a: &req.c3_slot_indices_a,
        c3_slot_indices_b: &req.c3_slot_indices_b,
        c3_total_slots: req.c3_total_slots,
        c4a_proof: &req.c4a_proof,
        c4b_proof: &req.c4b_proof,
        party_id: req.party_id,
    };
    let NodeDkgFoldProveResult {
        proof,
        step_timings,
    } = prove_node_dkg_fold(prover, &input, &job_id, &artifacts_dir).map_err(|e| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
            request.clone(),
        )
    })?;
    for step in step_timings {
        record_step(step);
    }
    Ok(ComputeResponse::zk(
        ZkResponse::NodeDkgFold(NodeDkgFoldResponse { proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_nodes_fold_step_proof(
    prover: &ZkProver,
    req: NodesFoldStepRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let accumulator_proof = generate_nodes_fold_step(
        prover,
        &req.inner_proof,
        req.prior_accumulator.as_ref(),
        req.slot_index,
        req.total_slots,
        &format!("{}-nodesfold-step-{}", req.e3_id, req.slot_index),
        artifacts_dir.as_str(),
    )
    .map_err(|e| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::NodesFoldStep(NodesFoldStepResponse { accumulator_proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_dkg_aggregation_proof(
    prover: &ZkProver,
    req: DkgAggregationRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    let job_id = zk_bb_work_id(&request);
    let input = DkgAggregationInput {
        node_fold_proofs: &req.node_fold_proofs,
        nodes_fold_proof: req.nodes_fold_proof.as_ref(),
        c5_proof: &req.c5_proof,
        party_ids: &req.party_ids,
        committee_addresses: &req.committee_addresses,
    };
    let proof = prove_dkg_aggregation(
        prover,
        &input,
        &job_id,
        req.params_preset,
        req.committee_size,
    )
    .map_err(|e| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::DkgAggregation(DkgAggregationResponse { proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_decryption_aggregation_proof(
    prover: &ZkProver,
    req: DecryptionAggregationRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    let job_id = zk_bb_work_id(&request);
    let jobs: Vec<DecryptionAggregationJob> = req
        .jobs
        .iter()
        .map(|j| DecryptionAggregationJob {
            c6_inner_proofs: &j.c6_inner_proofs,
            c6_slot_indices: &j.c6_slot_indices,
            c7_proof: &j.c7_proof,
        })
        .collect();
    let proofs = prove_decryption_aggregation_jobs(
        prover,
        req.c6_total_slots,
        &jobs,
        &req.committee_addresses,
        &job_id,
        req.params_preset,
        req.committee_size,
    )
    .map_err(|e| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::DecryptionAggregation(DecryptionAggregationResponse { proofs }),
        request.correlation_id,
        request.e3_id,
    ))
}

/// Helper to reduce boilerplate for ZK errors
fn make_zk_error(request: &ComputeRequest, msg: String) -> ComputeRequestError {
    ComputeRequestError::new(
        ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(msg)),
        request.clone(),
    )
}

/// Barretenberg work subdirectory under `work_dir`: must be unique for concurrent jobs that share
/// the same [`e3_events::E3id`] (e.g. three ciphernodes proving C0 in parallel).
///
/// Avoids `:` (from [`E3id`]'s `Display`) and `/` in path segments — some platforms / tooling are
/// picky about those in directory names.
fn zk_bb_work_id(request: &ComputeRequest) -> String {
    format!("{}_{}", request.e3_id, request.correlation_id)
        .chars()
        .map(|c| match c {
            ':' | '/' | '\\' => '_',
            c => c,
        })
        .collect()
}

fn handle_share_computation_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: ShareComputationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // 1. Build BFV threshold parameters
    let (threshold_params, _dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    let config = e3_zk_config::dkg::share_computation::Configs::new(
        req.params_preset,
        &threshold_params,
        req.committee_size,
    )
    .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;

    // 2. Decrypt sensitive witness fields
    let secret_bytes = req
        .secret_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("secret_raw decrypt: {}", e)))?;
    let secret_sss_bytes = req
        .secret_sss_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("secret_sss_raw decrypt: {}", e)))?;

    // 3. Deserialize secret polynomial
    let secret_poly = try_poly_pb_from_bytes(&secret_bytes, &threshold_params)
        .map_err(|e| make_zk_error(&request, format!("secret_raw: {}", e)))?;
    let mut secret = CrtPolynomial::from_fhe_polynomial(&secret_poly);
    if req.dkg_input_type == DkgInputType::SecretKey {
        secret
            .center(threshold_params.moduli())
            .map_err(|e| make_zk_error(&request, format!("Failed to center polynomial: {}", e)))?;
    }

    // 4. Deserialize Shamir shares (bincode-encoded SharedSecret)
    let shared_secret: SharedSecret = bincode::deserialize(&secret_sss_bytes)
        .map_err(|e| make_zk_error(&request, format!("secret_sss_raw deserialize: {}", e)))?;

    // Convert Vec<Array2<u64>> → Vec<Array2<BigInt>>
    let secret_sss: Vec<Array2<BigInt>> = shared_secret
        .moduli_data()
        .iter()
        .map(|arr| arr.mapv(BigInt::from))
        .collect();

    // 5. Build circuit data; the compiled Noir config contains the parity matrix.
    let circuit_data = ShareComputationCircuitData {
        dkg_input_type: req.dkg_input_type,
        secret,
        secret_sss,
    };

    let bb_work = zk_bb_work_id(&request);
    let inner_job_id = format!("{bb_work}_c2_inner");
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());

    // 7. Inner C2 proof (sk_share_computation or e_sm_share_computation)
    let circuit = ShareComputationCircuit;
    let proof = circuit
        .prove(
            prover,
            &config,
            &circuit_data,
            &inner_job_id,
            &artifacts_dir,
        )
        .map_err(|e| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
                request.clone(),
            )
        })?;

    Ok(ComputeResponse::zk(
        ZkResponse::ShareComputation(ShareComputationProofResponse {
            proof,
            dkg_input_type: req.dkg_input_type,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_pk_generation_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: PkGenerationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // 1. Build BFV parameters from the threshold preset
    let params = BfvParamSet::from(req.params_preset).build_arc();

    let config = e3_zk_config::threshold::pk_generation::Configs::new(
        req.params_preset,
        &params,
        req.committee_size,
    )
    .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;

    // 2. Decrypt sensitive witness fields
    let sk_bytes = req
        .sk
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("sk decrypt: {}", e)))?;
    let eek_bytes = req
        .eek
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("eek decrypt: {}", e)))?;
    let e_sm_bytes = req
        .e_sm
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("e_sm decrypt: {}", e)))?;

    // 3. Deserialize raw polynomial bytes → Poly
    let pk0_share_poly = try_poly_ntt_from_bytes(&req.pk0_share, &params)
        .map_err(|e| make_zk_error(&request, format!("pk0_share: {}", e)))?;

    let sk_poly = try_poly_pb_from_bytes(&sk_bytes, &params)
        .map_err(|e| make_zk_error(&request, format!("sk: {}", e)))?;

    let eek_poly = try_poly_ntt_from_bytes(&eek_bytes, &params)
        .map_err(|e| make_zk_error(&request, format!("eek: {}", e)))?;

    let e_sm_poly = try_poly_pb_from_bytes(&e_sm_bytes, &params)
        .map_err(|e| make_zk_error(&request, format!("e_sm: {}", e)))?;

    // 3. Convert Poly → CrtPolynomial
    let pk0_share = CrtPolynomial::from_fhe_polynomial(&pk0_share_poly);
    let sk = CrtPolynomial::from_fhe_polynomial(&sk_poly);
    let eek = CrtPolynomial::from_fhe_polynomial(&eek_poly);
    let e_sm = CrtPolynomial::from_fhe_polynomial(&e_sm_poly);
    let e_sm_lifted = Polynomial::from_fhe_polynomial(&e_sm_poly);

    // 4. Build circuit data
    let circuit_data = PkGenerationCircuitData {
        pk0_share,
        eek,
        e_sm,
        e_sm_lifted,
        sk,
    };

    // 5. Generate proof via Provable trait
    let circuit = PkGenerationCircuit;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());

    let proof = circuit
        .prove(prover, &config, &circuit_data, &bb_work, &artifacts_dir)
        .map_err(|e| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
                request.clone(),
            )
        })?;

    Ok(ComputeResponse::zk(
        ZkResponse::PkGeneration(PkGenerationProofResponse::new(proof)),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_pk_bfv_proof(
    prover: &ZkProver,
    req: PkBfvProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // NOTE: req.params_preset is expected to contain a DKG preset (e.g., InsecureDkg64)
    // because the proof is for the DKG circuit. This preset is converted to BFV parameters.
    let params = BfvParamSet::from(req.params_preset).build_arc();

    let config = e3_zk_config::dkg::pk::Configs::new(&params)
        .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;
    let pk_bfv = PublicKey::from_bytes(&req.pk_bfv, &params).map_err(|e| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(format!(
                "Failed to deserialize pk_bfv: {:?}",
                e
            ))),
            request.clone(),
        )
    })?;

    let circuit = PkCircuit;
    let circuit_data = pk_bfv;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = circuit
        .prove(prover, &config, &circuit_data, &bb_work, &artifacts_dir)
        .map_err(|e| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
                request.clone(),
            )
        })?;

    Ok(ComputeResponse::zk(
        ZkResponse::PkBfv(PkBfvProofResponse::new(proof)),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_share_encryption_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: ShareEncryptionProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // 1. Build DKG params from threshold preset
    let (_threshold_params, dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    let config = e3_zk_config::dkg::share_encryption::Configs::new(&dkg_params)
        .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;

    // 2. Decrypt sensitive witness data
    let share_row_bytes = req
        .share_row_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("share_row decrypt: {}", e)))?;
    let u_rns_bytes = req
        .u_rns_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("u_rns decrypt: {}", e)))?;
    let e0_rns_bytes = req
        .e0_rns_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("e0_rns decrypt: {}", e)))?;
    let e1_rns_bytes = req
        .e1_rns_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("e1_rns decrypt: {}", e)))?;

    // 3. Deserialize share row and re-encode as Plaintext
    let share_row: Vec<u64> = bincode::deserialize(&share_row_bytes)
        .map_err(|e| make_zk_error(&request, format!("share_row: {}", e)))?;
    let plaintext = Plaintext::try_encode(&share_row, Encoding::poly(), &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("plaintext encode: {:?}", e)))?;

    // 4. Deserialize ciphertext, public key, polys using DKG params
    let ciphertext = Ciphertext::from_bytes(&req.ciphertext_raw, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("ciphertext: {:?}", e)))?;
    let public_key = PublicKey::from_bytes(&req.recipient_pk_raw, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("recipient_pk: {:?}", e)))?;
    let u_rns = try_poly_ntt_from_bytes(&u_rns_bytes, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("u_rns: {}", e)))?;
    let e0_rns = try_poly_ntt_from_bytes(&e0_rns_bytes, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("e0_rns: {}", e)))?;
    let e1_rns = try_poly_ntt_from_bytes(&e1_rns_bytes, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("e1_rns: {}", e)))?;

    // 5. Build circuit data
    let circuit_data = ShareEncryptionCircuitData {
        plaintext,
        ciphertext,
        public_key,
        u_rns,
        e0_rns,
        e1_rns,
    };

    // 6. Generate proof (preset = threshold preset; Inputs::compute derives DKG internally)
    let circuit = ShareEncryptionCircuit;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = circuit
        .prove(prover, &config, &circuit_data, &bb_work, &artifacts_dir)
        .map_err(|e| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
                request.clone(),
            )
        })?;

    Ok(ComputeResponse::zk(
        ZkResponse::ShareEncryption(ShareEncryptionProofResponse {
            proof,
            dkg_input_type: req.dkg_input_type,
            recipient_party_id: req.recipient_party_id,
            row_index: req.row_index,
            esi_index: req.esi_index,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_dkg_share_decryption_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: DkgShareDecryptionProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    let (threshold_params, dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    let config = e3_zk_config::dkg::share_decryption::Configs::new(&threshold_params, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;

    let sk_bytes = req
        .sk_bfv
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("sk_bfv decrypt: {}", e)))?;
    let secret_key = deserialize_secret_key(&sk_bytes, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("sk_bfv deserialize: {}", e)))?;

    // Selected parties omit a ciphertext only for their own share.
    let h = req.num_honest_parties;
    let l = req.num_moduli;
    if req.own_plaintext_idx.is_some() != req.own_share_raw.is_some() {
        return Err(make_zk_error(
            &request,
            "own_plaintext_idx and own_share_raw must both be present or absent".to_string(),
        ));
    }
    if req.own_plaintext_idx.is_some_and(|idx| idx >= h) {
        return Err(make_zk_error(
            &request,
            format!(
                "own_plaintext_idx {:?} out of range (num_honest_parties={})",
                req.own_plaintext_idx, h
            ),
        ));
    }
    let num_external = h - usize::from(req.own_plaintext_idx.is_some());
    let expected_external_cts = num_external * l;
    if req.honest_ciphertexts_raw.len() != expected_external_cts {
        return Err(make_zk_error(
            &request,
            format!(
                "Expected {} external ciphertexts ({} parties * L={}), got {}",
                expected_external_cts,
                num_external,
                l,
                req.honest_ciphertexts_raw.len()
            ),
        ));
    }

    // Deserialize external ciphertexts in selected-party order.
    let mut external_ciphertexts: Vec<Vec<Ciphertext>> = Vec::with_capacity(num_external);
    for ext_idx in 0..num_external {
        let mut party_cts = Vec::with_capacity(l);
        for mod_idx in 0..l {
            let raw = &req.honest_ciphertexts_raw[ext_idx * l + mod_idx];
            let ct = Ciphertext::from_bytes(raw, &dkg_params).map_err(|e| {
                make_zk_error(
                    &request,
                    format!("ciphertext[{}][{}] deserialize: {:?}", ext_idx, mod_idx, e),
                )
            })?;
            party_cts.push(ct);
        }
        external_ciphertexts.push(party_cts);
    }

    // Use a plaintext slot only when the prover is one of the selected dealers.
    let mut honest_ciphertexts: Vec<Option<Vec<Ciphertext>>> = Vec::with_capacity(h);
    let mut external_iter = external_ciphertexts.into_iter();
    for slot in 0..h {
        if Some(slot) == req.own_plaintext_idx {
            honest_ciphertexts.push(None);
        } else {
            honest_ciphertexts.push(Some(
                external_iter
                    .next()
                    .expect("external_iter exhausted: lengths validated above"),
            ));
        }
    }

    let own_plaintext_share: Vec<Vec<u64>> = if let Some(raw) = req.own_share_raw.as_ref() {
        let own_share_bytes = raw
            .access_raw(cipher)
            .map_err(|e| make_zk_error(&request, format!("own_share decrypt: {}", e)))?;
        let share: Vec<Vec<u64>> = bincode::deserialize(&own_share_bytes)
            .map_err(|e| make_zk_error(&request, format!("own_share deserialize: {}", e)))?;
        if share.len() != l {
            return Err(make_zk_error(
                &request,
                format!(
                    "own_plaintext_share has {} moduli, expected {}",
                    share.len(),
                    l
                ),
            ));
        }
        share
    } else {
        Vec::new()
    };
    let n = dkg_params.degree();
    for (row_idx, row) in own_plaintext_share.iter().enumerate() {
        if row.len() != n {
            return Err(make_zk_error(
                &request,
                format!(
                    "own_plaintext_share[{}] has {} coefficients, expected {}",
                    row_idx,
                    row.len(),
                    n
                ),
            ));
        }
    }

    let circuit_data = ShareDecryptionCircuitData {
        secret_key,
        honest_ciphertexts,
        own_plaintext_share,
    };

    let circuit = ShareDecryptionCircuit;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = circuit
        .prove(prover, &config, &circuit_data, &bb_work, &artifacts_dir)
        .map_err(|e| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(e.to_string())),
                request.clone(),
            )
        })?;

    Ok(ComputeResponse::zk(
        ZkResponse::DkgShareDecryption(DkgShareDecryptionProofResponse {
            proof,
            dkg_input_type: req.dkg_input_type,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

/// ZK-verify a share proof (inner recursive circuits).
fn zk_verify_share_proof_bundle(
    prover: &ZkProver,
    proof: &Proof,
    e3_id_str: &str,
    party_id: u64,
    artifacts_dir: &str,
) -> Result<bool, ZkError> {
    prover.verify_proof(proof, e3_id_str, party_id, artifacts_dir)
}

fn handle_verify_share_proofs(
    prover: &ZkProver,
    req: VerifyShareProofsRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    let e3_id_str = request.e3_id.to_string();
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());

    // ECDSA validation (signature recovery, signer consistency, e3_id match)
    // is handled by ShareVerificationActor before dispatching to multithread.
    // This function performs ZK-only proof verification.
    let mut party_results = Vec::with_capacity(req.party_proofs.len());
    for party in req.party_proofs {
        let sender = party.sender_party_id;
        let mut party_result = PartyVerificationResult {
            sender_party_id: sender,
            all_verified: true,
            failed_signed_payload: None,
            recovered_address: None,
        };

        for signed_proof in &party.signed_proofs {
            // 1. Validate CircuitName matches expected circuits for this ProofType.
            let expected_circuits = signed_proof.payload.proof_type.circuit_names();
            if !expected_circuits.contains(&signed_proof.payload.proof.circuit) {
                info!(
                    "Circuit name mismatch for party {} ({:?}): expected {:?}, got {:?}",
                    sender,
                    signed_proof.payload.proof_type,
                    expected_circuits,
                    signed_proof.payload.proof.circuit
                );
                party_result.all_verified = false;
                party_result.failed_signed_payload = Some(signed_proof.clone());
                break;
            }

            // 2. A cryptographically invalid proof returns `Ok(false)`. A verifier process
            // failure is local infrastructure failure and must not accuse the proof sender.
            let proof = &signed_proof.payload.proof;
            match zk_verify_share_proof_bundle(prover, proof, &e3_id_str, sender, &artifacts_dir) {
                Ok(true) => {}
                Ok(false) => {
                    info!(
                        "ZK proof verification failed for party {} ({:?})",
                        sender, signed_proof.payload.proof_type
                    );
                    party_result.all_verified = false;
                    party_result.failed_signed_payload = Some(signed_proof.clone());
                    break;
                }
                Err(error) => {
                    return Err(ComputeRequestError::new(
                        ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(format!(
                            "proof verifier process failed for party {sender} ({:?}): {error}",
                            signed_proof.payload.proof_type
                        ))),
                        request.clone(),
                    ));
                }
            }
        }
        party_results.push(party_result);
    }

    Ok(ComputeResponse::zk(
        ZkResponse::VerifyShareProofs(VerifyShareProofsResponse { party_results }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_verify_share_decryption_proofs(
    prover: &ZkProver,
    req: VerifyShareDecryptionProofsRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    let e3_id_str = request.e3_id.to_string();
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());

    // ECDSA validation (signature recovery, signer consistency, e3_id match)
    // is handled by ShareVerificationActor before dispatching to multithread.
    // This function performs ZK-only proof verification.
    let mut party_results = Vec::with_capacity(req.party_proofs.len());
    for party in req.party_proofs {
        let sender = party.sender_party_id;

        // Guard: an empty ESM proof list would make verification vacuously true.
        if party.signed_e_sm_decryption_proofs.is_empty() {
            party_results.push(PartyVerificationResult {
                sender_party_id: sender,
                all_verified: false,
                failed_signed_payload: None,
                recovered_address: None,
            });
            continue;
        }

        let all_signed: Vec<&e3_events::SignedProofPayload> =
            std::iter::once(&party.signed_sk_decryption_proof)
                .chain(party.signed_e_sm_decryption_proofs.iter())
                .collect();
        let mut party_result = PartyVerificationResult {
            sender_party_id: sender,
            all_verified: true,
            failed_signed_payload: None,
            recovered_address: None,
        };

        for signed_proof in all_signed {
            let expected_circuits = signed_proof.payload.proof_type.circuit_names();
            if !expected_circuits.contains(&signed_proof.payload.proof.circuit) {
                info!(
                    "C4 circuit mismatch for party {}: expected {:?}, got {:?}",
                    sender, expected_circuits, signed_proof.payload.proof.circuit
                );
                party_result.all_verified = false;
                party_result.failed_signed_payload = Some(signed_proof.clone());
                break;
            }

            let proof = &signed_proof.payload.proof;
            match prover.verify_proof(proof, &e3_id_str, sender, &artifacts_dir) {
                Ok(true) => {}
                Ok(false) => {
                    info!(
                        "C4 ZK proof verification failed for party {} ({:?})",
                        sender, signed_proof.payload.proof_type
                    );
                    party_result.all_verified = false;
                    party_result.failed_signed_payload = Some(signed_proof.clone());
                    break;
                }
                Err(error) => {
                    return Err(ComputeRequestError::new(
                        ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(format!(
                            "C4 verifier process failed for party {sender} ({:?}): {error}",
                            signed_proof.payload.proof_type
                        ))),
                        request.clone(),
                    ));
                }
            }
        }
        party_results.push(party_result);
    }

    Ok(ComputeResponse::zk(
        ZkResponse::VerifyShareDecryptionProofs(VerifyShareDecryptionProofsResponse {
            party_results,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_decrypted_shares_aggregation_proof(
    prover: &ZkProver,
    mut req: DecryptedSharesAggregationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    // 1. Build threshold BFV parameters from preset
    let (threshold_params, _dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    let config = e3_zk_config::threshold::decrypted_shares_aggregation::Configs::new(
        &threshold_params,
        req.committee_size,
    )
    .map_err(|e| make_zk_error(&request, format!("circuit configuration: {e}")))?;

    if (req.threshold_m as usize, req.threshold_n as usize)
        != (
            config.committee.values().threshold,
            config.committee.values().n,
        )
    {
        return Err(make_zk_error(
            &request,
            "C7 request threshold does not match its configured committee".into(),
        ));
    }

    // 2. Sort d_share_polys by party ID — the Noir circuit requires
    //    party_ids in strictly increasing order for Lagrange sign computation.
    req.d_share_polys.sort_by_key(|(id, _)| *id);

    // 3. The circuit expects exactly threshold + 1 shares for Lagrange interpolation.
    //    We may have more honest parties than needed, so take the first threshold + 1.
    let required = req.threshold_m as usize + 1;
    if req.d_share_polys.len() > required {
        req.d_share_polys.truncate(required);
    }

    // 4. Determine dimensions
    let num_indices = req.plaintext.len();

    for (party_id, shares) in &req.d_share_polys {
        if shares.len() < num_indices {
            return Err(make_zk_error(
                &request,
                format!(
                    "party {} has {} shares but {} expected",
                    party_id,
                    shares.len(),
                    num_indices
                ),
            ));
        }
    }

    let mut proofs = Vec::with_capacity(num_indices);

    // 4. For each ciphertext index, build circuit data and generate proof
    for i in 0..num_indices {
        // a. Extract per-party shares for index i, deserialize to Poly
        let d_share_polys: Vec<fhe_math::rq::Poly<PowerBasis>> = req
            .d_share_polys
            .iter()
            .map(|(_, shares)| try_poly_pb_from_bytes(&shares[i], &threshold_params))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| {
                make_zk_error(&request, format!("d_share_polys[{}] deserialize: {}", i, e))
            })?;

        // b. Get party IDs (convert 0-based to 1-based for circuit)
        let reconstructing_parties: Vec<usize> = req
            .d_share_polys
            .iter()
            .map(|(id, _)| (*id as usize) + 1)
            .collect();

        // c. Decode plaintext at index i to Vec<u64>
        let message_vec = e3_bfv_client::decode_bytes_to_vec_u64(&req.plaintext[i].extract_bytes())
            .map_err(|e| make_zk_error(&request, format!("plaintext[{}] decode: {:?}", i, e)))?;

        // e. C7 uses noir-recursive-no-zk (non-ZK recursive); it is verified inside
        // `DecryptionAggregator` via `verify_honk_proof_non_zk`. The EVM-facing proof for on-chain
        // is `CircuitName::DecryptionAggregator`.
        let circuit_data = DecryptedSharesAggregationCircuitData {
            d_share_polys,
            reconstructing_parties,
            message_vec,
        };

        let circuit = DecryptedSharesAggregationCircuit;
        let idx_work_id = format!("{}_c7_{}", zk_bb_work_id(&request), i);
        let artifacts_dir = req
            .params_preset
            .artifacts_dir_for_committee(req.committee_size.as_str());
        let proof = circuit
            .prove_with_variant(
                prover,
                &config,
                &circuit_data,
                &idx_work_id,
                CircuitVariant::Default,
                &artifacts_dir,
            )
            .map_err(|e| {
                ComputeRequestError::new(
                    ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(format!(
                        "C7 proof[{}]: {}",
                        i, e
                    ))),
                    request.clone(),
                )
            })?;
        proofs.push(proof);
    }

    // 5. Return response
    Ok(ComputeResponse::zk(
        ZkResponse::DecryptedSharesAggregation(DecryptedSharesAggregationProofResponse { proofs }),
        request.correlation_id,
        request.e3_id,
    ))
}

#[cfg(test)]
mod aggregation_request_tests {
    use super::*;
    use e3_events::CorrelationId;
    use e3_utils::utility_types::ArcBytes;
    use fhe_traits::Serialize;

    #[test]
    fn aggregation_requests_reject_mismatched_thresholds_without_proof_tools() {
        use fhe::bfv::SecretKey;
        use fhe::mbfv::AggregateIter;
        use rand::SeedableRng;

        let temp = crate::test_utils::get_tempdir().unwrap();
        let prover = ZkProver::new(&ZkBackend {
            base_dir: temp.path().to_owned(),
            bb_binary: temp.path().join("absent-bb"),
            circuits_dir: temp.path().join("absent-circuits"),
            work_dir: temp.path().join("work"),
            config: Default::default(),
            using_custom_bb: true,
            bb_timeout: Duration::from_secs(1),
        });
        let preset = BfvPreset::InsecureThreshold64;
        let (params, _) = build_pair_for_preset(preset).unwrap();
        let crp = create_deterministic_crp_from_default_seed(&params);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        for size in [
            CiphernodesCommitteeSize::Minimum,
            CiphernodesCommitteeSize::Micro,
        ] {
            let committee = size.values();
            let shares: Vec<_> = (0..committee.h)
                .map(|_| {
                    let secret = SecretKey::random(&params, &mut rng);
                    PublicKeyShare::new(&secret, crp.clone(), &mut rng).unwrap()
                })
                .collect();
            let keyshare_bytes = shares
                .iter()
                .map(|share| ArcBytes::from_bytes(&share.to_bytes()))
                .collect();
            let public: PublicKey = shares.into_iter().aggregate().unwrap();
            let mut req = PkAggregationProofRequest {
                keyshare_bytes,
                aggregated_pk_bytes: ArcBytes::from_bytes(&public.to_bytes()),
                params_preset: preset,
                committee_n: committee.n,
                committee_h: committee.h,
                committee_threshold: committee.threshold,
            };
            let request = ComputeRequest::zk(
                ZkRequest::PkAggregation(req.clone()),
                CorrelationId::new(),
                E3id::new("threshold-guard", 1),
            );
            let accepted =
                handle_pk_aggregation_proof(&prover, req.clone(), request.clone()).unwrap_err();
            assert!(
                matches!(accepted.get_err(), ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(message)) if message.contains(&format!("insecure-64/{size}/default/threshold/pk_aggregation/pk_aggregation.json"))),
                "{accepted:?}"
            );
            req.committee_threshold += 1;
            let rejected = handle_pk_aggregation_proof(&prover, req, request.clone()).unwrap_err();
            assert!(format!("{:?}", rejected.get_err()).contains("C5 request threshold"));
            assert_eq!(rejected.request(), &request);

            let req = DecryptedSharesAggregationProofRequest {
                d_share_polys: vec![],
                plaintext: vec![],
                params_preset: preset,
                threshold_m: committee.threshold as u64,
                threshold_n: committee.n as u64,
                committee_size: size,
            };
            let request = ComputeRequest::zk(
                ZkRequest::DecryptedSharesAggregation(req.clone()),
                CorrelationId::new(),
                E3id::new("threshold-guard", 1),
            );
            // A zero-ciphertext batch isolates admission from proof generation.
            handle_decrypted_shares_aggregation_proof(&prover, req.clone(), request.clone())
                .unwrap();
            for (index, mut mismatch) in [req.clone(), req].into_iter().enumerate() {
                if index == 0 {
                    mismatch.threshold_m += 1;
                } else {
                    mismatch.threshold_n += 1;
                }
                let rejected =
                    handle_decrypted_shares_aggregation_proof(&prover, mismatch, request.clone())
                        .unwrap_err();
                assert!(format!("{:?}", rejected.get_err()).contains("C7 request threshold"));
                assert_eq!(rejected.request(), &request);
            }
        }
    }

    #[test]
    #[ignore = "requires E3_TEST_ARTIFACTS_ROOT insecure-64/small artifacts and E3_CUSTOM_BB"]
    fn local_small_c7_request_proves_ten_shares_with_the_canonical_committee() {
        let committee_size = CiphernodesCommitteeSize::Small;
        let committee = committee_size.values();
        assert_eq!(committee.threshold + 1, 10);
        assert_eq!(committee.h, 14);
        let params_preset = BfvPreset::InsecureThreshold64;
        let (params, _) = params_preset.build_pair().unwrap();
        let zero = fhe_math::rq::Poly::<PowerBasis>::zero(params.context_at_level(0).unwrap());
        let bytes = ArcBytes::from_bytes(&zero.to_bytes());
        let req = DecryptedSharesAggregationProofRequest {
            d_share_polys: (0..10).rev().map(|id| (id, vec![bytes.clone()])).collect(),
            plaintext: vec![ArcBytes::from_bytes(
                &e3_bfv_client::encode_vec_u64_to_bytes(&[0]),
            )],
            params_preset,
            threshold_m: committee.threshold as u64,
            threshold_n: committee.n as u64,
            committee_size,
        };
        let request = ComputeRequest::zk(
            ZkRequest::DecryptedSharesAggregation(req.clone()),
            CorrelationId::new(),
            E3id::new("7", 1),
        );
        let work = crate::test_utils::workspace_root()
            .join(format!("target/small-c7-runtime-{}", std::process::id()));
        let prover = ZkProver::new(&ZkBackend {
            base_dir: work.clone(),
            bb_binary: std::env::var_os("E3_CUSTOM_BB")
                .expect("set E3_CUSTOM_BB")
                .into(),
            circuits_dir: std::env::var_os("E3_TEST_ARTIFACTS_ROOT")
                .expect("set E3_TEST_ARTIFACTS_ROOT")
                .into(),
            work_dir: work,
            config: Default::default(),
            using_custom_bb: true,
            bb_timeout: Duration::from_secs(120),
        });
        let response =
            handle_decrypted_shares_aggregation_proof(&prover, req.clone(), request.clone())
                .unwrap();
        assert_eq!(response.correlation_id, request.correlation_id);
        assert_eq!(response.e3_id, request.e3_id);
        let ZkResponse::DecryptedSharesAggregation(result) = response.try_into_zk().unwrap() else {
            panic!("wrong C7 response");
        };
        assert_eq!(result.proofs.len(), 1);
        let artifacts = params_preset.artifacts_dir_for_committee(committee_size.as_str());
        assert!(DecryptedSharesAggregationCircuit
            .verify_with_variant(
                &prover,
                &result.proofs[0],
                "small-c7-runtime",
                0,
                CircuitVariant::Default,
                &artifacts
            )
            .unwrap());
    }
}
