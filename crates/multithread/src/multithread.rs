// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::report::MultithreadReport;
use crate::report::TrackDuration;
use crate::TaskPool;
use crate::TaskTimeouts;
use actix::prelude::*;
use actix::{Actor, Handler};
use anyhow::Result;
use e3_crypto::Cipher;
use e3_events::run_once;
use e3_events::trap_fut;

use e3_events::EType;
use e3_events::EffectsEnabled;
use e3_events::{
    BusHandle, ComputeRequest, ComputeRequestError, ComputeRequestErrorKind, ComputeRequestKind,
    ComputeResponse, DecryptedSharesAggregationProofRequest,
    DecryptedSharesAggregationProofResponse, DecryptionAggregationRequest,
    DecryptionAggregationResponse, DkgAggregationRequest, DkgAggregationResponse,
    DkgShareDecryptionProofRequest, DkgShareDecryptionProofResponse, EventPublisher,
    EventSubscriber, EventType, InterfoldEvent, InterfoldEventData, NodeDkgFoldRequest,
    NodeDkgFoldResponse, NodesFoldStepRequest, NodesFoldStepResponse, PartyVerificationResult,
    PkAggregationProofRequest, PkAggregationProofResponse, PkBfvProofRequest, PkBfvProofResponse,
    PkGenerationProofRequest, PkGenerationProofResponse, Proof, ShareComputationProofRequest,
    ShareComputationProofResponse, ShareEncryptionProofRequest, ShareEncryptionProofResponse,
    ThresholdShareDecryptionProofRequest, ThresholdShareDecryptionProofResponse, TypedEvent,
    VerifyShareDecryptionProofsRequest, VerifyShareDecryptionProofsResponse,
    VerifyShareProofsRequest, VerifyShareProofsResponse, ZkError as ZkEventError, ZkRequest,
    ZkResponse,
};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_polynomial::CrtPolynomial;
use e3_trbfv::calculate_decryption_key::calculate_decryption_key;
use e3_trbfv::calculate_decryption_share::calculate_decryption_share;
use e3_trbfv::calculate_threshold_decryption::calculate_threshold_decryption;
use e3_trbfv::gen_esi_sss::gen_esi_sss;
use e3_trbfv::gen_pk_share_and_sk_sss::gen_pk_share_and_sk_sss;
use e3_trbfv::helpers::deserialize_secret_key;
use e3_trbfv::helpers::try_poly_from_sensitive_bytes;
use e3_trbfv::helpers::try_poly_ntt_from_bytes;
use e3_trbfv::helpers::try_poly_pb_from_bytes;
use e3_trbfv::shares::SharedSecret;
use e3_trbfv::{TrBFVError, TrBFVFailure, TrBFVRequest, TrBFVResponse};
use e3_utils::SharedRng;
use e3_utils::MAILBOX_LIMIT;
use e3_zk_helpers::circuits::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::circuits::dkg::share_computation::utils::compute_parity_matrix;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::circuit::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::circuits::threshold::pk_generation::circuit::{
    PkGenerationCircuit, PkGenerationCircuitData,
};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_computation::{ShareComputationCircuit, ShareComputationCircuitData};
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuit;
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuitData;
use e3_zk_helpers::CiphernodesCommittee;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{
    generate_nodes_fold_step, prove_decryption_aggregation_jobs, prove_dkg_aggregation,
    prove_node_dkg_fold, CircuitVariant, DecryptionAggregationJob, DkgAggregationInput,
    NodeDkgFoldInput, NodeDkgFoldProveResult, Provable, ZkBackend, ZkError, ZkProver,
};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::PublicKeyShare;
use fhe_math::rq::PowerBasis;
use fhe_traits::{DeserializeParametrized, FheEncoder};
use ndarray::Array2;
use num_bigint::BigInt;
use rand::Rng;
use tracing::{error, info};

/// Multithread actor
pub struct Multithread {
    bus: BusHandle,
    rng: SharedRng,
    cipher: Arc<Cipher>,
    task_pool: TaskPool,
    report: Option<Addr<MultithreadReport>>,
    zk_prover: Option<Arc<ZkProver>>,
}

impl Multithread {
    pub fn new(
        bus: BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        report: Option<Addr<MultithreadReport>>,
    ) -> Self {
        Self {
            bus,
            rng,
            cipher,
            task_pool,
            report,
            zk_prover: None,
        }
    }

    /// Set the ZK prover for handling proof requests.
    pub fn with_zk_prover(mut self, prover: Arc<ZkProver>) -> Self {
        self.zk_prover = Some(prover);
        self
    }

    /// Subtract the given amount from the total number of available threads and return the result
    pub fn get_max_threads_minus(amount: usize) -> usize {
        let total_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        std::cmp::max(1, total_threads.saturating_sub(amount))
    }

    pub fn attach(
        bus: &BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        report: Option<Addr<MultithreadReport>>,
    ) -> Addr<Self> {
        let addr = Self::new(bus.clone(), rng.clone(), cipher.clone(), task_pool, report).start();

        // Gate ComputeRequest behind EffectsEnabled — proof generation should
        // not trigger during historical event replay.
        bus.subscribe(
            EventType::EffectsEnabled,
            run_once::<EffectsEnabled>({
                let bus = bus.clone();
                let addr = addr.clone();
                move |_| {
                    bus.subscribe(EventType::ComputeRequest, addr.clone().recipient());
                    info!("Multithread actor listening for events.");
                    Ok(())
                }
            })
            .recipient(),
        );

        addr
    }

    pub fn attach_with_zk(
        bus: &BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        report: Option<Addr<MultithreadReport>>,
        zk_backend: &ZkBackend,
    ) -> Addr<Self> {
        let zk_prover = Arc::new(ZkProver::new(zk_backend));
        let actor = Self::new(bus.clone(), rng.clone(), cipher.clone(), task_pool, report)
            .with_zk_prover(zk_prover);
        let addr = actor.start();
        bus.subscribe_all(
            &[
                EventType::E3Failed,
                EventType::E3StageChanged,
                EventType::E3RequestComplete,
            ],
            addr.clone().into(),
        );

        bus.subscribe(
            EventType::EffectsEnabled,
            run_once::<EffectsEnabled>({
                let bus = bus.clone();
                let addr = addr.clone();
                move |_| {
                    bus.subscribe(EventType::ComputeRequest, addr.clone().recipient());
                    info!("Multithread actor with ZK listening for events.");
                    Ok(())
                }
            })
            .recipient(),
        );

        addr
    }

    pub fn create_taskpool(threads: usize, max_tasks: usize) -> TaskPool {
        TaskPool::new(threads, max_tasks)
    }
}

impl Actor for Multithread {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for Multithread {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        if let InterfoldEventData::ComputeRequest(data) = data {
            ctx.notify(TypedEvent::new(data, ec))
        }
    }
}

impl Handler<TypedEvent<ComputeRequest>> for Multithread {
    type Result = ResponseFuture<()>;
    fn handle(&mut self, msg: TypedEvent<ComputeRequest>, _: &mut Self::Context) -> Self::Result {
        let cipher = self.cipher.clone();
        let rng = self.rng.clone();
        let bus = self.bus.clone();
        let pool = self.task_pool.clone();
        let report = self.report.clone();
        let zk_prover = self.zk_prover.clone();
        trap_fut(
            EType::Computation,
            &self.bus.clone(),
            handle_compute_request_event(msg, bus, cipher, rng, pool, report, zk_prover),
        )
    }
}

async fn handle_compute_request_event(
    msg: TypedEvent<ComputeRequest>,
    bus: BusHandle,
    cipher: Arc<Cipher>,
    rng: SharedRng,
    pool: TaskPool,
    report: Option<Addr<MultithreadReport>>,
    zk_prover: Option<Arc<ZkProver>>,
) -> anyhow::Result<()> {
    let msg_string = msg.to_string();
    let job_name = msg_string.clone();
    let (msg, ctx) = msg.into_components();
    let request_snapshot = msg.clone();

    let report_for_worker = report.clone();
    let pool_result = pool
        .spawn(job_name, TaskTimeouts::default(), move || {
            handle_compute_request(rng, cipher, zk_prover, msg, report_for_worker)
        })
        .await;

    let (result, duration) = match pool_result {
        Ok(v) => v,
        Err(pool_err) => {
            error!(
                "Task pool error for compute request '{}': {pool_err}",
                msg_string
            );
            let error_kind = match &request_snapshot.request {
                ComputeRequestKind::Zk(_) => ComputeRequestErrorKind::Zk(
                    ZkEventError::ProofGenerationFailed(format!("Pool error: {pool_err}")),
                ),
                ComputeRequestKind::TrBFV(ref trbfv_req) => {
                    let msg = format!("Pool error: {pool_err}");
                    ComputeRequestErrorKind::TrBFV(match trbfv_req {
                        TrBFVRequest::GenPkShareAndSkSss(_) => {
                            TrBFVError::GenPkShareAndSkSss(msg.into())
                        }
                        TrBFVRequest::GenEsiSss(_) => TrBFVError::GenEsiSss(msg.into()),
                        TrBFVRequest::CalculateDecryptionKey(_) => {
                            TrBFVError::CalculateDecryptionKey(msg.into())
                        }
                        TrBFVRequest::CalculateDecryptionShare(_) => {
                            TrBFVError::CalculateDecryptionShare(msg.into())
                        }
                        TrBFVRequest::CalculateThresholdDecryption(_) => {
                            TrBFVError::CalculateThresholdDecryption(msg.into())
                        }
                    })
                }
            };
            bus.publish(ComputeRequestError::new(error_kind, request_snapshot), ctx)?;
            return Ok(());
        }
    };

    if let Some(report) = report {
        report.do_send(TrackDuration::new(msg_string, duration))
    };

    match result {
        Ok(val) => bus.publish(val, ctx)?,
        Err(e) => {
            // Publish ComputeRequestError so ProofRequestActor can handle it
            // and continue without proof if needed
            bus.publish(e, ctx)?
        }
    };
    Ok(())
}

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

    // 5. Get 'a' (CRP) as CrtPolynomial
    let a = CrtPolynomial::from_fhe_polynomial(&crp.poly());

    // 6. Build committee and circuit data
    let committee = CiphernodesCommittee {
        n: req.committee_n,
        h: req.committee_h,
        threshold: req.committee_threshold,
    };

    let circuit_data = PkAggregationCircuitData {
        committee,
        public_key,
        pk0_shares,
        a,
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
    let artifacts_dir = prover.resolve_artifacts_dir(req.params_preset, committee.as_str());
    let proof = circuit
        .prove_with_variant(
            prover,
            &req.params_preset,
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

    // 2. Deserialize aggregated PublicKey
    let public_key = PublicKey::from_bytes(&req.aggregated_pk_bytes, &threshold_params)
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

        // Build circuit data
        let circuit_data = e3_zk_helpers::threshold::share_decryption::ShareDecryptionCircuitData {
            ciphertext,
            public_key: public_key.clone(),
            s: s.clone(),
            e,
            d_share,
        };

        // Generate proof
        let circuit = e3_zk_helpers::threshold::share_decryption::ShareDecryptionCircuit;
        let idx_work_id = format!("{bb_work_base}_c6_{i}");
        let proof = circuit
            .prove(
                prover,
                &req.params_preset,
                &circuit_data,
                &idx_work_id,
                &artifacts_dir,
            )
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

fn timefunc<F>(
    name: &str,
    id: u8,
    func: F,
) -> (Result<ComputeResponse, ComputeRequestError>, Duration)
where
    F: FnOnce() -> Result<ComputeResponse, ComputeRequestError>,
{
    info!("STARTING MULTITHREAD `{}({})`", name, id);
    let start = Instant::now();
    let out = func();
    let dur = start.elapsed();
    info!("FINISHED MULTITHREAD `{}`({}) in {:?}", name, id, dur);
    (out, dur)
}

/// Handle compute request. This function is run on a rayon threadpool.
fn handle_compute_request(
    rng: SharedRng,
    cipher: Arc<Cipher>,
    zk_prover: Option<Arc<ZkProver>>,
    request: ComputeRequest,
    report: Option<Addr<MultithreadReport>>,
) -> (Result<ComputeResponse, ComputeRequestError>, Duration) {
    let id: u8 = rand::rng().random();

    match request.request.clone() {
        ComputeRequestKind::TrBFV(trbfv_req) => {
            handle_trbfv_request(rng, cipher, trbfv_req, request, id)
        }
        ComputeRequestKind::Zk(zk_req) => {
            handle_zk_request(cipher, zk_prover, zk_req, request, id, report)
        }
    }
}

fn handle_trbfv_request(
    rng: SharedRng,
    cipher: Arc<Cipher>,
    trbfv_req: TrBFVRequest,
    request: ComputeRequest,
    id: u8,
) -> (Result<ComputeResponse, ComputeRequestError>, Duration) {
    match trbfv_req {
        TrBFVRequest::GenPkShareAndSkSss(req) => timefunc("gen_pk_share_and_sk_sss", id, || {
            let mut rng_guard = rng.lock().expect("SharedRng mutex poisoned");
            match gen_pk_share_and_sk_sss(&mut *rng_guard, &cipher, req) {
                Ok(o) => Ok(ComputeResponse::trbfv(
                    TrBFVResponse::GenPkShareAndSkSss(o),
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(e) => Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(TrBFVError::GenPkShareAndSkSss(
                        TrBFVFailure::from_error(&e),
                    )),
                    request,
                )),
            }
        }),
        TrBFVRequest::GenEsiSss(req) => timefunc("gen_esi_sss", id, || {
            let mut rng_guard = rng.lock().expect("SharedRng mutex poisoned");
            match gen_esi_sss(&mut *rng_guard, &cipher, req) {
                Ok(o) => Ok(ComputeResponse::trbfv(
                    TrBFVResponse::GenEsiSss(o),
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(e) => Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(TrBFVError::GenEsiSss(
                        TrBFVFailure::from_error(&e),
                    )),
                    request,
                )),
            }
        }),
        TrBFVRequest::CalculateDecryptionKey(req) => timefunc(
            "calculate_decryption_key",
            id,
            || match calculate_decryption_key(&cipher, req) {
                Ok(o) => Ok(ComputeResponse::trbfv(
                    TrBFVResponse::CalculateDecryptionKey(o),
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(e) => {
                    error!("Error calculating decryption key: {}", e);
                    Err(ComputeRequestError::new(
                        ComputeRequestErrorKind::TrBFV(TrBFVError::CalculateDecryptionKey(
                            TrBFVFailure::from_error(&e),
                        )),
                        request,
                    ))
                }
            },
        ),
        TrBFVRequest::CalculateDecryptionShare(req) => timefunc(
            "calculate_decryption_share",
            id,
            || match calculate_decryption_share(&cipher, req) {
                Ok(o) => Ok(ComputeResponse::trbfv(
                    TrBFVResponse::CalculateDecryptionShare(o),
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(e) => Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(TrBFVError::CalculateDecryptionShare(
                        TrBFVFailure::from_error(&e),
                    )),
                    request,
                )),
            },
        ),
        TrBFVRequest::CalculateThresholdDecryption(req) => timefunc(
            "calculate_threshold_decryption",
            id,
            || match calculate_threshold_decryption(req) {
                Ok(o) => Ok(ComputeResponse::trbfv(
                    TrBFVResponse::CalculateThresholdDecryption(o),
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(e) => Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(TrBFVError::CalculateThresholdDecryption(
                        TrBFVFailure::from_error(&e),
                    )),
                    request,
                )),
            },
        ),
    }
}

fn handle_zk_request(
    cipher: Arc<Cipher>,
    zk_prover: Option<Arc<ZkProver>>,
    zk_req: ZkRequest,
    request: ComputeRequest,
    id: u8,
    report: Option<Addr<MultithreadReport>>,
) -> (Result<ComputeResponse, ComputeRequestError>, Duration) {
    let Some(prover) = zk_prover else {
        return (
            Err(ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(
                    "ZK prover not configured".to_string(),
                )),
                request,
            )),
            Duration::ZERO,
        );
    };

    match zk_req {
        ZkRequest::PkBfv(req) => timefunc("zk_pk_bfv", id, || {
            handle_pk_bfv_proof(&prover, req, request.clone())
        }),
        ZkRequest::PkGeneration(req) => timefunc("zk_pk_generation", id, || {
            handle_pk_generation_proof(&prover, &cipher, req, request.clone())
        }),
        ZkRequest::ShareComputation(req) => timefunc("zk_share_computation", id, || {
            handle_share_computation_proof(&prover, &cipher, req, request.clone())
        }),
        ZkRequest::ShareEncryption(req) => timefunc("zk_share_encryption", id, || {
            handle_share_encryption_proof(&prover, &cipher, req, request.clone())
        }),
        ZkRequest::DkgShareDecryption(req) => timefunc("zk_dkg_share_decryption", id, || {
            handle_dkg_share_decryption_proof(&prover, &cipher, req, request.clone())
        }),
        ZkRequest::VerifyShareProofs(req) => timefunc("zk_verify_share_proofs", id, || {
            handle_verify_share_proofs(&prover, req, request.clone())
        }),
        ZkRequest::VerifyShareDecryptionProofs(req) => {
            timefunc("zk_verify_share_decryption_proofs", id, || {
                handle_verify_share_decryption_proofs(&prover, req, request.clone())
            })
        }
        ZkRequest::PkAggregation(req) => timefunc("zk_pk_aggregation", id, || {
            handle_pk_aggregation_proof(&prover, req, request.clone())
        }),
        ZkRequest::ThresholdShareDecryption(req) => {
            timefunc("zk_threshold_share_decryption", id, || {
                handle_threshold_share_decryption_proof(&prover, &cipher, req, request.clone())
            })
        }
        ZkRequest::DecryptedSharesAggregation(req) => {
            timefunc("zk_decrypted_shares_aggregation", id, || {
                handle_decrypted_shares_aggregation_proof(&prover, req, request.clone())
            })
        }
        ZkRequest::NodeDkgFold(req) => timefunc("zk_node_dkg_fold", id, || {
            handle_node_dkg_fold_proof(&prover, req, request.clone(), report.clone())
        }),
        ZkRequest::NodesFoldStep(req) => timefunc("zk_nodes_fold_step", id, || {
            handle_nodes_fold_step_proof(&prover, req, request.clone())
        }),
        ZkRequest::DkgAggregation(req) => timefunc("zk_dkg_aggregation", id, || {
            handle_dkg_aggregation_proof(&prover, req, request.clone())
        }),
        ZkRequest::DecryptionAggregation(req) => timefunc("zk_decryption_aggregation", id, || {
            handle_decryption_aggregation_proof(&prover, req, request.clone())
        }),
    }
}

fn handle_node_dkg_fold_proof(
    prover: &ZkProver,
    req: NodeDkgFoldRequest,
    request: ComputeRequest,
    report: Option<Addr<MultithreadReport>>,
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
    if let Some(report) = report {
        for step in step_timings {
            report.do_send(TrackDuration::new(
                format!("NodeDkgFold/{}", step.step),
                Duration::from_secs_f64(step.seconds),
            ));
        }
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
/// the same [`E3id`] (e.g. three ciphernodes proving C0 in parallel).
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

    // 5. Compute parity matrix
    let committee = req.committee_size.values();
    let parity_matrix =
        compute_parity_matrix(threshold_params.moduli(), committee.n, committee.threshold)
            .map_err(|e| make_zk_error(&request, format!("compute_parity_matrix: {}", e)))?;

    // 6. Build circuit data
    let circuit_data = ShareComputationCircuitData {
        dkg_input_type: req.dkg_input_type,
        secret,
        secret_sss,
        parity_matrix,
        n_parties: committee.n as u32,
        threshold: committee.threshold as u32,
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
            &req.params_preset,
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

    // 4. Build circuit data
    let committee = req.committee_size.values();
    let circuit_data = PkGenerationCircuitData {
        committee,
        pk0_share,
        eek,
        e_sm,
        sk,
    };

    // 5. Generate proof via Provable trait
    let circuit = PkGenerationCircuit;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());

    let proof = circuit
        .prove(
            prover,
            &req.params_preset,
            &circuit_data,
            &bb_work,
            &artifacts_dir,
        )
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
    // NOTE: req.params_preset is expected to contain a DKG preset (e.g., InsecureDkg512)
    // because the proof is for the DKG circuit. This preset is converted to BFV parameters.
    let params = BfvParamSet::from(req.params_preset).build_arc();
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
    let circuit_data = PkCircuitData { public_key: pk_bfv };
    let bb_work = zk_bb_work_id(&request);
    let preset_counterpart = req
        .params_preset
        .threshold_counterpart()
        .unwrap_or(BfvPreset::InsecureThreshold512);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    // But here we have to pass the InsecureThreshold512 preset because the underlaying witness generator
    // builds both params, but will only use the DKG one
    let proof = circuit
        .prove(
            prover,
            &preset_counterpart,
            &circuit_data,
            &bb_work,
            &artifacts_dir,
        )
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

    // 4. Dummy SecretKey (not used by Inputs::compute)
    let dummy_sk = SecretKey::random(&dkg_params, &mut rand::rng());

    // 5. Build circuit data
    let circuit_data = ShareEncryptionCircuitData {
        plaintext,
        ciphertext,
        public_key,
        secret_key: dummy_sk,
        u_rns,
        e0_rns,
        e1_rns,
        dkg_input_type: req.dkg_input_type,
    };

    // 6. Generate proof (preset = threshold preset; Inputs::compute derives DKG internally)
    let circuit = ShareEncryptionCircuit;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = circuit
        .prove(
            prover,
            &req.params_preset,
            &circuit_data,
            &bb_work,
            &artifacts_dir,
        )
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
    let (_threshold_params, dkg_params) = build_pair_for_preset(req.params_preset)
        .map_err(|e| make_zk_error(&request, format!("build_pair_for_preset: {}", e)))?;

    let sk_bytes = req
        .sk_bfv
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("sk_bfv decrypt: {}", e)))?;
    let secret_key = deserialize_secret_key(&sk_bytes, &dkg_params)
        .map_err(|e| make_zk_error(&request, format!("sk_bfv deserialize: {}", e)))?;

    // External slots = (H - 1), each carrying L ciphertexts.
    let h = req.num_honest_parties;
    let l = req.num_moduli;
    if req.own_plaintext_idx >= h {
        return Err(make_zk_error(
            &request,
            format!(
                "own_plaintext_idx {} out of range (num_honest_parties={})",
                req.own_plaintext_idx, h
            ),
        ));
    }
    let expected_external_cts = h.saturating_sub(1) * l;
    if req.honest_ciphertexts_raw.len() != expected_external_cts {
        return Err(make_zk_error(
            &request,
            format!(
                "Expected {} external ciphertexts ((H-1)={} * L={}), got {}",
                expected_external_cts,
                h.saturating_sub(1),
                l,
                req.honest_ciphertexts_raw.len()
            ),
        ));
    }

    // Deserialize external ciphertexts → [(H-1)][L]
    let num_external = h.saturating_sub(1);
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

    // Splice None at `own_plaintext_idx` so the H-sized vector matches ascending honest party_id order.
    let mut honest_ciphertexts: Vec<Option<Vec<Ciphertext>>> = Vec::with_capacity(h);
    let mut external_iter = external_ciphertexts.into_iter();
    for slot in 0..h {
        if slot == req.own_plaintext_idx {
            honest_ciphertexts.push(None);
        } else {
            honest_ciphertexts.push(Some(
                external_iter
                    .next()
                    .expect("external_iter exhausted: lengths validated above"),
            ));
        }
    }

    // Own-plaintext share rows: bincode `Vec<Vec<u64>>` shape [L][N].
    let own_share_bytes = req
        .own_share_raw
        .access_raw(cipher)
        .map_err(|e| make_zk_error(&request, format!("own_share decrypt: {}", e)))?;
    let own_plaintext_share: Vec<Vec<u64>> = bincode::deserialize(&own_share_bytes)
        .map_err(|e| make_zk_error(&request, format!("own_share deserialize: {}", e)))?;
    if own_plaintext_share.len() != l {
        return Err(make_zk_error(
            &request,
            format!(
                "own_plaintext_share has {} moduli, expected {}",
                own_plaintext_share.len(),
                l
            ),
        ));
    }
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
        dkg_input_type: req.dkg_input_type,
    };

    let circuit = ShareDecryptionCircuit;
    let bb_work = zk_bb_work_id(&request);
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = circuit
        .prove(
            prover,
            &req.params_preset,
            &circuit_data,
            &bb_work,
            &artifacts_dir,
        )
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
    let party_results: Vec<PartyVerificationResult> = req
        .party_proofs
        .into_iter()
        .map(|party| {
            let sender = party.sender_party_id;

            for signed_proof in &party.signed_proofs {
                // 1. Validate CircuitName matches expected circuits for this ProofType
                let expected_circuits = signed_proof.payload.proof_type.circuit_names();
                if !expected_circuits.contains(&signed_proof.payload.proof.circuit) {
                    info!(
                        "Circuit name mismatch for party {} ({:?}): expected {:?}, got {:?}",
                        sender,
                        signed_proof.payload.proof_type,
                        expected_circuits,
                        signed_proof.payload.proof.circuit
                    );
                    return PartyVerificationResult {
                        sender_party_id: sender,
                        all_verified: false,
                        failed_signed_payload: Some(signed_proof.clone()),
                        recovered_address: None,
                    };
                }

                // 2. ZK proof verification
                let proof = &signed_proof.payload.proof;
                let result =
                    zk_verify_share_proof_bundle(prover, proof, &e3_id_str, sender, &artifacts_dir);
                match result {
                    Ok(true) => continue,
                    Ok(false) | Err(_) => {
                        info!(
                            "ZK proof verification failed for party {} ({:?})",
                            sender, signed_proof.payload.proof_type
                        );
                        return PartyVerificationResult {
                            sender_party_id: sender,
                            all_verified: false,
                            failed_signed_payload: Some(signed_proof.clone()),
                            recovered_address: None,
                        };
                    }
                }
            }
            PartyVerificationResult {
                sender_party_id: sender,
                all_verified: true,
                failed_signed_payload: None,
                recovered_address: None,
            }
        })
        .collect();

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
    let party_results: Vec<PartyVerificationResult> = req
        .party_proofs
        .into_iter()
        .map(|party| {
            let sender = party.sender_party_id;

            // Guard: an empty esm_decryption_proofs vec would make this loop
            // vacuously true.  Defence-in-depth: reject any party with zero ESM proofs.
            if party.signed_e_sm_decryption_proofs.is_empty() {
                return PartyVerificationResult {
                    sender_party_id: sender,
                    all_verified: false,
                    failed_signed_payload: None,
                    recovered_address: None,
                };
            }

            // Flatten all signed proofs (SK + ESMs) and verify uniformly.
            let all_signed: Vec<&e3_events::SignedProofPayload> =
                std::iter::once(&party.signed_sk_decryption_proof)
                    .chain(party.signed_e_sm_decryption_proofs.iter())
                    .collect();

            for signed_proof in &all_signed {
                // 1. Validate CircuitName matches expected circuits for this ProofType
                let expected_circuits = signed_proof.payload.proof_type.circuit_names();
                if !expected_circuits.contains(&signed_proof.payload.proof.circuit) {
                    info!(
                        "C4 circuit mismatch for party {}: expected {:?}, got {:?}",
                        sender, expected_circuits, signed_proof.payload.proof.circuit
                    );
                    return PartyVerificationResult {
                        sender_party_id: sender,
                        all_verified: false,
                        failed_signed_payload: Some((*signed_proof).clone()),
                        recovered_address: None,
                    };
                }

                // 2. ZK proof verification
                let proof = &signed_proof.payload.proof;
                let result = prover.verify_proof(proof, &e3_id_str, sender, &artifacts_dir);
                match result {
                    Ok(true) => continue,
                    Ok(false) | Err(_) => {
                        info!(
                            "C4 ZK proof verification failed for party {} ({:?})",
                            sender, signed_proof.payload.proof_type
                        );
                        return PartyVerificationResult {
                            sender_party_id: sender,
                            all_verified: false,
                            failed_signed_payload: Some((*signed_proof).clone()),
                            recovered_address: None,
                        };
                    }
                }
            }

            PartyVerificationResult {
                sender_party_id: sender,
                all_verified: true,
                failed_signed_payload: None,
                recovered_address: None,
            }
        })
        .collect();

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
    let num_parties = req.d_share_polys.len();

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

        // d. Build committee
        let committee = e3_zk_helpers::CiphernodesCommittee {
            n: req.threshold_n as usize,
            h: num_parties,
            threshold: req.threshold_m as usize,
        };

        // e. C7 uses noir-recursive-no-zk (non-ZK recursive); it is verified inside
        // `DecryptionAggregator` via `verify_honk_proof_non_zk`. The EVM-facing proof for on-chain
        // is `CircuitName::DecryptionAggregator`.
        let circuit_data = DecryptedSharesAggregationCircuitData {
            committee,
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
                &req.params_preset,
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
