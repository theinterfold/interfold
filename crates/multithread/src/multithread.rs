// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::report::MultithreadReport;
use crate::report::TrackDuration;
use crate::TaskTimeouts;
use crate::{TaskPool, TaskPoolError};
use actix::prelude::*;
use actix::{Actor, Handler};
use alloy::primitives::keccak256;
use anyhow::Result;
use e3_crypto::Cipher;
use e3_events::trap_fut;

use e3_events::EType;
use e3_events::{
    BusHandle, ComputeRequest, ComputeRequestError, ComputeRequestErrorKind, ComputeRequestKind,
    ComputeResponse, DecryptedSharesAggregationProofRequest,
    DecryptedSharesAggregationProofResponse, DecryptionAggregationRequest,
    DecryptionAggregationResponse, DkgAggregationRequest, DkgAggregationResponse,
    DkgAggregationV2Request, DkgAggregationV2Response, DkgShareDecryptionProofRequest,
    DkgShareDecryptionProofResponse, E3Stage, E3id, EventPublisher, EventSubscriber, EventType,
    InterfoldEvent, InterfoldEventData, LbfvAggregationFoldRequest, LbfvAggregationFoldResponse,
    LbfvGenerationFoldRequest, LbfvGenerationFoldResponse, LbfvPkAggregationProofRequest,
    LbfvPkAggregationProofResponse, LbfvPkGenerationProofRequest, LbfvPkGenerationProofResponse,
    NodeDkgFoldRequest, NodeDkgFoldResponse, NodeDkgFoldV2Request, NodeDkgFoldV2Response,
    NodesFoldStepRequest, NodesFoldStepResponse, NodesFoldV2StepRequest, NodesFoldV2StepResponse,
    PartyVerificationResult, PkAggregationProofRequest, PkAggregationProofResponse,
    PkBfvProofRequest, PkBfvProofResponse, PkGenerationProofRequest, PkGenerationProofResponse,
    Proof, RlkAggregationProofRequest, RlkAggregationProofResponse, RlkGenerationProofRequest,
    RlkGenerationProofResponse, ShareComputationProofRequest, ShareComputationProofResponse,
    ShareEncryptionProofRequest, ShareEncryptionProofResponse,
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
use e3_trbfv::gen_lbfv_key_shares::deserialize_c1_secret_key;
use e3_trbfv::gen_lbfv_key_shares::gen_lbfv_key_shares;
use e3_trbfv::gen_pk_share_and_sk_sss::gen_pk_share_and_sk_sss;
use e3_trbfv::helpers::deserialize_secret_key;
use e3_trbfv::helpers::try_poly_from_sensitive_bytes;
use e3_trbfv::helpers::try_poly_ntt_from_bytes;
use e3_trbfv::helpers::try_poly_pb_from_bytes;
use e3_trbfv::shares::SharedSecret;
use e3_trbfv::{TrBFVError, TrBFVFailure, TrBFVRequest, TrBFVResponse};
use e3_utils::MAILBOX_LIMIT;
use e3_utils::{ArcBytes, SharedRng};
use e3_zk_helpers::circuits::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::circuits::dkg::share_computation::utils::compute_parity_matrix;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::circuit::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::circuits::threshold::pk_generation::circuit::{
    PkGenerationCircuit, PkGenerationCircuitData,
};
use e3_zk_helpers::circuits::threshold::pk_generation::{
    LbfvPkGenerationAdapter, LbfvPkGenerationCircuitData,
};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::lbfv_pk_aggregation::{
    LbfvPkAggregationCircuit, LbfvPkAggregationCircuitData,
};
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuit;
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuitData;
use e3_zk_helpers::threshold::rlk_aggregation::{RlkAggregationCircuit, RlkAggregationCircuitData};
use e3_zk_helpers::threshold::rlk_generation::{RlkGenerationAdapter, RlkGenerationCircuitData};
use e3_zk_helpers::CiphernodesCommittee;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::DEFAULT_C2_CHUNK_SIZE;
use e3_zk_prover::{
    generate_nodes_fold_step, load_staged_lbfv_pk_generation_limb_vk_hash,
    load_staged_rlk_generation_limb_vk_hash, prove_chunked_share_computation,
    prove_decryption_aggregation_jobs, prove_dkg_aggregation, prove_dkg_aggregation_v2,
    prove_lbfv_aggregation_fold_step_for_preset, prove_lbfv_generation_fold_step_for_preset,
    prove_lbfv_pk_generation_row, prove_node_dkg_fold, prove_node_dkg_fold_v2_for_preset,
    prove_nodes_fold_v2_step_for_preset, prove_rlk_generation_row, validate_c2_terminal_proof,
    validate_lbfv_pk_generation_terminal_proof, validate_rlk_generation_terminal_proof,
    C2TerminalAnchors, CircuitVariant, DecryptionAggregationJob, DkgAggregationInput,
    NodeDkgFoldInput, NodeDkgFoldProveResult, Provable, ZkBackend, ZkError, ZkProver,
};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::PublicKeyShare;
use fhe::trlbfv::{PublicKeyShare as LbfvPublicKeyShare, RelinKeyShare, RlkWitness};
use fhe_math::rq::{NttShoup, Poly, PowerBasis};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, FheEncoder};
use ndarray::Array2;
use num_bigint::BigInt;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, Zeroizing};

fn c2_chunk_size_for_preset(preset: BfvPreset) -> usize {
    match preset {
        BfvPreset::InsecureThreshold512 | BfvPreset::InsecureDkg512 => 128,
        _ => DEFAULT_C2_CHUNK_SIZE,
    }
}

use crate::effect_gate::ComputeEffectGate;

/// Multithread actor
pub struct Multithread {
    bus: BusHandle,
    rng: SharedRng,
    cipher: Arc<Cipher>,
    task_pool: TaskPool,
    task_scope: String,
    report: Option<Addr<MultithreadReport>>,
    zk_prover: Option<Arc<ZkProver>>,
    retry_logs: Arc<RetryLogLimiter>,
}

impl Multithread {
    pub fn new(
        bus: BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        task_scope: String,
        report: Option<Addr<MultithreadReport>>,
    ) -> Self {
        Self {
            bus,
            rng,
            cipher,
            task_pool,
            task_scope,
            report,
            zk_prover: None,
            retry_logs: Arc::new(RetryLogLimiter::default()),
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
        task_scope: String,
        report: Option<Addr<MultithreadReport>>,
        lifecycle_stages: HashMap<E3id, E3Stage>,
    ) -> Addr<Self> {
        let addr = Self::new(
            bus.clone(),
            rng.clone(),
            cipher.clone(),
            task_pool,
            task_scope,
            report,
        )
        .start();

        Self::subscribe_to_lifecycle(bus, &addr);
        ComputeEffectGate::attach(bus, addr.clone().recipient(), lifecycle_stages);
        info!("Multithread actor waiting behind the replay-safe effect gate.");

        addr
    }

    pub fn attach_with_zk(
        bus: &BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        task_scope: String,
        report: Option<Addr<MultithreadReport>>,
        zk_backend: &ZkBackend,
        lifecycle_stages: HashMap<E3id, E3Stage>,
    ) -> Addr<Self> {
        let zk_prover = Arc::new(ZkProver::new(zk_backend));
        let actor = Self::new(
            bus.clone(),
            rng.clone(),
            cipher.clone(),
            task_pool,
            task_scope,
            report,
        )
        .with_zk_prover(zk_prover);
        let addr = actor.start();
        Self::subscribe_to_lifecycle(bus, &addr);

        ComputeEffectGate::attach(bus, addr.clone().recipient(), lifecycle_stages);
        info!("Multithread actor with ZK waiting behind the replay-safe effect gate.");

        addr
    }

    fn subscribe_to_lifecycle(bus: &BusHandle, addr: &Addr<Self>) {
        bus.subscribe_all(
            &[
                EventType::E3Failed,
                EventType::E3StageChanged,
                EventType::E3RequestComplete,
            ],
            addr.clone().into(),
        );
    }

    pub fn create_taskpool(threads: usize, max_tasks: usize) -> TaskPool {
        TaskPool::new(threads, max_tasks)
    }

    fn task_group(&self, e3_id: &E3id) -> String {
        task_group(&self.task_scope, e3_id)
    }
}

fn task_group(scope: &str, e3_id: &E3id) -> String {
    format!("{scope}:{e3_id}")
}

#[cfg(test)]
mod task_group_tests {
    use super::*;

    #[test]
    fn shared_pool_groups_are_isolated_by_node() {
        let e3_id = E3id::new("round", 1);

        assert_ne!(task_group("node-a", &e3_id), task_group("node-b", &e3_id));
        assert_eq!(task_group("node-a", &e3_id), task_group("node-a", &e3_id));
    }

    #[test]
    fn prover_retry_delay_is_capped_and_backed_off() {
        assert_eq!(compute_retry_delay(1), Duration::from_secs(5));
        assert_eq!(compute_retry_delay(2), Duration::from_secs(15));
        assert_eq!(compute_retry_delay(3), Duration::from_secs(60));
        assert_eq!(compute_retry_delay(4), Duration::from_secs(300));
        assert_eq!(compute_retry_delay(5), Duration::from_secs(300));
        assert_eq!(compute_retry_delay(100), Duration::from_secs(300));
    }

    #[test]
    fn proof_and_keyshare_worker_failures_retry() {
        let zk_request = ComputeRequest::zk(
            ZkRequest::PkBfv(PkBfvProofRequest::new(
                e3_utils::ArcBytes::default(),
                BfvPreset::InsecureThreshold512,
                CiphernodesCommitteeSize::Minimum,
            )),
            e3_events::CorrelationId::new(),
            E3id::new("retry", 1),
        );
        let retryable = ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed("oom".to_owned())),
            zk_request.clone(),
        );
        let invalid = ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams("bad input".to_owned())),
            zk_request.clone(),
        );
        let trbfv = ComputeRequestError::new(
            ComputeRequestErrorKind::TrBFV(TrBFVError::GenPkShareAndSkSss(TrBFVFailure::from(
                "worker panic",
            ))),
            zk_request.clone(),
        );
        let threshold_decryption = ComputeRequestError::new(
            ComputeRequestErrorKind::TrBFV(TrBFVError::CalculateThresholdDecryption(
                TrBFVFailure::from("invalid threshold shares"),
            )),
            zk_request.clone(),
        );
        let keyshare_request = ComputeRequestKind::TrBFV(TrBFVRequest::GenEsiSss(
            e3_trbfv::gen_esi_sss::GenEsiSssRequest {
                trbfv_config: e3_trbfv::TrBFVConfig::new(
                    e3_utils::ArcBytes::from_bytes(b"params"),
                    3,
                    1,
                ),
                e_sm_raw: e3_crypto::SensitiveBytes::from_encrypted(&[1]),
            },
        ));

        assert!(is_retryable_compute_error(&retryable));
        assert!(is_retryable_compute_error(&trbfv));
        assert!(!is_retryable_compute_error(&invalid));
        assert!(!is_retryable_compute_error(&threshold_decryption));
        assert!(is_retryable_trbfv_request(&keyshare_request));
        assert!(!is_retryable_trbfv_request(&zk_request.request));
    }

    #[test]
    fn retry_warning_limiter_reports_suppressed_attempts_once_per_window() {
        let limiter = RetryLogLimiter::new(Duration::from_secs(60));
        let start = Instant::now();

        assert_eq!(limiter.observe_at(start), Some(0));
        assert_eq!(limiter.observe_at(start + Duration::from_secs(1)), None);
        assert_eq!(limiter.observe_at(start + Duration::from_secs(2)), None);
        assert_eq!(limiter.observe_at(start + Duration::from_secs(60)), Some(2));
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
        match data {
            InterfoldEventData::ComputeRequest(data) => ctx.notify(TypedEvent::new(data, ec)),
            InterfoldEventData::E3Failed(data) => {
                self.task_pool.cancel_group(&self.task_group(&data.e3_id))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.task_pool.cancel_group(&self.task_group(&data.e3_id))
            }
            InterfoldEventData::E3StageChanged(data)
                if matches!(data.new_stage, E3Stage::Complete | E3Stage::Failed) =>
            {
                self.task_pool.cancel_group(&self.task_group(&data.e3_id))
            }
            _ => {}
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
        let task_scope = self.task_scope.clone();
        let retry_logs = self.retry_logs.clone();
        trap_fut(
            EType::Computation,
            &self.bus.clone(),
            handle_compute_request_event(
                msg, bus, cipher, rng, pool, task_scope, report, zk_prover, retry_logs,
            ),
        )
    }
}

async fn handle_compute_request_event(
    msg: TypedEvent<ComputeRequest>,
    bus: BusHandle,
    cipher: Arc<Cipher>,
    rng: SharedRng,
    pool: TaskPool,
    task_scope: String,
    report: Option<Addr<MultithreadReport>>,
    zk_prover: Option<Arc<ZkProver>>,
    retry_logs: Arc<RetryLogLimiter>,
) -> anyhow::Result<()> {
    let msg_string = msg.to_string();
    let job_name = msg_string.clone();
    let (msg, ctx) = msg.into_components();
    let request_snapshot = msg.clone();
    let task_group = task_group(&task_scope, &msg.e3_id);

    let is_zk = matches!(&request_snapshot.request, ComputeRequestKind::Zk(_));
    let retries_local_worker_failures =
        is_zk || is_retryable_trbfv_request(&request_snapshot.request);
    let mut attempt = 1usize;
    let mut total_duration = Duration::ZERO;

    // Retry count is deliberately not capped. A fixed attempt limit could abandon recoverable
    // work before the protocol deadline. The E3 task group is the lifetime bound: terminal E3
    // events cancel queued work, retry delays, and every later attempt.
    loop {
        let prover_for_worker = if attempt > 1 {
            zk_prover
                .as_ref()
                .map(|prover| Arc::new(prover.with_slow_low_memory()))
        } else {
            zk_prover.clone()
        };
        let request_for_worker = request_snapshot.clone();
        let report_for_worker = report.clone();
        let rng_for_worker = rng.clone();
        let cipher_for_worker = cipher.clone();
        let pool_result = pool
            .spawn_in_group(
                task_group.clone(),
                job_name.clone(),
                TaskTimeouts::default(),
                move || {
                    handle_compute_request(
                        rng_for_worker,
                        cipher_for_worker,
                        prover_for_worker,
                        request_for_worker,
                        report_for_worker,
                    )
                },
            )
            .await;

        let (result, duration) = match pool_result {
            Ok(value) => value,
            Err(TaskPoolError::Cancelled(group)) => {
                info!(
                    task_group = group,
                    "Dropped compute request for a terminal E3"
                );
                return Ok(());
            }
            Err(pool_error) => {
                if retries_local_worker_failures {
                    let delay = compute_retry_delay(attempt);
                    log_compute_retry(
                        &retry_logs,
                        &request_snapshot,
                        attempt,
                        delay,
                        is_zk,
                        &format!("task pool error: {pool_error}"),
                    );
                    if let Err(TaskPoolError::Cancelled(group)) =
                        pool.wait_for_retry(&task_group, delay).await
                    {
                        info!(
                            task_group = group,
                            "Stopped compute recovery for a terminal E3"
                        );
                        return Ok(());
                    }
                    attempt = attempt.saturating_add(1);
                    continue;
                }

                error!(
                    request = %msg_string,
                    attempt,
                    error = %pool_error,
                    "Compute worker exhausted its recovery attempts"
                );
                let error_kind = pool_error_kind(&request_snapshot, &pool_error);
                bus.publish(ComputeRequestError::new(error_kind, request_snapshot), ctx)?;
                return Ok(());
            }
        };
        total_duration += duration;

        match result {
            Ok(value) => {
                if attempt > 1 {
                    info!(
                        e3_id = %request_snapshot.e3_id,
                        request = %msg_string,
                        attempt,
                        low_memory = is_zk,
                        "Compute request recovered after a worker failure"
                    );
                }
                if let Some(report) = report.as_ref() {
                    report.do_send(TrackDuration::new(msg_string, total_duration));
                }
                bus.publish(value, ctx)?;
                return Ok(());
            }
            Err(compute_error) if is_retryable_compute_error(&compute_error) => {
                let delay = compute_retry_delay(attempt);
                log_compute_retry(
                    &retry_logs,
                    &request_snapshot,
                    attempt,
                    delay,
                    is_zk,
                    &bounded_error(&compute_error),
                );
                if let Err(TaskPoolError::Cancelled(group)) =
                    pool.wait_for_retry(&task_group, delay).await
                {
                    info!(
                        task_group = group,
                        "Stopped compute recovery for a terminal E3"
                    );
                    return Ok(());
                }
                attempt = attempt.saturating_add(1);
                continue;
            }
            Err(compute_error) => {
                bus.publish(compute_error, ctx)?;
                return Ok(());
            }
        }
    }
}

const COMPUTE_RETRY_DELAYS_SECS: [u64; 4] = [5, 15, 60, 300];
const COMPUTE_RETRY_LOG_INTERVAL: Duration = Duration::from_secs(60);

fn compute_retry_delay(completed_attempt: usize) -> Duration {
    let seconds = COMPUTE_RETRY_DELAYS_SECS
        .get(completed_attempt.saturating_sub(1))
        .or_else(|| COMPUTE_RETRY_DELAYS_SECS.last())
        .copied()
        .expect("the retry schedule is not empty");
    Duration::from_secs(seconds)
}

#[derive(Debug)]
struct RetryLogWindow {
    last_warning: Option<Instant>,
    suppressed: u64,
}

#[derive(Debug)]
struct RetryLogLimiter {
    interval: Duration,
    window: Mutex<RetryLogWindow>,
}

impl RetryLogLimiter {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            window: Mutex::new(RetryLogWindow {
                last_warning: None,
                suppressed: 0,
            }),
        }
    }

    fn observe(&self) -> Option<u64> {
        self.observe_at(Instant::now())
    }

    fn observe_at(&self, now: Instant) -> Option<u64> {
        let mut window = self.window.lock().expect("retry log lock poisoned");
        let can_warn = window
            .last_warning
            .is_none_or(|last| now.saturating_duration_since(last) >= self.interval);
        if can_warn {
            let suppressed = std::mem::take(&mut window.suppressed);
            window.last_warning = Some(now);
            Some(suppressed)
        } else {
            window.suppressed = window.suppressed.saturating_add(1);
            None
        }
    }
}

impl Default for RetryLogLimiter {
    fn default() -> Self {
        Self::new(COMPUTE_RETRY_LOG_INTERVAL)
    }
}

fn is_retryable_compute_error(error: &ComputeRequestError) -> bool {
    matches!(
        error.get_err(),
        ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(_))
            | ComputeRequestErrorKind::TrBFV(
                TrBFVError::GenPkShareAndSkSss(_)
                    | TrBFVError::GenEsiSss(_)
                    | TrBFVError::CalculateDecryptionKey(_)
                    | TrBFVError::CalculateDecryptionShare(_)
            )
    )
}

fn is_retryable_trbfv_request(request: &ComputeRequestKind) -> bool {
    matches!(
        request,
        ComputeRequestKind::TrBFV(
            TrBFVRequest::GenPkShareAndSkSss(_)
                | TrBFVRequest::GenEsiSss(_)
                | TrBFVRequest::CalculateDecryptionKey(_)
                | TrBFVRequest::CalculateDecryptionShare(_)
        )
    )
}

fn bounded_error(error: &ComputeRequestError) -> String {
    const LIMIT: usize = 512;
    let value = error.to_string();
    if value.len() <= LIMIT {
        return value;
    }
    let mut end = LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

fn log_compute_retry(
    limiter: &RetryLogLimiter,
    request: &ComputeRequest,
    completed_attempt: usize,
    delay: Duration,
    low_memory_next_attempt: bool,
    reason: &str,
) {
    if let Some(suppressed_retries) = limiter.observe() {
        warn!(
            e3_id = %request.e3_id,
            request = %request,
            completed_attempt,
            retry_in_secs = delay.as_secs(),
            low_memory_next_attempt,
            suppressed_retries,
            error = %reason,
            "Compute worker failed; automatic recovery remains active"
        );
    } else {
        debug!(
            e3_id = %request.e3_id,
            request = %request,
            completed_attempt,
            retry_in_secs = delay.as_secs(),
            error = %reason,
            "Compute worker retry scheduled"
        );
    }
}

fn pool_error_kind(
    request: &ComputeRequest,
    pool_error: &TaskPoolError,
) -> ComputeRequestErrorKind {
    match &request.request {
        ComputeRequestKind::Zk(_) => ComputeRequestErrorKind::Zk(
            ZkEventError::ProofGenerationFailed(format!("Pool error: {pool_error}")),
        ),
        ComputeRequestKind::TrBFV(trbfv_request) => {
            let message = format!("Pool error: {pool_error}");
            ComputeRequestErrorKind::TrBFV(match trbfv_request {
                TrBFVRequest::GenPkShareAndSkSss(_) => {
                    TrBFVError::GenPkShareAndSkSss(message.into())
                }
                TrBFVRequest::GenEsiSss(_) => TrBFVError::GenEsiSss(message.into()),
                TrBFVRequest::CalculateDecryptionKey(_) => {
                    TrBFVError::CalculateDecryptionKey(message.into())
                }
                TrBFVRequest::CalculateDecryptionShare(_) => {
                    TrBFVError::CalculateDecryptionShare(message.into())
                }
                TrBFVRequest::CalculateThresholdDecryption(_) => {
                    TrBFVError::CalculateThresholdDecryption(message.into())
                }
                TrBFVRequest::GenLbfvKeyShares(_) => TrBFVError::GenLbfvKeyShares(message.into()),
            })
        }
    }
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

fn ensure_lbfv_preset(
    preset: BfvPreset,
    request: &ComputeRequest,
) -> Result<(), ComputeRequestError> {
    if !e3_fhe_params::supports_lbfv(preset) {
        return Err(make_zk_error(
            request,
            format!("l-BFV row proofs require an l-BFV preset; received {preset:?}"),
        ));
    }
    Ok(())
}

fn validated_row_instance(
    proof_type: e3_events::ProofType,
    proof: &Proof,
    requested_row: u32,
    params_preset: BfvPreset,
    request: &ComputeRequest,
) -> Result<u32, ComputeRequestError> {
    let identity = proof_type
        .identity(proof, e3_fhe_params::lbfv_row_count(params_preset))
        .map_err(|error| make_zk_error(request, error.to_string()))?;
    if identity.instance != requested_row {
        return Err(make_zk_error(
            request,
            format!(
                "proof row {} does not match requested row {requested_row}",
                identity.instance
            ),
        ));
    }
    Ok(identity.instance)
}

fn build_lbfv_pk_generation_data(
    cipher: &Cipher,
    req: &LbfvPkGenerationProofRequest,
    request: &ComputeRequest,
) -> Result<LbfvPkGenerationCircuitData, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, request)?;
    let (params, _) = build_pair_for_preset(req.params_preset)
        .map_err(|error| make_zk_error(request, format!("build_pair_for_preset: {error}")))?;
    let secret_key_bytes = req
        .secret_key_bytes
        .access(cipher)
        .map_err(|error| make_zk_error(request, format!("secret_key_bytes decrypt: {error}")))?;
    let secret_key = deserialize_c1_secret_key(&secret_key_bytes, &params).map_err(|error| {
        make_zk_error(request, format!("secret_key_bytes deserialize: {error}"))
    })?;
    let public_key_share = LbfvPublicKeyShare::from_bytes(&req.public_key_share_bytes, &params)
        .map_err(|error| {
            make_zk_error(
                request,
                format!("public_key_share_bytes deserialize: {error}"),
            )
        })?;
    LbfvPkGenerationAdapter::new(req.params_preset)
        .and_then(|adapter| {
            adapter.row_data(
                req.committee_size.values(),
                req.proof_domain,
                req.party_id,
                req.row_index,
                &secret_key,
                &public_key_share,
            )
        })
        .map_err(|error| make_zk_error(request, error.to_string()))
}

fn build_rlk_generation_data(
    cipher: &Cipher,
    req: &RlkGenerationProofRequest,
    request: &ComputeRequest,
) -> Result<RlkGenerationCircuitData, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, request)?;
    let (params, _) = build_pair_for_preset(req.params_preset)
        .map_err(|error| make_zk_error(request, format!("build_pair_for_preset: {error}")))?;
    let expected_rows = params.moduli().len();
    if req.errors_d0_bytes.len() != expected_rows || req.errors_d2_bytes.len() != expected_rows {
        return Err(make_zk_error(
            request,
            format!(
                "RLK witness requires {expected_rows} d0 and d2 error rows; received {} and {}",
                req.errors_d0_bytes.len(),
                req.errors_d2_bytes.len()
            ),
        ));
    }

    let secret_key_bytes = req
        .secret_key_bytes
        .access(cipher)
        .map_err(|error| make_zk_error(request, format!("secret_key_bytes decrypt: {error}")))?;
    let secret_key = deserialize_c1_secret_key(&secret_key_bytes, &params).map_err(|error| {
        make_zk_error(request, format!("secret_key_bytes deserialize: {error}"))
    })?;
    let r_bytes = req
        .r_bytes
        .access(cipher)
        .map_err(|error| make_zk_error(request, format!("r_bytes decrypt: {error}")))?;
    let r = deserialize_secret_key(&r_bytes, &params)
        .map_err(|error| make_zk_error(request, format!("r_bytes deserialize: {error}")))?;
    let share = RelinKeyShare::from_bytes(&req.rlk_share_bytes, &params)
        .map_err(|error| make_zk_error(request, format!("rlk_share_bytes deserialize: {error}")))?;
    let context = params
        .context_at_level(0)
        .map_err(|error| make_zk_error(request, format!("RLK context: {error}")))?;
    let decrypt_errors = |name: &str,
                          rows: &[e3_crypto::SensitiveBytes]|
     -> Result<Vec<Poly<NttShoup>>, ComputeRequestError> {
        rows.iter()
            .enumerate()
            .map(|(row_index, row)| {
                let bytes = row.access(cipher).map_err(|error| {
                    make_zk_error(request, format!("{name}[{row_index}] decrypt: {error}"))
                })?;
                Poly::<NttShoup>::from_bytes(&bytes, context).map_err(|error| {
                    make_zk_error(request, format!("{name}[{row_index}] deserialize: {error}"))
                })
            })
            .collect()
    };
    let mut witness = RlkWitness {
        r: Zeroizing::new(r),
        errors_d0: decrypt_errors("errors_d0_bytes", &req.errors_d0_bytes)?,
        errors_d2: decrypt_errors("errors_d2_bytes", &req.errors_d2_bytes)?,
    };
    let data = RlkGenerationAdapter::new(req.params_preset)
        .and_then(|adapter| {
            adapter.row_data(
                req.committee_size.values(),
                req.proof_domain,
                req.party_id,
                req.row_index,
                &secret_key,
                &share,
                &witness,
            )
        })
        .map_err(|error| make_zk_error(request, error.to_string()));
    witness.errors_d0.zeroize();
    witness.errors_d2.zeroize();
    data
}

fn build_lbfv_pk_aggregation_data(
    req: &LbfvPkAggregationProofRequest,
    request: &ComputeRequest,
) -> Result<LbfvPkAggregationCircuitData, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, request)?;
    let committee = req.committee_size.values();
    validate_lbfv_aggregation_parties(&req.party_ids, req.share_bytes.len(), &committee, request)?;
    let (params, _) = build_pair_for_preset(req.params_preset)
        .map_err(|error| make_zk_error(request, format!("build_pair_for_preset: {error}")))?;
    let shares = req
        .share_bytes
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            LbfvPublicKeyShare::from_bytes(bytes, &params).map_err(|error| {
                make_zk_error(
                    request,
                    format!("share_bytes[{index}] deserialize: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LbfvPkAggregationCircuitData {
        committee,
        proof_domain: req.proof_domain,
        aggregator_party_id: req.aggregator_party_id,
        party_ids: req.party_ids.clone(),
        row_index: req.row_index,
        shares,
    })
}

fn build_rlk_aggregation_data(
    req: &RlkAggregationProofRequest,
    request: &ComputeRequest,
) -> Result<RlkAggregationCircuitData, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, request)?;
    let committee = req.committee_size.values();
    validate_lbfv_aggregation_parties(&req.party_ids, req.share_bytes.len(), &committee, request)?;
    let (params, _) = build_pair_for_preset(req.params_preset)
        .map_err(|error| make_zk_error(request, format!("build_pair_for_preset: {error}")))?;
    let shares = req
        .share_bytes
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            RelinKeyShare::from_bytes(bytes, &params).map_err(|error| {
                make_zk_error(
                    request,
                    format!("share_bytes[{index}] deserialize: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RlkAggregationCircuitData {
        committee,
        proof_domain: req.proof_domain,
        aggregator_party_id: req.aggregator_party_id,
        party_ids: req.party_ids.clone(),
        row_index: req.row_index,
        shares,
    })
}

fn validate_lbfv_aggregation_parties(
    party_ids: &[u32],
    share_count: usize,
    committee: &e3_zk_helpers::CiphernodesCommittee,
    request: &ComputeRequest,
) -> Result<(), ComputeRequestError> {
    if share_count != committee.h || party_ids.len() != committee.h {
        return Err(make_zk_error(
            request,
            format!(
                "l-BFV aggregation requires exactly {} party IDs and shares; received {} and {}",
                committee.h,
                party_ids.len(),
                share_count
            ),
        ));
    }
    if party_ids
        .iter()
        .any(|party_id| usize::try_from(*party_id).map_or(true, |id| id >= committee.n))
    {
        return Err(make_zk_error(
            request,
            format!(
                "l-BFV aggregation party IDs must be less than {}",
                committee.n
            ),
        ));
    }
    if party_ids.windows(2).any(|ids| ids[0] >= ids[1]) {
        return Err(make_zk_error(
            request,
            "l-BFV aggregation party IDs must be unique and strictly ascending".to_owned(),
        ));
    }
    Ok(())
}

fn handle_lbfv_pk_generation_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: LbfvPkGenerationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    req.validate_operation_id()
        .map_err(|error| make_zk_error(&request, error.to_string()))?;
    let data = build_lbfv_pk_generation_data(cipher, &req, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let limb_vk_hash = load_staged_lbfv_pk_generation_limb_vk_hash(prover, &artifacts_dir)
        .map_err(|error| make_zk_error(&request, error.to_string()))?;
    let proof = prove_lbfv_pk_generation_row(
        prover,
        req.params_preset,
        &data,
        &limb_vk_hash,
        &zk_bb_work_id(&request),
        &artifacts_dir,
    )
    .map(|row| row.terminal_proof)
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    let row_index = validated_row_instance(
        e3_events::ProofType::LbfvPkGeneration,
        &proof,
        req.row_index,
        req.params_preset,
        &request,
    )?;
    Ok(ComputeResponse::zk(
        ZkResponse::LbfvPkGeneration(LbfvPkGenerationProofResponse {
            operation_id: req.operation_id,
            proof,
            row_index,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_rlk_generation_proof(
    prover: &ZkProver,
    cipher: &Cipher,
    req: RlkGenerationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    req.validate_operation_id()
        .map_err(|error| make_zk_error(&request, error.to_string()))?;
    let data = build_rlk_generation_data(cipher, &req, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let limb_vk_hash =
        load_staged_rlk_generation_limb_vk_hash(prover, &artifacts_dir).map_err(|error| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
                request.clone(),
            )
        })?;
    let proof = prove_rlk_generation_row(
        prover,
        req.params_preset,
        &data,
        &limb_vk_hash,
        &zk_bb_work_id(&request),
        &artifacts_dir,
    )
    .map(|proofs| proofs.terminal_proof)
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    let row_index = validated_row_instance(
        e3_events::ProofType::RlkGeneration,
        &proof,
        req.row_index,
        req.params_preset,
        &request,
    )?;
    Ok(ComputeResponse::zk(
        ZkResponse::RlkGeneration(RlkGenerationProofResponse {
            operation_id: req.operation_id,
            proof,
            row_index,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_lbfv_pk_aggregation_proof(
    prover: &ZkProver,
    req: LbfvPkAggregationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    req.validate_operation_id()
        .map_err(|error| make_zk_error(&request, error.to_string()))?;
    let data = build_lbfv_pk_aggregation_data(&req, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = LbfvPkAggregationCircuit
        .prove(
            prover,
            &req.params_preset,
            &data,
            &zk_bb_work_id(&request),
            &artifacts_dir,
        )
        .map_err(|error| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
                request.clone(),
            )
        })?;
    let row_index = validated_row_instance(
        e3_events::ProofType::LbfvPkAggregation,
        &proof,
        req.row_index,
        req.params_preset,
        &request,
    )?;
    Ok(ComputeResponse::zk(
        ZkResponse::LbfvPkAggregation(LbfvPkAggregationProofResponse {
            operation_id: req.operation_id,
            proof,
            row_index,
            party_ids: req.party_ids,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_rlk_aggregation_proof(
    prover: &ZkProver,
    req: RlkAggregationProofRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    req.validate_operation_id()
        .map_err(|error| make_zk_error(&request, error.to_string()))?;
    let data = build_rlk_aggregation_data(&req, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = RlkAggregationCircuit
        .prove(
            prover,
            &req.params_preset,
            &data,
            &zk_bb_work_id(&request),
            &artifacts_dir,
        )
        .map_err(|error| {
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
                request.clone(),
            )
        })?;
    let row_index = validated_row_instance(
        e3_events::ProofType::RlkAggregation,
        &proof,
        req.row_index,
        req.params_preset,
        &request,
    )?;
    Ok(ComputeResponse::zk(
        ZkResponse::RlkAggregation(RlkAggregationProofResponse {
            operation_id: req.operation_id,
            proof,
            row_index,
            party_ids: req.party_ids,
        }),
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
        let circuit_data = e3_zk_helpers::threshold::share_decryption::ShareDecryptionCircuitData {
            ciphertext,
            public_key: public_key.clone(),
            s: s.clone(),
            e,
            d_share,
            domain_hi: domain.hi,
            domain_lo: domain.lo,
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
    debug!("STARTING MULTITHREAD `{}({})`", name, id);
    let start = Instant::now();
    let out = func();
    let dur = start.elapsed();
    debug!("FINISHED MULTITHREAD `{}`({}) in {:?}", name, id, dur);
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
            let mut rng_guard = match rng.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("Recovering the shared random generator after a TrBFV worker panic");
                    poisoned.into_inner()
                }
            };
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
            let mut rng_guard = match rng.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("Recovering the shared random generator after a TrBFV worker panic");
                    poisoned.into_inner()
                }
            };
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
        TrBFVRequest::GenLbfvKeyShares(req) => timefunc("gen_lbfv_key_shares", id, || {
            if let Err(error) = req.validate_operation_id() {
                return Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(TrBFVError::GenLbfvKeyShares(
                        TrBFVFailure::from_error(&error),
                    )),
                    request,
                ));
            }
            let mut job_rng = match lbfv_generation_rng(&cipher, &req.generation_seed) {
                Ok(rng) => rng,
                Err(error) => {
                    return Err(ComputeRequestError::new(
                        ComputeRequestErrorKind::TrBFV(TrBFVError::GenLbfvKeyShares(
                            TrBFVFailure::from_error(&error),
                        )),
                        request,
                    ));
                }
            };
            match gen_lbfv_key_shares(&mut job_rng, &cipher, req) {
                Ok(output) => Ok(ComputeResponse::trbfv(
                    TrBFVResponse::GenLbfvKeyShares(output),
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(error) => Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(TrBFVError::GenLbfvKeyShares(
                        TrBFVFailure::from_error(&error),
                    )),
                    request,
                )),
            }
        }),
    }
}

fn lbfv_generation_rng(
    cipher: &Cipher,
    encrypted_seed: &e3_crypto::SensitiveBytes,
) -> anyhow::Result<ChaCha20Rng> {
    let seed_bytes = encrypted_seed.access(cipher)?;
    anyhow::ensure!(
        seed_bytes.len() == 32,
        "l-BFV generation seed must contain exactly 32 bytes"
    );
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(rng)
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
                ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(
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
        ZkRequest::LbfvPkGeneration(req) => timefunc("zk_lbfv_pk_generation", id, || {
            handle_lbfv_pk_generation_proof(&prover, &cipher, req, request.clone())
        }),
        ZkRequest::RlkGeneration(req) => timefunc("zk_rlk_generation", id, || {
            handle_rlk_generation_proof(&prover, &cipher, req, request.clone())
        }),
        ZkRequest::LbfvPkAggregation(req) => timefunc("zk_lbfv_pk_aggregation", id, || {
            handle_lbfv_pk_aggregation_proof(&prover, req, request.clone())
        }),
        ZkRequest::RlkAggregation(req) => timefunc("zk_rlk_aggregation", id, || {
            handle_rlk_aggregation_proof(&prover, req, request.clone())
        }),
        ZkRequest::LbfvGenerationFold(req) => timefunc("zk_lbfv_generation_fold", id, || {
            handle_lbfv_generation_fold_proof(&prover, req, request.clone())
        }),
        ZkRequest::NodeDkgFoldV2(req) => timefunc("zk_node_dkg_fold_v2", id, || {
            handle_node_dkg_fold_v2_proof(&prover, req, request.clone())
        }),
        ZkRequest::NodesFoldV2Step(req) => timefunc("zk_nodes_fold_v2_step", id, || {
            handle_nodes_fold_v2_step_proof(&prover, req, request.clone())
        }),
        ZkRequest::LbfvAggregationFold(req) => timefunc("zk_lbfv_aggregation_fold", id, || {
            handle_lbfv_aggregation_fold_proof(&prover, req, request.clone())
        }),
        ZkRequest::DkgAggregationV2(req) => timefunc("zk_dkg_aggregation_v2", id, || {
            handle_dkg_aggregation_v2_proof(&prover, req, request.clone())
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

fn handle_lbfv_generation_fold_proof(
    prover: &ZkProver,
    req: LbfvGenerationFoldRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let trusted_pk_limb_key_hash =
        load_staged_lbfv_pk_generation_limb_vk_hash(prover, &artifacts_dir)
            .map_err(|error| make_zk_error(&request, error.to_string()))?;
    let proof = prove_lbfv_generation_fold_step_for_preset(
        prover,
        &req.pk_proof,
        &req.rlk_proof,
        req.prior_accumulator.as_ref(),
        req.row_index,
        &ArcBytes::from_bytes(&trusted_pk_limb_key_hash),
        &req.trusted_limb_key_hash,
        req.params_preset,
        &zk_bb_work_id(&request),
        artifacts_dir.as_str(),
    )
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::LbfvGenerationFold(LbfvGenerationFoldResponse { proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_node_dkg_fold_v2_proof(
    prover: &ZkProver,
    req: NodeDkgFoldV2Request,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = prove_node_dkg_fold_v2_for_preset(
        prover,
        &req.legacy_node_fold_proof,
        &req.c1_proof,
        &req.generation_proof,
        req.party_id,
        req.params_preset,
        req.committee_size,
        &zk_bb_work_id(&request),
        artifacts_dir.as_str(),
    )
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::NodeDkgFoldV2(NodeDkgFoldV2Response { proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_nodes_fold_v2_step_proof(
    prover: &ZkProver,
    req: NodesFoldV2StepRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, &request)?;
    info!(
        e3_id = %request.e3_id,
        slot = req.slot_index,
        total_slots = req.total_slots,
        "Multithread: proving NodesFoldV2Step"
    );
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = prove_nodes_fold_v2_step_for_preset(
        prover,
        &req.inner_proof,
        req.prior_accumulator.as_ref(),
        req.slot_index,
        req.total_slots,
        req.params_preset,
        req.committee_size,
        &format!("{}-nodesfold-v2-{}", req.e3_id, req.slot_index),
        artifacts_dir.as_str(),
    )
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    info!(
        e3_id = %request.e3_id,
        slot = req.slot_index,
        "Multithread: proved NodesFoldV2Step"
    );
    Ok(ComputeResponse::zk(
        ZkResponse::NodesFoldV2Step(NodesFoldV2StepResponse {
            accumulator_proof: proof,
        }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_lbfv_aggregation_fold_proof(
    prover: &ZkProver,
    req: LbfvAggregationFoldRequest,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, &request)?;
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());
    let proof = prove_lbfv_aggregation_fold_step_for_preset(
        prover,
        &req.pk_proof,
        &req.rlk_proof,
        req.prior_accumulator.as_ref(),
        req.row_index,
        req.committee_size.values().h,
        req.params_preset,
        &zk_bb_work_id(&request),
        artifacts_dir.as_str(),
    )
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::LbfvAggregationFold(LbfvAggregationFoldResponse { proof }),
        request.correlation_id,
        request.e3_id,
    ))
}

fn handle_dkg_aggregation_v2_proof(
    prover: &ZkProver,
    req: DkgAggregationV2Request,
    request: ComputeRequest,
) -> Result<ComputeResponse, ComputeRequestError> {
    ensure_lbfv_preset(req.params_preset, &request)?;
    let proof = prove_dkg_aggregation_v2(
        prover,
        &req.nodes_fold_proof,
        &req.c5_proof,
        &req.aggregation_fold_proof,
        &req.party_ids,
        &req.committee_addresses,
        &zk_bb_work_id(&request),
        req.params_preset,
        req.committee_size,
    )
    .map_err(|error| {
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkEventError::ProofGenerationFailed(error.to_string())),
            request.clone(),
        )
    })?;
    Ok(ComputeResponse::zk(
        ZkResponse::DkgAggregationV2(DkgAggregationV2Response { proof }),
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
    let lbfv_operation_id = match &request.request {
        ComputeRequestKind::TrBFV(request) => request.lbfv_operation_id(),
        ComputeRequestKind::Zk(request) => request.lbfv_operation_id(),
    };
    if let Some(operation_id) = lbfv_operation_id {
        return format!("lbfv_{operation_id}");
    }

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
        chunk_size: c2_chunk_size_for_preset(req.params_preset) as u32,
    };

    let bb_work = zk_bb_work_id(&request);
    let inner_job_id = format!("{bb_work}_c2_inner");
    let artifacts_dir =
        prover.resolve_artifacts_dir(req.params_preset, req.committee_size.as_str());

    // 7. Chunk proofs and terminal C2 projection. The production path uses the compiled default
    // chunk size; the `zk_cli --chunk-size` option does not reach this handler.
    let proof = prove_chunked_share_computation(
        prover,
        req.params_preset,
        &circuit_data,
        &inner_job_id,
        &artifacts_dir,
    )
    .map(|result| result.proof)
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
    let (threshold_params, dkg_params) = build_pair_for_preset(req.params_preset)
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

    let committee_n = req.committee_size.values().n;
    if req.recipient_party_id >= committee_n {
        return Err(make_zk_error(
            &request,
            format!(
                "recipient_party_id {} is outside committee size {}",
                req.recipient_party_id, committee_n
            ),
        ));
    }
    // C3 encrypts one threshold Shamir row per proof. The ciphertext itself uses DKG parameters,
    // but row_index belongs to the threshold secret's modulus domain.
    let n_moduli = threshold_params.moduli().len();
    if req.row_index >= n_moduli {
        return Err(make_zk_error(
            &request,
            format!(
                "row_index {} is outside modulus count {}",
                req.row_index, n_moduli
            ),
        ));
    }
    let party_idx = u32::try_from(req.recipient_party_id)
        .map_err(|e| make_zk_error(&request, format!("recipient_party_id: {e}")))?;
    let mod_idx = u32::try_from(req.row_index)
        .map_err(|e| make_zk_error(&request, format!("row_index: {e}")))?;

    // 4. Dummy SecretKey (not used by Inputs::compute)
    let dummy_sk = SecretKey::random(&dkg_params, &mut rand::rng());

    // 5. Build circuit data
    let committee_val = req.committee_size.values();
    let circuit_data = ShareEncryptionCircuitData {
        plaintext,
        ciphertext,
        public_key,
        secret_key: dummy_sk,
        u_rns,
        e0_rns,
        e1_rns,
        dkg_input_type: req.dkg_input_type,
        party_idx,
        mod_idx,
        chunk_size: c2_chunk_size_for_preset(req.params_preset) as u32,
        committee: committee_val,
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
    if req.recipient_party_id >= req.committee_size.values().n as u64 {
        return Err(make_zk_error(
            &request,
            format!(
                "recipient_party_id {} is outside committee N",
                req.recipient_party_id
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
        recipient_party_id: req.recipient_party_id,
        own_plaintext_share,
        dkg_input_type: req.dkg_input_type,
        chunk_size: c2_chunk_size_for_preset(req.params_preset) as u32,
        committee: req.committee_size.values(),
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

                // Bind C2 terminal proofs to their deployment-time VK anchors
                // before generic proof verification. A failure marks the signed
                // proof invalid, like any other ZK failure.
                let proof_type = signed_proof.payload.proof_type;
                if matches!(
                    proof_type,
                    e3_events::ProofType::C2aSkShareComputation
                        | e3_events::ProofType::C2bESmShareComputation
                ) {
                    let anchor_result = C2TerminalAnchors::load(prover, proof_type, &artifacts_dir)
                        .and_then(|anchors| {
                            validate_c2_terminal_proof(
                                req.params_preset,
                                req.committee_size,
                                proof_type,
                                &signed_proof.payload.proof,
                                &anchors,
                            )
                        });
                    if let Err(error) = anchor_result {
                        info!(
                            "C2 terminal proof VK binding failed for party {sender} ({proof_type:?}): {error}"
                        );
                        return PartyVerificationResult {
                            sender_party_id: sender,
                            all_verified: false,
                            failed_signed_payload: Some(signed_proof.clone()),
                            recovered_address: None,
                        };
                    }
                }

                if proof_type == e3_events::ProofType::RlkGeneration {
                    if let Err(error) = validate_rlk_generation_terminal_proof(
                        prover,
                        &signed_proof.payload.proof,
                        &artifacts_dir,
                    ) {
                        info!(
                            "RLK terminal proof VK binding failed for party {sender}: {error}"
                        );
                        return PartyVerificationResult {
                            sender_party_id: sender,
                            all_verified: false,
                            failed_signed_payload: Some(signed_proof.clone()),
                            recovered_address: None,
                        };
                    }
                }

                if proof_type == e3_events::ProofType::LbfvPkGeneration {
                    if let Err(error) = validate_lbfv_pk_generation_terminal_proof(
                        prover,
                        &signed_proof.payload.proof,
                        &artifacts_dir,
                    ) {
                        info!(
                            "l-BFV public-key terminal proof VK binding failed for party {sender}: {error}"
                        );
                        return PartyVerificationResult {
                            sender_party_id: sender,
                            all_verified: false,
                            failed_signed_payload: Some(signed_proof.clone()),
                            recovered_address: None,
                        };
                    }
                }

                // ZK proof verification
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

#[cfg(test)]
mod tests {
    use super::*;
    use e3_crypto::SensitiveBytes;
    use e3_events::CorrelationId;
    use e3_fhe_params::lbfv_crs_seed;
    use e3_trbfv::lbfv_operation::LbfvOperationId;
    use e3_utils::ArcBytes;
    use fhe::bfv::CommonRandomPolyVec;
    use fhe_math::rq::traits::TryConvertFrom;
    use fhe_traits::Serialize as FheSerialize;

    fn proof_domain() -> e3_committee_hash::LbfvProofDomainContext {
        e3_zk_helpers::threshold::lbfv_proof_domain::sample_lbfv_proof_domain()
    }

    fn compute_request(request: ZkRequest) -> ComputeRequest {
        ComputeRequest::zk(request, CorrelationId::new(), E3id::new("7", 1))
    }

    fn operation_id(value: u8) -> LbfvOperationId {
        LbfvOperationId([value; 32])
    }

    #[tokio::test]
    async fn lbfv_generation_rng_uses_the_encrypted_request_seed() {
        let cipher = Cipher::from_password("lbfv-generation-seed-test")
            .await
            .unwrap();
        let seed = SensitiveBytes::new([42; 32], &cipher).unwrap();
        let mut first = lbfv_generation_rng(&cipher, &seed).unwrap();
        let mut second = lbfv_generation_rng(&cipher, &seed).unwrap();
        let first_bytes: [u8; 64] = first.random();
        let second_bytes: [u8; 64] = second.random();

        assert_eq!(first_bytes, second_bytes);
        assert!(
            lbfv_generation_rng(&cipher, &SensitiveBytes::new([1; 31], &cipher).unwrap()).is_err()
        );
    }

    #[test]
    fn lbfv_work_id_uses_the_stable_operation_id() {
        let mut request_data = LbfvPkGenerationProofRequest {
            operation_id: operation_id(0),
            proof_domain: proof_domain(),
            party_id: 1,
            public_key_share_bytes: ArcBytes::from_bytes(&[3]),
            secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
            row_index: 2,
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        request_data.operation_id = request_data.expected_operation_id();
        let first = compute_request(ZkRequest::LbfvPkGeneration(request_data.clone()));
        let retry = compute_request(ZkRequest::LbfvPkGeneration(request_data));

        assert_eq!(zk_bb_work_id(&first), zk_bb_work_id(&retry));
        assert!(zk_bb_work_id(&first).starts_with("lbfv_"));
    }

    #[tokio::test]
    async fn builds_lbfv_pk_generation_data_from_serialized_request() {
        let preset = BfvPreset::SecureThreshold16384;
        let committee_size = CiphernodesCommitteeSize::Minimum;
        let (params, _) = build_pair_for_preset(preset).unwrap();
        let crp = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(preset).unwrap()).unwrap();
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key_share =
            LbfvPublicKeyShare::contribute_with_crp(&secret_key, &crp, &mut rng).unwrap();
        let c1_secret = Poly::<PowerBasis>::try_convert_from(
            secret_key.coeffs.as_ref(),
            params.context_at_level(0).unwrap(),
            false,
        )
        .unwrap();
        let cipher = Cipher::from_password("lbfv-row-test").await.unwrap();
        let request_data = LbfvPkGenerationProofRequest {
            operation_id: operation_id(1),
            proof_domain: proof_domain(),
            party_id: 0,
            public_key_share_bytes: ArcBytes::from_bytes(&public_key_share.to_bytes()),
            secret_key_bytes: SensitiveBytes::new(c1_secret.to_bytes(), &cipher).unwrap(),
            row_index: 3,
            params_preset: preset,
            committee_size,
        };
        let request = compute_request(ZkRequest::LbfvPkGeneration(request_data.clone()));

        let data = build_lbfv_pk_generation_data(&cipher, &request_data, &request).unwrap();

        assert_eq!(data.row_index, request_data.row_index);
        assert_eq!(data.committee, committee_size.values());
        assert_eq!(data.pk0_share.limbs.len(), preset.metadata().num_moduli);
    }

    #[test]
    fn lbfv_pk_aggregation_accepts_canonical_party_order() {
        let preset = BfvPreset::SecureThreshold16384;
        let committee_size = CiphernodesCommitteeSize::Minimum;
        let sample = LbfvPkAggregationCircuitData::generate_sample_for_row(
            preset,
            committee_size.values(),
            2,
        )
        .unwrap();
        let request_data = LbfvPkAggregationProofRequest {
            operation_id: operation_id(2),
            proof_domain: sample.proof_domain,
            aggregator_party_id: sample.aggregator_party_id,
            party_ids: vec![0, 1],
            share_bytes: sample
                .shares
                .iter()
                .map(|share| ArcBytes::from_bytes(&share.to_bytes()))
                .collect(),
            row_index: 2,
            params_preset: preset,
            committee_size,
        };
        let request = compute_request(ZkRequest::LbfvPkAggregation(request_data.clone()));

        let data = build_lbfv_pk_aggregation_data(&request_data, &request).unwrap();

        assert_eq!(data.shares, sample.shares);
    }

    #[tokio::test]
    async fn lbfv_builders_reject_unsupported_presets_and_invalid_counts() {
        let cipher = Cipher::from_password("lbfv-row-errors").await.unwrap();
        let unsupported = LbfvPkGenerationProofRequest {
            operation_id: operation_id(1),
            proof_domain: proof_domain(),
            party_id: 0,
            public_key_share_bytes: ArcBytes::from_bytes(&[]),
            secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
            row_index: 0,
            params_preset: BfvPreset::SecureThreshold8192,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        let request = compute_request(ZkRequest::LbfvPkGeneration(unsupported.clone()));
        assert!(build_lbfv_pk_generation_data(&cipher, &unsupported, &request).is_err());

        let wrong_pk_count = LbfvPkAggregationProofRequest {
            operation_id: operation_id(2),
            proof_domain: proof_domain(),
            aggregator_party_id: 0,
            party_ids: vec![0],
            share_bytes: vec![ArcBytes::from_bytes(&[])],
            row_index: 0,
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        let request = compute_request(ZkRequest::LbfvPkAggregation(wrong_pk_count.clone()));
        assert!(build_lbfv_pk_aggregation_data(&wrong_pk_count, &request).is_err());

        let wrong_rlk_count = RlkAggregationProofRequest {
            operation_id: operation_id(3),
            proof_domain: proof_domain(),
            aggregator_party_id: 0,
            party_ids: vec![0],
            share_bytes: vec![ArcBytes::from_bytes(&[])],
            row_index: 0,
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        let request = compute_request(ZkRequest::RlkAggregation(wrong_rlk_count.clone()));
        assert!(build_rlk_aggregation_data(&wrong_rlk_count, &request).is_err());

        for party_ids in [vec![0, 0], vec![1, 0], vec![0, 3]] {
            let noncanonical = LbfvPkAggregationProofRequest {
                operation_id: operation_id(2),
                proof_domain: proof_domain(),
                aggregator_party_id: 0,
                party_ids,
                share_bytes: vec![ArcBytes::from_bytes(&[]); 2],
                row_index: 0,
                params_preset: BfvPreset::SecureThreshold16384,
                committee_size: CiphernodesCommitteeSize::Minimum,
            };
            let request = compute_request(ZkRequest::LbfvPkAggregation(noncanonical.clone()));
            assert!(build_lbfv_pk_aggregation_data(&noncanonical, &request).is_err());
        }

        let incomplete_witness = RlkGenerationProofRequest {
            operation_id: operation_id(4),
            proof_domain: proof_domain(),
            party_id: 0,
            rlk_share_bytes: ArcBytes::from_bytes(&[]),
            secret_key_bytes: SensitiveBytes::from_encrypted(&[]),
            r_bytes: SensitiveBytes::from_encrypted(&[]),
            errors_d0_bytes: Vec::new(),
            errors_d2_bytes: Vec::new(),
            row_index: 0,
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        let request = compute_request(ZkRequest::RlkGeneration(incomplete_witness.clone()));
        assert!(build_rlk_generation_data(&cipher, &incomplete_witness, &request).is_err());
    }
}
