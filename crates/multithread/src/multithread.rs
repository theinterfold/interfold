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
use anyhow::Result;
use e3_crypto::Cipher;
use e3_events::trap_fut;

#[cfg(test)]
use e3_committee::CiphernodesCommitteeSize;
use e3_events::EType;
use e3_events::{
    BusHandle, ComputeRequest, ComputeRequestError, ComputeRequestErrorKind, ComputeRequestKind,
    ComputeResponse, E3Stage, E3id, EventPublisher, EventSubscriber, EventType, InterfoldEvent,
    InterfoldEventData, TypedEvent, ZkError as ZkEventError, ZkRequest,
};
#[cfg(test)]
use e3_events::{PkBfvProofRequest, VerifyShareProofsRequest};
#[cfg(test)]
use e3_fhe_params::BfvPreset;
#[cfg(test)]
use e3_trbfv::TrBFVFailure;
use e3_trbfv::{TrBFVError, TrBFVRequest};
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
use e3_zk_helpers::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuit;
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuitData;
use e3_zk_helpers::CiphernodesCommittee;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::DEFAULT_C2_CHUNK_SIZE;
use e3_zk_prover::{
    generate_nodes_fold_step, prove_chunked_share_computation, prove_decryption_aggregation_jobs,
    prove_dkg_aggregation, prove_node_dkg_fold, validate_c2_terminal_proof, C2TerminalAnchors,
    CircuitVariant, DecryptionAggregationJob, DkgAggregationInput, NodeDkgFoldInput,
    NodeDkgFoldProveResult, Provable, ZkBackend, ZkError, ZkProver,
};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::PublicKeyShare;
use fhe_math::rq::PowerBasis;
use fhe_traits::{DeserializeParametrized, FheEncoder};
use ndarray::Array2;
use num_bigint::BigInt;
use rand::Rng;
use tracing::{debug, error, info, warn};

use crate::effect_gate::{ComputeEffectGate, RunningJob, RunningJobs};

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
    /// The requests that this worker runs, which the effect gate reads.
    running: RunningJobs,
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
            running: RunningJobs::default(),
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

    #[allow(clippy::too_many_arguments)]
    pub fn attach(
        bus: &BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        task_scope: String,
        report: Option<Addr<MultithreadReport>>,
        lifecycle_stages: HashMap<E3id, E3Stage>,
        canonical_keys: e3_request::canonical_key::CanonicalPublicKeys,
    ) -> Addr<Self> {
        let actor = Self::new(
            bus.clone(),
            rng.clone(),
            cipher.clone(),
            task_pool,
            task_scope,
            report,
        );
        let running = actor.running.clone();
        let addr = actor.start();

        Self::subscribe_to_lifecycle(bus, &addr);
        ComputeEffectGate::attach(
            bus,
            addr.clone().recipient(),
            lifecycle_stages,
            canonical_keys,
            running,
        );
        info!("Multithread actor waiting behind the replay-safe effect gate.");

        addr
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attach_with_zk(
        bus: &BusHandle,
        rng: SharedRng,
        cipher: Arc<Cipher>,
        task_pool: TaskPool,
        task_scope: String,
        report: Option<Addr<MultithreadReport>>,
        zk_backend: &ZkBackend,
        lifecycle_stages: HashMap<E3id, E3Stage>,
        canonical_keys: e3_request::canonical_key::CanonicalPublicKeys,
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
        let running = actor.running.clone();
        let addr = actor.start();
        Self::subscribe_to_lifecycle(bus, &addr);

        ComputeEffectGate::attach(
            bus,
            addr.clone().recipient(),
            lifecycle_stages,
            canonical_keys,
            running,
        );
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
}

fn task_group(scope: &str, e3_id: &E3id) -> String {
    e3_task_pool::scoped_task_group(scope, e3_id)
}

/// Accusation re-verification outlives a failed E3, so it runs in its own group. A cancelled
/// group stays cancelled, so the failure could not spare it in the E3's group.
fn accusation_task_group(scope: &str, e3_id: &E3id) -> String {
    format!("{scope}:{e3_id}:accusation")
}

fn request_task_group(scope: &str, request: &ComputeRequest) -> String {
    match request.request {
        ComputeRequestKind::Zk(ZkRequest::ReverifyAccusedProof(_)) => {
            accusation_task_group(scope, &request.e3_id)
        }
        _ => task_group(scope, &request.e3_id),
    }
}

/// The task groups of the work that `event` ends. A failure ends the protocol work; the end of the
/// request also ends its accusation work.
fn ended_task_groups(scope: &str, event: &InterfoldEventData) -> Vec<String> {
    let (e3_id, ends_accusations) = match event {
        InterfoldEventData::E3Failed(data) => (&data.e3_id, false),
        InterfoldEventData::E3StageChanged(data) if data.new_stage == E3Stage::Failed => {
            (&data.e3_id, false)
        }
        InterfoldEventData::E3StageChanged(data) if data.new_stage.is_terminal() => {
            (&data.e3_id, true)
        }
        InterfoldEventData::E3RequestComplete(data) => (&data.e3_id, true),
        _ => return Vec::new(),
    };
    let mut groups = vec![task_group(scope, e3_id)];
    if ends_accusations {
        groups.push(accusation_task_group(scope, e3_id));
    }
    groups
}

#[cfg(test)]
mod task_group_tests {
    use super::*;

    #[test]
    fn a_failure_ends_protocol_work_and_the_request_end_ends_accusation_work() {
        let e3_id = E3id::new("7", 1);
        let protocol = task_group("node", &e3_id);
        let accusation = accusation_task_group("node", &e3_id);
        let stage = |new_stage| {
            InterfoldEventData::from(e3_events::E3StageChanged {
                e3_id: e3_id.clone(),
                previous_stage: E3Stage::CommitteeFinalized,
                new_stage,
            })
        };
        let failed = InterfoldEventData::from(e3_events::E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: e3_events::FailureReason::DKGInvalidShares,
        });
        let complete = InterfoldEventData::from(e3_events::E3RequestComplete {
            e3_id: e3_id.clone(),
        });

        assert_eq!(ended_task_groups("node", &failed), vec![protocol.clone()]);
        assert_eq!(
            ended_task_groups("node", &stage(E3Stage::Failed)),
            vec![protocol.clone()]
        );
        let both = vec![protocol.clone(), accusation.clone()];
        assert_eq!(ended_task_groups("node", &complete), both);
        assert_eq!(ended_task_groups("node", &stage(E3Stage::Complete)), both);
        assert!(ended_task_groups("node", &stage(E3Stage::KeyPublished)).is_empty());

        let request =
            |kind| ComputeRequest::zk(kind, e3_events::CorrelationId::new(), e3_id.clone());
        let proofs = VerifyShareProofsRequest {
            party_proofs: vec![],
            params_preset: e3_fhe_params::BfvPreset::default(),
            committee_size: e3_committee::CiphernodesCommitteeSize::Micro,
        };
        assert_eq!(
            request_task_group(
                "node",
                &request(ZkRequest::ReverifyAccusedProof(proofs.clone()))
            ),
            accusation
        );
        assert_eq!(
            request_task_group("node", &request(ZkRequest::VerifyShareProofs(proofs))),
            protocol
        );
    }

    /// Through the worker and a real task pool: a failure cancels the E3's protocol work, its
    /// accusation work still runs, and the end of the request cancels that too. Without a prover,
    /// a ZK request that runs ends with an error result at once; a cancelled one ends with none.
    #[actix::test]
    async fn a_failure_cancels_protocol_work_and_leaves_accusation_work_until_the_request_ends(
    ) -> anyhow::Result<()> {
        use e3_events::{
            CorrelationId, E3Failed, E3RequestComplete, Event, EventConstructorWithTimestamp,
            EventSource, FailureReason, GetEvents, Unsequenced,
        };
        use rand::SeedableRng;

        let (bus, history) = crate::effect_gate::tests::test_bus();
        let rng: SharedRng = Arc::new(Mutex::new(rand_chacha::ChaCha20Rng::seed_from_u64(7)));
        let cipher = Arc::new(Cipher::from_password("test-password").await?);
        let worker = Multithread::new(
            bus,
            rng,
            cipher,
            TaskPool::new(1, 8),
            "node".to_string(),
            None,
        )
        .start();
        let e3_id = E3id::new("7", 1);
        let proofs = VerifyShareProofsRequest {
            party_proofs: vec![],
            params_preset: e3_fhe_params::BfvPreset::default(),
            committee_size: e3_committee::CiphernodesCommitteeSize::Micro,
        };
        let request = |kind| ComputeRequest::zk(kind, CorrelationId::new(), e3_id.clone());
        let event = |data: InterfoldEventData, seq: u64| {
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                data,
                None,
                seq.into(),
                None,
                EventSource::Local,
            )
            .into_sequenced(seq)
        };
        let results = || async {
            let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
            Ok::<_, anyhow::Error>(
                events
                    .iter()
                    .filter_map(|event| match event.get_data() {
                        InterfoldEventData::ComputeRequestError(error) => {
                            Some(error.request().correlation_id)
                        }
                        InterfoldEventData::ComputeResponse(response) => {
                            Some(response.correlation_id)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };

        let failed = E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGInvalidShares,
        };
        worker.send(event(failed.into(), 1)).await?;
        let accusation = request(ZkRequest::ReverifyAccusedProof(proofs.clone()));
        let protocol = request(ZkRequest::VerifyShareProofs(proofs.clone()));
        worker.send(event(accusation.clone().into(), 2)).await?;
        worker.send(event(protocol.into(), 3)).await?;
        actix::clock::sleep(Duration::from_millis(200)).await;
        assert_eq!(results().await?, vec![accusation.correlation_id]);

        let complete = E3RequestComplete {
            e3_id: e3_id.clone(),
        };
        worker.send(event(complete.into(), 4)).await?;
        let late = request(ZkRequest::ReverifyAccusedProof(proofs));
        worker.send(event(late.into(), 5)).await?;
        actix::clock::sleep(Duration::from_millis(200)).await;
        assert_eq!(results().await?, vec![accusation.correlation_id]);
        Ok(())
    }

    /// The worker notes a request as running from its intake until its result, also while the
    /// request waits in the pool's queue, so the effect gate does not send it again meanwhile.
    #[actix::test]
    async fn a_request_runs_from_its_intake_until_its_result() -> anyhow::Result<()> {
        use e3_events::{CorrelationId, EventConstructorWithTimestamp, EventSource, Unsequenced};
        use rand::SeedableRng;

        let (bus, _history) = crate::effect_gate::tests::test_bus();
        let rng: SharedRng = Arc::new(Mutex::new(rand_chacha::ChaCha20Rng::seed_from_u64(7)));
        let cipher = Arc::new(Cipher::from_password("test-password").await?);
        let pool = TaskPool::new(1, 8);
        let worker = Multithread::new(bus, rng, cipher, pool.clone(), "node".to_string(), None);
        let running = worker.running.clone();
        let worker = worker.start();

        // A long task holds the pool's one thread, so the request waits in the queue.
        let blocked = actix::spawn(async move {
            pool.spawn("blocker".to_string(), TaskTimeouts::default(), || {
                thread::sleep(Duration::from_millis(400))
            })
            .await
        });
        actix::clock::sleep(Duration::from_millis(50)).await;
        let request = ComputeRequest::zk(
            ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
                party_proofs: vec![],
                params_preset: e3_fhe_params::BfvPreset::default(),
                committee_size: e3_committee::CiphernodesCommitteeSize::Micro,
            }),
            CorrelationId::new(),
            E3id::new("7", 1),
        );
        let id = request.correlation_id;
        worker
            .send(
                InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    request.into(),
                    None,
                    1,
                    None,
                    EventSource::Local,
                )
                .into_sequenced(1),
            )
            .await?;
        actix::clock::sleep(Duration::from_millis(100)).await;
        assert!(running.any(&[id]), "a queued request runs");

        // Without a prover, the request ends with an error result once it gets the thread.
        blocked.await?.map_err(|error| anyhow::anyhow!("{error}"))?;
        actix::clock::sleep(Duration::from_millis(200)).await;
        assert!(
            !running.any(&[id]),
            "a request with a result no longer runs"
        );
        Ok(())
    }

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
                BfvPreset::InsecureThreshold64,
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
        if let InterfoldEventData::ComputeRequest(data) = data {
            ctx.notify(TypedEvent::new(data, ec));
            return;
        }
        for group in ended_task_groups(&self.task_scope, &data) {
            self.task_pool.cancel_group(&group);
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
        // The request runs, queued or in a worker, until its future ends.
        let running = self.running.start(msg.correlation_id);
        trap_fut(
            EType::Computation,
            &self.bus.clone(),
            handle_compute_request_event(
                msg, bus, cipher, rng, pool, task_scope, report, zk_prover, retry_logs, running,
            ),
        )
    }
}

#[allow(clippy::too_many_arguments)]
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
    _running: RunningJob,
) -> anyhow::Result<()> {
    let msg_string = msg.to_string();
    let job_name = msg_string.clone();
    let (msg, ctx) = msg.into_components();
    let request_snapshot = msg.clone();
    let task_group = request_task_group(&task_scope, &msg);

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
        ComputeRequestKind::TrBFV(trbfv_request) => ComputeRequestErrorKind::TrBFV(
            trbfv_request.failure(format!("Pool error: {pool_error}").into()),
        ),
    }
}

fn timefunc<F, T>(name: &str, id: u8, func: F) -> (T, Duration)
where
    F: FnOnce() -> T,
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

    match &request.request {
        ComputeRequestKind::TrBFV(trbfv_req) => {
            let (result, duration) = timefunc(trbfv_req.operation_name(), id, || {
                trbfv_req.execute(&rng, &cipher)
            });
            let result = match result {
                Ok(response) => Ok(ComputeResponse::trbfv(
                    response,
                    request.correlation_id,
                    request.e3_id,
                )),
                Err(error) => Err(ComputeRequestError::new(
                    ComputeRequestErrorKind::TrBFV(error),
                    request,
                )),
            };
            (result, duration)
        }
        ComputeRequestKind::Zk(kind) => {
            let Some(prover) = zk_prover else {
                return (
                    Err(ComputeRequestError::new(
                        ComputeRequestErrorKind::Zk(ZkEventError::InvalidParams(
                            "ZK prover not configured".to_string(),
                        )),
                        request,
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
        chunk_size: DEFAULT_C2_CHUNK_SIZE as u32,
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
        chunk_size: DEFAULT_C2_CHUNK_SIZE as u32,
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
    if req.recipient_party_id >= req.committee_size.values().n as u64 {
        return Err(make_zk_error(
            &request,
            format!(
                "recipient_party_id {} is outside committee N",
                req.recipient_party_id
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
        recipient_party_id: req.recipient_party_id,
        own_plaintext_share,
        dkg_input_type: req.dkg_input_type,
        chunk_size: DEFAULT_C2_CHUNK_SIZE as u32,
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
                })
            })
        }
    }
}
