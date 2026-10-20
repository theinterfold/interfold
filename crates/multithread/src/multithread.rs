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
use e3_zk_prover::{execute_zk_request, zk_operation_name, ZkBackend, ZkProver};
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
                    Duration::ZERO,
                );
            };
            timefunc(zk_operation_name(kind), id, || {
                execute_zk_request(&prover, &cipher, request, &mut |step| {
                    if let Some(report) = report.as_ref() {
                        report.do_send(TrackDuration::new(
                            format!("NodeDkgFold/{}", step.step),
                            Duration::from_secs_f64(step.seconds),
                        ));
                    }
                })
            })
        }
    }
}
