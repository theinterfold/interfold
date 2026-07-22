// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use rayon::ThreadPool;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;
use tokio::{sync::Semaphore, task::JoinHandle, time::sleep};
use tracing::{debug, error, info, warn, Level};

const DEFAULT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_EXECUTION_DEADLINE: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadlineAction {
    /// A running CPU closure cannot be safely interrupted. Production therefore fails the process
    /// closed and lets the OS reclaim all worker resources at once.
    AbortProcess,
    #[cfg(test)]
    ReturnError,
}

/// Bounded waiting and execution policy for CPU jobs.
#[derive(Debug, Clone, Copy)]
pub struct TaskPoolPolicy {
    admission_timeout: Duration,
    execution_deadline: Duration,
    deadline_action: DeadlineAction,
}

impl TaskPoolPolicy {
    pub fn fail_stop(admission_timeout: Duration, execution_deadline: Duration) -> Self {
        assert!(
            !admission_timeout.is_zero(),
            "admission timeout must be positive"
        );
        assert!(
            !execution_deadline.is_zero(),
            "execution deadline must be positive"
        );
        Self {
            admission_timeout,
            execution_deadline,
            deadline_action: DeadlineAction::AbortProcess,
        }
    }

    #[cfg(test)]
    fn return_error(admission_timeout: Duration, execution_deadline: Duration) -> Self {
        Self {
            admission_timeout,
            execution_deadline,
            deadline_action: DeadlineAction::ReturnError,
        }
    }
}

impl Default for TaskPoolPolicy {
    fn default() -> Self {
        Self::fail_stop(DEFAULT_ADMISSION_TIMEOUT, DEFAULT_EXECUTION_DEADLINE)
    }
}

/// A bounded executor for CPU-bound tasks backed by a Rayon thread pool.
#[derive(Debug, Clone)]
pub struct TaskPool {
    semaphore: Arc<Semaphore>,
    thread_pool: Arc<ThreadPool>,
    policy: TaskPoolPolicy,
}

#[derive(Debug, Error)]
pub enum TaskPoolError {
    #[error("{0}")]
    SemaphoreError(String),

    #[error("{0}")]
    RecvError(RecvError),

    #[error("Task panicked: {0}")]
    Panic(String),

    #[error("Task '{task_name}' was not admitted within {timeout:?}")]
    AdmissionTimeout {
        task_name: String,
        timeout: Duration,
    },

    #[error("Task '{task_name}' exceeded its hard execution deadline of {deadline:?}")]
    ExecutionDeadline {
        task_name: String,
        deadline: Duration,
    },
}

struct RunningTaskGuard {
    task_name: String,
    finished: Arc<AtomicBool>,
    action: DeadlineAction,
    armed: bool,
}

impl RunningTaskGuard {
    fn enforce_deadline(&self, reason: &str) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        error!(
            task = %self.task_name,
            %reason,
            "CPU task outlived its bounded async owner"
        );
        match self.action {
            DeadlineAction::AbortProcess => std::process::abort(),
            #[cfg(test)]
            DeadlineAction::ReturnError => {}
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RunningTaskGuard {
    fn drop(&mut self) {
        if self.armed {
            self.enforce_deadline("request future was cancelled while CPU work was still running");
        }
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl TaskPool {
    /// Creates a new pool with `threads` worker threads and at most `max_tasks` concurrent tasks.
    pub fn new(threads: usize, max_tasks: usize) -> TaskPool {
        Self::new_with_policy(threads, max_tasks, TaskPoolPolicy::default())
    }

    pub fn new_with_policy(threads: usize, max_tasks: usize, policy: TaskPoolPolicy) -> TaskPool {
        assert!(
            threads > 0,
            "task pool must have at least one worker thread"
        );
        assert!(max_tasks > 0, "task pool must admit at least one task");
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("Failed to build thread pool");

        Self {
            thread_pool: Arc::new(thread_pool),
            semaphore: Arc::new(Semaphore::new(max_tasks)),
            policy,
        }
    }

    pub async fn spawn<OP, T: Debug + Send + 'static>(
        &self,
        task_name: String,
        timed_logs: impl Into<TaskTimeouts>, // [(10, Level::WARN), (30, Level::ERROR)]
        op: OP,
    ) -> Result<T, TaskPoolError>
    where
        OP: FnOnce() -> T + Send + 'static,
    {
        let timeouts = timed_logs.into();
        // Limit the requests and get them to block
        let _permit = tokio::time::timeout(self.policy.admission_timeout, self.semaphore.acquire())
            .await
            .map_err(|_| TaskPoolError::AdmissionTimeout {
                task_name: task_name.clone(),
                timeout: self.policy.admission_timeout,
            })?
            .map_err(|_| TaskPoolError::SemaphoreError(task_name.to_owned()))?;

        // Warn of long running jobs
        let warning_task_name = task_name.clone();
        let _warning_handle = AbortOnDrop(tokio::spawn(async move {
            let mut elapsed = Duration::ZERO;

            for log in timeouts.iter() {
                let target = Duration::from_secs(log.0);

                // Sleep only for the remaining time to reach target
                if target > elapsed {
                    sleep(target - elapsed).await;
                    elapsed = target;
                }
                let msg = format!(
                    "Job '{}' has been running for {:?}",
                    warning_task_name, target
                );
                match log.1 {
                    Level::WARN => warn!(msg),
                    Level::ERROR => error!(msg),
                    Level::INFO => info!(msg),
                    Level::DEBUG => debug!(msg),
                    _ => (),
                }
            }

            let heartbeat = Duration::from_secs(60);
            loop {
                sleep(heartbeat).await;
                elapsed += heartbeat;
                warn!(
                    "Job '{}' still running after {:?}",
                    warning_task_name, elapsed
                );
            }
        }));

        // This uses channels to track pending and complete tasks when
        // using the thread pool
        let (tx, rx) = tokio::sync::oneshot::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = finished.clone();
        self.thread_pool.spawn(move || {
            // Catch panics inside the Rayon thread so we can report them
            // as errors instead of silently dropping the oneshot sender.
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(op)) {
                Ok(t) => Ok(t),
                Err(panic_info) => {
                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    error!("Rayon task panicked: {}", panic_msg);
                    Err(TaskPoolError::Panic(panic_msg))
                }
            };
            // Publish completion before waking the async owner. A cancellation racing the channel
            // wake must not mistake a completed closure for an orphan and abort the process.
            worker_finished.store(true, Ordering::Release);
            if let Err(res) = tx.send(result) {
                error!(
                    "There was an error sending the result from the multithread actor: result = {:?}",
                    res
                );
            }
        });

        let mut guard = RunningTaskGuard {
            task_name: task_name.clone(),
            finished,
            action: self.policy.deadline_action,
            armed: true,
        };
        let deadline = self.policy.execution_deadline;
        let result = tokio::time::timeout(deadline, rx).await;
        let output = match result {
            Ok(received) => {
                guard.disarm();
                received.map_err(TaskPoolError::RecvError)??
            }
            Err(_) => {
                guard.enforce_deadline("hard execution deadline elapsed");
                guard.disarm();
                return Err(TaskPoolError::ExecutionDeadline {
                    task_name,
                    deadline,
                });
            }
        };

        Ok(output)
    }
}

#[derive(Debug, Clone)]
pub struct TaskTimeouts(pub Vec<TimedLog>);

impl<const N: usize> From<[(u64, Level); N]> for TaskTimeouts {
    fn from(arr: [(u64, Level); N]) -> Self {
        Self(arr.into_iter().map(|(s, l)| TimedLog(s, l)).collect())
    }
}

impl Deref for TaskTimeouts {
    type Target = Vec<TimedLog>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TaskTimeouts {
    pub fn new(logs: Vec<TimedLog>) -> Self {
        Self(logs)
    }
}

impl Default for TaskTimeouts {
    fn default() -> Self {
        [(30, Level::INFO), (120, Level::WARN)].into()
    }
}

impl From<(u64, Level)> for TimedLog {
    fn from((s, level): (u64, Level)) -> Self {
        Self(s, level)
    }
}

#[derive(Debug, Clone)]
pub struct TimedLog(pub u64, pub tracing::Level);

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::mpsc;

    const ABORT_CHILD_ENV: &str = "E3_TASK_POOL_ABORT_CHILD";

    fn diagnostic_policy(admission_ms: u64, execution_ms: u64) -> TaskPoolPolicy {
        TaskPoolPolicy::return_error(
            Duration::from_millis(admission_ms),
            Duration::from_millis(execution_ms),
        )
    }

    #[tokio::test]
    async fn panicking_job_is_reported() {
        let pool = TaskPool::new_with_policy(1, 1, diagnostic_policy(100, 100));
        let result = pool
            .spawn("panic".to_string(), TaskTimeouts::new(vec![]), || {
                panic!("boom")
            })
            .await;
        assert!(matches!(result, Err(TaskPoolError::Panic(message)) if message == "boom"));
    }

    #[tokio::test]
    async fn queued_job_has_a_bounded_admission_wait() {
        let pool = TaskPool::new_with_policy(1, 1, diagnostic_policy(20, 500));
        let first_pool = pool.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            first_pool
                .spawn("first".to_string(), TaskTimeouts::new(vec![]), move || {
                    let _ = started_tx.send(());
                    std::thread::sleep(Duration::from_millis(100));
                    1
                })
                .await
        });
        started_rx.await.expect("first task should start");

        let second = pool
            .spawn("second".to_string(), TaskTimeouts::new(vec![]), || 2)
            .await;
        assert!(matches!(
            second,
            Err(TaskPoolError::AdmissionTimeout { .. })
        ));
        assert_eq!(
            first.await.expect("first owner task should join").unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn execution_deadline_releases_admission_permit() {
        let pool = TaskPool::new_with_policy(2, 1, diagnostic_policy(100, 20));
        let (release_tx, release_rx) = mpsc::channel();
        let result = pool
            .spawn("hung".to_string(), TaskTimeouts::new(vec![]), move || {
                let _ = release_rx.recv();
                1
            })
            .await;
        assert!(matches!(
            result,
            Err(TaskPoolError::ExecutionDeadline { .. })
        ));

        assert_eq!(
            pool.spawn("next".to_string(), TaskTimeouts::new(vec![]), || 2)
                .await
                .unwrap(),
            2
        );
        release_tx.send(()).expect("release timed-out worker");
    }

    #[tokio::test]
    async fn cancelling_owner_releases_permit_and_does_not_leave_warning_task() {
        let pool = TaskPool::new_with_policy(2, 1, diagnostic_policy(100, 500));
        let owner_pool = pool.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let owner = tokio::spawn(async move {
            owner_pool
                .spawn(
                    "cancelled".to_string(),
                    TaskTimeouts::default(),
                    move || {
                        let _ = started_tx.send(());
                        let _ = release_rx.recv();
                    },
                )
                .await
        });
        started_rx.await.expect("cancelled task should start");
        owner.abort();
        let _ = owner.await;

        assert_eq!(
            pool.spawn("next".to_string(), TaskTimeouts::new(vec![]), || 3)
                .await
                .unwrap(),
            3
        );
        release_tx.send(()).expect("release cancelled worker");
    }

    #[test]
    fn production_deadline_aborts_process() {
        if std::env::var_os(ABORT_CHILD_ENV).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("build child runtime");
            runtime.block_on(async {
                let pool = TaskPool::new_with_policy(
                    1,
                    1,
                    TaskPoolPolicy::fail_stop(
                        Duration::from_millis(100),
                        Duration::from_millis(10),
                    ),
                );
                let _ = pool
                    .spawn("must-abort".to_string(), TaskTimeouts::new(vec![]), || {
                        std::thread::sleep(Duration::from_secs(5));
                    })
                    .await;
            });
            panic!("fail-stop deadline returned instead of aborting");
        }

        let status =
            Command::new(std::env::current_exe().expect("resolve current test executable"))
                .args([
                    "--exact",
                    "pool::tests::production_deadline_aborts_process",
                    "--nocapture",
                ])
                .env(ABORT_CHILD_ENV, "1")
                .status()
                .expect("run fail-stop child process");
        assert!(!status.success(), "deadline child must terminate non-zero");
    }
}
