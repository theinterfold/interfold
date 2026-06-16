// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use rayon::ThreadPool;
use std::fmt::Debug;
use std::ops::Deref;
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;
use tokio::{sync::Semaphore, time::sleep};
use tracing::{debug, error, info, warn, Level};

/// A bounded executor for CPU-bound tasks backed by a Rayon thread pool.
#[derive(Debug, Clone)]
pub struct TaskPool {
    semaphore: Arc<Semaphore>,
    thread_pool: Arc<ThreadPool>,
}

#[derive(Debug, Error)]
pub enum TaskPoolError {
    #[error("{0}")]
    SemaphoreError(String),

    #[error("{0}")]
    RecvError(RecvError),

    #[error("Task panicked: {0}")]
    Panic(String),
}

impl TaskPool {
    /// Creates a new pool with `threads` worker threads and at most `max_tasks` concurrent tasks.
    pub fn new(threads: usize, max_tasks: usize) -> TaskPool {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("Failed to build thread pool");

        Self {
            thread_pool: Arc::new(thread_pool),
            semaphore: Arc::new(Semaphore::new(max_tasks)),
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
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| TaskPoolError::SemaphoreError(task_name.to_owned()))?;

        // Warn of long running jobs
        let warning_handle = tokio::spawn(async move {
            let mut elapsed = Duration::ZERO;

            for log in timeouts.iter() {
                let target = Duration::from_secs(log.0);

                // Sleep only for the remaining time to reach target
                if target > elapsed {
                    sleep(target - elapsed).await;
                    elapsed = target;
                }
                let msg = format!("Job '{}' has been running for {:?}", task_name, target);
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
                warn!("Job '{}' still running after {:?}", task_name, elapsed);
            }
        });

        // This uses channels to track pending and complete tasks when
        // using the thread pool
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.thread_pool.spawn(move || {
            // Catch panics inside the Rayon thread so we can report them
            // as errors instead of silently dropping the oneshot sender.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(op));
            match result {
                Ok(t) => {
                    if let Err(res) = tx.send(Ok(t)) {
                        error!(
                            "There was an error sending the result from the multithread actor: result = {:?}",
                            res
                        );
                    }
                }
                Err(panic_info) => {
                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    error!("Rayon task panicked: {}", panic_msg);
                    let _ = tx.send(Err(TaskPoolError::Panic(panic_msg)));
                }
            }
        });

        let output = rx.await.map_err(TaskPoolError::RecvError)??;

        warning_handle.abort();

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
