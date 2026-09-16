// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use rayon::ThreadPool;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Mutex;
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;
use tokio::sync::{watch, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn, Level};

/// A bounded executor for CPU-bound tasks backed by a Rayon thread pool.
#[derive(Debug, Clone)]
pub struct TaskPool {
    semaphore: Arc<Semaphore>,
    thread_pool: Arc<ThreadPool>,
    task_groups: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
}

#[derive(Debug, Error)]
pub enum TaskPoolError {
    #[error("{0}")]
    SemaphoreError(String),

    #[error("{0}")]
    RecvError(RecvError),

    #[error("Task panicked: {0}")]
    Panic(String),

    #[error("Task group cancelled: {0}")]
    Cancelled(String),
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
            task_groups: Arc::new(Mutex::new(HashMap::new())),
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
        self.spawn_inner(None, task_name, timed_logs, op).await
    }

    pub(crate) async fn spawn_in_group<OP, T: Debug + Send + 'static>(
        &self,
        group: String,
        task_name: String,
        timed_logs: impl Into<TaskTimeouts>,
        op: OP,
    ) -> Result<T, TaskPoolError>
    where
        OP: FnOnce() -> T + Send + 'static,
    {
        self.spawn_inner(Some(group), task_name, timed_logs, op)
            .await
    }

    pub(crate) fn cancel_group(&self, group: &str) {
        let sender = {
            let mut groups = self.task_groups.lock().expect("task group lock poisoned");
            groups
                .entry(group.to_owned())
                .or_insert_with(|| watch::channel(false).0)
                .clone()
        };
        sender.send_replace(true);
    }

    fn subscribe_group(&self, group: &str) -> watch::Receiver<bool> {
        let mut groups = self.task_groups.lock().expect("task group lock poisoned");
        groups
            .entry(group.to_owned())
            .or_insert_with(|| watch::channel(false).0)
            .subscribe()
    }

    async fn spawn_inner<OP, T: Debug + Send + 'static>(
        &self,
        group: Option<String>,
        task_name: String,
        timed_logs: impl Into<TaskTimeouts>,
        op: OP,
    ) -> Result<T, TaskPoolError>
    where
        OP: FnOnce() -> T + Send + 'static,
    {
        let timeouts = timed_logs.into();
        let mut cancellation = group.as_deref().map(|group| self.subscribe_group(group));
        if cancellation
            .as_ref()
            .is_some_and(|receiver| *receiver.borrow())
        {
            return Err(TaskPoolError::Cancelled(
                group.as_deref().expect("group is present").to_owned(),
            ));
        }

        let _permit = if let Some(receiver) = cancellation.as_mut() {
            tokio::select! {
                biased;
                _ = receiver.changed() => {
                    return Err(TaskPoolError::Cancelled(
                        group.as_deref().expect("group is present").to_owned(),
                    ));
                }
                permit = self.semaphore.acquire() => {
                    permit.map_err(|_| TaskPoolError::SemaphoreError(task_name.to_owned()))?
                }
            }
        } else {
            self.semaphore
                .acquire()
                .await
                .map_err(|_| TaskPoolError::SemaphoreError(task_name.to_owned()))?
        };

        if cancellation
            .as_ref()
            .is_some_and(|receiver| *receiver.borrow())
        {
            return Err(TaskPoolError::Cancelled(
                group.as_deref().expect("group is present").to_owned(),
            ));
        }

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
        let worker_cancellation = cancellation.clone();
        let worker_group = group.clone();
        self.thread_pool.spawn(move || {
            if worker_cancellation
                .as_ref()
                .is_some_and(|receiver| *receiver.borrow())
            {
                let _ = tx.send(Err(TaskPoolError::Cancelled(
                    worker_group.expect("group is present"),
                )));
                return;
            }

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

        let output = rx.await.map_err(TaskPoolError::RecvError).and_then(|v| v);
        warning_handle.abort();
        output
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Condvar, Mutex};
    use tokio::time::timeout;

    async fn assert_group_cancellation(max_tasks: usize, wait_for_rayon_queue: bool) {
        let pool = TaskPool::new(1, max_tasks);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let running = {
            let pool = pool.clone();
            let release = release.clone();
            tokio::spawn(async move {
                pool.spawn_in_group(
                    "terminal-e3".to_owned(),
                    "running".to_owned(),
                    TaskTimeouts::new(Vec::new()),
                    move || {
                        let _ = started_tx.send(());
                        let (lock, wake) = &*release;
                        let mut released = lock.lock().expect("release lock poisoned");
                        while !*released {
                            released = wake.wait(released).expect("release lock poisoned");
                        }
                        1_u8
                    },
                )
                .await
            })
        };

        timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("running task did not start")
            .expect("running task dropped its start signal");

        let queued_ran = Arc::new(AtomicBool::new(false));
        let queued = {
            let pool = pool.clone();
            let queued_ran = queued_ran.clone();
            tokio::spawn(async move {
                pool.spawn_in_group(
                    "terminal-e3".to_owned(),
                    "queued".to_owned(),
                    TaskTimeouts::new(Vec::new()),
                    move || {
                        queued_ran.store(true, Ordering::SeqCst);
                        2_u8
                    },
                )
                .await
            })
        };
        if wait_for_rayon_queue {
            timeout(Duration::from_secs(2), async {
                while pool.semaphore.available_permits() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("queued task did not enter the Rayon queue");
        } else {
            tokio::task::yield_now().await;
        }

        pool.cancel_group("terminal-e3");
        {
            let (lock, wake) = &*release;
            *lock.lock().expect("release lock poisoned") = true;
            wake.notify_all();
        }

        assert_eq!(
            timeout(Duration::from_secs(2), running)
                .await
                .expect("running task timed out")
                .expect("running task join failed")
                .expect("running task failed"),
            1
        );
        assert!(matches!(
            timeout(Duration::from_secs(2), queued)
                .await
                .expect("queued task timed out")
                .expect("queued task join failed"),
            Err(TaskPoolError::Cancelled(group)) if group == "terminal-e3"
        ));
        assert!(!queued_ran.load(Ordering::SeqCst));

        assert!(matches!(
            pool.spawn_in_group(
                "terminal-e3".to_owned(),
                "late".to_owned(),
                TaskTimeouts::new(Vec::new()),
                || 3_u8,
            )
            .await,
            Err(TaskPoolError::Cancelled(group)) if group == "terminal-e3"
        ));

        let fresh = pool
            .spawn_in_group(
                "active-e3".to_owned(),
                "fresh".to_owned(),
                TaskTimeouts::new(Vec::new()),
                || 3_u8,
            )
            .await
            .expect("fresh task failed");
        assert_eq!(fresh, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_group_drops_semaphore_queued_work() {
        assert_group_cancellation(1, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_group_skips_work_queued_inside_rayon() {
        assert_group_cancellation(2, true).await;
    }
}
