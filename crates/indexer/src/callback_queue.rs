// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_evm_helpers::threshold_queue::{ThresholdItem, ThresholdQueue};
use eyre::Result;
use std::{future::Future, pin::Pin, sync::Arc};
use tracing::info;

/// Callback for CallbackQueue
type Callback = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

#[derive(Clone)]
/// A callback that has an execute time associated with it
pub struct TimedCallback {
    time: u64,
    callback: Callback,
}

impl ThresholdItem for TimedCallback {
    type Item = Callback;

    fn item(&self) -> Self::Item {
        self.callback.clone()
    }

    fn within_threshold(&self, threshold: u64) -> bool {
        self.time <= threshold
    }
}

// We need to ensure Ord is satisfied to use this in the threshold queue
impl Eq for TimedCallback {}

impl PartialEq for TimedCallback {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl PartialOrd for TimedCallback {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimedCallback {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time.cmp(&other.time)
    }
}

#[derive(Clone)]
/// A queue of callbacks that can be executed when a given timestamp has been passed. This is a
/// specialization of a ThresholdQueue.
pub struct CallbackQueue {
    inner: ThresholdQueue<TimedCallback>,
}

impl CallbackQueue {
    /// Create a new queue
    pub fn new() -> Self {
        Self {
            inner: ThresholdQueue::new(),
        }
    }

    /// Push a callback to the queue to be executed at or before the given time.
    pub fn push<F, Fut>(&self, time: u64, callback: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        info!("ADDING CALLBACK TO time={}", time);
        self.inner.push(TimedCallback {
            time,
            callback: Arc::new(move || Box::pin(callback())),
        })
    }

    /// Execute all pending callbacks up to and including the given time
    pub async fn execute_until_including(&self, time: u64) -> Result<()> {
        let handlers = self.inner.take_until_including(time);
        if !handlers.is_empty() {
            info!("found {} handlers", handlers.len());
        }
        for callback in handlers {
            callback().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn test_single_callback_executes() {
        let queue = CallbackQueue::new();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        queue.push(100, move || {
            let called = called_clone.clone();
            async move {
                *called.lock().unwrap() = true;
                Ok(())
            }
        });

        queue.execute_until_including(100).await.unwrap();
        assert!(*called.lock().unwrap());
    }

    #[tokio::test]
    async fn test_callback_not_executed_before_threshold() {
        let queue = CallbackQueue::new();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        queue.push(100, move || {
            let called = called_clone.clone();
            async move {
                *called.lock().unwrap() = true;
                Ok(())
            }
        });

        queue.execute_until_including(50).await.unwrap();
        assert!(!*called.lock().unwrap());
    }

    #[tokio::test]
    async fn test_multiple_callbacks_execute() {
        let queue = CallbackQueue::new();
        let counter = Arc::new(Mutex::new(0));

        let c1 = counter.clone();
        queue.push(50, move || {
            let c = c1.clone();
            async move {
                *c.lock().unwrap() += 1;
                Ok(())
            }
        });

        let c2 = counter.clone();
        queue.push(100, move || {
            let c = c2.clone();
            async move {
                *c.lock().unwrap() += 1;
                Ok(())
            }
        });

        let c3 = counter.clone();
        queue.push(150, move || {
            let c = c3.clone();
            async move {
                *c.lock().unwrap() += 1;
                Ok(())
            }
        });

        queue.execute_until_including(100).await.unwrap();
        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_error_propagation() {
        let queue = CallbackQueue::new();

        queue.push(100, || async { Err(eyre::eyre!("test error")) });

        let result = queue.execute_until_including(100).await;
        assert!(result.is_err());
    }
}
