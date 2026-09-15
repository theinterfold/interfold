// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::domain::log_window::MAX_LOG_WINDOW;
use actix::prelude::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Clone)]
struct MockLogProvider {
    inner: Arc<Mutex<MockState>>,
}

struct MockState {
    block_number: u64,
    log_responses: VecDeque<Result<Vec<Log>, String>>,
    timestamp_responses: VecDeque<Result<u64, String>>,
    timestamp_calls: u32,
    get_logs_calls: u32,
}

impl MockLogProvider {
    fn new(block_number: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState {
                block_number,
                log_responses: VecDeque::new(),
                timestamp_responses: VecDeque::new(),
                timestamp_calls: 0,
                get_logs_calls: 0,
            })),
        }
    }

    fn push_logs(&self, logs: Vec<Log>) {
        self.inner.lock().unwrap().log_responses.push_back(Ok(logs));
    }

    fn push_error(&self, msg: &str) {
        self.inner
            .lock()
            .unwrap()
            .log_responses
            .push_back(Err(msg.to_string()));
    }

    fn get_logs_call_count(&self) -> u32 {
        self.inner.lock().unwrap().get_logs_calls
    }

    fn push_timestamp(&self, timestamp: u64) {
        self.inner
            .lock()
            .unwrap()
            .timestamp_responses
            .push_back(Ok(timestamp));
    }

    fn push_timestamp_error(&self, message: &str) {
        self.inner
            .lock()
            .unwrap()
            .timestamp_responses
            .push_back(Err(message.to_string()));
    }

    fn timestamp_call_count(&self) -> u32 {
        self.inner.lock().unwrap().timestamp_calls
    }

    fn set_block_number(&self, block_number: u64) {
        self.inner.lock().unwrap().block_number = block_number;
    }
}

#[async_trait]
impl LogProvider for MockLogProvider {
    async fn fetch_logs(&self, _filter: &Filter) -> Result<Vec<Log>, anyhow::Error> {
        let mut state = self.inner.lock().unwrap();
        state.get_logs_calls += 1;
        match state.log_responses.pop_front() {
            Some(Ok(logs)) => Ok(logs),
            Some(Err(msg)) => Err(anyhow!("{}", msg)),
            None => Ok(vec![]),
        }
    }

    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error> {
        Ok(self.inner.lock().unwrap().block_number)
    }

    async fn fetch_block_timestamp(&self, _block_number: u64) -> Result<u64, anyhow::Error> {
        let mut state = self.inner.lock().unwrap();
        state.timestamp_calls += 1;
        match state.timestamp_responses.pop_front() {
            Some(Ok(timestamp)) => Ok(timestamp),
            Some(Err(message)) => Err(anyhow!(message)),
            None => Ok(0),
        }
    }
}

struct TestCollector {
    tx: mpsc::UnboundedSender<InterfoldEvmEvent>,
}

impl Actor for TestCollector {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvmEvent> for TestCollector {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvmEvent, _: &mut Self::Context) {
        let _ = self.tx.send(msg);
    }
}

fn make_test_log(block_number: u64) -> Log {
    Log {
        block_number: Some(block_number),
        ..Default::default()
    }
}

/// A log as a provider that populates `blockTimestamp` returns it.
fn make_timestamped_log(block_number: u64, timestamp: u64) -> Log {
    Log {
        block_number: Some(block_number),
        block_timestamp: Some(timestamp),
        ..Default::default()
    }
}

fn setup_collector() -> (
    EvmEventProcessor,
    mpsc::UnboundedReceiver<InterfoldEvmEvent>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let addr = TestCollector { tx }.start();
    (addr.recipient(), rx)
}

mod backfill;
mod fetch;
