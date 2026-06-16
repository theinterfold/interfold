// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use actix::{Actor, Addr, AsyncContext, Handler, Message, Recipient};
use e3_utils::MAILBOX_LIMIT;
use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::debug;

use super::batch_router::FlushSeq;

#[derive(Message)]
#[rtype(result = "()")]
pub struct StartTimelock {
    seq: u64,
    now: Duration,
    delay: Duration,
}

impl StartTimelock {
    pub fn new(seq: u64, now: Duration, delay: Duration) -> Self {
        Self { seq, now, delay }
    }
    pub fn new_micros(seq: u64, now: u64, delay: u64) -> Self {
        Self::new(
            seq,
            Duration::from_micros(now),
            Duration::from_micros(delay),
        )
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now_micros(&self) -> u64;
}

// Production implementation
#[derive(Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_micros(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_micros() as u64
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Tick;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Timelock {
    expiry: Duration,
    seq: u64,
}

impl Timelock {
    pub fn new(expiry: Duration, seq: u64) -> Self {
        Self { expiry, seq }
    }
}

impl Ord for Timelock {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expiry.cmp(&other.expiry)
    }
}

impl PartialOrd for Timelock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct TimelockQueue {
    timelocks: BinaryHeap<Reverse<Timelock>>,
    batch_router: Recipient<FlushSeq>,
    clock: Arc<dyn Clock>,
    interval: Option<u64>, // Seconds
}

impl TimelockQueue {
    pub fn new(batch_router: impl Into<Recipient<FlushSeq>>) -> Self {
        Self::with_clock(batch_router, Arc::new(SystemClock), Some(1))
    }

    pub fn spawn(batch_router: impl Into<Recipient<FlushSeq>>) -> Addr<Self> {
        Self::new(batch_router).start()
    }

    pub fn with_clock(
        batch_router: impl Into<Recipient<FlushSeq>>,
        clock: Arc<dyn Clock>,
        interval: Option<u64>,
    ) -> Self {
        Self {
            batch_router: batch_router.into(),
            timelocks: BinaryHeap::new(),
            clock,
            interval,
        }
    }

    fn next_timelock_lt(&mut self, now: Duration) -> bool {
        if let Some(peek) = self.timelocks.peek() {
            peek.0.expiry <= now
        } else {
            false
        }
    }
}

impl Actor for TimelockQueue {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        let Some(interval) = self.interval else {
            debug!("TimelockQueue in manual mode - will tick when requested.");
            return;
        };

        // Send Tick to self every second
        debug!("TimelockQueue is ticking every {}s", interval);
        ctx.run_interval(Duration::from_secs(interval), |_, ctx| {
            ctx.address().do_send(Tick);
        });
    }
}

impl Handler<StartTimelock> for TimelockQueue {
    type Result = ();
    fn handle(&mut self, msg: StartTimelock, _: &mut Self::Context) -> Self::Result {
        debug!("Start timelock: {:?}", msg.delay);
        let expiry = msg.now + msg.delay;
        self.timelocks.push(Reverse(Timelock::new(expiry, msg.seq)));
    }
}

impl Handler<Tick> for TimelockQueue {
    type Result = ();
    fn handle(&mut self, _: Tick, _: &mut Self::Context) -> Self::Result {
        let now_time = Duration::from_micros(self.clock.now_micros());
        debug!(
            "Running timelock tick. waiting times: {:?}.",
            self.timelocks
                .iter()
                .map(|t| t.0.expiry.saturating_sub(now_time))
                .collect::<Vec<_>>(),
        );

        while !self.timelocks.is_empty() && self.next_timelock_lt(now_time) {
            if let Some(tl) = self.timelocks.pop() {
                let seq = tl.0.seq;
                debug!("Flushing seq {}", seq);
                self.batch_router.do_send(FlushSeq(seq));
            }
        }
    }
}

#[cfg(test)]
pub mod mock_clock {

    use std::{
        sync::{
            atomic::{AtomicU64, Ordering as AtomicOrdering},
            Arc,
        },
        time::Duration,
    };

    use super::Clock;

    #[derive(Clone)]
    pub struct MockClock {
        current_time: Arc<AtomicU64>,
    }

    impl MockClock {
        pub fn new(initial_time: u64) -> Self {
            Self {
                current_time: Arc::new(AtomicU64::new(initial_time)),
            }
        }

        pub fn set(&self, time: Duration) {
            self.current_time
                .store(time.as_micros() as u64, AtomicOrdering::SeqCst);
        }

        pub fn advance(&self, micros: Duration) {
            self.current_time
                .fetch_add(micros.as_micros() as u64, AtomicOrdering::SeqCst);
        }
    }

    impl Clock for MockClock {
        fn now_micros(&self) -> u64 {
            self.current_time.load(AtomicOrdering::SeqCst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::prelude::*;
    use mock_clock::MockClock;
    use std::sync::{Arc, Mutex};
    use tokio::time::sleep;

    // ==================== Mock Router ====================

    struct MockBatchRouter {
        received_seqs: Arc<Mutex<Vec<u64>>>,
    }

    impl MockBatchRouter {
        fn new(received_seqs: Arc<Mutex<Vec<u64>>>) -> Self {
            Self { received_seqs }
        }
    }

    impl Actor for MockBatchRouter {
        type Context = Context<Self>;
    }

    impl Handler<FlushSeq> for MockBatchRouter {
        type Result = ();

        fn handle(&mut self, msg: FlushSeq, _: &mut Self::Context) -> Self::Result {
            self.received_seqs.lock().unwrap().push(msg.0);
        }
    }

    // ==================== Tests ====================

    #[actix::test]
    async fn test_tick_with_mock_clock_no_expiry() {
        let received_seqs = Arc::new(Mutex::new(Vec::new()));
        let mock_router = MockBatchRouter::new(received_seqs.clone()).start();

        let clock = MockClock::new(1000); // Start at t=1000
        let queue =
            TimelockQueue::with_clock(mock_router.recipient(), Arc::new(clock.clone()), None)
                .start();

        // Add timelock expiring at t=2000
        queue
            .send(StartTimelock::new_micros(42, 1000, 1000))
            .await
            .unwrap();

        // Tick at t=1000 - nothing should expire
        queue.send(Tick).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        assert!(received_seqs.lock().unwrap().is_empty());
    }

    #[actix::test]
    async fn test_tick_with_mock_clock_after_expiry() {
        let received_seqs = Arc::new(Mutex::new(Vec::new()));
        let mock_router = MockBatchRouter::new(received_seqs.clone()).start();

        let clock = MockClock::new(1000);
        let queue =
            TimelockQueue::with_clock(mock_router.recipient(), Arc::new(clock.clone()), None)
                .start();

        // Add timelock expiring at t=2000
        queue
            .send(StartTimelock::new_micros(42, 1000, 1000))
            .await
            .unwrap();

        // Advance clock past expiry
        clock.set(Duration::from_millis(2500));

        // Now tick should flush
        queue.send(Tick).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        let seqs = received_seqs.lock().unwrap();
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0], 42);
    }

    #[actix::test]
    async fn test_tick_exact_expiry_boundary() {
        let received_seqs = Arc::new(Mutex::new(Vec::new()));
        let mock_router = MockBatchRouter::new(received_seqs.clone()).start();

        let clock = MockClock::new(1000);
        let queue =
            TimelockQueue::with_clock(mock_router.recipient(), Arc::new(clock.clone()), None)
                .start();

        // Add timelock expiring at exactly t=2000
        queue
            .send(StartTimelock::new_micros(42, 1000, 1000))
            .await
            .unwrap();

        // Set clock to exact expiry time
        clock.set(Duration::from_millis(2000));

        queue.send(Tick).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        // Should flush at exact expiry (<=)
        let seqs = received_seqs.lock().unwrap();
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0], 42);
    }

    #[actix::test]
    async fn test_tick_one_microsecond_before_expiry() {
        let received_seqs = Arc::new(Mutex::new(Vec::new()));
        let mock_router = MockBatchRouter::new(received_seqs.clone()).start();

        let clock = MockClock::new(1000);
        let queue =
            TimelockQueue::with_clock(mock_router.recipient(), Arc::new(clock.clone()), None)
                .start();

        // Add timelock expiring at t=2000
        queue
            .send(StartTimelock::new_micros(42, 1000, 1000))
            .await
            .unwrap();

        // Set clock to 1 microsecond before expiry
        clock.set(Duration::from_micros(1999));

        queue.send(Tick).await.unwrap();
        sleep(Duration::from_micros(10)).await;

        // Should NOT flush
        assert!(received_seqs.lock().unwrap().is_empty());
    }

    #[actix::test]
    async fn test_multiple_timelocks_partial_expiry() {
        let received_seqs = Arc::new(Mutex::new(Vec::new()));
        let mock_router = MockBatchRouter::new(received_seqs.clone()).start();

        let clock = MockClock::new(0);
        let queue =
            TimelockQueue::with_clock(mock_router.recipient(), Arc::new(clock.clone()), None)
                .start();

        // Add timelocks with different expiries
        queue
            .send(StartTimelock::new_micros(1, 0, 1000))
            .await
            .unwrap(); // expires at 1000
        queue
            .send(StartTimelock::new_micros(2, 0, 2000))
            .await
            .unwrap(); // expires at 2000
        queue
            .send(StartTimelock::new_micros(3, 0, 3000))
            .await
            .unwrap(); // expires at 3000

        // Advance to 1500 - only first should expire
        clock.set(Duration::from_micros(1500));
        queue.send(Tick).await.unwrap();
        sleep(Duration::from_micros(10)).await;

        {
            let seqs = received_seqs.lock().unwrap();
            assert_eq!(seqs.len(), 1);
            assert_eq!(seqs[0], 1);
        }

        // Advance to 2500 - second should expire
        clock.set(Duration::from_micros(2500));
        queue.send(Tick).await.unwrap();
        sleep(Duration::from_micros(10)).await;

        {
            let seqs = received_seqs.lock().unwrap();
            assert_eq!(seqs.len(), 2);
            assert_eq!(seqs[1], 2);
        }

        // Advance to 5000 - third should expire
        clock.set(Duration::from_micros(5000));
        queue.send(Tick).await.unwrap();
        sleep(Duration::from_micros(10)).await;

        {
            let seqs = received_seqs.lock().unwrap();
            assert_eq!(seqs.len(), 3);
            assert_eq!(seqs[2], 3);
        }
    }

    #[actix::test]
    async fn test_clock_advance_helper() {
        let received_seqs = Arc::new(Mutex::new(Vec::new()));
        let mock_router = MockBatchRouter::new(received_seqs.clone()).start();

        let clock = MockClock::new(1000);
        let queue =
            TimelockQueue::with_clock(mock_router.recipient(), Arc::new(clock.clone()), None)
                .start();

        queue
            .send(StartTimelock::new_micros(42, 1000, 500))
            .await
            .unwrap();

        // Use advance instead of set
        clock.advance(Duration::from_millis(600)); // Now at 1600, expiry is 1500

        queue.send(Tick).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        assert_eq!(received_seqs.lock().unwrap().len(), 1);
    }
}
