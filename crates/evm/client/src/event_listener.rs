// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{
    network::Ethereum,
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockNumberOrTag, Filter, Log},
    sol_types::SolEvent,
};
use eyre::Result;
use futures::stream::StreamExt;
use futures_util::future::FutureExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::{Notify, RwLock};

type EventHandler =
    Box<dyn Fn(&Log) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Sentinel for [`LiveProgress::processing_block`] meaning "no log is being applied right now".
pub const NOT_PROCESSING: u64 = u64::MAX;

/// What the live subscription is doing, for an owner that persists an applied-block cursor.
///
/// Such an owner learns how far the chain has moved from BLOCK HEADERS, which arrive on a separate
/// subscription that knows nothing about whether this listener has finished applying the logs of
/// those blocks. Two things can go wrong, and this type is what makes both observable:
///
/// - A raw handler FAILS. The store no longer reflects the chain, but the header stream keeps
///   advancing; without a synchronous signal the owner would claim the failed block as applied
///   before the aborted subscription surfaced to it.
/// - A raw handler is merely SLOW. Nothing has failed, but while a log in block `N` is still being
///   written, headers for `N+1` and `N+2` can arrive and move a persisted cursor past `N`. On a
///   restart the catch-up resumes above the cursor and that log is never replayed — a permanent
///   hole produced by latency alone.
#[derive(Debug)]
pub struct LiveProgress {
    /// Cleared the instant a raw handler fails.
    pub healthy: AtomicBool,
    /// Block whose raw handlers are running, or [`NOT_PROCESSING`] when idle.
    ///
    /// Raw handlers are awaited sequentially in the subscription loop, so at most one block is
    /// ever in flight. An owner must not claim this block or anything above it as applied.
    pub processing_block: AtomicU64,
    /// Whether the log subscription is currently established on the node.
    subscribed: AtomicBool,
    subscribed_notify: Notify,
}

impl Default for LiveProgress {
    fn default() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            processing_block: AtomicU64::new(NOT_PROCESSING),
            subscribed: AtomicBool::new(false),
            subscribed_notify: Notify::new(),
        }
    }
}

impl LiveProgress {
    /// Announce that the log subscription is live on the node.
    pub fn mark_subscribed(&self) {
        self.subscribed.store(true, Ordering::SeqCst);
        self.subscribed_notify.notify_waiters();
    }

    /// Announce that there is no live subscription — call before (re)connecting.
    pub fn mark_unsubscribed(&self) {
        self.subscribed.store(false, Ordering::SeqCst);
    }

    /// Resolve once the log subscription is established.
    ///
    /// This is what makes the replay's overlap with the subscription real rather than assumed. A
    /// catch-up that finishes BEFORE the subscription exists leaves the blocks mined in between in
    /// neither path, and the cursor then advances past them — a permanent hole, reported as
    /// covered. An owner should wait on this and replay once more.
    pub async fn wait_subscribed(&self) {
        loop {
            // Registered before the flag is read, so a `mark_subscribed` racing this cannot be
            // missed between the check and the await.
            let notified = self.subscribed_notify.notified();
            if self.subscribed.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    /// The highest block an owner may claim as applied, given a chain head of `head`.
    ///
    /// `None` while a raw handler has failed: nothing is safe to claim until the listener has
    /// reconnected and replayed.
    pub fn applied_ceiling(&self, head: u64) -> Option<u64> {
        if !self.healthy.load(Ordering::SeqCst) {
            return None;
        }

        let in_flight = self.processing_block.load(Ordering::SeqCst);
        match in_flight {
            NOT_PROCESSING => Some(head),
            // Block 0 is being written and there is nothing beneath it. `saturating_sub` would
            // answer `Some(0)` — claiming the very block still in flight, which is the one thing
            // this function exists to prevent.
            0 => None,
            // Strictly below the block being written: that block is not applied yet.
            block => Some(head.min(block - 1)),
        }
    }
}

#[derive(Clone)]
pub struct EventListener {
    provider: Arc<dyn Provider<Ethereum>>,
    filter: Filter,
    handlers: Arc<RwLock<HashMap<B256, Vec<EventHandler>>>>,
    /// Handlers that receive every log, whatever its topic.
    raw_handlers: Arc<RwLock<Vec<EventHandler>>>,
    /// Shared with an owner that persists an applied-block cursor. See [`LiveProgress`].
    progress: Option<Arc<LiveProgress>>,
}

impl EventListener {
    pub fn new(provider: Arc<dyn Provider<Ethereum>>, filter: Filter) -> Self {
        Self {
            provider,
            filter,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            raw_handlers: Arc::new(RwLock::new(Vec::new())),
            progress: None,
        }
    }

    /// Share a [`LiveProgress`] so an owner can tell how far this listener has actually applied.
    ///
    /// Required for any owner that persists an applied-block cursor; owners with no such cursor
    /// can ignore this entirely and nothing changes for them.
    pub fn set_progress(&mut self, progress: Arc<LiveProgress>) {
        self.progress = Some(progress);
    }

    /// Register a handler that receives EVERY log this listener sees, undecoded.
    ///
    /// The typed `add_event_handler` above binds a handler to one event signature, which is right
    /// for reacting to a known event. This one exists for the opposite job: retaining logs whose
    /// meaning belongs to the caller, not to this crate — an index that serves a client's own
    /// queries has to keep events it has no ABI for.
    pub async fn add_raw_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Log) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let wrapped = Box::new(move |log: &Log| {
            let handler = Arc::clone(&handler);
            let log = log.clone();
            async move { handler(log).await }.boxed()
        });

        self.raw_handlers.write().await.push(wrapped);
    }

    pub async fn add_event_handler<E, F, Fut>(&self, handler: F)
    where
        E: SolEvent + Send + Clone + 'static,
        F: Fn(E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let signature = E::SIGNATURE_HASH;
        let handler = Arc::new(handler);
        let wrapped_handler = Box::new(move |log: &Log| {
            let handler = Arc::clone(&handler);
            let log = log.clone();
            async move {
                let decoded = log.log_decode::<E>()?;
                let event = decoded.inner.data;
                handler(event.clone()).await
            }
            .boxed()
        });

        self.handlers
            .write()
            .await
            .entry(signature)
            .or_insert_with(Vec::new)
            .push(wrapped_handler);
    }

    pub async fn listen(&self) -> Result<()> {
        let mut stream = self
            .provider
            .subscribe_logs(&self.filter)
            .await?
            .into_stream();

        // Only now is the subscription actually registered on the node. An owner waiting on this
        // can replay the blocks mined between its last head read and this moment, which is the one
        // range neither the replay nor the subscription would otherwise cover.
        if let Some(progress) = &self.progress {
            progress.mark_subscribed();
        }

        while let Some(log) = stream.next().await {
            // Raw handlers run first and are awaited, not spawned: they are what persists the log,
            // and a typed handler that reacts to it should not be able to observe a state the
            // index has not recorded yet.
            //
            // The guard is released before each await, exactly as the typed path below does. Held
            // across the handler it would deadlock anything that registers a handler from inside
            // one, and would serialise every handler's IO into this subscription loop.
            // Published BEFORE the handlers run and cleared only once they have all finished, so
            // an owner advancing a cursor from block headers cannot claim this block while it is
            // still being written. Latency alone used to be enough to lose a log permanently.
            if let (Some(progress), Some(block)) = (&self.progress, log.block_number) {
                progress.processing_block.store(block, Ordering::SeqCst);
            }

            let raw_count = self.raw_handlers.read().await.len();
            let mut failure = None;
            for i in 0..raw_count {
                let fut = {
                    let guard = self.raw_handlers.read().await;
                    let Some(handler) = guard.get(i) else { break };
                    handler(&log)
                };
                // Propagated, not logged and dropped. `catch_up` aborts on a raw-handler error so
                // the caller's cursor cannot advance past unapplied work; the live path swallowing
                // the same error left a permanent hole beneath a cursor that claimed the block was
                // applied, and the read API then served that range from the index — short, and
                // indistinguishable from a complete answer.
                //
                // The health flag is cleared FIRST, so a cursor driven by block headers on another
                // task stops immediately rather than when this error surfaces to the caller.
                if let Err(e) = fut.await {
                    if let Some(progress) = &self.progress {
                        progress.healthy.store(false, Ordering::SeqCst);
                    }
                    failure = Some(e);
                    break;
                }
            }

            if let Some(e) = failure {
                // Left as-is on purpose: the in-flight marker stays pinned to the block that
                // failed, so nothing can claim it while the listener is down.
                return Err(e.wrap_err("a raw log handler failed; aborting the subscription"));
            }

            if let Some(progress) = &self.progress {
                progress
                    .processing_block
                    .store(NOT_PROCESSING, Ordering::SeqCst);
            }

            if let Some(topic0) = log.topic0() {
                let topic_val = *topic0;
                if let Some(handlers) = self.handlers.read().await.get(topic0) {
                    for handler in handlers {
                        let log_clone = log.clone();
                        let fut = handler(&log_clone);
                        tokio::spawn(async move {
                            // Spawn the future so that the handlers are processed concurrently
                            if let Err(e) = fut.await {
                                eprintln!("Error processing event 0x{:x}: {:?}", topic_val, e);
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// The current chain head, used to bound a catch-up range.
    pub async fn head_block(&self) -> Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }

    /// Replay historical logs through the registered handlers, inclusive of both bounds.
    ///
    /// `listen` subscribes from the head, so every log emitted while this process was down is
    /// invisible to it — a subscription has no memory. Anything that treats the store as a
    /// complete picture of the chain (an API serving a frontend, rather than a coordinator
    /// reacting to live events) therefore needs this to close the gap on boot and after a
    /// reconnect.
    ///
    /// Two differences from the live path, both deliberate:
    ///
    /// - Handlers run SEQUENTIALLY and in block order. The live path spawns them concurrently,
    ///   which is fine when events arrive one at a time, but replaying a range that way would
    ///   interleave writes for the same round and let a later event lose to an earlier one.
    /// - A handler error aborts the catch-up rather than being logged and skipped. Continuing
    ///   would advance the caller's cursor past an event that was never applied, turning a
    ///   transient failure into a permanent hole.
    ///
    /// Queried in windows of `chunk` blocks because hosted providers cap `eth_getLogs` ranges.
    pub async fn catch_up(&self, from_block: u64, to_block: u64, chunk: u64) -> Result<u64> {
        if from_block > to_block {
            return Ok(0);
        }

        let chunk = chunk.max(1);
        let mut processed = 0u64;
        let mut start = from_block;

        while start <= to_block {
            let end = start.saturating_add(chunk - 1).min(to_block);

            let filter = self
                .filter
                .clone()
                .from_block(BlockNumberOrTag::Number(start))
                .to_block(BlockNumberOrTag::Number(end));

            let mut logs = self.provider.get_logs(&filter).await?;

            // Providers are not required to return logs in order, and the handlers below are
            // order-sensitive: `block_number`/`log_index` is the chain's own ordering.
            //
            // A log with no block number (pending, in principle unreachable here) sorts LAST
            // rather than first: sorting `Option` directly put the one entry whose position
            // cannot be verified ahead of every entry whose position is known.
            logs.sort_by_key(|log| {
                (
                    log.block_number.unwrap_or(u64::MAX),
                    log.log_index.unwrap_or(u64::MAX),
                )
            });

            for log in &logs {
                let raw_count = self.raw_handlers.read().await.len();
                for i in 0..raw_count {
                    let fut = {
                        let guard = self.raw_handlers.read().await;
                        let Some(handler) = guard.get(i) else { break };
                        handler(log)
                    };
                    fut.await?;
                }

                let Some(topic0) = log.topic0() else {
                    processed += 1;
                    continue;
                };
                let topic_val = *topic0;

                // The read guard is taken per log and released before awaiting the handler, so a
                // handler that registers further handlers cannot deadlock against it.
                let count = self
                    .handlers
                    .read()
                    .await
                    .get(topic0)
                    .map(|h| h.len())
                    .unwrap_or(0);

                for i in 0..count {
                    let fut = {
                        let guard = self.handlers.read().await;
                        let Some(handlers) = guard.get(&topic_val) else {
                            break;
                        };
                        handlers[i](log)
                    };
                    fut.await?;
                }

                processed += 1;
            }

            start = end.saturating_add(1);
        }

        Ok(processed)
    }

    pub fn provider(&self) -> Arc<dyn Provider<Ethereum>> {
        self.provider.clone()
    }

    /// Create a contract listener that will listen to events from all addresses.
    pub async fn create_contract_listener(rpc_url: &str, addresses: &[&str]) -> Result<Self> {
        let provider = Arc::new(ProviderBuilder::new().connect(rpc_url).await?);

        let address = addresses
            .iter()
            .map(|a| a.parse::<Address>().map_err(|e| eyre::eyre!("{e}")))
            .collect::<Result<Vec<_>>>()?;
        let filter = Filter::new()
            .address(address)
            .from_block(BlockNumberOrTag::Latest);
        Ok(EventListener::new(provider, filter))
    }
}

#[cfg(test)]
mod live_progress_tests {
    use super::*;

    #[test]
    fn an_idle_listener_lets_the_owner_claim_the_whole_head() {
        let progress = LiveProgress::default();

        assert_eq!(progress.applied_ceiling(100), Some(100));
    }

    #[test]
    fn a_block_being_written_is_not_claimable_and_neither_is_anything_above_it() {
        let progress = LiveProgress::default();
        progress.processing_block.store(80, Ordering::SeqCst);

        // 80 is still in flight, so the highest honest claim is 79 — even though the chain has
        // reached 100 and the header stream would happily assert that.
        assert_eq!(progress.applied_ceiling(100), Some(79));
    }

    #[test]
    fn the_ceiling_never_exceeds_the_head_the_owner_asked_about() {
        let progress = LiveProgress::default();
        progress.processing_block.store(500, Ordering::SeqCst);

        assert_eq!(progress.applied_ceiling(100), Some(100));
    }

    #[test]
    fn block_zero_in_flight_leaves_nothing_claimable() {
        let progress = LiveProgress::default();
        progress.processing_block.store(0, Ordering::SeqCst);

        // Nothing exists below block 0, so there is no honest claim to make — and it must not
        // wrap to u64::MAX either. The name of this test is the invariant.
        assert_eq!(progress.applied_ceiling(100), None);
    }

    #[test]
    fn an_unhealthy_listener_lets_the_owner_claim_nothing() {
        let progress = LiveProgress::default();
        progress.healthy.store(false, Ordering::SeqCst);

        assert_eq!(progress.applied_ceiling(100), None);
    }

    #[tokio::test]
    async fn waiting_on_an_already_subscribed_listener_returns_immediately() {
        let progress = LiveProgress::default();
        progress.mark_subscribed();

        // Would hang if the flag were only observable through a notification.
        progress.wait_subscribed().await;
    }

    #[tokio::test]
    async fn a_waiter_is_released_when_the_subscription_comes_up() {
        let progress = Arc::new(LiveProgress::default());
        let waiter = progress.clone();

        let handle = tokio::spawn(async move { waiter.wait_subscribed().await });

        // Yield first so the waiter is parked on the notification rather than racing the flag.
        tokio::task::yield_now().await;
        progress.mark_subscribed();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("wait_subscribed should be released by mark_subscribed")
            .expect("the waiting task should not panic");
    }

    #[tokio::test]
    async fn unsubscribing_makes_the_next_wait_block_again() {
        let progress = Arc::new(LiveProgress::default());
        progress.mark_subscribed();
        progress.wait_subscribed().await;

        // A reconnect: the previous iteration's flag must not let the overlap pass fire against a
        // subscription that no longer exists.
        progress.mark_unsubscribed();

        let waiter = progress.clone();
        let handle = tokio::spawn(async move { waiter.wait_subscribed().await });

        // Give the task real time to finish if it were going to, then assert that it did not: the
        // point is that the previous iteration's flag no longer releases it.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "wait_subscribed should still block after mark_unsubscribed"
        );

        progress.mark_subscribed();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("resubscribing should release the waiter")
            .expect("the waiting task should not panic");
    }
}
