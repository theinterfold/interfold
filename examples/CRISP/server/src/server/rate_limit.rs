// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A sliding-window rate limiter for the vote relay.
//!
//! `/voting/broadcast` signs and pays for a transaction on behalf of whoever calls it, so an
//! unthrottled caller can spend the relay's funds as fast as it can post proofs. Two windows
//! bound that, and they are consumed at different points on purpose:
//!
//! - **Caller admission** ([`RateLimiter::check_caller`]) runs first, before any work, against
//!   one hot client.
//! - **Global reservation** ([`RateLimiter::try_reserve_global`]) caps durable work that can spend
//!   relay funds across all callers. The route reserves before admission and returns the slot when
//!   validation or infrastructure fails, so rejected traffic does not exhaust the shared window.
//!
//! The limits are deliberately generous for people and tight for loops: one honest ballot costs
//! minutes of client-side proving, so a human cannot reach them.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Broadcasts one caller may relay per window.
const PER_CALLER_LIMIT: usize = 10;

/// Transactions the relay pays for per window across all callers.
const GLOBAL_LIMIT: usize = 120;

/// The sliding window both limits are counted over.
const WINDOW: Duration = Duration::from_secs(60);

/// Upstream calls one caller may cause per window through `/chain/*`.
///
/// Counted in CALLS, not requests: a JSON-RPC batch of 64 is 64 sequential upstream requests held
/// open on one connection, and charging it as one would leave the fan-out this bounds unbounded.
/// Sized for a browser, not a person — a cold page load in either frontend resolves a few hundred
/// reads across the proposal list and the delegate directory, so this has to clear that with room
/// to spare while still stopping a loop.
const CHAIN_PER_CALLER_LIMIT: usize = 1_200;

/// No global window on reads.
///
/// The relay has one because it spends money; reads cost upstream quota, which is shared but not
/// drained. A global read cap would turn one busy client into an outage for everyone else, which
/// is a worse failure than the one it prevents. The per-caller window is the bound here.
const CHAIN_GLOBAL_LIMIT: usize = usize::MAX;

/// Why a request was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum RateLimitExceeded {
    /// The caller sent more than [`PER_CALLER_LIMIT`] requests inside the window.
    Caller,
    /// The relay reserved more than [`GLOBAL_LIMIT`] transactions inside the window.
    Global,
}

/// A shared sliding-window limiter. Cheap to clone via `web::Data`; one instance must be built
/// outside the `HttpServer` factory closure, or every worker gets its own counters and the
/// effective limit multiplies by the worker count.
pub struct RateLimiter {
    state: Mutex<State>,
    per_caller_limit: usize,
    global_limit: usize,
}

/// The limiter for the chain read endpoints.
///
/// A distinct type rather than a second `RateLimiter`: actix keys `app_data` by type, so two
/// instances of one type are one instance, and the relay's window would silently become the
/// read window (10 requests a minute, which is a blank page).
pub struct ChainRateLimiter {
    limiter: RateLimiter,
    /// Whether a caller may be identified by `Forwarded` / `X-Forwarded-For`.
    ///
    /// Carried here rather than read from `CONFIG` at the point of use, so that identifying a
    /// caller needs no environment. `CONFIG` is a `Lazy` that panics when the process has no
    /// configuration — which is every test run — and one such panic poisons it for the rest of
    /// the suite.
    trust_proxy_headers: bool,
}

impl ChainRateLimiter {
    /// The safe default: identify callers by their socket peer, which cannot be forged.
    pub fn new() -> Self {
        Self::with_trust(false)
    }

    pub fn with_trust(trust_proxy_headers: bool) -> Self {
        Self {
            limiter: RateLimiter::with_limits(CHAIN_PER_CALLER_LIMIT, CHAIN_GLOBAL_LIMIT),
            trust_proxy_headers,
        }
    }

    pub fn trusts_proxy_headers(&self) -> bool {
        self.trust_proxy_headers
    }

    /// Charge `cost` upstream calls to `caller` and answer whether they fit in the window.
    pub fn check_caller_cost(&self, caller: &str, cost: usize) -> Result<(), RateLimitExceeded> {
        self.limiter.check_caller_cost(caller, cost)
    }
}

impl Default for ChainRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

struct State {
    /// Recent request instants per caller. Pruned on every check, so a caller that goes quiet
    /// costs nothing after one window.
    per_caller: HashMap<String, Vec<Instant>>,
    /// Recent global reservations across all callers.
    global: Vec<Instant>,
}

fn within_window(cutoff: Option<Instant>) -> impl Fn(&Instant) -> bool {
    move |t| cutoff.is_none_or(|c| *t > c)
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_limits(PER_CALLER_LIMIT, GLOBAL_LIMIT)
    }

    pub fn with_limits(per_caller_limit: usize, global_limit: usize) -> Self {
        Self {
            state: Mutex::new(State {
                per_caller: HashMap::new(),
                global: Vec::new(),
            }),
            per_caller_limit,
            global_limit,
        }
    }

    /// Record one request from `caller` and answer whether it is within the caller window.
    ///
    /// A refused request is not recorded, so being refused does not extend the refusal.
    pub fn check_caller(&self, caller: &str) -> Result<(), RateLimitExceeded> {
        self.check_caller_at(caller, 1, Instant::now())
    }

    /// Record `cost` units of work from `caller` and answer whether they are within the window.
    ///
    /// All-or-nothing: a request whose cost does not fit is refused whole and recorded not at all,
    /// rather than admitted for as much of it as happens to fit.
    pub fn check_caller_cost(&self, caller: &str, cost: usize) -> Result<(), RateLimitExceeded> {
        self.check_caller_at(caller, cost, Instant::now())
    }

    /// Reserve one slot of the global transaction quota.
    ///
    /// Return this reservation if the request fails before durable work is admitted.
    pub fn try_reserve_global(&self) -> Result<(), RateLimitExceeded> {
        self.try_reserve_global_at(Instant::now())
    }

    /// Return a reservation when request validation or infrastructure fails before durable work
    /// is admitted. Durable jobs keep their reservation because they can still spend relay funds.
    pub fn release_global_reservation(&self) {
        self.state
            .lock()
            .expect("rate limiter mutex poisoned")
            .global
            .pop();
    }

    fn check_caller_at(
        &self,
        caller: &str,
        cost: usize,
        now: Instant,
    ) -> Result<(), RateLimitExceeded> {
        let within = within_window(now.checked_sub(WINDOW));

        let mut state = self.state.lock().expect("rate limiter mutex poisoned");

        // Prune every caller, not only this one, so idle callers do not accumulate forever.
        state.per_caller.retain(|_, times| {
            times.retain(|t| within(t));
            !times.is_empty()
        });

        let times = state.per_caller.entry(caller.to_string()).or_default();
        // A zero-cost request is still a request: charge at least one, or an empty batch is free
        // to send in a loop.
        let cost = cost.max(1);
        if times.len().saturating_add(cost) > self.per_caller_limit {
            return Err(RateLimitExceeded::Caller);
        }

        times.extend(std::iter::repeat_n(now, cost));
        Ok(())
    }

    fn try_reserve_global_at(&self, now: Instant) -> Result<(), RateLimitExceeded> {
        let within = within_window(now.checked_sub(WINDOW));

        let mut state = self.state.lock().expect("rate limiter mutex poisoned");

        state.global.retain(|t| within(t));
        if state.global.len() >= self.global_limit {
            return Err(RateLimitExceeded::Global);
        }

        state.global.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_caller_limit_and_refuses_the_next() {
        let limiter = RateLimiter::new();
        let now = Instant::now();

        for _ in 0..PER_CALLER_LIMIT {
            assert_eq!(limiter.check_caller_at("a", 1, now), Ok(()));
        }
        assert_eq!(
            limiter.check_caller_at("a", 1, now),
            Err(RateLimitExceeded::Caller)
        );

        // Another caller is unaffected by the first one's refusal.
        assert_eq!(limiter.check_caller_at("b", 1, now), Ok(()));
    }

    #[test]
    fn a_caller_recovers_once_the_window_slides_past() {
        let limiter = RateLimiter::new();
        let start = Instant::now();

        for _ in 0..PER_CALLER_LIMIT {
            assert_eq!(limiter.check_caller_at("a", 1, start), Ok(()));
        }
        assert_eq!(
            limiter.check_caller_at("a", 1, start),
            Err(RateLimitExceeded::Caller)
        );

        let later = start + WINDOW + Duration::from_secs(1);
        assert_eq!(limiter.check_caller_at("a", 1, later), Ok(()));
    }

    #[test]
    fn the_global_window_caps_reservations() {
        let limiter = RateLimiter::new();
        let now = Instant::now();

        for _ in 0..GLOBAL_LIMIT {
            assert_eq!(limiter.try_reserve_global_at(now), Ok(()));
        }
        assert_eq!(
            limiter.try_reserve_global_at(now),
            Err(RateLimitExceeded::Global)
        );

        let later = now + WINDOW + Duration::from_secs(1);
        assert_eq!(limiter.try_reserve_global_at(later), Ok(()));
    }

    #[test]
    fn caller_admission_does_not_consume_global_quota() {
        let limiter = RateLimiter::new();
        let now = Instant::now();

        // Invalid traffic stops at caller admission; the global window must stay untouched so
        // it cannot be drained by requests that never reach a transaction.
        for i in 0..GLOBAL_LIMIT * 2 {
            let _ = limiter.check_caller_at(&format!("caller-{i}"), 1, now);
        }

        assert_eq!(limiter.try_reserve_global_at(now), Ok(()));
    }

    #[test]
    fn failed_admission_can_return_its_global_reservation() {
        let limiter = RateLimiter::with_limits(1, 1);
        assert_eq!(limiter.try_reserve_global(), Ok(()));
        limiter.release_global_reservation();
        assert_eq!(limiter.try_reserve_global(), Ok(()));
    }

    #[test]
    fn a_batch_is_charged_per_call_not_per_request() {
        let limiter = RateLimiter::with_limits(100, usize::MAX);
        let now = Instant::now();

        // Two 40-call batches fit; the third would take the total past 100.
        assert_eq!(limiter.check_caller_at("a", 40, now), Ok(()));
        assert_eq!(limiter.check_caller_at("a", 40, now), Ok(()));
        assert_eq!(
            limiter.check_caller_at("a", 40, now),
            Err(RateLimitExceeded::Caller)
        );

        // Refusing the batch charged nothing, so what does fit still gets through.
        assert_eq!(limiter.check_caller_at("a", 20, now), Ok(()));
    }

    #[test]
    fn an_empty_batch_still_costs_one() {
        let limiter = RateLimiter::with_limits(2, usize::MAX);
        let now = Instant::now();

        assert_eq!(limiter.check_caller_at("a", 0, now), Ok(()));
        assert_eq!(limiter.check_caller_at("a", 0, now), Ok(()));
        assert_eq!(
            limiter.check_caller_at("a", 0, now),
            Err(RateLimitExceeded::Caller)
        );
    }

    #[test]
    fn the_chain_limiter_clears_a_page_load_and_stops_a_loop() {
        let limiter = ChainRateLimiter::new();
        let mut charged = 0;

        // Batches of 64, the frontends' cap, until the window refuses one.
        while limiter.check_caller_cost("a", 64).is_ok() {
            charged += 64;
            assert!(charged <= CHAIN_PER_CALLER_LIMIT, "window never closed");
        }

        // Well past what a cold page load costs, and far below unbounded.
        assert!(charged >= 1_000, "refused too early: {charged}");
    }

    #[test]
    fn a_refused_request_is_not_counted() {
        let limiter = RateLimiter::new();
        let start = Instant::now();

        for _ in 0..PER_CALLER_LIMIT {
            assert_eq!(limiter.check_caller_at("a", 1, start), Ok(()));
        }
        // Hammering while refused must not push the recovery point further out.
        for _ in 0..100 {
            assert_eq!(
                limiter.check_caller_at("a", 1, start),
                Err(RateLimitExceeded::Caller)
            );
        }

        let later = start + WINDOW + Duration::from_secs(1);
        assert_eq!(limiter.check_caller_at("a", 1, later), Ok(()));
    }
}
