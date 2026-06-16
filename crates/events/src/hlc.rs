// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use rand::Rng;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HlcError {
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("system clock error")]
    ClockError,

    #[error(
        "drift exceeded: remote {remote_ts} is more than {max_drift}μs ahead of local {local_ts}"
    )]
    DriftExceeded {
        remote_ts: u64,
        local_ts: u64,
        max_drift: u64,
    },
    #[error("counter overflow: timestamp {ts} has exhausted all counter values")]
    CounterOverflow { ts: u64 },
}

/// HLC timestamp
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HlcTimestamp {
    /// Physical timestamp in microseconds since UNIX epoch
    pub ts: u64,
    /// Logical counter for same-timestamp ordering
    pub counter: u32,
    /// Unique node identifier for tie-breaking
    pub node: u32,
}

impl HlcTimestamp {
    /// Create a new Timestamp
    pub fn new(ts: u64, counter: u32, node: u32) -> Self {
        Self { ts, counter, node }
    }

    /// Extract wall time from a u128 timestamp
    pub fn wall_time(ts: u128) -> u64 {
        Self::from_u128(ts).ts
    }

    /// Packs the HLC timestamp into a 128bit big-endian representation.
    ///
    /// Layout:
    /// ```text
    /// ┌────────────────┬────────────────┬────────────────┐
    /// │   ts (u64)     │  counter (u32) │   node (u32)   │
    /// │  bytes 0..8    │  bytes 8..12   │  bytes 12..16  │
    /// └────────────────┴────────────────┴────────────────┘
    /// ```
    ///
    /// This format uses simple fixed-width integers rather than bit-packing,
    /// making it trivial to reimplement in other languages (Go, TypeScript, Python, etc.)
    /// without fancy bit packing. Big-endian preserves lexicographic sort order.
    pub fn pack(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&self.ts.to_be_bytes());
        buf[8..12].copy_from_slice(&self.counter.to_be_bytes());
        buf[12..16].copy_from_slice(&self.node.to_be_bytes());
        buf
    }

    /// Unpacks the HLC timestamp from a 128bit big-endian representation.
    pub fn unpack(bytes: [u8; 16]) -> Self {
        Self {
            ts: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            counter: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            node: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
        }
    }

    /// Converts to u128, preserving sort order.
    pub fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.pack())
    }

    /// Reconstructs from a u128 created by `to_u128()`.
    pub fn from_u128(n: u128) -> Self {
        Self::unpack(n.to_be_bytes())
    }

    /// Unpacks the HLC timestamp from a slice that is expected to be a 128bit big-endian representation.
    pub fn unpack_slice(bytes: &[u8]) -> Result<Self, HlcError> {
        if bytes.len() != 16 {
            return Err(HlcError::InvalidLength {
                expected: 16,
                got: bytes.len(),
            });
        }
        Ok(Self::unpack(bytes.try_into().unwrap()))
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ts
            .cmp(&other.ts)
            .then(self.counter.cmp(&other.counter))
            .then(self.node.cmp(&other.node))
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<HlcTimestamp> for u128 {
    fn from(value: HlcTimestamp) -> Self {
        value.to_u128()
    }
}

impl From<u128> for HlcTimestamp {
    fn from(value: u128) -> Self {
        HlcTimestamp::from_u128(value)
    }
}

/// A Hybrid Logical Clock for generating monotonically increasing, globally unique timestamps.
///
/// HLCs combine physical time with logical counters to ensure timestamps always increase,
/// even when the system clock doesn't advance between operations.
///
/// # Example
///
/// ```
/// # use e3_events::hlc::{Hlc, HlcTimestamp, HlcError, HlcMethods};
/// # fn main() -> Result<(), HlcError> {
/// let hlc = Hlc::new(1); // Node id
/// let ts1 = hlc.tick()?;
/// let ts2 = hlc.tick()?;
/// assert!(ts2 > ts1);
///
/// // Receiving a remote timestamp
/// let remote = HlcTimestamp::new(ts1.ts + 1000, 0, 2);
/// let ts3 = hlc.receive(&remote)?;
/// assert!(ts3 > remote);
///
/// // Pack to u128 for storage/transmission
/// let ts2_num: u128 = ts2.into();
/// let ts3_num: u128 = ts3.into();
///
/// // Ordering is preserved!
/// assert!(ts3_num > ts2_num);
///
/// // Unpack from bytes
/// let restored: HlcTimestamp = ts3_num.into();
/// assert_eq!(ts3, restored);
///
/// // Packed bytes preserve sort order
/// assert!(ts2.pack() > ts1.pack());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Hlc {
    /// Inner state guarded by mutex
    inner: Arc<Mutex<HlcInner>>,
    /// Our node id
    node: u32,
    /// Maximum drift amount
    max_drift: u64,
    /// An injectable function to pass in a system clock for testing
    clock: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
}

#[derive(PartialEq)]
struct HlcInner {
    /// Current timestamp value
    ts: u64,
    /// Current logical counter
    counter: u32,
}

impl Default for Hlc {
    fn default() -> Self {
        let random_id: u32 = rand::rng().random();
        Self::new(random_id)
    }
}

impl PartialEq for Hlc {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
            && self.node == other.node
            && self.max_drift == other.max_drift
        // note clock ignored because it is only used in testing
    }
}

impl Hlc {
    const DEFAULT_MAX_DRIFT: u64 = 5 * 60 * 1_000_000; // 5 min

    pub fn new(node: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HlcInner { ts: 0, counter: 0 })),
            node,
            max_drift: Self::DEFAULT_MAX_DRIFT,
            clock: None,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(node: &str) -> Self {
        let mut h = DefaultHasher::new();
        node.hash(&mut h);
        let id: u64 = h.finish();
        Self::new(id as u32)
    }

    pub fn with_state(ts: u64, counter: u32, node: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HlcInner { ts, counter })),
            node,
            max_drift: Self::DEFAULT_MAX_DRIFT,
            clock: None,
        }
    }

    pub fn with_max_drift(mut self, max_drift: u64) -> Self {
        self.max_drift = max_drift;
        self
    }

    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Send + Sync + 'static + Fn() -> u64,
    {
        self.clock = Some(Arc::new(clock));
        self
    }

    pub fn node(&self) -> u32 {
        self.node
    }

    /// Seed the clock's physical-time floor so it can never regress below an
    /// already-emitted timestamp across a restart (H15). A node boots with a
    /// fresh HLC at `ts: 0` and re-derives time from the system clock, so a
    /// backward wall-clock jump would let freshly-`tick`ed events sort *before*
    /// events already persisted before the crash. Seeding `inner.ts` to the
    /// highest persisted timestamp makes `tick`/`receive` (which both take a
    /// `max`) monotone with respect to durable history. Counter is reset to 0:
    /// the very next `tick` at the same `ts` bumps it to 1, staying above the
    /// persisted value.
    pub fn seed_physical_floor(&self, ts: u64) {
        let mut inner = self.inner.lock().unwrap();
        if ts > inner.ts {
            inner.ts = ts;
            inner.counter = 0;
        }
    }

    pub fn get(&self) -> HlcTimestamp {
        let inner = self.inner.lock().unwrap();
        HlcTimestamp {
            ts: inner.ts,
            counter: inner.counter,
            node: self.node,
        }
    }

    fn now_physical(&self) -> Result<u64, HlcError> {
        match self.clock {
            Some(ref f) => Ok(f()),
            None => Hlc::system_now(),
        }
    }

    fn system_now() -> Result<u64, HlcError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .map_err(|_| HlcError::ClockError)
    }
}

impl HlcMethods for Hlc {
    type Error = HlcError;
    fn tick(&self) -> Result<HlcTimestamp, HlcError> {
        let now = self.now_physical()?;
        let mut inner = self.inner.lock().unwrap();

        if now > inner.ts {
            inner.ts = now;
            inner.counter = 0;
        } else {
            inner.counter = match inner.counter.checked_add(1) {
                Some(c) => c,
                None => {
                    inner.ts = inner
                        .ts
                        .checked_add(1)
                        .ok_or(HlcError::CounterOverflow { ts: inner.ts })?;
                    0
                }
            };
        }

        Ok(HlcTimestamp {
            ts: inner.ts,
            counter: inner.counter,
            node: self.node,
        })
    }

    fn receive(&self, remote: &HlcTimestamp) -> Result<HlcTimestamp, HlcError> {
        let now = self.now_physical()?;

        if remote.ts > now.saturating_add(self.max_drift) {
            return Err(HlcError::DriftExceeded {
                remote_ts: remote.ts,
                local_ts: now,
                max_drift: self.max_drift,
            });
        }

        let mut inner = self.inner.lock().unwrap();
        let max_ts = inner.ts.max(remote.ts).max(now);

        // When physical time is the max, just reset counter to 0
        if max_ts == now && max_ts != inner.ts && max_ts != remote.ts {
            inner.ts = now;
            inner.counter = 0;
            return Ok(HlcTimestamp {
                ts: inner.ts,
                counter: inner.counter,
                node: self.node,
            });
        }

        let new_counter = if max_ts == inner.ts && max_ts == remote.ts {
            inner.counter.max(remote.counter)
        } else if max_ts == inner.ts {
            inner.counter
        } else {
            // max_ts == remote.ts
            remote.counter
        };

        // Increment counter, handling overflow
        if let Some(next_counter) = new_counter.checked_add(1) {
            inner.counter = next_counter;
            inner.ts = max_ts;
        } else {
            // Counter overflow - advance timestamp and reset
            inner.ts = max_ts
                .checked_add(1)
                .ok_or(HlcError::CounterOverflow { ts: max_ts })?;
            inner.counter = 0;
        }

        Ok(HlcTimestamp {
            ts: inner.ts,
            counter: inner.counter,
            node: self.node,
        })
    }
}

pub trait HlcMethods {
    type Error: From<HlcError>;
    fn tick(&self) -> Result<HlcTimestamp, Self::Error>;
    fn receive(&self, remote: &HlcTimestamp) -> Result<HlcTimestamp, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    fn arb_timestamp() -> impl Strategy<Value = HlcTimestamp> {
        (any::<u64>(), any::<u32>(), any::<u32>())
            .prop_map(|(ts, counter, node)| HlcTimestamp::new(ts, counter, node))
    }

    fn arb_reasonable_timestamp() -> impl Strategy<Value = HlcTimestamp> {
        let now = Hlc::system_now().unwrap_or(0);
        (0..=now, any::<u32>(), any::<u32>())
            .prop_map(|(ts, counter, node)| HlcTimestamp::new(ts, counter, node))
    }

    proptest! {

          #[test]
          fn roundtrip(ts in arb_timestamp()) {
              let packed = ts.pack();
              let unpacked = HlcTimestamp::unpack(packed);
              prop_assert_eq!(ts, unpacked);
          }

          #[test]
          fn roundtrip_slice(ts in arb_timestamp()) {
              let packed = ts.pack();
              let unpacked = HlcTimestamp::unpack_slice(&packed).unwrap();
              prop_assert_eq!(ts, unpacked);
          }

          #[test]
          fn unpack_rejects_wrong_length(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
              if bytes.len() != 16 {
                  prop_assert!(HlcTimestamp::unpack_slice(&bytes).is_err());
              }
          }


          #[test]
          fn ordering_total(a in arb_timestamp(), b in arb_timestamp()) {
              let lt = a < b;
              let eq = a == b;
              let gt = a > b;
              prop_assert_eq!(
                  (lt as u8) + (eq as u8) + (gt as u8),
                  1,
                  "exactly one ordering relation must hold"
              );
          }

          #[test]
          fn ordering_antisymmetric(a in arb_timestamp(), b in arb_timestamp()) {
              if a < b {
                  prop_assert!((b >= a));
              }
              if a > b {
                  prop_assert!((b <= a));
              }
          }

          #[test]
          fn ordering_transitive(a in arb_timestamp(), b in arb_timestamp(), c in arb_timestamp()) {
              if a < b && b < c {
                  prop_assert!(a < c);
              }
              if a > b && b > c {
                  prop_assert!(a > c);
              }
          }

          #[test]
          fn ordering_reflexive(a in arb_timestamp()) {
              prop_assert!(a == a);
              prop_assert!(a <= a);
              prop_assert!(a >= a);
          }

          #[test]
          fn packed_ordering_matches(a in arb_timestamp(), b in arb_timestamp()) {
              let packed_a = a.pack();
              let packed_b = b.pack();
              prop_assert_eq!(a.cmp(&b), packed_a.cmp(&packed_b));
          }


          #[test]
          fn tick_monotonic(ts in arb_reasonable_timestamp()) {
              let hlc = Hlc::with_state(ts.ts, ts.counter, ts.node);
              let before = hlc.get();
              let after = hlc.tick().unwrap();
              prop_assert!(after > before, "tick must produce greater timestamp");
          }

          #[test]
          fn sequential_ticks_increase(ts in arb_reasonable_timestamp(), n in 1usize..100) {
              let hlc = Hlc::with_state(ts.ts, ts.counter, ts.node);
              let mut prev = hlc.tick().unwrap();
              for _ in 0..n {
                  let next = hlc.tick().unwrap();
                  prop_assert!(next > prev, "sequential ticks must increase");
                  prev = next;
              }
          }

          #[test]
          fn tick_preserves_node(ts in arb_reasonable_timestamp()) {
              let hlc = Hlc::with_state(ts.ts, ts.counter, ts.node);
              let after = hlc.tick().unwrap();
              prop_assert_eq!(after.node, ts.node);
          }


          #[test]
          fn receive_advances_past_local(
              local in arb_reasonable_timestamp(),
              remote in arb_reasonable_timestamp()
          ) {
              let hlc = Hlc::with_state(local.ts, local.counter, local.node)
                  .with_max_drift(u64::MAX);
              let before = hlc.get();
              let after = hlc.receive(&remote).unwrap();
              prop_assert!(after > before, "receive must advance past local");
          }

          #[test]
          fn receive_advances_past_remote(
              local in arb_reasonable_timestamp(),
              remote in arb_reasonable_timestamp()
          ) {
              let hlc = Hlc::with_state(local.ts, local.counter, local.node)
                  .with_max_drift(u64::MAX);
              let after = hlc.receive(&remote).unwrap();
              prop_assert!(after > remote, "receive must advance past remote");
          }

          #[test]
          fn receive_preserves_node(
              local in arb_reasonable_timestamp(),
              remote in arb_reasonable_timestamp()
          ) {
              let hlc = Hlc::with_state(local.ts, local.counter, local.node)
                  .with_max_drift(u64::MAX);
              let after = hlc.receive(&remote).unwrap();
              prop_assert_eq!(after.node, local.node);
          }

          #[test]
          fn receive_never_regresses_ts(
              local in arb_reasonable_timestamp(),
              remote in arb_reasonable_timestamp()
          ) {
              let hlc = Hlc::with_state(local.ts, local.counter, local.node)
                  .with_max_drift(u64::MAX);
              let before_ts = hlc.get().ts;
              let after = hlc.receive(&remote).unwrap();
              prop_assert!(after.ts >= before_ts, "receive must not regress timestamp");
          }

          #[test]
          fn receive_rejects_excessive_drift(node in any::<u32>(), drift in 1u64..1_000_000) {
              let max_drift = 60_000_000u64; // 60 seconds
              let hlc = Hlc::new(node).with_max_drift(max_drift);
              let now = Hlc::system_now().unwrap();

              let future_remote = HlcTimestamp::new(now + max_drift + drift, 0, node + 1);
              let result = hlc.receive(&future_remote);

              prop_assert!(
                  matches!(result, Err(HlcError::DriftExceeded { .. })),
                  "should reject timestamp too far in future"
              );
          }

          #[test]
          fn receive_accepts_within_drift(node in any::<u32>(), offset in 0u64..60_000_000) {
              let max_drift = 60_000_000u64;
              let hlc = Hlc::new(node).with_max_drift(max_drift);
              let now = Hlc::system_now().unwrap();

              let remote = HlcTimestamp::new(now + offset, 0, node + 1);
              let result = hlc.receive(&remote);

              prop_assert!(result.is_ok(), "should accept timestamp within drift");
          }





    #[test]
      fn test_receive_when_now_is_max_should_not_advance_timestamp_prop(
          local_ts in 0u64..1_000_000_000,
          local_counter in any::<u32>(),
          remote_ts in 0u64..1_000_000_000,
          remote_counter in any::<u32>(),
          local_node in any::<u32>(),
          remote_node in any::<u32>(),
      ) {
          // Ensure `now` is strictly greater than both local_ts and remote_ts
          let now = local_ts.max(remote_ts).saturating_add(1);

          let hlc = Hlc::with_state(local_ts, local_counter, local_node)
              .with_clock(move || now);

          let remote = HlcTimestamp {
              ts: remote_ts,
              counter: remote_counter,
              node: remote_node,
          };

          let result = hlc.receive(&remote).unwrap();

          // When physical time is the max, the HLC should use `now` as the timestamp
          // with counter reset to 0 - it should NOT advance beyond `now`
          prop_assert_eq!(
              result.ts, now,
              "timestamp should equal physical time, not physical time + 1"
          );
          prop_assert_eq!(
              result.counter, 0,
              "counter should reset to 0 when physical time advances"
          );
      }
    }

    #[test]
    fn u128_roundtrip_and_ordering() {
        let a = HlcTimestamp::new(100, 5, 1);
        let b = HlcTimestamp::new(100, 5, 2);

        assert_eq!(a, HlcTimestamp::from_u128(a.to_u128()));
        assert_eq!(b, HlcTimestamp::from_u128(b.to_u128()));
        assert!(a.to_u128() < b.to_u128());
    }

    #[test]
    fn new_initializes_to_zero() {
        let hlc = Hlc::new(42);
        let ts = hlc.get();
        assert_eq!(ts.ts, 0);
        assert_eq!(ts.counter, 0);
        assert_eq!(ts.node, 42);
    }

    #[test]
    fn with_state_sets_values() {
        let hlc = Hlc::with_state(100, 5, 42);
        let ts = hlc.get();
        assert_eq!(ts.ts, 100);
        assert_eq!(ts.counter, 5);
        assert_eq!(ts.node, 42);
    }

    #[test]
    fn tick_increments_counter_when_time_unchanged() {
        let hlc = Hlc::with_state(u64::MAX, 0, 1);
        let ts1 = hlc.tick().unwrap();
        let ts2 = hlc.tick().unwrap();
        let ts3 = hlc.tick().unwrap();

        assert_eq!(ts1.counter, 1);
        assert_eq!(ts2.counter, 2);
        assert_eq!(ts3.counter, 3);
        assert_eq!(ts1.ts, u64::MAX);
    }

    #[test]
    fn tick_resets_counter_when_time_advances() {
        let hlc = Hlc::with_state(0, 999, 1);
        let ts = hlc.tick().unwrap();

        assert_eq!(ts.counter, 0);
        assert!(ts.ts > 0);
    }

    #[test]
    fn seed_physical_floor_prevents_regression_below_seed() {
        // Simulate a restart where the wall clock jumped backwards: the system
        // clock reports an earlier physical time than already-emitted history.
        let hlc = Hlc::new(1).with_clock(|| 1_000);
        hlc.seed_physical_floor(5_000);

        let ts = hlc.tick().unwrap();
        // Even though now_physical() == 1_000, the seed floor keeps us ahead.
        assert_eq!(ts.ts, 5_000);
        assert_eq!(ts.counter, 1);
    }

    #[test]
    fn seed_physical_floor_is_noop_when_below_current() {
        let hlc = Hlc::with_state(9_000, 4, 1);
        hlc.seed_physical_floor(5_000);
        let ts = hlc.get();
        assert_eq!(ts.ts, 9_000);
        assert_eq!(ts.counter, 4);
    }

    #[test]
    fn receive_picks_max_timestamp() {
        let hlc = Hlc::with_state(100, 5, 1).with_max_drift(u64::MAX);
        let remote = HlcTimestamp::new(200, 3, 2);
        let result = hlc.receive(&remote).unwrap();

        assert!(result.ts >= 200);
    }

    #[test]
    fn receive_merges_counters_when_ts_equal() {
        let hlc = Hlc::with_state(u64::MAX, 5, 1).with_max_drift(u64::MAX);
        let remote = HlcTimestamp::new(u64::MAX, 10, 2);
        let result = hlc.receive(&remote).unwrap();

        assert_eq!(result.counter, 11); // max(5, 10) + 1
    }

    #[test]
    fn ordering_tiebreaks_on_counter() {
        let a = HlcTimestamp::new(100, 5, 1);
        let b = HlcTimestamp::new(100, 6, 1);
        assert!(a < b);
    }

    #[test]
    fn ordering_tiebreaks_on_node() {
        let a = HlcTimestamp::new(100, 5, 1);
        let b = HlcTimestamp::new(100, 5, 2);
        assert!(a < b);
    }

    #[test]
    fn hash_consistent_with_eq() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = HlcTimestamp::new(100, 5, 1);
        let b = HlcTimestamp::new(100, 5, 1);

        let hash = |ts: &HlcTimestamp| {
            let mut h = DefaultHasher::new();
            ts.hash(&mut h);
            h.finish()
        };

        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
    }

    #[test]
    fn concurrent_ticks_unique() {
        let hlc = Arc::new(Hlc::new(1));
        let mut handles = vec![];

        for _ in 0..10 {
            let hlc = Arc::clone(&hlc);
            handles.push(thread::spawn(move || {
                (0..1000).map(|_| hlc.tick().unwrap()).collect::<Vec<_>>()
            }));
        }

        let all_timestamps: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        let unique: HashSet<_> = all_timestamps.iter().collect();

        assert_eq!(
            all_timestamps.len(),
            unique.len(),
            "all {} timestamps must be unique, got {} unique",
            all_timestamps.len(),
            unique.len()
        );
    }

    #[test]
    fn concurrent_ticks_ordered() {
        let hlc = Arc::new(Hlc::new(1));
        let mut handles = vec![];

        for _ in 0..4 {
            let hlc = Arc::clone(&hlc);
            handles.push(thread::spawn(move || {
                let mut timestamps = Vec::with_capacity(1000);
                for _ in 0..1000 {
                    timestamps.push(hlc.tick().unwrap());
                }
                // Each thread's timestamps should be strictly increasing
                for window in timestamps.windows(2) {
                    assert!(window[0] < window[1]);
                }
                timestamps
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn concurrent_receive_and_tick() {
        let hlc = Arc::new(Hlc::new(1).with_max_drift(u64::MAX));
        let mut handles = vec![];

        // Tickers
        for _ in 0..4 {
            let hlc = Arc::clone(&hlc);
            handles.push(thread::spawn(move || {
                (0..500).map(|_| hlc.tick().unwrap()).collect::<Vec<_>>()
            }));
        }

        // Receivers
        for i in 0..4 {
            let hlc = Arc::clone(&hlc);
            handles.push(thread::spawn(move || {
                (0..500)
                    .map(|j| {
                        let remote = HlcTimestamp::new(j as u64 * 1000, 0, 100 + i);
                        hlc.receive(&remote).unwrap()
                    })
                    .collect::<Vec<_>>()
            }));
        }

        let all_timestamps: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        let unique: HashSet<_> = all_timestamps.iter().collect();

        assert_eq!(
            all_timestamps.len(),
            unique.len(),
            "all timestamps must be unique under mixed operations"
        );
    }
}
