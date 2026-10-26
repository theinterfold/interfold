# e3-utils

## Purpose

Shared mechanical helpers for runtime/adapters: bounded decoding, byte wrappers, retry and receipt
handling, Actix/Tokio channels, paths, and diagnostic formatting. Capability-specific protocol
decisions live in their owning crates.

## Map

| Location                                                                                                                           | Responsibility                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [`bounded_bincode.rs`](src/bounded_bincode.rs), [`serde_bytes.rs`](src/serde_bytes.rs), [`utility_types.rs`](src/utility_types.rs) | Bounded wire decoding, byte-serde contract, and shared byte/RNG types.            |
| [`actix/`](src/actix)                                                                                                              | Recipient/channel/one-shot adapters and synchronous handler bridging.             |
| [`retry.rs`](src/retry.rs), [`transaction.rs`](src/transaction.rs)                                                                 | Retry classification/backoff and receipt-status checks.                           |
| [`helpers.rs`](src/helpers.rs), [`path.rs`](src/path.rs), [`formatters.rs`](src/formatters.rs)                                     | Ordered extraction, one-time ownership, enumerated paths, and bounded formatting. |
| [`ordered_set.rs`](src/ordered_set.rs)                                                                                             | Sorted set with order-independent equality and hash, serialized as a sequence.    |

These are independent leaf helpers, not a runtime pipeline. Callers select explicit byte budgets,
retry policy, and acknowledgment behavior; no capability policy is inferred by the utility layer.

## Decode bounded data

```rust
use e3_utils::deserialize_bounded;

let encoded = bincode::serialize(&vec![1_u64, 2, 3]).unwrap();
let decoded: Vec<u64> = deserialize_bounded(&encoded, 1024).unwrap();
assert_eq!(decoded, vec![1, 2, 3]);
```

`deserialize_bounded(bytes, max_bytes)` uses the repository's legacy bincode-1 fixed-integer format,
enforces the byte budget through a reader, and rejects trailing bytes. `deserialize_exact` uses the
supplied encoded length as its budget. Neither validates application authorization or the semantic
meaning of the decoded value.

## Other entry points

- `ArcBytes` shares byte vectors; `SharedRng` is the common mutex-backed ChaCha20 RNG type.
- `AsBytesSerde` and the re-exported `BytesSerde` derive encode human-readable hex versus binary
  byte strings. See [derive usage](../utils-derive/README.md) for caller dependencies/validation.
- `retry_with_backoff` distinguishes `RetryError::Retry` and `RetryError::Failure` according to
  caller classification. Its waits double from the initial delay, capped at five minutes before
  adding up to 10% jitter. `backoff_delay(base, attempt, cap)` exposes the same calculation;
  attempts start at 1. RPC defaults use three attempts and a two-second initial delay.
- `require_successful_receipt` checks a transaction receipt rather than mistaking RPC submission for
  successful execution.
- `actix` exposes message/channel adapters and `NotifySync`; `OnceTake` transfers a shared value at
  most once. Awaited acknowledgments and fire-and-forget sends have different contracts.
- `enumerate_path`, ordering, and formatting helpers avoid duplicating mechanical conversions.

## Tests

Run `cargo test --locked -p e3-utils`. Inline cases cover malformed/over-budget/trailing bincode,
byte wrapper capacity/serde use, receipt status, enumerated paths, bounded formatting, and one-shot
actor execution. Retry cases cover exponential growth, the cap, and the jitter interval. No chain
RPC or prover is required. Serialized helpers serve saved/wire data; see
[upgrades](../../docs/architecture/upgrades.md) and [AGENTS.md](AGENTS.md) for compatibility
changes.
