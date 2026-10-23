# Indexer catch-up and coverage

## Purpose

`e3-indexer` maintains application-side E3/committee/output projections from Interfold logs and lets
consumers attach raw/typed callbacks. It combines [EVM listeners](../evm-helpers/README.md) with a
consumer-provided store; it is not the ciphernode's protocol event journal.

## Map

| Location                                                   | Responsibility                                                                                 |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [`indexer.rs`](src/indexer.rs)                             | Construction, built-in projections/key assembly, callbacks, catch-up, and cursor coordination. |
| [`models.rs`](src/models.rs), [`traits.rs`](src/traits.rs) | E3/committee data and the application store interface.                                         |
| [`repo.rs`](src/repo.rs)                                   | Projection accessors and updates preserving already-indexed round state.                       |
| [`callback_queue.rs`](src/callback_queue.rs)               | Timestamp-scheduled application callbacks.                                                     |
| [`tests/integration.rs`](tests/integration.rs)             | Local-contract indexing, backfill, and listener-lifetime scenarios.                            |

## Usage and catch-up

`InterfoldIndexer::<InMemoryStore, ReadOnly>::from_endpoint_address_in_mem(rpc_url, addresses)`
creates a read-only in-memory indexer. Custom stores/signing clients use the other constructors in
`indexer.rs`. Register `add_raw_log_handler` or `add_event_handler`, optionally configure backfill,
then await `listen()`. Query with `get_e3`, or use `get_store` for application data.
[`tests/integration.rs`](tests/integration.rs) shows concrete callback/store wiring.

`InterfoldIndexer::configure_backfill` opts a consumer into historical catch-up and cursor writes.
Without it, the subscription starts at head and writes no recovery cursor. This matters because
application handlers can send transactions or initialize rounds: replay is not automatically safe
for every consumer. Opted-in raw handlers must be idempotent and return failed writes as errors.

## What the cursor means

`INDEXER_CURSOR_KEY` (`_indexer:cursor`) is a best-effort **raw-handler** applied-block watermark:

- Typed live handlers run concurrently and log/drop their errors; cursor progress says nothing about
  their completion. Consumers must inspect the typed projection they require.
- Backfill advances only after every raw handler in a window succeeds, sequentially in block order.
  A raw-handler failure clears live health and aborts that subscription, rather than sealing a gap.
- Live headers are separate from logs. Progress is capped by `LiveProgress::applied_ceiling` as well
  as the one-block header hedge; head height alone cannot claim that slow raw work has finished.
- Concurrent block callbacks use `fetch_max` for a monotonic in-memory claim. That does **not**
  order their subsequent asynchronous store inserts. Write failures are logged, so persisted cursor
  state is not an atomic completion ledger for all projections.

The listener catches up twice on each connection: first until the independently read head converges,
then again after `wait_subscribed` confirms a live subscription. The second pass covers blocks mined
between the first head read and subscription admission. Only its success sets `caught_up`; headers
cannot advance the cursor while that handoff range is outstanding. Duplicate overlap is intentional:
for example CRISP log append deduplicates by `(block_number,log_index)`.

Repeated catch-up failure can resume live subscription with the old cursor and `caught_up` false. It
does not claim the unreplayed range; later attempts must still recover it. A persisted watermark
alone is therefore neither complete event coverage nor Ethereum finality/reorg rollback.

## Consumer ownership

Coverage records in stores without delete can outlive the deployment/configuration that created
them; consumers need their live bindings, not only the stored record.

Committee-key bytes are untrusted until assembled and checked against the proven request-time
commitment. [DKG transport](../../docs/architecture/dkg.md) owns that boundary. CRISP's request/key
convergence, deferred census discovery, and selection cache have separate application state; see
[encrypted computation](../../docs/architecture/encrypted-computation.md). The watermark cannot
stand in for those state checks.

## Tests

Prepare root `pnpm fixtures:build` with bash, solc, and jq: the build script invokes Solidity
fixture compilation even for checks. `cargo test --locked -p e3-indexer` exercises inline
callback/repository/key-assembly tests and the Anvil-backed integration target. Listener
subscription/progress tests are in [event_listener.rs](../evm-helpers/src/event_listener.rs),
runnable with `cargo test -p e3-evm-helpers`. They do not establish all-handler crash consistency or
atomicity of concurrent cursor writes. See [AGENTS.md](AGENTS.md) for handler/cursor changes and
ownership hazards.
