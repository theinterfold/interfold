# e3-evm

This crate owns chain ingestion and transaction adapters. Contract/lifecycle rules stay with their
domain owner; keep receipt/preflight failures distinct from accepted chain facts.

- Reader watermarks advance only after verified/decoded observations; subscriptions wake canonical
  backfill rather than proving completeness. A loopback URL does not imply development finality.
- Preserve adaptive log-range retry at the same start block and its one-block failure floor. Reader
  session narrowing and one-shot fetch narrowing have different lifetimes.
- Canonical key/decryption authority comes from confirmed history before intent dedup, not gossip or
  an opportunistic registry read. Only local result intents can cause publication transactions.
- Slash submissions have a durable semantic outbox. Other writer gates rebuild from journaled
  intents plus chain preflights; in-process nonce serialization is not a distributed nonce journal.
- Resolve each enabled chain's slashing manager from Interfold at startup. A configured fallback
  after exhausted reads/zero response is a degraded path that can name a retired manager; keep its
  error and warning visible, chain-specific signing domain, and configured backfill start.

See [selection](../../docs/architecture/committee-selection.md),
[decryption](../../docs/architecture/threshold-decryption.md), and
[slashing](../../docs/architecture/slashing.md). `build.rs` invokes solc and rewrites the emit-logs
fixture JSON even for a Cargo check; edit its Solidity source, not generated ABI/bytecode. Prepare
root `pnpm evm:build` / `pnpm fixtures:build` with solc/jq, then use `cargo test --locked -p e3-evm`
with Anvil where required. Preflight unit tests do not establish reorg rollback or exactly-once
transactions.
