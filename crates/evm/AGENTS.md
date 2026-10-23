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
- Preserve saved slash-intent times and remaining rank delays across restart. Permanent decoded
  errors must exist in the Rust ABI and end retries; transport/unknown errors remain retryable.
- Resolve each enabled chain's slashing manager only from Interfold. Exhausted reads/zero response
  fail full-node startup; configuration is a fallback only for disabled chains. Preserve the
  chain-specific signing domain, deploy-block backfill, and live manager-replacement stop.
- `fetch_operator_committees` trusts the obligation views only when every index answers at one
  confirmed block hash; any failed read falls back to the event scan. Check the saved block hash
  before and after a resumed read: another hash rescans from the deploy block, and a missing block
  (a lagging provider) returns the result unsaved.

See [selection](../../docs/architecture/committee-selection.md),
[decryption](../../docs/architecture/threshold-decryption.md), and
[slashing](../../docs/architecture/slashing.md). `build.rs` invokes solc and rewrites the emit-logs
fixture JSON even for a Cargo check; edit its Solidity source, not generated ABI/bytecode. Use the
[README test targets/prerequisites](README.md#tests-and-build-prerequisites). Reader changes need
the affected history/handoff scenario; preflight unit tests do not establish reorg rollback or
exactly-once transactions.
