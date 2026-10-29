# e3-evm-helpers

This crate supplies application-side listeners, contract helpers, retries, and nonce handling;
ciphernode ingestion policy belongs in `e3-evm`.

- Listener progress must describe successfully applied observations, not just received headers.
  Preserve catch-up/subscription coordination and propagate handler failures to cursor owners.
- Keep nonce serialization scoped to its provider/signer use. A process-local nonce manager does not
  coordinate independent processes or create a durable transaction outbox.
- Retry classification and confirmation queues are observable delivery behavior. Cover duplicate,
  out-of-order, and failed-handler paths when changing them, not only successful live callbacks.
- `build.rs` always invokes `scripts/build_fixtures.sh`: even `cargo check` needs solc, jq, and bash
  and can rewrite fixture JSON. Edit Solidity fixture sources, not their generated ABI/bytecode.

Use the [README tests/prerequisites](README.md#tests-and-build-prerequisites). See the
[indexer guidance](../indexer/AGENTS.md) before changing shared listener/cursor semantics; a
local-chain test is not reorg or exactly-once assurance.
