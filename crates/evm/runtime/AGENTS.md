# e3-evm

This crate serves the CLI's chain commands. The node's chain adapter is
[e3-chain](../../ciphernode/chain/); do not add node ingestion or transaction policy here.

- Preserve adaptive log-range retry at the same start block and its one-block failure floor.
- `fetch_operator_committees` trusts the obligation views only when every index answers at one
  confirmed block hash; any failed read falls back to the event scan. Check the saved block hash
  before and after a resumed read: another hash rescans from the deploy block, and a missing block
  (a lagging provider) returns the result unsaved.
- Permanent decoded errors must exist in the Rust ABI.

Use the [README test target](README.md#tests).
