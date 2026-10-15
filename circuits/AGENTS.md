# Working on Noir circuits

Shared constraints belong in `lib/src/`; `bin/` packages expose their witness/public-input boundary.
[README.md](README.md) maps circuit names and commands;
[proof statements](../docs/architecture/proof-statements.md) owns cross-language rules and limits.

- Public-input order, coefficient/CRT/party axes, signed-field encoding, and recursive VK genealogy
  are proof interfaces. Coordinate their Rust witness and Solidity consumers, not just Noir callers.
- Change generators rather than generated bounds, parity matrices, or active selectors. Use the
  [circuit builder](../scripts/README.md#circuit-builder) for preset/committee switches and artifact
  regeneration; a valid witness alone does not establish deployed verifier compatibility.
- Files inside discovered `bin/` packages and hashed shared-source directories contribute to source
  identity, including any README there. Avoid incidental churn in those paths and report intentional
  hash changes. Do not hand-restamp artifacts to hide a changed source identity.
- `pnpm noir:lint` can skip when nargo is absent and deletes generated `Prover.toml` files in
  checked packages. `pnpm noir:test` temporarily rewrites active committee/preset selectors and
  restores them on exit; neither is safe to run concurrently with another preset build in this
  checkout.

Use the pinned nargo/bb versions from `crates/zk-prover/versions.json`. Start with the changed
package's `nargo test`, then the affected root Noir suite. Statement/aggregation changes also need
the prepared Rust real-proof and contract acceptance paths in the
[artifact workflow](../docs/architecture/circuit-artifacts.md); report missing tools and skips.
