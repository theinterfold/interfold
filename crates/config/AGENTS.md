# e3-config

Keep network profiles and compiled release identity here. Node profile resolution and paths belong
to [e3-ciphernode-config](../ciphernode/config/README.md); loading and program settings belong to
the [CLI](../cli/README.md#configuration-loading). Chain settings belong to
[e3-evm-config](../evm/config/README.md).

- Never change a released built-in network ID. Bootstrap aliases and explicit peer normalization
  distinguish public networks; preserve their rejection and migration behavior.
- `protocol-release.toml` is consumed by Rust and contract tooling. Keep the workspace version and
  release-ID hash domain aligned; a source/package move must not change identity or counters.
- Public network/release configuration is admission input, not proof that a chain or peer is
  trusted. Leave runtime chain-ID and compatibility checks at their existing boundaries.

Use the [README tests](README.md#tests). For counter or admission changes, consult
[upgrades](../../docs/architecture/upgrades.md) and test affected startup callers too.
