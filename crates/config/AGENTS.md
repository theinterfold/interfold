# e3-config

Keep node profile resolution and path derivation here; runtime components consume resolved settings.
File discovery, YAML/environment/CLI precedence, and program settings belong to the
[CLI](../cli/README.md#configuration-loading), not this crate. Chain/RPC/contract-endpoint settings
belong to [e3-evm-config](../evm/config/README.md).

- Relative key, database, and log paths have different bases; use `PathsEngine` rather than cwd
  joins. Preserve the loaded file's location when deriving project-local paths.
- Path changes can select another identity or durable store. Cover project-local and default OS
  layouts, named nodes, absolute overrides, and relative overrides before changing resolution.
- Public network/release configuration is admission input, not proof that a chain or peer is
  trusted. Leave runtime chain-ID and compatibility checks at their existing boundaries.

Use the [README tests](README.md#tests). For changes to durable locations or release counters,
consult [upgrades](../../docs/architecture/upgrades.md) and test affected startup callers too.
