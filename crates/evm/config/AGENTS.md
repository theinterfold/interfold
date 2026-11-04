# e3-evm-config

Keep connection and chain-setting interpretation independent of node profiles, application loading,
and provider I/O. Runtime chain/release validation and transaction/recovery policy stay in
[e3-evm](../runtime/AGENTS.md); ABI facts stay in `contracts`.

- Preserve configuration keys, serde representations, endpoint conversions, and contract ordering.
  Authentication and deploy-block handling must not change as a side effect of moving types.
- A loopback endpoint may proxy a public chain. Only explicit configuration changes confirmation
  depth, polling interval, or log-window defaults; keep nonzero validation and genesis-read guards.
- These settings are not verified chain facts. Do not infer deployed identity or compatibility from
  a configured chain ID or address.

Use the [README tests](README.md#tests). Ingestion changes also need the affected runtime history
scenario; field/encoding changes need explicit compatibility review, not just a changed fixture.
