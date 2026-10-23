# e3-aggregator

Public-key and plaintext aggregation own persisted phase decisions; effects own proof/chain work. Do
not replace the canonical roster with the fastest local arrivals or infer full committee from an
already-filtered set of shares.

- Standbys persist validated inputs too. Readiness must describe a phase that can actually resume
  before failover starts its budget. Demotion does not discard work the former aggregator started.
- Preserve zero-based runtime IDs versus one-based decryption coordinates and full-N versus
  selected-H indexing. Decryption needs T+1 valid roster shares, not H; late backups do not mutate
  in-flight batch.
- Hydration validates signed C6 inputs/C7 bindings even in Complete. Missing key authority leaves
  saved state dormant; it does not authorize replacing it or blocking the shared router on RPC.
- Finalization retains request-time chain context and absolute deadline; each retry uses a fresh
  read provider. Canonical key publication ends DKG removals even for an incomplete standby.

See [DKG](../../docs/architecture/dkg.md) and
[decryption](../../docs/architecture/threshold-decryption.md). Use the
[README test map and prerequisites](README.md#tests). Phase/recovery changes need the affected
standby, demotion, and restart histories; local mocks do not establish recursive proof validity.
