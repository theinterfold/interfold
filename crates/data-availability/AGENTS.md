# e3-data-availability

This crate owns content-addressed transport and bridge-proof encoding, not application job finality.

- Validate object bounds before publication and rehash retrieved bytes against the reference. An
  Ethereum-verified availability receipt does not make arbitrary RPC response bytes trustworthy.
- Keep VectorX's returned leaf hash distinct from the bridge's next hashing step; pre-hashing again
  at this boundary breaks real proofs even if mock object retrieval passes.
- `AvailMerkleProofInput` must remain ABI-identical to the contract interface. Preserve checked
  coordinate conversions and finalized publication block numbers when assembling references.
- Pending bridge proofs are retryable absence, not verified inclusion or permanent failure. Keep the
  optional Avail reader/submitter features separate from the default HTTP/mock boundary.

Use the [README tests/feature checks](README.md#tests), including the optional adapters for Avail
changes. Mock tests do not establish bridge finality; see
[data availability](../../docs/architecture/data-availability.md).
