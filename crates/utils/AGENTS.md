# e3-utils

Keep shared mechanical helpers here; capability-specific protocol rules belong with their owners.

- Bounded bincode decoding deliberately uses the reader API, fixed integers, and complete
  consumption. The slice decoder can disable its limit; do not simplify away allocation/trailing
  byte defenses or change the legacy encoding while retaining the same helper name.
- `BytesSerde` / `AsBytesSerde` preserve human-readable hex versus binary bytes. Validate lengths in
  each type and keep the self-crate alias used by generated macro paths.
- Retriable versus permanent failure is caller-visible behavior; don't retry semantic rejection
  indefinitely. Successful RPC submission is not a successful transaction receipt.
- Actix/Tokio bridging helpers must preserve acknowledgment and error behavior. A fire-and-forget
  channel send is not equivalent to awaited completion of the underlying work.

Run `cargo test --locked -p e3-utils`, including malformed-length/trailing-byte and macro consumer
coverage for encoding changes. These helpers serve durable/wire data; consult
[upgrades](../../docs/architecture/upgrades.md) before changing serialized behavior.
