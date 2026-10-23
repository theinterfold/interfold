# e3-data-availability

## Purpose

Content-addressed data transport for Interfold applications: publication coordinates, retrieval, and
Avail/VectorX bridge-proof encoding. Application job scheduling and Ethereum acceptance remain with
their respective owners.

## Map

| Location                   | Responsibility                                                                    |
| -------------------------- | --------------------------------------------------------------------------------- |
| [`lib.rs`](src/lib.rs)     | Content references, transport traits, bounds, HTTP reader, and VectorX proof ABI. |
| [`avail.rs`](src/avail.rs) | Feature-gated Avail retrieval and signed submission/finalization.                 |

Publication produces pending coordinates; a later bridge query supplies the Ethereum proof and final
reference. Retrieval checks bytes against that reference independently of bridge acceptance. The
adapters share the content-hash/bounds boundary, so changing transport does not make RPC bytes
authoritative.

## Publication and retrieval

`DataAvailabilityPublisher` separates `publish(bytes)` from `proof(publication)`. Publication
returns a `PendingPublication`; poll for `ProofStatus::Ready { reference, abi_proof }` before
submitting the proof to the application contract. `Pending` is retryable proof absence, not verified
inclusion. `DataReference` records the content hash, finalized block number, and leaf index used for
later retrieval.

`DataAvailabilityReader::retrieve(reference)` returns verified object bytes. The public
`verify_retrieved_bytes` helper validates bounds and Keccak-256 against the reference; readers must
not trust RPC bytes merely because Ethereum accepted an availability receipt. Objects must be
nonempty and at most `MAX_OBJECT_BYTES` (one MiB).

## Adapters and features

- Default features are empty. `HttpObjectReader::new(base_url)` reads the local mock's
  `/objects/0x<hash>` endpoint; `VectorXBridgeApi::new(base_url, destination_chain_id)` queries
  bridge proofs.
- `avail-read` enables `AvailReader::new(endpoint)` for Avail RPC retrieval.
- `avail-submit` enables `AvailPublisher` with endpoint, application ID, signing secret, and bridge
  configuration. Use its [constructor](src/avail.rs) for the complete arguments.

These optional adapters require the corresponding live Avail/bridge services; default unit tests do
not. `AvailMerkleProofInput` is the Solidity-compatible bridge ABI type, not a generic Merkle-proof
format. See [data availability](../../docs/architecture/data-availability.md) for the
application/contract flow and trust boundary.

## Tests

Run `cargo test --locked -p e3-data-availability`; check optional adapters with
`cargo check --locked -p e3-data-availability --features avail-read,avail-submit`.

Inline tests cover substituted bytes, bridge response/URL shape, Solidity proof encoding, and
optional endpoint validation. They do not publish to Avail or wait for bridge finality; those
require configured live services. See [AGENTS.md](AGENTS.md) for adapter-change guidance.
