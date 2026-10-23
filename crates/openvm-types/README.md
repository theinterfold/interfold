# e3-openvm-types

## Purpose

Shared host/guest input framing and public journal for the OpenVM Secure Process. This crate defines
bytes and domain identity, not worker/backend execution.

## Map

[`src/lib.rs`](src/lib.rs) is the shared format implementation. `GuestHeader` encodes computation
metadata; `write_items`/`ItemReader` frame a bounded stream; `ComputeDomain`/`ComputeJournal`
describe the public result and explicitly ordered ABI words. Its inline tests pin these bytes. The
host writes the stream, the worker/guest reads it, and the verifier consumes the journal.

## Input stream

`GuestHeader` holds `ComputeDomain`, encoded BFV parameters, ciphertext indices, and published
metadata. `encode()` / `decode()` use fixed-integer bincode and reject trailing bytes.
`write_items(writer, exact_size_iterator)` writes framed byte items; `ItemReader::new(reader)` reads
the count and `next_item()` checks each length before allocation. `MAX_ITEM_BYTES` bounds an
individual item.

The stream order is header, every ciphertext, then the selected ciphertexts in the prescribed
second-pass order. The [host](../openvm-host/src/lib.rs) writes this stream for the
[OpenVM worker](../openvm-prover/README.md); native encoding alone does not prove guest parity.

## Public journal

`ComputeJournal::new(domain, result)` derives a journal from the authenticated computation result.
`abi_bytes()` emits `JOURNAL_BYTES` (nine 32-byte ABI words), including the full
chain/deployment/E3/encryption-scheme/committee-key domain and result commitments. Use this explicit
ABI method, not a generic serde encoding of the Rust struct, for Solidity receipt verification.

The journal is public and replay-bound; input/selection framing is not a substitute for that domain.
See [encrypted computation](../../docs/architecture/encrypted-computation.md) for the application,
guest, and contract boundary.

## Tests

Run `cargo test --locked -p e3-openvm-types`. Inline tests pin journal word order, header exact
consumption, item framing, and rejection of truncated/padded streams; no worker or GPU is needed.
Real proof compatibility requires the matching
[OpenVM setup and parity flow](../openvm-prover/README.md). Format-change responsibilities are in
[AGENTS.md](AGENTS.md).
