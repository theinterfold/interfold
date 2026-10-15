# e3-data

Maintain persistence mechanisms here, with typed repository keys owned by capability factories.
[README.md](README.md) explains the storage API and operational backup/repair boundary.

- The commit log is replay authority; Sled indexes/snapshots are derived. Preserve append/sync and
  acknowledged-write distinctions rather than treating an actor mailbox send as durability.
- Log blobs and their versioned references form one durable unit. Verify digest/length before
  decode, retain referenced blobs, and only collect unreferenced files after committed-log scanning.
- Repair may reconcile a provably uncommitted physical tail; indexed corruption must fail closed. Do
  not turn normal open/read paths into destructive salvage.
- Preserve repository scopes, bincode layouts, and error propagation across in-memory and Sled
  implementations. A memory-only regression cannot establish crash/flush guarantees.

Run `cargo test --locked -p e3-data`, including temporary-directory log/blob tests for durable I/O
changes. Consult [persistence](../../docs/architecture/persistence-and-replay.md) and
[upgrades](../../docs/architecture/upgrades.md) before changing formats or locations.
