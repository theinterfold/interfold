# Ciphernode composition and services

The ciphernode's engine, its adapters, its assembly, and the commands that operate it share this
family. Each remains an independently importable package in the root Cargo workspace; this directory
is not a package or nested workspace.

- [engine](engine/) runs the [protocol machine](../protocol/): it journals each input, commits the
  machine's effects in the same transaction, and replays the journal on restart.
- [chain](chain/) reads the contracts' events in order and sends the node's transactions.
- [p2p](p2p/) carries the committee's messages and blobs over libp2p.
- [jobs](jobs/) runs the CPU work (key generation, shares, proofs) off the engine.
- [node](node/) wires the engine to the adapters, the keys, and the data folder.
- [config](config/README.md) resolves node profiles, paths, and network/release identity.
- [daemon-server](daemon-server/README.md) provides loopback CLI control transport.
- [entrypoint](entrypoint/README.md) owns the process fence, the store record, the node password,
  and the `interfold nodes` process manager.

The [CLI](../cli/README.md) and CLI-owned [initializer](../init/README.md) remain standalone roots:
they serve application projects as well as ciphernode operators. [console](../console/README.md) and
[filesystem](../fs/README.md) capabilities remain separate roots rather than becoming node-specific
utilities.

Checkout-relative paths for this family's members start with `crates/ciphernode/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks. The
[decision log](../../docs/architecture/node-v2-decisions.md) records the node's design;
[upgrades](../../docs/architecture/upgrades.md) owns compatibility and rollback decisions.
