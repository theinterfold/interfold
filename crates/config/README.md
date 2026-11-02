# e3-config

## Purpose

Resolves network identity, bootstrap policy, and compiled node release identity. Node profiles and
paths belong to [e3-ciphernode-config](../ciphernode/config/README.md); chain settings belong to
[e3-evm-config](../evm/config/README.md). Runtime adapters still check chain identity, deployed
releases, and peer compatibility.

## Map

[`network.rs`](src/network.rs) resolves built-in/custom network IDs and bootstrap peers.
[`node_release.rs`](src/node_release.rs) compiles [release counters](protocol-release.toml) and
derives the release ID from the exact workspace version.

Resolving settings alone does not contact or authenticate a chain or peer.

## Network and release boundaries

Network IDs distinguish deployments, not releases. Built-in IDs are fixed; custom networks require
an explicit 32-byte ID. Release protocol versions additionally scope P2P admission. Node generation
does not create a separate overlay.

Follow [upgrades](../../docs/architecture/upgrades.md) before changing counters or release identity;
the manifest is also read by contract deployment tooling.

## Tests

Run `cargo test --locked -p e3-config`. Inline tests cover network profiles and release identity
without starting a node or contacting configured RPCs. Changes to admission also need affected
[network tests](../net/README.md#tests). See [AGENTS.md](AGENTS.md) for identity/counter hazards.
