# Part 7: Contract and Ciphernode Upgrades

## Version model

Interfold uses three separate identifiers:

- `releaseId = keccak256("interfold.node.release:v1:" + exactSemver)` identifies one build release.
- `protocolVersion` increases for an incompatible contract, event, cryptographic, or protocol
  change.
- `nodeGeneration` increases when a node-only bug or security fix must become mandatory.

Every P2P protocol name includes `protocolVersion`, so incompatible releases cannot gossip,
discover, or synchronize with each other. P2P encoding remains separate. Increase
`GOSSIP_WIRE_MAJOR` or `SYNC_WIRE_MAJOR` when the corresponding wire format becomes incompatible
within the same protocol version.

The fhe.rs v0.4.1 upgrade raises `protocol_version` from 4 to 5. Its smudging bound and BFV
validation rules change the DKG and proof inputs. Its non-centered plaintext scale also changes the
CRISP ballot check and its circuit artifacts. Drain active E3s and install matching circuit
artifacts and verifier routes before requests resume. The circuit ID domain changes from
`interfold-bfv-v1` to `interfold-bfv-v2` for both parameter sets. Old clients must update their
expected configuration IDs before they submit new requests. The RISC Zero guest in `crates/support`
uses a separate, content-addressed Interfold revision. Rebuild its image and provenance record
before changing that guest revision or its fhe.rs pin.

## Compatible rolling release

```text
build backward-compatible release
  -> keep protocol_version and node_generation unchanged
  -> publish the versioned binary without a governance transaction
  -> operators restart one at a time without dropping an active committee below threshold
  -> new node verifies the required counters and acknowledges its releaseId and counters
  -> old compatible nodes remain eligible
```

Use `pnpm --dir packages/interfold-contracts upgrade:node-release --action prepare` to confirm that
the release needs no governance transaction. Do not change either compatibility counter in this
path. A compatible contract-only change also needs no node policy change.

## Mandatory node-only release

```text
increase node_generation and build release
  -> pause new E3 requests
  -> wait for activeE3Count == 0 and unreleasedCommitteeCount == 0
  -> governance raises the required node generation
  -> BondingRegistry invalidates all active statuses in O(1)
  -> old nodes cannot become active or enter new committees
  -> upgraded nodes start, verify policy, acknowledge, and refresh themselves
  -> upgraded nodes remain on the existing protocol-version P2P network
  -> wait until active release-ready nodes cover the largest committee N
  -> governance resumes requests
```

If the bug affects network parsing, message meaning, or peer safety, use a protocol-version cutover
instead. A node-generation cutover changes committee eligibility but does not isolate old peers.

Prepare with `upgrade:node-release --action prepare --mandatory`. After operators restart, use
`upgrade:node-release --action resume` to build the checked resume transaction.

## Contract or protocol upgrade

Increase `protocol_version`. Pause and drain first. One governance proposal must upgrade the
contracts and raise the required protocol version. Restart nodes after that proposal executes.
Upgrade at least one configured bootstrap peer before the remaining operators. Resume only after the
on-chain active count can fill every configured committee and the new-version peers can discover
each other.

Treat the contracts, verifier routes, ciphernode protocol version, CRISP program, CRISP server, and
DAO application addresses as one cutover. Do not run a mixed stack. Use this order:

```text
pause new requests and drain every E3 and committee
  -> deploy immutable replacement routers and the new CRISP program
  -> execute the protocol implementation, route, program, and required-version updates
  -> run the route and verification-key validator against every enabled pair
  -> restart the matching server and ciphernode release
  -> update the server and DAO application addresses
  -> verify server health and peer discovery
  -> resume requests
```

On a testnet, a fresh protocol, CRISP, and DAO stack is an acceptable alternative to an in-place
upgrade. It must still pass the same route and verification-key validation before it accepts an E3.
The old and new stacks must use separate addresses so clients cannot silently combine them.

The initial VRF upgrade follows this combined path because it introduces the controller and changes
both `Interfold` and `BondingRegistry`.

## Secure CRISP activation on mainnet

The bootstrap deployment does not become production-ready when CRISP contracts are deployed. With
requests paused and all E3s and committees drained, `upgrade:secure-crisp` prepares one atomic
governance batch that:

```text
snapshot the operator counts and registry root
  -> upgrade Interfold, CiphernodeRegistry, BondingRegistry, and E3RefundManager in place
  -> deploy and wire a replacement SlashingManager
  -> copy every configured slash policy, including policies that are currently disabled
  -> preserve the registered operators and revoke the drained old manager
  -> deploy a replacement VRF consumer against the existing funded subscription
  -> add the new consumer and switch the registry without replacing the subscription
  -> register the secure BFV parameter set and all committee thresholds
  -> install the secure minimum, micro, and small verifier routes
  -> install the PK, decryption, and ciphertext verifiers
  -> register and bind the CRISP program
  -> close the bootstrap program and each configured incompatible E3 program to new requests
  -> raise the required node protocol version and invalidate old node eligibility
  -> keep requests paused
```

Run `upgrade:secure-crisp:validate` after governance executes the batch. The validator checks the
four proxy implementations, the complete slashing dependency graph, the preserved operator counts
and registry root, the reused VRF subscription and its two consumers, every verifier route and VK
anchor, the CRISP receipt-verifier binding, each retired E3 program, and the paused and drained
state. The old VRF consumer stays authorized through validation and the first successful E3. Remove
it in a later cleanup transaction. Publish a new SemVer ciphernode artifact from the same release
source before governance executes the batch. Restart matching ciphernodes after execution, and
resume only after at least the largest configured committee size has acknowledged the new protocol
and is online. Do not use the older CRISP-only builder on mainnet because it cannot install the
protocol-side secure configuration.

Registry, BondingRegistry, and refund-manager address replacement still requires an empty operator
generation. A SlashingManager rotation is different: when the same registry and bonding proxies
remain in place, the replacement can preserve operators. The migration requires paused requests, no
active E3, no unreleased or unresolved committee, no active slashing assignment, and no active ban.
The registry accepts the manager only after Interfold, BondingRegistry, and the replacement manager
all point to the same dependency graph.

After the nodes restart, run
`upgrade:secure-crisp:resume -- --network mainnet --ciphernodes-restarted`. It reruns the complete
activation validator and requires enough release-ready active operators for the largest committee
before it writes the checked DAO/Safe unpause transaction. On-chain active status is not a
heartbeat, so the flag is an explicit operator confirmation that those processes are online and
mutually reachable.

The CRISP server probes `earliestVotingStart()` when it creates a round. During an ordered legacy
cutover, a new server can derive the same lower bound from the live Interfold randomness, sortition,
and DKG windows if the old CRISP program does not expose that selector. This fallback supports the
short migration interval only. Deploy and register the new program, then update the server and DAO
application address before requests resume. An old server cannot create valid rounds against the new
program because it does not schedule the separate voting start required by that program.

## Durable state across an incompatible release

`SCHEMA_VERSION` (`crates/sync/src/sync/schema_version.rs`) is the durable format marker. The
preflight admits only an exact match and refuses to guess in either direction: older on-disk state
halts as an upgrade with no migration, newer state halts as a downgrade. A raised schema therefore
makes every populated data directory unloadable until the operator clears it.

The operator key and the libp2p keypair live in the same key/value store as that state, under
`//eth_private_key` and `//libp2p/keypair`. Deleting the data directory destroys the identity that
holds the bond, and `nodes purge` additionally removes the configuration directory holding the
cipher key file. Neither is a safe reset.

`interfold node reset-data` is the supported path. It takes the same `ProcessFence` as `start`, so
it refuses while a node runs, copies both secrets out as ciphertext without the password, backs them
up at mode `0600`, removes the event logs and the key/value store, then restores and reads them back
to confirm.

The event log is not one file. `EventSystem::persisted` passes `config.log_file()` through
`enumerate_path`, which inserts a per-aggregate index before the extension, so the durable logs are
`log.<aggregate>` rather than `log`. `AggregateId` is the chain id, with `0` reserved for events
that carry no chain (`AggregateId::from_chain_id`: `None -> 0`), and `AggregateConfig::new` always
inserts aggregate `0`. A mainnet node therefore holds `log.0` and `log.1`; a Sepolia node holds
`log.0` and `log.11155111`.

A reset that removes only `config.log_file()` deletes nothing, because that path is never written.
The key/value store is cleared, the event log survives, and the next start halts with
`no schema marker` — a worse state than before the reset, since the marker that made the old state
coherent is gone. The reset enumerates the real paths and verifies afterwards that none survive.

```text
raise SCHEMA_VERSION in a release
  -> populated data directories halt at preflight
  -> operator stops the node
  -> node reset-data preserves identity and clears both state stores
  -> preflight sees an identity-only store, stamps the current schema, and proceeds
  -> node re-syncs from each contract deploy_block
```

Both stores must be cleared together. The marker lives in the key/value store, so clearing only that
leaves an unmarked event log; `has_existing_state` is then true and the preflight halts with
`no schema marker` instead of starting. `preflight.rs` treats the complete identity pair as the one
exception that still counts as a fresh store, which is what the reset relies on.

`ciphernode.jsonl` sits beside the logs in the same directory but is not durable state. It is the
append-only operational log written by `LogCollector`, never read back, and a reset leaves it in
place.

A schema raise is an upgrade-window action. `assertUpgradeWindow` already requires paused requests,
zero active E3s, and zero unreleased committees, so no in-flight round loses state to this. The
command is not a general repair tool: a node in a live committee that resets loses its keyshare and
fails that E3.

## Failure and rollback

The required counters never decrease. For a bad node-only release, pause, drain, build the previous
code as a new release, and increase `node_generation`. For a contract or protocol rollback, restore
the safe behavior under a new, higher `protocol_version` and do not lower `node_generation`; do not
reuse the old version numbers. Raise the required counters before resuming. This makes the rollback
explicit and prevents nodes from silently returning to an older vulnerable release.

Release acknowledgement is operator self-attestation, not proof of the running executable. It
prevents accidental mixed deployments. Threshold cryptography and on-chain verification remain the
controls against a malicious operator.

The on-chain active count is also not a heartbeat. Before resuming, operations must confirm that the
release-ready processes are online and can reach the upgraded bootstrap and one another. Check both
the admitted connection count and the protocol-topic subscriber count on every node. A transport
connection without the matching gossip subscription is not ready for committee work. A stuck E3 or
unreleased committee delays a mandatory cutover until normal failure finalization drains it.
