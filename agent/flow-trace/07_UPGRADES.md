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

The v0.19 DKG message layout requires storage schema 8, threshold-keyshare recovery schema 8, gossip
wire major 5, and sync wire major 4. Both `ThresholdShareCreated` and `DecryptionKeyShared` include
a dealer signature. Their event-log records, recovery inputs, and DHT payloads are incompatible with
the unsigned layout. Protocol version 6 and node generation 2 remain the release cutover values.
This change requires drain-and-resync; it has no layout migration.

## Compatible rolling release

The release workflow packages the circuits before it compiles the binaries and ciphernode image.
`download-circuits` exposes the uploaded archive's SHA-256 as a build input. `e3-zk-prover` embeds
that pin for its crate version. Binary and image builds compare the pin in `interfold noir status`
with the archive digest before publication. See `agent/invariants/04_BUILD_CONFIG.md` for the build
dependency and Docker argument rules.

Circuit installation checks every pair in `crates/zk-prover/supported-configurations.json` before it
replaces the installed circuits and version record. Local and CI callers can explicitly request a
nonempty subset. `noir setup --circuits-archive` accepts repeated `--circuits-configuration` options
for this purpose. An archive cannot select its own required configuration set.

If circuit replacement or the version update fails, the installer attempts rollback and returns the
original installation error. It logs each failed rollback rename with its source and target paths.
If the previous circuits cannot be restored, it retains the staging directory and logs its path for
recovery.

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

A release that changes the off-chain ticket ranking is compatible on chain but not in a mixed fleet.
Example: the VRF `CommitteeRequested.seed` byte order
(`crates/evm/src/randomness_provider/events.rs`, `Seed::from`). Old and new nodes shortlist
different submitters, so fewer than N distinct owners can submit and `CiphernodeRegistryOwnable`
fails the E3 with `InsufficientCommitteeMembers`. The registry scores each submitted ticket itself,
so no honest node is slashed. Pause new E3 requests for such a rollout and resume after the
operators have upgraded.

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
  -> refresh every captured registration, including inactive operators
  -> wait for a later timestamp and check snapshot owner capacity covers the largest N
  -> confirm the eligible nodes are online and can reach one another
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
full registration refresh is complete, the snapshot owner count can fill every configured committee,
and the new-version peers can discover each other.

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

The BFV circuits use `interfold-bfv-v3` with compiled `protocol_version = 6` and
`node_generation = 2`. The configuration ID binds this circuit version even when BFV parameters stay
unchanged. The builder generates both precomputed IDs. Runtime readers, the indexer, CRISP intake,
request tooling, and the SDK use the same IDs and reject v1 and v2 requests. The indexer skips
historical keys for unsupported configuration IDs without storing them. This lets its catch-up
cursor advance across drained unsupported rounds to recover supported rounds. Recursive folds carry
fixed leaf, fold, and genesis VK hashes. Final aggregator public input zero binds the complete
recursive VK tree. These proof formats require a governance cutover, not a mixed rolling release.
Rebuild all six artifact pairs and replace the immutable BFV verifier wrappers and routers before
requests resume.

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
activation validator and checks both release-ready operators and snapshot owner capacity for the
largest committee before it writes the checked DAO/Safe unpause transaction. The capacity check
requires the full registration refresh to be complete before the `T-1` boundary. On-chain active
status is not a heartbeat, so the flag is an explicit operator confirmation that those processes are
online and mutually reachable.

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
makes every populated data directory unloadable until the operator clears it. The older-schema halt
names `interfold node reset-data`. The newer-schema halt names the newer release and the backup
taken before the upgrade, because the reset guard of an older binary cannot read a newer store
reliably. When the event logs decode with this binary, `interfold node validate` reports the same
schema failure and skips the checks that read snapshots (`crates/entrypoint/src/validate.rs`). An
event log that does not decode shows as unreadable, with no schema line.

The operator key and the libp2p keypair live in the same key/value store as that state, under
`//eth_private_key` and `//libp2p/keypair`. Deleting the data directory destroys the identity that
holds the bond, and `nodes purge` additionally removes the configuration directory holding the
cipher key file. Neither is a safe reset. `nodes purge` and `purge-all` require `--yes`. Before they
delete anything, they check each node whose store, event log, or key file they would delete
(`crates/entrypoint/src/nodes/purge/`). They take the same `ProcessFence` as `start`. They open the
node's store, and sled refuses a store that another process has open. They run the key-share check
that `reset-data` uses (`crates/entrypoint/src/nodes/state_guard.rs`). They also refuse for a node
that they cannot check. Its store can be missing at the configured path, or that store can hold no
operator key. They report every refusal at once, because `--allow-active-e3s` overrides the
key-share and cannot-check refusals together. No flag overrides a refusal for a node that the purge
sees running. The commands also delete the identity. Before the first deletion, the purge writes a
`purge-in-progress` marker into each node folder that it empties. A later purge treats only a folder
with that marker as its own leftover and finishes the deletion. An empty folder without the marker,
such as the mount point of a volume that is not mounted, still needs its store. Another file or a
link with the marker's name stops the purge before it deletes anything.

The purge has limits. It finds stores with its own configuration and environment, so it cannot see a
node that runs with another `E3_DATA_DIR`, `data_dir`, or working directory. It cannot tell whether
an operator key is the node's own, so a stale copy of a store at the configured path passes. It
finds stores only directly inside node folders.

`interfold node reset-data` is the supported path. It takes the same `ProcessFence` as `start`, so
it refuses while a node runs, copies both secrets out as ciphertext without the password, backs them
up at mode `0600`, removes the event logs and the key/value store, then restores and reads them back
to confirm.

Before it deletes anything, the command lists every key-share record by key prefix
(`//threshold_keyshare/`, `//threshold_keyshare_recovery/v1/`, and
`//threshold_keyshare_recovery_payloads/v1/`) and reads the `//e3_lifecycle` stage map. It refuses
when the E3 of such a record is not `Complete` in that map, including an E3 that the map does not
list, and it lists each such E3 with its stage, because the chain cannot restore that key share. A
`Failed` stage also refuses: the node records its own local failures, such as a DKG timeout, as
`Failed` while the E3 can continue on chain. The check reads only whether a record exists and does
not decode it, so it also protects a store that an older schema wrote. Both reads fail on a storage
error, which the ordinary read path reports as an absent record, and a key that does not parse fails
the check. `--allow-active-e3s` overrides the refusals
(`crates/entrypoint/src/nodes/state_guard.rs`).

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

The node role marker (`//node_role`) is in the same key/value store, so a reset also clears it. The
next start stamps the role that it runs with. This is the supported way to turn a full node into a
bootstrap node, or the reverse, on the same data directory.

`ciphernode.jsonl` sits beside the logs in the same directory but is not durable state. It is the
append-only operational log written by `LogCollector`, never read back, and a reset leaves it in
place.

A schema raise is an upgrade-window action. `assertUpgradeWindow` already requires paused requests,
zero active E3s, and zero unreleased committees, so no in-flight round loses state to this. The
command is not a general repair tool: a node in a live committee that resets loses its keyshare and
fails that E3. The stage-map check refuses that case unless the operator overrides it.

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
