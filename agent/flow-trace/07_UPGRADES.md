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

The initial VRF upgrade follows this combined path because it introduces the controller and changes
both `Interfold` and `BondingRegistry`.

## Secure CRISP activation on mainnet

The bootstrap deployment does not become production-ready when CRISP contracts are deployed. With
requests paused and all E3s and committees drained, `upgrade:secure-crisp` prepares one atomic
governance batch that:

```text
upgrade Interfold to the secure chain-aware crypto configuration
  -> register the secure BFV parameter set and all committee thresholds
  -> install the secure minimum, micro, and small verifier routes
  -> install the PK, decryption, and ciphertext verifiers
  -> register and bind the CRISP program
  -> raise the required node protocol version and invalidate old node eligibility
  -> keep requests paused
```

Run `upgrade:secure-crisp:validate` after governance executes the batch. The validator checks the
implementation, every verifier route and VK anchor, the CRISP receipt-verifier binding, and the
paused and drained state. Publish a new SemVer ciphernode artifact from the same release source
before governance executes the batch. Restart matching ciphernodes after execution, and resume only
after at least the largest configured committee size has acknowledged the new protocol and is
online. Do not use the older CRISP-only builder on mainnet because it cannot install the
protocol-side secure configuration.

After the nodes restart, run
`upgrade:secure-crisp:resume -- --network mainnet --ciphernodes-restarted`. It reruns the complete
activation validator and requires enough release-ready active operators for the largest committee
before it writes the checked DAO/Safe unpause transaction. On-chain active status is not a
heartbeat, so the flag is an explicit operator confirmation that those processes are online and
mutually reachable.

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
