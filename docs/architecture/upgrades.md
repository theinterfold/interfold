# Releases, protocol cutovers, and rollback

Owners: [release configuration](../../crates/config/protocol-release.toml),
[upgrade tooling](../../packages/interfold-contracts/scripts/upgrade/),
[storage preflight](../../crates/sync/src/sync/), and
[node state commands](../../crates/entrypoint/src/nodes/). Follow
[Protocol compatibility](../../CONTRIBUTING.md#protocol-compatibility) for human rollout approval.
This is reference policy, not authorization to perform a release.

## Independent version boundaries

| Value                                                               | Meaning                                                                          |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `releaseId = keccak256("interfold.node.release:v1:" + exactSemver)` | Exact release identity, not remote attestation of executable.                    |
| `protocol_version` / on-chain protocolVersion                       | Incompatible contracts, events, cryptography, protocol behavior and P2P overlay. |
| `node_generation` / nodeGeneration                                  | Mandatory node-only release within a protocol overlay.                           |
| GOSSIP_WIRE_MAJOR / SYNC_WIRE_MAJOR                                 | Incompatible payload/frame changes, even inside one protocol version.            |
| SCHEMA_VERSION / per-owner recovery schemas                         | Persisted layout boundary; not automatically coupled to release counters.        |

Enabled ciphernode chains verify governance-selected NodeReleaseRegistry before readers/protocol
actors start, acknowledge exact compiled release/counters, and refresh eligibility. Missing
controller or stale version/generation fails startup. Every P2P name/topic/Identify includes
protocol version; differing Identify disconnects, so incompatible nodes cannot discover/gossip/sync.
Node-generation changes do **not** isolate unsafe old peers. Acknowledgment is operator
self-attestation against accidental skew, not Byzantine protection; proofs, signatures, thresholds,
and slashing remain necessary.

Release acknowledgment gets three attempts with capped exponential backoff and jitter. Each attempt
rereads the acknowledged release and operator status. A mined acknowledgment is not sent again when
the exact release/counters already match and the operator is active or unregistered.

## Choose rollout deliberately

- **Compatible rolling:** keep both counters, verify mixed-peer/storage/deployed-verifier
  compatibility, restart one operator at a time without falling below required committee
  participation. No governance transaction is needed solely for a new release ID. A compatible
  contract-only change need not change node policy. `upgrade:node-release --action prepare` confirms
  the no-governance path.
- **Mandatory node-only:** increase generation; pause new requests; drain `activeE3Count` and
  `unreleasedCommitteeCount`; governance raises required generation. O(1) eligibility invalidation
  removes old nodes from committees. Upgraded nodes acknowledge/refresh on the same P2P protocol.
  Refresh **all captured registrations**, including inactive ones, wait a later timestamp, check T−1
  owner capacity for largest N, and verify actual online/topic readiness before checked resume. Use
  prepare `--mandatory` and `--action resume`. Unsafe parsing/peer meaning requires protocol
  cutover.
- **Contract/protocol:** increase protocol version; pause/drain first; one governance batch upgrades
  implementations, routes, programs, and required version. Upgrade bootstrap before remaining nodes;
  restart matching server/client/DAO addresses, validate every enabled route/VK, full registration
  refresh, and discovery/topic readiness before resuming. Do not run a mixed application stack.
  Fresh testnet stacks may use distinct addresses but still require the same validation.
- **Incompatible storage:** drain and controlled reset/resync, unless an explicitly reviewed/tested
  migration exists. An operator reset is breaking behavior, not an implementation cleanup.

An on-chain-compatible ranking change can still be fleet-incompatible: changing VRF seed byte order
makes nodes shortlist different owners, preventing formation though Solidity independently scores
tickets. Pause requests for that coordinated rollout; no honest node is slashed for the failed
selection. When release counter changes are mandatory, governance can only raise them with requests
paused and both drain counters zero. Never decrease required counters.

Release acknowledgment/CLI sends use twice estimated gas: same-timestamp checkpoint overwrites
during estimation can become new checkpoint appends when mined (~40k additional gas in the observed
fork). This compensates estimation timing, not a substitute for receipt validation.

## v0.19 protocol/crypto cutover

The v0.19 source declared protocol **8**, generation **2**, circuit domain `interfold-bfv-v5`. The
signed DKG layouts require storage schema 8, threshold-keyshare recovery schema 8, gossip major 5,
sync major 4. ThresholdShareCreated/DecryptionKeyShared bundle signatures change log/recovery/DHT
bytes; there is no unsigned-layout migration. Drain-and-resync, rebuild all six artifact pairs, and
replace immutable wrappers/routers before serving requests. A historical 0.19 test build reporting
protocol 7 does not satisfy this cutover; the source's compiled values are explicit, not inferred
from SemVer.

Sampler/smudging/BFV validation and non-centered C3/user-encryption/CRISP k1 scale change witnesses
and bounds. The workspace pins the fhe.rs `dev` revision. Node, client configuration IDs, circuit archives, and
OpenVM guest/receipt identity must match; v1–v4 requests cannot be treated as v5. Runtime/SDK
tooling reject old configuration IDs for new requests.

**Mainnet parameter-set index 1 remains the previous secure tuple.** Register the new secure tuple
at index **2** in the paused/drained governance batch; never overwrite/reinterpret old E3 records.
Validate its exact bytes before resume. Current nodes/request clients reject index 1. Indexer
current index-0/index-2 keys use local v5 parameters; historical index-0/index-1 v1 keys use
append-only registry bytes checked against frozen crypto ID. Other unsupported IDs are skipped
without storing keys so catch-up can reach supported rounds.

`upgrade:v19` / `scripts/upgrade/v19Cutover.ts prepare` deploys linked Interfold implementation and
BFV routes, then prepares one batch: upgrade Interfold; register missing index 2/thresholds; install
PK/decryption routers/OpenVM ciphertext verifier; register/bind new CRISP and retire earlier
programs; require protocol 8/generation 2; keep paused. Mainnet requires `--openvm-identity`.
Preparation verifies drain/pause, records against live implementation, CRISP owner/binding, common
image/receipt identity, guest commitments, Halo2 runtime hash, Avail bridge/windows, and signer.
CRISP is not in this repository: `prepare` reads the CRISP deployment record from
`--crisp-deployments <path>`, the `packages/crisp-contracts/deployed_contracts.json` of the
[CRISP repository](https://github.com/theinterfold/CRISP). A missing option or file stops the
script. `validate`, `refresh`, and `resume` read the saved plan, not the record.

`upgrade:v19:validate` is read-only/repeatable; `--write-records` updates deployment records and
deployed_contracts for release provenance. After execution restart matching nodes;
`upgrade:v19:refresh` reads registration logs and refreshes each inactive entry. In the next block,
`upgrade:v19:resume -- --ciphernodes-restarted` revalidates readiness/capacity and writes the
unpause batch. The `--ciphernodes-restarted` flag is an explicit operator confirmation of
running/reachable processes, not evidence inferred from active status.
`upgrade:v19:simulate -- --crisp-dir <CRISP checkout>` exercises the sequence on an Anvil mainnet
fork. It overwrites the `mainnet` entry of the checkout's
`packages/crisp-contracts/deployed_contracts.json` with the fork's addresses, passes that file as
`--crisp-deployments`, and restores the file when it ends.

During an ordered legacy CRISP server cutover, missing `earliestVotingStart()` can temporarily fall
back to live protocol windows. Install/register new program and update server/DAO addresses before
resume; old servers do not schedule the required separate voting start and cannot make valid new
rounds.

## Aztec v6 toolchain cutover

The cutover declared protocol **9**, generation **2**; the l-BFV proof tree later raised protocol to **10**. `bb` 6.0.0 and Noir `v1.0.0-rc.3`
change every verification key, VK tree anchor, and Honk verifier; proofs do not verify across
toolchains, so a mixed fleet attests honest peers' proofs as invalid. Use the contract/protocol
rollout: pause/drain, publish all six artifact pairs, replace PK/decryption wrappers and routers in
the governance batch that raises the required protocol version, and upgrade every node before
resume. Persisted peer proofs from in-flight E3s are not foldable under bb 6; drain them first.
Storage schema and gossip/sync wire majors are unchanged.

## Parameter set 7 rollout (`secure-16384-simd-d6`)

**Upgrade class: governance for the contracts, compatible rolling for the nodes.** Set 7 adds two
`BfvPreset` variants after set 6 (discriminants 0..11 are unchanged), a 24 MiB committee public key
cap, a `DkgFoldAttestationVerifier` that tries every committee shape that fits a public-input
length, and generated `ActiveCryptoConfig` constants. `SCHEMA_VERSION`, the gossip and sync wire
majors, the storage layouts, the contract ABIs and the events do not change. This is not a
drain-and-resync change. Every contract step is an owner or Safe transaction, and one of them has a
two-day timelock.

**Counters: `protocol_version` stays 10 and `node_generation` stays 2.** The rules ask for a bump
when a release becomes incompatible. A release that adds set 7 is incompatible only for E3s that use
set 7, and only governance can create those, through `setParamSet(7)`.

- Sets 5 and 6 appended variants the same way and bumped nothing. A node on the previous release
  cannot decode a record or message of the new preset, and it cannot roll back after it stored one.
  The CHANGELOG states this for set 5 and for set 7.
- A bump pauses and drains every deployment, splits the P2P overlay, and cannot be reversed, because
  required counters never decrease. Off testnet, `ActiveCryptoConfig.isParamSetSupported` accepts
  only set 2, so no mainnet E3 can use set 7. The cost lands on deployments that never use set 7.
- Old nodes stay sortition-eligible, so the gate is the order below, not a counter. The `v10` test
  release `v0.20.0-lbfv.gca9825b` predates sets 6 and 7: a committee that includes such a node
  cannot take part in a set-7 DKG [INFERENCE: not run].
- If chain-enforced exclusion of old nodes is wanted, the existing lever is a mandatory node-only
  release (`node_generation` 3). It needs pause and drain, applies fleet-wide on every chain, and
  cannot be lowered again. Decide that before step 6. The repository does not require it.

Prerequisites outside this section: the `v10` cutover is complete, and the circuit archive and
`supported-configurations.json` pins contain the three d6 pairs. Download and local installation
fail closed for every node until those artifacts exist, so no node can install the release without
them.

### Order

| #   | Action                                                                                                                                                                                                                                                                                                  | Tool                                                                                                   |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| 1   | Deploy a new `DkgFoldAttestationVerifier`. The registry owner calls `proposeDkgFoldAttestationVerifier`. The two-day timelock starts now, so do this first.                                                                                                                                             | Manual. `deployAndSaveDkgFoldAttestationVerifier` returns an existing deployment and cannot redeploy.  |
| 2   | Upgrade `CiphernodeRegistryOwnable`. The batch redeploys `RegistrySortitionLib` (an external, linked library), relinks the implementation, and upgrades the proxy. This sets the 24 MiB cap.                                                                                                            | `pnpm --dir packages/interfold-contracts upgrade:ciphernodeRegistryOwnable`                            |
| 3   | Upgrade `Interfold`. The batch redeploys `InterfoldLifecycle` and `InterfoldPricing` (both link `ActiveCryptoConfig`), the implementation, and the proxy.                                                                                                                                               | `upgrade:interfold`                                                                                    |
| 4   | Deploy the d6 Honk wrappers, three `BfvPkVerifierV2` routes for set 7, and new `BfvPkVerifierRouter` and `BfvDecryptionVerifierRouter` contracts. Routes are immutable, so each router lists every enabled set. Install them with `setPkVerifier` and `setDecryptionVerifier`. Run `validateBfvRoutes`. | Manual. `scripts/upgrade/bfvRouteChecks.ts` validates; `v19Cutover.ts` installs routes for set 2 only. |
| 5   | After the timelock, call `commitDkgFoldAttestationVerifier` with the same address.                                                                                                                                                                                                                      | Manual. The call reverts with `VerifierUpdateTimelockActive` before the timelock ends.                 |
| 6   | Release the node, the indexer and the SDK with the 24 MiB cap and the set-7 preset. Operators install it one at a time. Confirm each operator through `operatorNodeRelease`.                                                                                                                            | `upgrade:node-release --action prepare` confirms that no governance transaction is needed.             |
| 7   | Enable set 7: `setParamSet(7, encoded)`, then `setCommitteeThresholds` if a size is missing. Request the first E3 with the minimum committee, then micro, then small.                                                                                                                                   | Manual. `v19Cutover.ts` builds `setParamSet` for index 2 only.                                         |

Steps 1 to 5 and step 6 can run in parallel. Step 7 needs all of them. Step 2 before step 3 keeps
the cap ahead of any request. Step 6 is complete only when every operator that can enter a committee
has acknowledged the new release. Compare `operatorNodeRelease(operator).releaseId` with
`keccak256("interfold.node.release:v1:" + semver)`.

The new SDK throws when a caller passes `maxBufferedBytes` between 16 and 24 MiB. The default is 64
MiB.

A request freezes its `DkgFoldAttestationVerifier` (`_committeeDependencies[e3Id]`). Committing the
new verifier does not repair an earlier E3. E3s that exist before step 5 keep the verifier that they
froze.

### What fails out of order

| Done early or skipped                   | Result                                                                                                                                                                                                                                                                                                         |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setParamSet(7)` before step 3          | Reverts `UnsupportedCryptoConfig`: the old `ActiveCryptoConfig` does not know set 7.                                                                                                                                                                                                                           |
| Set 7 enabled before step 4             | The request passes. `BfvPkVerifierRouter` has no route, so `publishCommittee` reverts with `InvalidPublicInputsLength`, `VkHashMismatch` or `ParamSetRouteMismatch`, and the E3 times out.                                                                                                                     |
| Set 7 requested before step 5           | The E3 froze the old fold verifier. A 69-input statement maps to shape (5,9), `_isV2Statement` fails, and the trBFV branch reverts `AttestationBindingCountMismatch`. `publishCommittee` never succeeds, the DKG times out, and `markE3Failed` blames the ciphernodes. Committing later does not help that E3. |
| Set 7 requested before step 2           | The key envelope is above 16 MiB. The old library rejects `totalLength` above 16 MiB with `InvalidPublicKeyChunk` for every chunk, so the key never publishes and the E3 fails in `KeyPublished`.                                                                                                                   |
| Set 7 enabled before step 6             | Old nodes drop set-7 chunk events and cannot decode the preset. A committee with such a member loses that member. The old indexer rejects a key above its cap, so clients never see the key.                                                                                                                   |
| Step 6 without the d6 circuit artifacts | Installation fails closed on the missing pairs, so the node stays on the old release.                                                                                                                                                                                                                          |

### Rollback

1. `setRequestsPaused(true)`. Wait until every set-7 E3 has completed or failed. `activeE3Count` and
   `unreleasedCommitteeCount` count all sets, so check each set-7 E3 with `getE3Stage`.
2. Do not undo steps 1, 2, 5 and 6. The cap only grows, so replay of older keys is unchanged. The
   new fold verifier accepts the old shapes. Nodes cannot decode stored set-7 records on the
   previous release, so they stay on the new release. No counter changes.
3. `paramSetRegistry` entries cannot be removed, and there is no per-set switch. While requests stay
   paused, no set-7 E3 starts. To end set 7 for good, ship contracts that no longer accept it. Under
   [Rollback and evidence](#rollback-and-evidence) that is a new implementation under a higher
   `protocol_version`, not a bytecode revert. Historical set-7 E3s may hit `UnsupportedCryptoConfig`
   on any path that reads `ActiveCryptoConfig` after such a change [INFERENCE: not traced]. Settle
   them first.
4. To replace the fold verifier, propose the new address and wait two days again. A node-only fix
   after this change raises `node_generation`. Neither counter goes down.

### Tooling gaps

`upgrade:ciphernodeRegistryOwnable` and `upgrade:interfold` already redeploy the libraries and link
them (`safeProxyUpgrade.ts`). These parts have no script: the fold verifier redeploy, propose and
commit; the in-place addition of a route to the PK and decryption routers; the standalone
`setParamSet`; and a drain check per parameter set. `safeProxyUpgrade.ts` is the only Safe template,
and it ties plan, proposal and deployment records together, so these steps stay manual. Use
`validateBfvRoutes` after step 4 and the E3 smoke requests of step 7 as the acceptance check.

## Dependency replacement

There are **no concurrent registry generations**. Each request validates/snapshots one coherent
graph; snapshots support drain routing, not early activation of a replacement. Generic replacement
drains E3s, committees, assignments, bans, locks, and slash routes; registry/bonding/refund
replacement additionally needs an empty operator generation. Then wire/validate the complete
reciprocal graph before requests. SlashingManager-only replacement may preserve operators if
registry/bonding proxies stay, replacement API/bindings are valid, all old obligations drain, and
one atomic batch switches the complete graph before revoking the old manager. Drain or explicitly
migrate legacy proposals/bans and retry legacy reserved routes before changing their accounting.
[Slashing](slashing.md) owns those prerequisites.

## Controlled state reset, never directory deletion

Preflight accepts exact SCHEMA_VERSION before decoding, repairing, or opening logs/indexes. Older
state halts as no migration; newer state halts as unsupported downgrade and names newer
release/pre-upgrade backup. Read raw marker and detect unmarked log segments without decoding.
`node validate --repair` cannot bypass mismatch. v0.19 requires its **new binary** for reset: v0.18
and older lack keyshare guards.

### Insecure testnet preset reset

`InsecureThreshold64` and `InsecureDkg64` occupy persisted `BfvPreset` discriminants 0 and 1.
On-chain parameter-set index 0 carries the degree-64 tuple. Degree-512 stores used the same
discriminants under schema 8, so the schema marker cannot reject them. Before starting against a
fresh testnet stack, testnet nodes must run `interfold node reset-data` under the guards below.
Redeploy a testnet that holds degree-512 index-0 E3s; do not upgrade it in place or reinterpret
those E3s with degree-64 parameters. This requirement does not replace mainnet's secure index-2
cutover procedure. The l-BFV presets (`insecure`, `insecure-simd`, `secure-16384-simd`,
`secure-16384-simd-d6`) use appended `BfvPreset` variants and on-chain indices 4, 5, 6 and 7. They do
not reuse index 0.

### Identity and active-state guards

The l-BFV protocol-4 contribution-wire cutoff uses typed fhe.rs `LBFVPublicKeyShare` and
`LBFVRelinKeyShare` envelopes, not older bare contribution bytes. Version-3 PK documents carry
signed PK row proofs without C1 and reject versions 1/2. Drain active work before a coordinated
development-data cutoff and rebuild matching artifacts/consumers; do not reinterpret retained opaque
payloads. This is separate from the insecure preset reset and is not authorization to erase operator
identities or active keyshares.

Operator/libp2p keys are in the same store under `//eth_private_key` and `//libp2p/keypair`;
deleting a data directory destroys bonded identity. `nodes purge` also deletes cipher-key
configuration. Use `interfold node reset-data`: take ProcessFence, refuse running node, copy
encrypted identities without password into mode-0600 backup, clear store **and every aggregate
log**, restore/readback identities. EventSystem enumerates `log.<aggregate>` (0 plus chain ID), not
the nominal `config.log_file()`. Deleting only that unwritten nominal path leaves unmarked logs and
makes startup fail. Verify all real paths removed. Keep operational `ciphernode.jsonl`; it is not
replayed durable state.

Before deleting, inspect all threshold-keyshare/keyshare-recovery/payload key prefixes, not just the
lifecycle map. Any record whose E3 is not Complete (including absent or locally Failed) refuses:
chain cannot recreate secret shares. Prefix existence works without decoding old-schema values; read
errors or malformed keys fail closed. Also inspect every `//evm_writers/slashing/` record and refuse
unsubmitted reports, even for Complete E3s; undecodable/unknown records fail. List both groups of
refusals. `--allow-active-e3s` overrides these protections; it does not make lost keyshares/evidence
recoverable.

`nodes purge`/`purge-all` require `--yes`, run the same guards for every affected node, take
process/store locks, and refuse missing/uncheckable identity stores. No flag overrides a
running-node refusal. `purge-in-progress` markers are written before deletion; only marked leftovers
may be continued. An unmarked empty mount still needs its store; a conflicting marker file/link
stops deletion.

Start writes `<keyfile>.store-record` with every prior store path (latest last). Purge locks/checks
each recorded store for keyshares and latest store for identity, so different
E3_DATA_DIR/config/working directories or stale copies do not hide live shares. Missing recorded
stores refuse unless marked by prior purge; permanently moved stores require operator record
maintenance. Unused keyfiles need their record too; direct unrecorded config keys refuse and key
folders need a corresponding node/store. **Limit:** older keyfiles without a record rely on
configured/node-folder stores, which a stale copy can pass; discovery finds stores only directly
inside node folders. Override covers cannot-check refusals alongside active-state refusals, not
proof of safe purge.

Reset clears schema/role markers and leaves identity-only store as the explicit fresh-state
exception; next start stamps new role/schema and resyncs from deploy_block. Clearing only store or
logs is invalid. This is also the supported full↔bootstrap role change. DAppNode's historical
v0.2.3 bridge atomically renames `.enclave` to `.interfold`, preserves identities, and stamps schema
1 for shipped v0.1.8 data; ambiguous dual roots fail closed. The current Mainnet and Sepolia
packages migrate no `.enclave` root; each keeps its own `/data` volume and refuses a saved
configuration for another network. Container state must stay in configured persistent volume;
entrypoint refuses competing state locations rather than initializing another identity.

The image entrypoint, not baked image metadata, supplies E3_CONFIG_DIR/E3_DATA_DIR for the
persistent `/home/ciphernode/.local/share/interfold` volume. Explicit `--entrypoint interfold` keeps
the caller's location. Entry resolves key/database paths with and without those overrides for the
selected `--name`, keeps the location holding state, and refuses state at both. It initializes
password/wallet only when missing and tolerates an unremovable read-only secrets mount. Operators of
older images must follow the one-time state-location migration in the running guide, not delete an
apparently empty volume.

Every schema raise needs an upgrade window, even without an on-chain required-counter change (which
otherwise supplies no pause/drain check). Wait for all active work and accusation submission
deadlines, scheduled lifecycle + one day, plus any retained unsubmitted reports. Reset is not
general repair for an active committee; local Failed is not proof that the chain no longer needs its
shares.

## Rollback and evidence

Project program tooling uses a separate `runner/` crate and `e3-program-runner`. Projects retaining
`.interfold/support` must adopt the template runner and remove the old workspace members before CLI
compile/start succeeds. This source-layout migration is not a node-state reset or permission to
change the guest's processor, policy, or deployed receipt identity. Follow the
[runner guide](../../crates/program-runner/README.md#compatibility-and-limits).

Counters never decrease. For bad node-only code, pause/drain and publish restored safe behavior
under a new release ID and **higher generation**. For protocol/contracts, restore safety under
**higher protocol version**, never lower generation or reuse old values. Raise required counters
before resume. Old schema backups need compatible binaries; use tested rollback/recovery rather than
opening new layouts with an old executable.

Before resume check actual processes, expected directed gossip subscriptions, and upgraded bootstrap
reachability. Active count is not a heartbeat. Stuck E3/unreleased committees delay cutover until
normal terminal processing drains them. [Artifact checks](circuit-artifacts.md) are additional
prerequisites.

[Node release tests](../../packages/interfold-contracts/test/Registry/NodeReleaseRegistry.spec.ts),
[V19 cutover tests](../../packages/interfold-contracts/test/Deployment/V19Cutover.spec.ts),
[schema preflight tests](../../crates/entrypoint/tests/validate_older_schema.rs), and
[state guards](../../crates/entrypoint/src/nodes/state_guard.rs) guard their owner boundaries. Run
`pnpm evm:test`/focused Cargo tests and the prepared fork simulation for changed cutover behavior.
These checks do not replace a human-approved rollout/rollback decision or establish safety of
arbitrary operator overrides.
