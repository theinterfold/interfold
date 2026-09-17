# Mainnet protocol v4 upgrade plan

Status: planning and implementation

This plan covers the protocol v4 migration, the production CRISP deployment, the
ciphernode rollout, and the first mainnet E3. Keep mainnet requests paused until
all validation steps pass.

## Progress tracker

- [x] Record the production control accounts and ownership path.
- [x] Add an operator-preserving service dependency migration.
- [x] Extend the upgrade builder for all four proxies, SlashingManager, and
      Chainlink VRF.
- [x] Extend post-upgrade validation for the complete dependency graph.
- [x] Preserve and validate the existing funded VRF subscription.
- [x] Pass contract tests, storage-layout validation, and a mainnet-fork
      rehearsal.
- [ ] Merge the patch PR and publish the tested patch release.
- [ ] Confirm the production CRISP, Avail, Boundless, and deployment accounts.
- [ ] Generate, independently decode, sign, and execute the final Safe batch.
- [ ] Roll out matching ciphernodes and services while requests remain paused.
- [ ] Unpause with a separate transaction and monitor the first mainnet E3.

## Control accounts

| Account                | Address                                      | Responsibility                                                          |
| ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------- |
| Interfold DAO          | `0x652a31c669f9AB37f6040f279139a75D04F2679e` | Owns the protocol contracts, ProxyAdmins, and protocol configuration.   |
| Aragon Admin plugin    | `0xF21e25455988887EE797050080141eba67B33920` | Executes DAO calls that an authorized Safe submits.                     |
| Cayman Foundation Safe | `0x8B43b2852fc5031D01DDfCDF702973D93A2FF593` | Submits protocol upgrade and treasury actions through the Admin plugin. |
| BVI Safe               | `0x5429D8c7fD14023f3c414126F94BbE25A05fC018` | Owns FOLD and controls its administrative roles.                        |

Both Safes currently use the same five owners and a 3-of-5 threshold:

- `0xCb83ef506989534463a0E3F6E5526a8FE26897B3`
- `0xA8C3c4B6aE7f31193057A6d8833980853Ef71f85`
- `0xC3F8EBC47A4C47D91b643a4C64d34eA7B2584260`
- `0x26f8034baBfbcA2233350a0Dca1CCcE3d01Fa41F`
- `0x7b4273f9291aEAC9ea85f44093Aca5fC873A7Cf5`

Use this control path for the upgrade:

```text
Cayman Foundation Safe
    -> Aragon Admin plugin
        -> Interfold DAO
            -> protocol contracts and ProxyAdmins
```

The BVI Safe does not need to execute the protocol upgrade. It continues to
control FOLD unless a separate governance action changes token custody.

## Service accounts

Confirm these public addresses before deployment. Do not record private keys or
seed phrases in this repository.

- `[NEEDS TECHNICAL INPUT: production CRISP Ethereum signer address]`
- `[NEEDS TECHNICAL INPUT: production Avail App ID and funded account address]`
- `[NEEDS TECHNICAL INPUT: production Boundless account address]`
- `[NEEDS TECHNICAL INPUT: funded deployment account address]`

The deployment account pays gas only. Transfer all ownership and administrative
roles directly to the DAO.

## Current mainnet state

The preflight snapshot found this state:

- Protocol requests are paused.
- `activeE3Count` is zero.
- `unreleasedCommitteeCount` is zero.
- Mainnet has not processed an E3.
- The registry contains 24 operators. Of these operators, 22 are active.
- The slashing system has no proposals, active bans, or active E3 assignments.
- The node release policy is protocol `1`, generation `1`.
- Release `v0.15.0` requires protocol `4`, generation `1`.
- The DAO owns the four protocol ProxyAdmins.
- The existing Chainlink VRF subscription is DAO-owned and funded with native
  ETH.

Repeat this snapshot immediately before transaction generation. Stop if any
drained-state value is nonzero.

## Patch verification evidence

The reusable service migration passed a mainnet-fork rehearsal at block
`25997099`. The rehearsal executed the complete governance path:

```text
Cayman Foundation Safe
    -> Aragon Admin plugin
        -> Interfold DAO
            -> 16 migration actions
```

The post-migration checks confirmed this state:

- Registered operator count remained `24`.
- Active operator count remained `22`.
- The registry root remained
  `14387956784588433754754076083243010695491582041770780857621437663477240335108`.
- The replacement SlashingManager used the existing protocol proxies and the old
  SlashingManager lost its authorization.
- The replacement VRF provider became a consumer of subscription
  `71691575116496141995004949171983957552865884917816221241212802244435226877128`.
- The VRF subscription was reused. It was not canceled, replaced, or refunded.

The deployed legacy VRF provider does not expose `pendingRequestCount`. The
migration tooling treats this view as an optional capability. It still checks
the provider configuration, subscription ownership, funding, and consumer
membership. Future providers that expose the view also receive the pending
request check.

These results are rehearsal evidence, not authorization for a live transaction.
Repeat the fork simulation with a current block and the final production
addresses before Safe signatures are collected.

## Migration blockers

### Registry dependency migration

`CiphernodeRegistryOwnable.setSlashingManager` requires an empty operator
registry. Mainnet has 24 registered operators. Deregistration is not an
acceptable migration because it starts the operator exit delay.

The patch updates the existing registry setter to use a reusable service
migration validator. The validator:

- Require DAO ownership.
- Require protocol requests to be paused.
- Require zero active E3s.
- Require zero unreleased committees.
- Validate the replacement contract and its dependency graph.
- Preserve all operator registration and activity state.
- Reject a no-op migration.
- Emit the standard dependency-change event.

Do not encode a mainnet address, protocol version, or deployment name in the
contract. The same function must support later drained-state dependency
migrations.

### Upgrade script coverage

The current secure CRISP upgrade script does not migrate these components:

- `BondingRegistry`
- `E3RefundManager`
- `SlashingManager`
- `ChainlinkVrfRandomnessProvider`

The patch extends the script and validator so that one fork-tested DAO batch
updates the complete dependency graph.

The BondingRegistry proxy must receive the current implementation even though
its storage remains in place. Its deployed implementation recognizes the older
`ISlashingManager` ERC-165 interface ID. The replacement manager implements the
current interface ID.

### Production governance configuration

Do not use old CrispVoting payloads. The old payloads reference the obsolete
CRISP program and the Minimum insecure configuration.

Query the live private CrispVoting installation. Its CRISP program address is
immutable. Install a new plugin instance if the existing plugin references the
old program.

Use these production settings:

- Committee size: Small (`2`)
- Parameter set: secure-8192 (`1`)
- Roster threshold: `H=14`
- Committee size: `N=19`
- Voting source: `BondedVotes`

## Patch release gate

Complete these actions before mainnet deployment:

1. Implement the reusable registry dependency migration.
2. Add unit tests for all migration preconditions and state preservation.
3. Extend the secure upgrade script for all changed protocol components.
4. Extend the post-upgrade validator for the complete dependency graph.
5. Simulate the full batch against a current mainnet fork.
6. Confirm that all 24 operator records remain unchanged.
7. Run contract, storage-layout, size, documentation, and invariant checks.
8. Merge the patch PR.
9. Publish a patch release from the tested commit.

Stop if the fork simulation changes operator identity, bond, activity, or
release state.

## Deployment preparation

Deploy these components without activating requests:

1. Deploy the updated Interfold implementation and linked libraries.
2. Deploy the updated CiphernodeRegistry implementation.
3. Deploy the updated E3RefundManager implementation and linked library.
4. Deploy a new SlashingManager with DAO administration.
5. Deploy an updated Chainlink VRF provider contract.
6. Add the new provider to the existing funded VRF subscription.
7. Deploy all secure BFV verifier routes.
8. Deploy the production CRISP program and Avail verifier.
9. Leave the CRISP program unbound until the DAO batch executes.

The VRF subscription is not replaced. The upgrade replaces only its
consumer/provider contract. Add the new consumer before the DAO switches the
registry. Remove the old consumer after final validation.

## Atomic DAO batch

Simulate and execute one atomic DAO batch. The batch must leave requests paused.

The generated batch performs these actions:

1. Upgrade CiphernodeRegistry, Interfold, BondingRegistry, and E3RefundManager
   in place.
2. Connect the new SlashingManager to the four existing protocol proxy
   addresses.
3. Copy each configured enabled slashing policy to the new manager.
4. Authorize the configured slasher, when one exists.
5. Set the new SlashingManager in BondingRegistry and Interfold.
6. Set the new SlashingManager in CiphernodeRegistry. This call validates the
   final graph.
7. Revoke the old SlashingManager after all old obligations are zero.
8. Accept ownership of the updated Chainlink VRF provider when required.
9. Add the updated provider to the existing funded subscription.
10. Set the updated provider and request timeout in CiphernodeRegistry.
11. Install the secure verifier routes.
12. Set the Minimum threshold to `H=2`, `N=3`.
13. Set the Micro threshold to `H=5`, `N=9`.
14. Set the Small threshold to `H=14`, `N=19`.
15. Register and bind the new CRISP program.
16. Remove the obsolete CRISP program and bootstrap mock program.
17. Set the node release policy to protocol `4`, generation `1`.

The fork simulation determines the exact dependency-call order. Do not reorder
the final batch after the simulation passes.

## Safe review and execution

Generate one Aragon-wrapped Safe transaction file for the Cayman Foundation
Safe.

Verify these properties before signatures:

- The Safe target is the Aragon Admin plugin.
- The transaction value is zero.
- The Safe operation is `CALL`.
- The inner target is the DAO.
- Every inner call matches the fork-tested manifest.
- Every implementation and service address has deployed code.

Require two independent transaction decodes before the 3-of-5 Safe approval.

## Post-upgrade validation

Keep requests paused. Validate these properties:

- All proxy implementations match the deployment manifest.
- The DAO owns all protocol contracts and ProxyAdmins.
- The complete SlashingManager dependency graph is consistent.
- All 24 operator records are unchanged.
- All secure verifier hashes match the release artifacts.
- The CRISP program uses the expected Interfold, Avail verifier, signer, and
  image ID.
- The VRF subscription remains DAO-owned and funded.
- The new VRF provider is an authorized subscription consumer.
- The node release policy is protocol `4`, generation `1`.
- `activeE3Count` remains zero.
- `unreleasedCommitteeCount` remains zero.
- Requests remain paused.

## Service and node rollout

Complete these actions before unpause:

1. Deploy the production CRISP server.
2. Deploy the production program server.
3. Update the DAO application addresses.
4. Pin exact CRISP package versions until all npm tags are consistent.
5. Upgrade and restart at least 19 matching ciphernodes.
6. Confirm each node release acknowledgement.
7. Confirm P2P connectivity and DKG topic membership.
8. Confirm sufficient disk capacity and clean startup logs.

Mainnet has no E3 data. Operators can clear obsolete runtime data before the
upgraded nodes start.

## Unpause and first E3

Use a separate Cayman Safe transaction to unpause requests. Do not include
unpause in the main upgrade batch.

Use conservative timing for the first mainnet E3:

- VRF window: 1 hour
- Ticket window: 10 minutes
- DKG window: 6 hours
- Compute window: 7 days
- Decryption window: 6 hours
- Avail and VectorX finalization allowance: 3 hours

Monitor DKG, Boundless, Avail, VectorX, decryption, settlement, and node storage
during the first E3.

## Cleanup

Complete these actions after the first successful E3:

1. Remove the old VRF provider from the subscription consumer list.
2. Confirm that the old SlashingManager has no remaining obligations.
3. Revoke any remaining old SlashingManager authorization.
4. Decide whether the BVI Safe must retain Admin plugin permission.
5. Decide when to disable the Aragon Admin bootstrap path.
6. Store the decoded Safe payloads, deployment manifest, and validation report.

## Stop conditions

Do not execute the mainnet batch if one of these conditions is true:

- A drained-state value is nonzero.
- The registry migration is not included in a tested patch release.
- The fork simulation fails.
- The final Safe transaction differs from the simulated transaction.
- A service account or production Avail App ID is unknown.
- Fewer than 19 compatible ciphernodes are ready.
- A verifier hash differs from the release artifact.
- The private CrispVoting installation state is unknown.
- The production application cannot use the new addresses and exact SDK package
  versions.
