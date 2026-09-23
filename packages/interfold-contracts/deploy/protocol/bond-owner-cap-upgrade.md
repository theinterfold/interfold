# Bond-owner committee cap

## Scope

New E3 requests select at most one operator per request-time bond owner.
Operators submit their best tickets. The contract retains the best submission
per owner, then the best N owner candidates. This is not first-come selection.
Ticket numbers remain one-based.

Ownership, eligibility, and ticket balances use the request timestamp minus one
second. Ticket price remains frozen by the request. Later owner transfers cannot
change that request's groups. A new namespace stores owner checkpoints without
changing the legacy registry layout. Existing operators need no re-registration
or collateral movement.

The cap applies to recorded owner addresses, not people. Different owner
wallets, later transfers of control, and collusion can bypass the intended
concentration protection. Bond owners at finalization still receive rewards
under the existing reward snapshot rule. They need not equal the owners used for
admission.

## Components

- Upgrade the existing BondingRegistry proxy with its newly linked
  BondingOwnershipLib.
- Upgrade the existing CiphernodeRegistry proxy with its newly linked
  RegistrySortitionLib.
- Release the updated ciphernode candidate-submission logic.
- Preserve proxy addresses, governance ownership, asset configuration, and
  release-policy counters.
- Do not rebuild DKG or decryption circuits for this change.

The existing deployment helpers already link both libraries. No initializer or
owner-list migration is required. BondingRegistry now exposes
`bondOwnerAt(operator, timepoint)` through `IBondOwnerHistory`; the previous
`IBondingRegistry` interface ID stays unchanged.

## Rollout checks

This document is not authorization to deploy or submit governance transactions.

1. Pause new requests through the existing governance process.
2. Confirm the exact implementations, linked libraries, storage layouts, and
   ProxyAdmin owners.
3. Confirm the target stack already uses the current VRF and timestamp-based
   sortition layout.
4. Deploy and link both implementations from the same reviewed commit.
5. Upgrade BondingRegistry before CiphernodeRegistry, preferably in one reviewed
   Safe batch.
6. Verify owner history against current owners and a local fork's transfer
   tests.
7. Update participating nodes before accepting capped requests.
8. Count distinct active owners with sufficient tickets and available machines.
   Keep spare owners.
9. Verify a new request emits `CommitteeBondOwnerCapEnabled` on a local fork or
   testnet.
10. Resume requests only after the deployment checks and committee-formation
    test pass.

Small requires 19 distinct eligible owners to form a committee. H=14 does not
reduce that requirement. The existing request guard counts active operators, not
owners. An insufficient owner pool can accept payment and then fail formation.
The `committee:new` task now checks distinct eligible owners at a single chain
block before fee approval and payment. It reads the configured committee size,
request-boundary owners, eligibility, and ticket balances from the deployed
stack. RPC errors and an observed reorg stop the task. Direct callers must do
their own preflight. The result is not a reservation or an online check, and
state can change before the request is mined.

The runtime shortlists N-plus-buffer distinct owners by their best ticket and
retains all operators within those groups as backups. Finalization-attempt ranks
visit each owner's best operator before its backups. Nodes outside those owner
groups do not submit. Backup operators still use the normal submission window;
this does not add a coordinator or a staged retry protocol. With exactly N
owners, every owner is needed and all its eligible operators may submit.
Benchmark ticket gas and formation time on the target network before resuming.

## Compatibility and rollback

The appended policy field defaults to zero for existing requests. Their
admission rule remains uncapped. New requests use the cap; the contract probes
the history API before requesting VRF. Never enable capped requests with a
bonding implementation that cannot record owner history.

Ownership history starts at this upgrade. Its lazy baseline supports new capped
requests; it does not reconstruct transfers made before the upgrade. Deploying
either implementation from an older incompatible storage generation requires a
separate migration review.

No P2P event or existing persisted Rust schema changes. A new versioned
repository stores owner history from `BondOwnerSet`. Startup reconstructs
missing chain projections from aggregate zero's event log through its snapshot
cursor. Existing snapshots remain authoritative. Missing owner history falls
back to all eligible submissions; the on-chain cap still applies. Restored
ticket intents keep their original ticket number and finalization rank.

Older nodes cannot bypass the contract cap, but their candidate cutoff may omit
owners needed for formation. A voluntary binary rollout is therefore a liveness
prerequisite. Raising mandatory node generation is separate and retains its
existing pause-and-drain guards; this change does not bypass them.

In-place proxy upgrades are distinct from changing dependency addresses or
release-policy counters. Preserving old requests here does not authorize
unrelated graph migrations during an E3.

After capped requests exist, do not roll back either proxy to code that omits
owner-history writes or ignores the cap. Keep requests paused and deploy a
forward correction that preserves the frozen policy. Existing uncapped rounds
are not retroactively protected.

## Validation

- `pnpm evm:test`: formation, ownership transfers, refunds, slashing, rewards,
  and upgrade regressions.
- `cargo test -p e3-sortition`: owner shortlist, backups, transfer boundaries,
  capacity, reservations, and failover tests.
- `cargo test -p e3-ciphernode-builder`: owner-history backfill, schema
  rejection, and restored ticket intents.
- `cargo test -p e3-sync`: bounded event-log replay and recovery projection.
- `pnpm -C packages/interfold-contracts compile:contracts --force`
- `pnpm -C packages/interfold-contracts validate:upgrade`
- `pnpm -C packages/interfold-contracts size:check`

`test/Registry/BondOwnerSortition.spec.ts` checks submission-order independence,
obligation replacement, insufficient owners, transfer snapshots, and the
zero-valued legacy policy field. Its Small test registers 28 funded operators
under one owner plus 18 other owners and verifies 19 selected owners. Legacy
storage tests explicitly seed missing pre-upgrade fields; they do not replace a
deployment-specific fork rehearsal.
