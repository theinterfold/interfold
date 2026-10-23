# Bonded voting power

Owners: `BondedCheckpoints`, `BondedVotes`, `BondingRegistry`, `InterfoldToken`, and CRISP's census.
Sources and guards are in the [contracts](../../packages/interfold-contracts/contracts/) and
[BondedVotes tests](../../packages/interfold-contracts/test/Registry/BondedVotes.spec.ts). This
governance attribution is separate from [committee eligibility](registration-and-bonding.md).

## One token, one clock, no duplicate weight

`BondedVotes.getPastVotes` adds the configured votes source's attribution to bonded weight held or
represented by the account. The source can be the FOLD token (wallet votes) or an escrow adapter
(locked votes). The denominator is always **the token's** `getPastTotalSupply`, not the escrow's.
Escrow and registry custody move tokens without burning them; their attributed votes remain inside
that supply. Total attributed weight must never exceed it.

Every source must use the token's ERC-6372 timestamp clock. At construction compare both history and
non-token votes-source clocks with the token. Clock agreement proves units, not asset identity: also
require `checkpoints.registry().getCiphernodeBondToken() == token` and, for an escrow source,
`votesSource.escrow().token() == token` (`VotesSourceMismatch` otherwise). An escrow source must
answer `lockedBalanceAt` at construction or fail `LockedBalancesUnsupported`; silently returning
zero later would disenfranchise the holders it exists to count.

Escrowed and bonded FOLD cannot overlap because they have distinct custody. Vesting locks remain in
the wallet and **can** overlap bonds: bond credit satisfies a lock. Only with an escrow source, add
`max(locked - bonded, 0)` capped at the current wallet balance, alongside bonded history. Otherwise
a slash could leave a lock voting on tokens now held by the slash recipient. With the token itself
as votes source, wallet FOLD already includes vesting locks, so do not add them again.

**Open gap:** `lockedBalanceAt` evaluates the account's **current** lock schedule at a timestamp; it
is not checkpointed history. Locks or claim locks created after a snapshot, and current wallet
balances, change a past answer. Following a slash, under an escrow votes source, the vesting term
can count tokens that another account also counts at that past time. Therefore this configuration
does not guarantee that summed past votes stay within past supply. CRISP's CUSTOM-credit divisor
depends on that assumption; [encrypted computation](encrypted-computation.md) records the
consequence. Do not describe present-state lock evaluation as historical balances.

`balanceOf` is delegation-independent FOLD ownership, because Aragon TokenVoting uses it for member
and proposal admission. Attribute custody to its beneficial owners, not twice to custodians:
subtract `totalCiphernodeBondLiability` (saturating) from the registry's balance; net the escrow's
own entry to zero; read each locker's FOLD amount through `votingPowerForAccount`, not escrow
NFT-count `balanceOf`. The repository has only a mock escrow. `getVotes` needs no registry
subtraction because the registry never delegates wallet votes.

## Bonded history and deployment

While attached, every `_bondedByOwner` mutation synchronizes the **new total**, not a delta, in the
same transaction. Bond, slash, and claim call `_syncBondedCheckpoint`; claim mutates via a storage
pointer in BondingAssetLib, so its caller records history. Ownership transfer synchronizes both
owners in BondingOwnershipLib. Unbonding does not change custody or total and deliberately writes no
history. For synchronized owners, `bonded(owner) == totalBonded(owner)` catches missed sites instead
of silent delta drift. Skip duplicate values: permissionless resync must not grow history once per
block.

Attachment does not backfill owners. An owner bonded before configuration reads zero until its next
mutation or `resyncBondedCheckpoint`. `setBondedCheckpoints` is one-shot per bond token and verifies
both the registry binding and a successful zero-address sync. A `registry()` getter alone cannot
prove the contract implements `sync`. While unset, synchronization is a no-op so configuration
cannot freeze bonding. Repointing an attached history is refused because it would rewrite past
answers.

Bond-token rotation drains all old bonds and detaches history. Its last owner totals are zero;
freeze that settled era instead of mixing a new asset's units into the old token's votes. A new era
needs a fresh checkpoint contract and voting adapter, not reinterpretation of existing history.

`protocol/deployContracts` deploys BondedCheckpoints bound to the **proxy**, then governance
attaches it after initialization. Only `--action activate-voting` constructs BondedVotes, after the
configured registry can answer its token binding. `protocol/validate` reads back history/registry
and adapter token/history/registry bindings. These reads cannot distinguish an older adapter without
exclusions; `readExcludedAccounts` probes code and compares configured exclusions. `activate-voting`
reuses only a matching list, validation fails a missing/changed required list, and deployment
replaces mismatches. Safe proxy upgrades attach the pair if absent and append resync calls for
`bondedResyncOwners`; without those calls pre-existing owners remain at zero.

## Delegation and exclusions

Bonded delegation moves weight, never copies it. `delegateBonded` unlinks any existing delegate
before recording a request. Only the requested delegate can `acceptBonded`; pending requests move no
weight. `acceptBonded` sets owner→delegate and delegate slot in one timestamped call; `_unlink`
clears both. Any new request-writing path must preserve the no-current-delegate premise or one owner
counts twice. Settled timepoints cannot be rewritten; `getPastVotes` rejects unsettled ones.

One delegate represents at most three (`MAX_BONDED_OWNERS`) owners because each source must be read
again on every query. Only owner/current delegate can end the link; `dropBonded(owner)` must check
its caller. Escrow and wallet delegation stay in their own sources, not duplicated here. Emit
`BondedDelegateChanged`, not IVotes `DelegateChanged`: CRISP's
[token census](https://github.com/theinterfold/CRISP/blob/main/server/src/server/token_holders/etherscan.rs)
discovers bonded delegates from that event. `EtherscanClient::get_delegate_candidates` collects
nonzero `toDelegate` addresses, then `getPastVotes` filters them at the snapshot. When
`BondedVotes.votesSource()` is not the token, the census also reads the source adapter's
`DelegateChanged` events: an escrow delegate can have votes without a lock NFT or token log. A
replacement adapter starts with no delegations.

Excluded addresses are fixed at construction (mainnet configuration names the Foundation and Gnosis
Guild Safes). `getPastVotes`, `getVotes`, and `balanceOf` return zero, and either excluded endpoint
makes `delegateBonded` revert `ExcludedAccount`. New linking paths must keep this check. Exclusion
follows the address, not the tokens: transferred FOLD or transferred bond ownership counts at the
recipient. The adapter cannot govern delegation inside its votes source: excluded FOLD delegated
there can count at a nonexcluded delegate; votes delegated there to an excluded address count
nowhere. Exclusion lowers the numerator, not the token supply denominator.

## Evidence limits

Run `pnpm evm:test` for the adapter, checkpoint, token, and registry suites. Their
binding/delegation guards do not close the historical vesting-lock gap. The escrow integration
contract is a requirement for a real deployment, not assurance supplied by the mock. A new votes
source, token rotation, or changed historical weighting needs explicit compatibility and governance
review before deployment.
