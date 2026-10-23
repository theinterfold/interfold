# Requests and committee selection

Owners: [Interfold contracts](../../packages/interfold-contracts/contracts/),
[sortition](../../crates/sortition/src/), and [EVM ingestion](../../crates/evm/src/). Collateral and
eligibility belong to [registration](registration-and-bonding.md), proof-backed key publication to
[DKG](dkg.md), and actor delivery to [persistence](persistence-and-replay.md).

## Request-time contract

E3 IDs are full uint256 values: controller address in the high 160 bits, controller-local sequence
in the low 96. Contracts, signatures, storage, and indexers preserve every bit; Rust/indexer decimal
strings are not smaller numeric IDs. Key chunk publication resolves the controller with
`e3Id >> 96`.

`Interfold.request(E3RequestParams)` accepts committee size, input window, program, parameter-set
index, application parameters, expected fee token, expected crypto configuration, and maximum fee.
Before accepting a paid request it requires:

- unpaused admission and one coherent reciprocal Interfold/registry/bonding/slashing/refund/ticket
  graph, with matching operator membership;
- a supported configuration in `ActiveCryptoConfig`: scheme, exact parameter hash, and circuit
  version, with `[H,N]` snapshotted separately (index zero is H);
- a registered deployed program advertising `IE3Program` and `IE3ProgramDataAvailability` via
  bounded ERC-165 calls; failed, short, or false answers reject with `E3ProgramInterfaceMissing`;
- an ordered future input window and a worst-case lifecycle within `maxDuration` (30-day production
  maximum), including frozen randomness, sortition, DKG, compute, and decryption budgets;
- N active operators **and N snapshot bond owners** at request timestamp T−1 under the current
  eligibility version, with every captured registration refreshed;
- expected token/configuration equality and `totalFee <= maxFee`, before exact escrow transfer.

Mainnet supports secure-8192 at minimum/micro/small; configured launch `minCommitteeSize = 19`
admits Small only. Sepolia/local also support insecure-64. A route being configured does not itself
authorize its price-policy committee size. Different tuples, H/N, or verifier thresholds require
matching artifacts and contracts. Runtime rejects a request or saved E3 whose crypto ID differs from
its build's expected ID. [Upgrades](upgrades.md) preserves historical parameter-set index 1 and new
secure index 2; never reinterpret old requests.

The request snapshots dependencies, treasury, service/slash work allocation and policy, fee token,
parameter hash/configuration, verifier addresses, committee root, ticket price, and all timeout
windows. Program retirement affects new requests only. A program's `validate` sees the provisional
E3 and must check that `e3.e3Program == address(this)` before recording application state (ZEN2-12).

Production initialization registers one deployed program and assigns the configured protocol owner.
`MockE3Program` is stateless bootstrap with no application rules; mutable controls belong only to
its harness. Its deterministic test receipt is not production DA. Keep requests paused until a real
program is registered/wired; no contract automatically enforces that operational condition.
Deployment scripts allow mock program/ciphertext verifier only on local/Sepolia through
`assertMockDeploymentAllowed`. Even bootstrap requests retain mandatory scheme/decryption gates.
Retire incompatible bootstrap interfaces before resuming an upgrade.

The service price models N-wide work and H decryption work, not T. Availability covers request time
through input-window end, so delaying an equal-duration window costs more. Pricing sums weighted
phase terms before floor division; margin floors again and applies to service cost, not the positive
flat randomness fee. The rounding bound is per request in raw token units, not asserted below one
unit. Pair-count divisions are exact. Splitting repeats the randomness charge. Each request receives
`serviceFee` escrow; the flat fee is credited to the request-time treasury separately and never
refunded. SDK callers obtain a fresh quote unless they supply an explicit maximum. The older
historical "fee consent accepted" finding does not override today's in-call
token/configuration/max-fee guards.

## Unpredictable, immutable sortition

Committee seed is separate from the computation's `keccak256(prevrandao,e3Id)` seed. Store the paid
request before one asynchronous `IRandomnessProvider` draw. Freeze provider, request ID, response
deadline, and submission window; never re-request the same E3. Production uses Chainlink VRF v2.5
subscription funding on Ethereum mainnet/Sepolia (plus local development support), not generic chain
support. Require subscription `balance >= floor * (pending + 1)` so concurrent draws cannot all
spend the same reserve.

Reject same-Ethereum-request-block, future-dated, or late responses. A timely accepted seed remains
readable after terminal cleanup for replay. Expiry sets advisory
`degraded`/`RandomnessCircuitBreakerTripped`, not a permissionless registry-global provider reset.
Governance repointing clears degradation. Both provider replacement and response-timeout changes
require paused requests and release of every committee obligation. See
[randomness timeout controls](../pages/internals/sortition.mdx#timeouts-and-the-degraded-flag).

```text
seed  = keccak256(abi.encode(randomWord, chainid, registry, e3Id, requestId))
score = keccak256(abi.encodePacked(operator, ticketNumber, e3Id, uint256(seed)))
```

Rust's `Seed::from(U256)` uses the little-endian representation `hash_to_score` decodes. Both paths
must produce byte-identical scores. The fulfillment reader reads accepted context at its block;
without historical block state it may use retained current context only while the registry reports
the seed ready. Retry a failed registry read once with a fresh same-chain provider, retain a
successful reconnection, otherwise reject the log and fail closed. Watch provider history as well as
the current address on restart. Provider rotation requires coordinated node restart before resume.

For request timestamp T, every operator's eligibility, ticket balance, owner, and eligible count are
read at T−1; `requestBlock` is a preserved ABI/storage name for a **timestamp**, not a block number.
The request freezes ticket price and IMT root. Current registration/activity are additional liveness
checks, never substitutes for snapshot facts. `_validateNodeEligibility` reads the bonding
registry's ticket-balance history, not a separate direct votes-token boundary.

## Snapshot owners and capacity

New requests retain the best submission per `bondOwnerAt(operator,T−1)`, then the lowest N owner
scores; ties break by ascending operator address. Both ownership write paths checkpoint before
assignment. Later transfers cannot buy a second seat for one snapshot owner. Lazy history baselines
cover capped requests, not arbitrary pre-upgrade timestamps. Old requests keep the appended zero
policy's uncapped selection. The on-chain cap is independent of the submitting binary; it does not
establish human uniqueness or prevent pre-request wallet splitting/collusion.

Rust shortlists N-plus-buffer distinct owners with their eligible operator backups. An
operator-count cutoff must not discard necessary owners. If any eligible operator lacks owner
history, turn the owner shortlist off and rank every eligible operator; Solidity still rejects zero
snapshot owners. Committee formation requires N distinct snapshot owners, not N submissions.

`BondOwnerCapacityLib` maintains epoch-scoped activity/owner counts. Configuration resets it; legacy
unrefreshed operators contribute zero, and duplicate refresh cannot double count. Return zero for an
older policy timestamp or an incomplete registration refresh. Capture legacy registration membership
before its first mutation/check. Underestimation during migration is safe; overestimation is not.
Capacity proves neither online availability nor independent people. Insufficient capacity reverts
fees and treasury credit before a VRF draw.

Before dispatching its canonical ticket, a selected node persists one provisional `active_jobs`
reservation. Replay reuses it. Canonical committee finalization retains selected reservations and
releases unselected ones; failure/completion releases idempotently. This makes concurrent local
requests see capacity already used during ticket submission, not only after DKG.

Startup releases reservations for E3s that lifecycle records as terminal. A finalization delivered
after a terminal event cannot reserve capacity again, including during historical chain sync.

Ticket numbers range from 1 through frozen availableTickets; take each operator's best score. Local
or remote active-job counts never shrink that canonical range or owner shortlist. Only this node's
voluntary load limit decides whether it submits its canonical ticket; recovered intents retain
ticket number/finalization rank. Submission rank is not the normalized DKG party ID. Registry
fulfillment verification is bounded to 15 seconds; uncertain state rejects the log, never silent
polling/skipping.

## Finalization and lifecycle clocks

Ticket submissions include `committeeDeadline`; `finalizeCommittee` requires strictly later time.
Members schedule staggered calls, but the first successful transaction locks canonical on-chain
order. It must finalize by `committeeDeadline + dkgWindow`, inclusive: delaying finalization cannot
buy more paid lifetime. Fewer than N submissions fails with supplier-paid
`InsufficientCommitteeMembers`. Finalization snapshots every operator's reward recipient and retains
its collateral obligation.

The Rust finalizer retains request/context/ticket before effects, re-arms its absolute deadline
after EffectsEnabled, retries temporary timestamp errors, and opens a fresh read provider for each
attempt so a dead WebSocket cannot permanently stop it. `E3Requested` is
`(uint256 e3Id, E3 e3, bytes32 indexed cryptoConfigId)`; preserve the indexed configuration
boundary.

| Stage                             | Absolute boundary                                                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `Requested`, no usable randomness | Frozen response deadline. Only after it can the original requester cancel.                                                |
| `Requested`, seed ready           | Fulfillment time + full frozen submission window; a threshold-ready committee remains finalizable through its DKG cutoff. |
| `CommitteeFinalized`              | Resolved committee deadline + frozen DKG window, not a new window from finalization.                                      |
| `KeyPublished`                    | `max(keyPublicationTime,inputWindowEnd) + computeWindow`. Key publication must itself be no later than input-window end.  |
| `CiphertextReady`                 | Ciphertext publication time + frozen decryption window.                                                                   |

Request validation reserves the later of input-window end or worst-case randomness+sortition+DKG,
then compute and decryption. Governance cannot alter an in-flight timeout snapshot. The 75% share
checkpoint is not a protocol deadline; see [DKG](dkg.md). Failure grace limits callers, not these
clocks.

Candidate top-N obligations lock exits on submission, release a displaced candidate, and retain
winners at finalization. Terminal release clears bounded owner-candidate entries using snapshot
owners even after ownership transfers; legacy uncapped requests skip owner cleanup. Preserve
finalized committee and accepted randomness context for replay. Finalized release also waits past
the accusation deadline. [Registration](registration-and-bonding.md#deactivation-and-exit) defines
the exit-delay floor.

The operator IMT reuses freed indices before appending without changing historical roots. Its
reachable cap is `2**TREE_DEPTH - 1` (1,048,575 at depth 20), matching LazyIMT's strict
`index < maxIndex`. Warn at 80% of that cap, not a fictitious final reachable leaf (ZEN2-13).

## Evidence and ingestion limits

[Sortition tests](../../packages/interfold-contracts/test/E3Lifecycle/Sortition.spec.ts),
[owner tests](../../packages/interfold-contracts/test/Registry/BondOwnerSortition.spec.ts),
[capacity tests](../../packages/interfold-contracts/test/Registry/CommitteeCapacity.spec.ts), and
[VRF tests](../../packages/interfold-contracts/test/Randomness/ChainlinkVrfRandomnessProvider.spec.ts)
own request/selection boundaries. Run `pnpm evm:test` and `cargo test -p e3-sortition` for affected
behavior; cross-layer changes also need `pnpm test:integration` with the relevant scenario.

Chain readers default to one confirmation even through a loopback proxy; only explicit
single-process development uses zero and a 250 ms rather than 7 s RPC poll interval. Live
subscriptions are wake-ups: canonical `eth_getLogs` backfill delivers from watermark to confirmed
head, including a five-second periodic backfill at every depth. Retry/reconnect rather than silently
skip missing timestamps or logs. Unsupported preset/committee enums in a well-formed request are
benign `Processed` skips for older binaries; ABI/topic failures or unknown stage/failure enums
reject and stop ingestion, never invent values. `CommitteeFormationFailed`, activation, viability,
and settlement logs remain durable facts. Confirmation depth is **not reorg rollback**; see
[persistence](persistence-and-replay.md).
