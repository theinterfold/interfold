# Failure and settlement

Owners: `InterfoldLifecycle`, `FailurePayerLib`, `InterfoldPricing`, and `E3RefundManager` in
[contracts](../../packages/interfold-contracts/contracts/), plus the
[Interfold writer](../../crates/evm/src/interfold_writing/). [Slashing](slashing.md) owns
evidence/proposals; this document owns who pays and when claims mature.

## Detection is not settlement

Every nonterminal stage has its
[request-frozen deadline](committee-selection.md#finalization-and-lifecycle-clocks). Failure checks
compare the raw deadline: `E3TimeoutConfig` has no grace field. Before
`deadline + markFailedGracePeriod`, only requester, owner, or an active finalized member may call
`markE3Failed`; afterward anyone may. Provisional/expelled members have no protected caller
authority. Reject `None`, sentinel, or future unclassified failure values before changing stage.

The writer restores stage and request-time registry from durable state, watches `Requested`,
`CommitteeFinalized`, `KeyPublished`, and `CiphertextReady`, and rechecks stage/failure condition
before submission. Finalized members stagger by canonical party ID; nonmembers wait for the
permissionless grace boundary. Canonical progress cancels the old watch and stale discovery results.

Only the original requester can cancel a still-`Requested` E3 after its frozen randomness deadline
with no usable seed. Record `CommitteeFormationTimeout`, release the registry obligation, and leave
refund processing permissionless. Pending/timely VRF cannot be selectively canceled or re-requested.

`processE3Failure` consumes the service escrow once, resolves active honest nodes from the
request-time registry, transfers the exact E3 fee token to the frozen refund manager, and calls
`calculateRefund`. Unexpected registry failure reverts and restores payment rather than inventing an
empty roster. Any effects-enabled same-chain node may submit; failures before selection cannot
depend on an aggregator role. Startup restores failed IDs from lifecycle state.

Recognize `NoPaymentToRefund` (already processed) and `SettlementBlocked` only from decoded revert
data, never RPC error text containing a selector. Simulate before taking the nonce guard. A blocked
settlement retries from 30 seconds with doubling to 30 minutes, plus up to 10% jitter, without
emitting a false protocol error. Failed stage/deadline reads and failure transactions use the same
backoff policy with a separate per-E3 attempt count, cleared on success. Both backoffs are
process-local and reset on restart.

## Payer and immutable base split

| Payer                                | Failure reasons                                                                                                                                                     | Service escrow                                                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Requester / data or compute provider | `NoInputsReceived`, `ComputeTimeout`, `ComputeProviderExpired`, `ComputeProviderFailed`, `RequesterCancelled`                                                       | Pay completed work and request-time protocol share; refund the unspent remainder.                                                 |
| Supplier / ciphernodes               | `CommitteeFormationTimeout`, `InsufficientCommitteeMembers`, `DKGTimeout`, `DKGInvalidShares`, `DecryptionTimeout`, `DecryptionInvalidShares`, `VerificationFailed` | Return **100%** to requester, no protocol cut or fee-funded node reward. Honest providers can receive actual ticket slashes only. |

The positive flat randomness fee is **not escrow**. After an accepted randomness request it remains
a request-time treasury claim on success, failure, or cancellation. No node receives it and no
refund returns it. Base escrow is `originalPayment`; protocol compensation is a residual of those
funds, not insurance for an external outage.

Use the request-time allocation/treasury/policy snapshot. For example, default requester-fault
`KeyPublished`/`CiphertextReady` allocation is 50% work, 45% refund, 5% protocol; these are policy
defaults, not fixed requirements for all requests. With no honest recipients return their work share
to the requester. If a nonzero node allocation is smaller than node count, route it to snapshot
treasury rather than create zero-value claims. Freeze `perNodeAmount` at calculation; the last
failed- E3 base claimant routes residual dust to treasury, never an inflated personal reward.

Slash execution cannot change an already-calculated requester refund or its `perNodeAmount`, even
when slash and fee assets coincide. Protected slash reserves cannot fund a base refund. Requester
and honest-node claim ledgers are independent, so an account with both roles may claim each
allocation exactly once.

## The reporting and proposal gate

Failed-E3 `calculateRefund` requires `SlashingManager.settlementOpen(e3Id)`: the frozen accusation
window is closed **and** no `affectsCommittee` proposal remains open. A never-finalized committee
can settle immediately; non-expelling penalties do not gate. Increment `_openCommitteeProposals` on
opening and decrement on every terminal path. Both lanes reject expelling proposals after the
reporting deadline for every non-complete E3, including overdue rounds not yet marked failed. Lane B
still admits late non-expelling penalties and completed-round proposals while assigned dependencies
remain valid.

`settlementCutoff = slashSubmissionDeadline + MAX_APPEAL_WINDOW + APPEAL_RESOLUTION_GRACE` retains
its ABI/formula but **never bypasses** an open proposal. Time only makes resolution possible:
unappealed proposals/rejected appeals need successful execution; unresolved appeals need governance
resolution or permissionless expiry. Failed execution leaves settlement blocked. The reporting
allowance is one day after scheduled worst-case lifecycle, not after `markE3Failed`; its operational
sufficiency is an open assumption, not established by tests. ZEN2-04's repository patch still awaits
audit re-review.

If an expulsion leaves fewer than H active members, failure is atomic with slash/ban/expulsion and
uses existing supplier-paid `InsufficientCommitteeMembers` without changing enum layout. Callback
failure rolls back all effects. A request already marked Failed with requester-paid reason can be
corrected **only** by its request-time manager and **only before** refund calculation. Stage remains
Failed, `activeE3Count` stays unchanged, and a no-longer-applicable correction is a no-op rather
than reverting the expulsion. Completed rounds permit admitted later slashes without failing again.
Key, ciphertext, and plaintext publication require current committee viability; ciphertext
publication rechecks stage and viability after the mutable application callback.

## Success rewards and proposal-aware claims

Completion credits the request-time `protocolShareBps` to treasury and divides the remaining service
pool among active members. Floor remainder goes to slot `e3Id % activeCount`, not always the same
physical operator. Credits are pull claims, not publication-time transfers; failed recipients cannot
block completion or peer claims. Each operator's payout recipient was frozen at committee
finalization, so later owner transfers cannot redirect this E3's rewards.

Unclaimed allocations remain **operator-keyed** in `_operatorEntitlements`, not recipient-keyed
balances. Every claim path rechecks `pendingExpulsions` and `excluded`, including `claimReward`,
`claimHeldSuccessReward`, `claimSlashedFunds`, and permissionless `claimOperator*` entry points. An
unresolved expelling proposal holds only that operator's shares, even if opened after settlement;
clearing releases them, execution reallocates them, and peers continue claiming. Already-claimed
allocations remain final. Two operators sharing one recipient remain independent.

On failed E3s the reporting gate resolves every admitted expulsion **before** the base split, so
that split uses the post-expulsion roster. Post-settlement base/slash reallocation paths serve
successful E3s, not a license to recalculate failed refunds. Legacy recipient ledgers remain
claimable across the entitlement upgrade; a deployment must inspect whether they hold balances, not
assume the old historical "mainnet has processed no E3" statement remains true. `claimReward` emits
one receipt covering legacy and operator-held rewards.

## Slash assets keep their denomination

Every ticket slash is reserved and escrowed first by `(manager,proposalId)` with its target, token,
exact amount, E3, and frozen refund destination. [Slashing](slashing.md#execution-and-fund-routing)
owns atomic retry. At terminal settlement, each proposal distributes separately:

- Failed E3: actual slash asset to active honest nodes, excluding that proposal's target; none means
  all to snapshot treasury, not an extra requester rebate.
- Successful E3: snapshot `successSlashedNodeBps` (default 5,000) to eligible nodes and remainder to
  snapshot treasury. Non-expelling penalties exclude their target from **their own** proceeds only.

Hold only unresolved accused recipients. Preserve per-target `_heldSlashFrom` buckets through
reallocation, walking the canonical committee even after targets leave the active roster. A
round-wide "penalized" flag would make payouts depend on proposal order. Clear buckets and sum
together on claim.

Each proposal's percentage floors independently; treasury gets that percentage remainder. Divide the
node pool in canonical address order and give its remainder to the final eligible node on both
success and failure paths. Compared with aggregating routes, nodes can lose at most one base unit
per extra route; no value is lost. Token-specific protected liabilities and independent pull ledgers
avoid oracle conversion, mixed decimals, or failed-recipient griefing.

Bond slashes differ: FOLD remains in registry custody as `slashedCiphernodeBond`. Only owner-called
`withdrawSlashedFunds` moves it to `slashedFundsTreasury` and releases matching
`totalCiphernodeBondLiability` together. It does not become a ticket-compensation pool.

## Coverage and unresolved policy

[E3 integration](../../packages/interfold-contracts/test/E3Lifecycle/E3Integration.spec.ts),
[expulsion](../../packages/interfold-contracts/test/Slashing/CommitteeExpulsion.spec.ts),
[slashing](../../packages/interfold-contracts/test/Slashing/SlashingManager.spec.ts), and
[pull-payment tests](../../packages/interfold-contracts/test/Pricing/PullPaymentsAndAllowlist.spec.ts)
own contract settlement. [Writer code and tests](../../crates/evm/src/interfold_writing/) own retry
classification. Run `pnpm evm:test` and affected `cargo test -p e3-evm` tests. These checks do not
establish that evidence will arrive within the reporting window or that an outage is fairly funded.

DA losses follow the stalled stage: requester-paid `ComputeTimeout` before ciphertext duty,
ciphernode-paid `DecryptionTimeout` after it (no completed-DKG base reward). There is no DA-specific
payer or funded insurance. Skipping pending ballots, repointing a provider, or extending a deadline
is not an authorized repair. [Data availability](data-availability.md#trust-and-provider-rotation)
retains ZEN2-02/08/15's accepted limitations and incident response.
