# Accusations and slashing

Owners: [accusation workflow](../../crates/slashing/src/accusation_voting/),
[commitment consistency](../../crates/slashing/src/commitment_consistency/),
[slash writer](../../crates/evm/src/slashing_writing/), and `SlashingManager` in
[contracts](../../packages/interfold-contracts/contracts/). [Settlement](failure-settlement.md) owns
payer, reward holds, and claim allocation; [registration](registration-and-bonding.md) owns
collateral exit gates.

## From verification to authenticated votes

Each finalized E3 has an AccusationManager and CommitmentConsistencyChecker, recreated from
persisted committee/E3 metadata before replay. Proof check failures or cross-circuit commitment
inconsistency can start an accusation. A local verifier, missing VK, prover, signer, storage, or
task-pool error is **not** cryptographic evidence: keep the exact input and retry, never accuse a
peer for infrastructure failure. The `zk-prover` accusation path is a compatibility re-export;
`e3-slashing` owns decisions.

Typed admission precedes caching, vote creation, and pending-window mutation. Validate E3/chain,
canonical membership/party slot, signature, proof type, circuit, and signed timing. Local
accusations reject own address **or** own finalized party ID. Received accusations reject equal
signed accuser and accused addresses: `accused_party_id` is not in the digest and cannot decide
received self-accusation admission. Only C3a/C3b may forward a payload; other proof types need local
evidence. A bogus signature cannot accuse its labeled dealer.

The workflow compares available local verification evidence or re-verifies admissible forwarded C3
evidence. Quorum is `agree_count >= H`, derived from committee size: legacy E3 `threshold_m`
contains circuit threshold **T**, not accusation quorum. All counted voters are distinct active
committee members, not the accused. All affirmative votes must bind the same evidence hash for
`AccusedFaulted`. Different preimages produce `Equivocation`, currently local evidence only: the
single-preimage on-chain format cannot prove every payload. Timeout without quorum is
`Inconclusive`, not slashable.

The byte contract must agree between Rust and Solidity:

```text
accusationId = keccak256(abi.encodePacked(chainId, e3Id, accused, proofType))
VOTE_TYPEHASH = keccak256("AccusationVote(uint256 e3Id,bytes32 accusationId,address voter,bytes32 dataHash,uint256 issuedAt,uint256 deadline)")
structHash = keccak256(abi.encode(VOTE_TYPEHASH, e3Id, accusationId, voter, dataHash, issuedAt, deadline))
digest = keccak256("\x19\x01" || domainSeparator || structHash)
domain = EIP712("InterfoldSlashing", "1", chainId, verifyingContract)
```

Accusers converge on the latest valid signed window. The accused cannot move it, no message can
shorten it, and each accuser moves it at most once. Governance can keep/increase vote validity
immediately; every reduction, including zero, requires a two-day propose/commit delay and expires
two days after becoming ready. Direct keep/increase clears pending changes. Live zero disables new
Lane A reports. Each E3 freezes its nonzero maximum vote window and objective reporting deadline
(worst-case lifecycle

- one day); assignment closure and manager retirement must wait past it.

**Open gap:** hydration recreates recipients, not accumulated votes or timers. Peers must resend
valid messages before signed deadlines. Request-router slashable-failure teardown is also
memory-only: one day plus maximum vote validity after a local failure, or completion on restart. A
local Failed lifecycle lacks its reason, so restart can prematurely complete accusation work; see
[persistence gaps](persistence-and-replay.md#remaining-durability-gaps).

## Durable submission, local exclusion, and two lanes

At node startup, each enabled chain reads `Interfold.slashingManager()` and uses that result for
reader/writer routing and its EIP-712 signing domain. A differing configured address warns but does
not override a live result. After two failed-read retries, a zero result, or for a disabled chain
without a provider, configuration is the fallback. **Operational limit:** that address can be
retired; the failed-read path logs ERROR and lasts until restart. An E3 without its chain's manager
cannot start accusation work; startup requires at least one resolved manager. Configured deploy
blocks still control backfill. [Resolution tests](../../crates/evm/src/slashing_manager_address.rs)
pin address precedence, not availability of every historical manager after arbitrary governance
changes.

The writer saves `AccusedFaulted` in a versioned per-chain outbox before policy/RPC work, coalesced
by the contract replay tuple, and waits for `EffectsEnabled`. Startup backfills missing records from
EventStore. Every committee node reads the policy. Disabled policy produces durable E3-local
`CommitteeMemberExcluded`; clear intent only after observing it. Failed reads invent no exclusion;
enabled non-attestation configuration is a terminal configuration error.

Agreeing voters sort ascending by address; ranks 0–2 submit at rank × 30 seconds. Other ranks do not
submit. Prefer `proposeSlashByDkgParty` when canonical slot resolves, else `proposeSlash` by
address. Temporary RPC/nonce/unknown errors retry after 30 seconds. Confirmed submission, matching
execution, or durable exclusion clears the intent; duplicate evidence/stale attribution is terminal.
**Gap:** the intent persists but its due time does not, so restart repeats the full fallback delay.
`SlashSubmission` in `workflow.rs` owns these pure decisions; the writer runs its effects.

Local exclusion changes only this E3's availability. Sortition enriches it with canonical party ID;
collectors, applicable aggregators, and failover stop waiting for that member. It does **not**
slash, ban, hold rewards, expel on chain, or prevent future selection. Before canonical key
publication it can fail a fixed-roster DKG; after publication public-key aggregators ignore DKG
removals while chain failures and T+1 plaintext viability remain authoritative.

| Lane                      | Admission                                                                                           | Execution                                                                                                               |
| ------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| A, `proposeSlash`         | Permissionless; enabled `requiresProof` policy; committee target; authenticated H-voter attestation | Immediate only with zero appeal window; otherwise deferred and appealable. This is **not on-chain ZK re-verification**. |
| B, `proposeSlashEvidence` | `SLASHER_ROLE`; enabled non-proof policy; snapshotted dependencies and E3 membership                | Always delayed with appeal window; reason is explicit bytes32.                                                          |

Lane A derives reason from proof type and checks matching array lengths, strictly ascending voters,
active membership, no accused voter, ECDSA signatures, common preimage/hash, nonfuture issue time,
signed deadline, E3 maximum window, and objective submission deadline. Its semantic evidence replay
key binds chain/E3/accused/proof type. Lane B's consumed evidence key binds E3/operator/Keccak
evidence. Policies snapshot penalty amounts, ban/committee flags, and appeal window at proposal
time.

Valid policies require at least one nonzero penalty; `!requiresProof` requires `appealWindow > 0`.
Retained `failureReason` is zero or `InsufficientCommitteeMembers`; it does not choose attribution
on execution. Both lanes open the same proposal-scoped registry lock and, if expelling, an
entitlement hold. After the frozen reporting deadline, neither lane opens an expelling proposal for
a non-complete E3, even one overdue but not marked Failed. Completed-round Lane B proposals and
non-expelling penalties retain their enforcement paths.
[Settlement](failure-settlement.md#the-reporting-and-proposal-gate) defines when these proposals
must resolve before a failed payer is fixed.

Operator **or bond owner** can appeal once before `executableAt`. Governance can uphold
(cancel/release) or reject (execution still needed). After executable time plus seven-day resolution
grace, anyone can `expireAppeal`, conclusively upholding an unresolved appeal and clearing its
locks/holds. Otherwise anyone can execute an unappealed or rejected proposal once mature.
Counters/holds close atomically on terminal paths; an execution revert cannot silently clear an open
gate.

## Execution and fund routing

Slash active ticket/bond balance first, then pending exits including locked tranches. Record actual
amounts, not requested amounts if collateral is insufficient. Bond slashes reduce owner's aggregate
bond credit and history immediately. Apply configured ban and E3 expulsion atomically. If active
count falls below H, fail/reclassify through request-time Interfold with supplier-paid reason;
failed callback reverts penalty, ban, and expulsion together. Canonical successful key publication
ends only local DKG removal work, not contract penalties or later decryption viability checks.

Before moving ticket funds, reserve them in BondingRegistry by `(manager,proposalId)` and record
durable route E3/target/token/amount/frozen refund destination. Initial bounded self-call atomically
transfers exact collateral and updates escrow liability; consume route state before callbacks and
restore it if either step reverts. Failure leaves the **slash** executed but funds reserved and
route permissionlessly retryable. A completed retry is an idempotent false/no-op. Treasury/other
managers cannot spend the reserve. Late successful escrow can settle independently after terminal
state; it never mutates base refund buckets.
[Settlement](failure-settlement.md#slash-assets-keep-their-denomination) defines denominations and
recipients.

Before upgrading to proposal-scoped reservations, retry legacy routes until
`reservedSlashedTicketBalance == 0`. Drain or explicitly migrate legacy callback-only proposals/bans
before replacing their registry gates; an empty new aggregate is not evidence that old obligations
are gone. Entitlement-aware refund-manager installation requires no E3 or expelling proposal in
flight; old policy snapshots lack manager addresses and cannot be safely backfilled.

`SLASHER_ROLE` is administered by `GOVERNANCE_ROLE`, not DEFAULT_ADMIN; deploy scripts grant
governance explicitly. Default-admin transfer is two-step with two days. Manual bans require
distinct proposers and confirmers; unban is single-step and refreshes registry activity.
`SlashProposed`/`SlashExecuted` retain lane A=0/B=1, and Rust's ABI includes `executed`/lane; raw
log fallback retains omitted typed fields. SlashingManager is deliberately **non-upgradeable**:
replacement requires redeployment and governance rotation, with old E3 assignments/locks/bans/routes
retained until clear. There are no concurrent registry generations; [upgrades](upgrades.md) owns the
drain policy.

## Existing guards

- [Lane tests](../../packages/interfold-contracts/test/Slashing/SlashingLanes.spec.ts) include
  deferred Lane A collateral holds, old-manager gates, appeal expiry, and cross-deployment/chain
  rejection.
  [Expulsion tests](../../packages/interfold-contracts/test/Slashing/CommitteeExpulsion.spec.ts)
  cover atomic viability and callbacks. Run `pnpm evm:test`.
- [Typed accusation admission](../../crates/slashing/src/accusation_voting/transitions/admission.rs)
  and [writer workflow](../../crates/evm/src/slashing_writing/workflow.rs) contain owner-level
  tests; use `cargo test -p e3-slashing` / `cargo test -p e3-evm` as relevant.
- `pnpm rust:test:slashing` exercises the existing proof/slashing integration harness. It does not
  reconstruct volatile votes/timers across a process crash or prove the one-day reporting allowance.
