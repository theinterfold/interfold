# Application data availability

Owners: [ciphernode DA coordinator](../../crates/evm/src/data_availability/),
[CRISP server](https://github.com/theinterfold/CRISP/tree/main/server), and
[DA contract adapter](../../packages/interfold-contracts/contracts/). Committee public keys use
bounded Ethereum event chunks, not Avail; [DKG](dkg.md) owns their commitment validation. Voter and
aggregate ciphertexts use Avail with VectorX finalization on Ethereum. CRISP lives in its own
[repository](https://github.com/theinterfold/CRISP); this document covers its availability flow
because that flow uses the DA coordinator, the compute provider, and the OpenVM host of this
repository.

## Exact bytes and two-step commitment

The content address is `keccak256(exact serialized bytes)`, also Avail proof API's `leaf`. The
official bridge hashes that leaf again for its submitted-data tree. Solidity first requires leaf =
contentHash; every reader hashes retrieved bytes before decode/use. An App ID or successful RPC is
not proof. Reject zero content hash: Avail pads its Merkle tree with zero leaves (ZEN2-05).

```text
validate ballot proof and bytes → durably store exact ciphertext → sign InputAvailability
    → publishInput → reserve leaf/index, emit InputCommitted, increment pendingInputCount
    → Avail submit_data → VectorX anchor/proof
    → permissionless finalizeInput → emit InputPublished, decrement pendingInputCount
```

The voter need not stay online. Reserving the leaf at commitment lets masks/revotes name its parent
while availability is pending. The signing server already holds bytes; other indexers wait for
InputPublished, fetch Avail, and hash-check. The committed tuple cannot change during finalization.
No aggregate computation is valid until **all** committed inputs finalize
(`pendingInputCount == 0`).

SDK staging envelopes are one **flat ABI parameter sequence** of six fields, not a wrapped struct
with a leading tuple offset. Server parameter-decodes, removes ciphertext, adds signed expiry, and
parameter-encodes the seven-field commitment Solidity ABI-decodes. Preserve that wire shape.

The ballot proof binds commitment/digest/slot/parent, **not encryptedVoteHash**. A caller checking
its own supplied bytes against its own supplied hash proves only internal consistency. Before
issuing the first attestation or funded job, `validate_input_ciphertext` therefore reads
request-time BFV parameters, checks derived config ID against `e3CryptoConfigIds`, decodes exactly
two components, and recomputes SAFE commitment. Reject disagreement with the proof-bound commitment.
A semaphore bounds blocking-thread validation work. Votes/updates/masks use the same path. Without
it a copied proof with different bytes could create endless paid jobs that selection later drops.

Already-committed input restaging skips new-input proof/ciphertext/cutoff checks: the committed
content hash fixes its bytes, and its pending DA still must finalize even if selection will exclude
it. The first attestation covered validated bytes. A server with lost jobs can thus recover the same
committed ballot after cutoff, but Avail intake refuses after computeDeadline. If an unfinalized
commitment leaves chain, renew attestation and recommit before cutoff rather than discard recovery.

## Fixed schedule and exact boundaries

For request R, earliest voting start S reserves frozen randomness+sortition+DKG. Production maxima
are 1 hour + 10 minutes + 6 hours = **25,800 seconds**. Key publication early cannot open voting
before S, and late key cannot shift it. CRISP contract validates the start before charging fees,
requires at least one hour of ballot commitments, and with nonzero DA window requires computeWindow
at least that window. Server repeats configured minima as an early check, not the security boundary.

Let V be commitment cutoff and A = V + availabilityFinalizationWindow be input-window end. The
proposal records S/V; Interfold sees `[S,A]`. Production finalization tail is three hours.
`E3_DURATION` measures S→A: minimum 14,400 seconds, 43,200 gives nine commitment hours plus three
finalization hours. DAO launch uses five days of ballots then that tail. Server reads windows on
startup; local zero-window mocks may use shorter schedules. Apps suggest ten extra minutes for
create transaction inclusion. [Avail timing](https://docs.availproject.org/docs/da/build/turbo-da)
describes 20-second blocks; [VectorX](https://docs.availproject.org/docs/da/build/vectorx) bridges
360-block ranges (roughly two hours before proving/inclusion). Three hours is **operating margin,
not a promise**.

| Boundary                                         | Result                                                            |
| ------------------------------------------------ | ----------------------------------------------------------------- |
| New commitment at V−1                            | Allowed; at V rejected (exclusive cutoff).                        |
| Existing input finalized at computeDeadline      | Allowed; at deadline+1 rejected (inclusive recovery boundary).    |
| Any committed pending input remains              | Aggregate verification rejected. Last finalization wakes compute. |
| Aggregate output before A                        | Rejected; after A only through computeDeadline.                   |
| New aggregate Avail job with <=3 hours remaining | Refused; receipt/proof/publication still need time.               |

For the earliest one-hour vote: V=S+3,600, A=S+14,400, computeDeadline=A+computeWindow; latest
decryption deadline adds decryptionWindow. This fits the protocol's 30-day reservation. Input
promises expire after ten minutes without Ethereum commitment. Recovery through computeDeadline is
best effort, not a new long-lived availability guarantee; alert before the three-hour aggregate
cutoff.

## Durable jobs and finalized observations

Store staged bytes and job state in persistent Sled **before signing**. One content-addressed object
may serve several jobs. Enforce one-megabyte object limit before input commitment/output job
creation; limit unfinished-object bytes, release only when no nonterminal job references them.
Admission is per statement, never per target slot: anyone can mask someone else's slot, so a
withheld per-slot attestation would deny the owner service. Canonicalize decimal E3 IDs at shared
job identity boundaries (`042`=42). Exact-statement replay returns its existing job; a different
valid seal for identical aggregate output also does not buy a second publication.

Before spending aggregate Avail funds, verify output hash/SAFE commitment/OpenVM proof through exact
on-chain `CRISPProgram.verify` and require closed input window. Otherwise a public webhook could
fund invalid work or a root that changes after another input. Transient compute callback failures
retry five times. **Gap:** this callback is not a durable outbox; process exit between proof
production and CRISP acceptance requires operator result recovery or compute resubmission. Durable
DA begins after intake.

The browser retains each exact encoded ballot before broadcast until availability final/failure, and
restages it after server DB loss or two-minute response timeout instead of generating another
ciphertext and stranding the first leaf. Pending availability does not block another vote/mask.
Client cancellation does not cancel a paid server step: job steps run in owned tasks. Worker resumes
saved commitment, Avail, bridge, Ethereum, and retrieval steps, with at most four concurrent steps,
30-second retries, and an eight-minute outer bound longer than Avail's internal finality wait.

Every retirement or irreversible recovery decision uses **finalized Ethereum state**, not receipt or
chain head. Wait for finalized timestamp ≥ exclusive commitment cutoff/attestation expiry, or
**strictly after** inclusive compute deadline, before declaring absent publication failed. This
avoids mixed-time load-balanced RPC races. It applies in worker, status endpoint, and
submitted-transaction reconciliation:

- `AwaitingCommitment` becomes Committed only when final state contains the input. Relay receipts
  keep provisional transaction hash, stop duplicate wallet prompts, and do not start paid
  publication.
- A publication becomes `AwaitingFinality`, retaining Ethereum payload, Avail coordinates,
  seal/staged envelope, and local object. Retire only when final. If absent from finalized **and
  head** state, return Ready and resend. Contract one-shot gates make harmless slow repeats
  idempotent.
- If a provisional relayed commitment disappears, renew attestation/recommit while relay may send,
  otherwise take wallet path. A Created job seen at head enters AwaitingCommitment, not another
  relay.
- Expired uncommitted promises release bytes only after historical final-state absence; late
  observation of a timely commitment must remain recoverable. Output-failure cleanup likewise waits
  for finality.

Worker/status share per-job ownership; a busy status request returns persisted view without writing
an old copy over progress/Avail coordinates. Created status is read-only; only worker reconciles
Created. A committed job waits if head already contains another publication, avoiding paid duplicate
work after DB recovery. If that observation disappears it publishes itself.

Candidate VectorX proofs retain their originating Avail coordinates. A syntactically valid bridge
answer can fail Ethereum Merkle verification; return to AwaitingProof for replacement, not a second
Avail payment. Older records with defaulted missing coordinates still decode but need operator
recovery. If timeout interrupts Avail after broadcast before saving receipt, retry can pay twice;
content binding preserves correctness but not cost. Input retrieval retries until
computation/output/terminal deadline ends the need; an arbitrary retry cap would turn temporary
outage into data loss.

Public HTTP errors do not expose raw RPC/database text: ballot reverts are stable client errors,
infrastructure errors retryable service failures. Access logs record method and route template, not
caller address or job-bearing request path.

## Relay funding is not a protocol guarantee

Admission funding reservations use per-request tokens (RAII), not release-by-position. Commit quota
in the synchronous durable-job write under lock before later awaits; client cancellation cannot
return quota for work the worker owns. After ambiguous flush failure inspect record: live keeps
reservation, missing/still-failed returns it. Existing nonfailed jobs return **before** charging
quota; restarted failed jobs create a new funding obligation. Admitted reservations last the
original 60-second window; per-caller traffic limits still bound replay loops.

Relay defaults are three inputs per slot and no round cap. Mainnet requires explicit
`MAINNET_RELAY`, round cap, and positive balance floor; other nonlocal chains require explicit floor
(zero permits floorless sends). Startup verifies RPC chain matches CHAIN_ID. Durable relay ledger is
per **instance**, not signer key or on-chain round; multiple instances can each exhaust limits. For
one key-wide limit, route all clients to one relaying instance (`VITE_INTERFOLD_API`), disable relay
elsewhere, and move it only with no open round. Persist its initial ledger epoch even with relay
off. Rounds opened before that epoch or with unknown start use wallet path: the ledger cannot
account earlier relays.

Every send rechecks enabled flags/limits/floor. An unreadable/insufficient balance takes wallet
path, preserving finalizeInput funds. Pending transaction reservations can justify a five-minute
funding grace, but end it when cutoff is <five minutes away; stuck pending work cannot consume all
wallet opportunity. `send_from_wallet: true` skips relay accounting/balance; that choice persists on
the job but is not part of job identity. Past a cap the service still signs and offers wallet
submission: refusal would reintroduce per-slot denial. Masks can exhaust a slot's relay allowance
and expose the owner's later wallet address/confirmation burden; without timely wallet confirmation
input is lost.

All same-process signer transactions share one nonce sequence, reserving lowest unused nonce ≥
pending chain count before broadcast. Fill failures reserve nothing; local signing/definitive
refusal releases; ambiguous broadcast retains reservation. Lowest uncounted nonce expires after two
minutes. Another process using the same key can still collide: this is not distributed nonce
coordination.

## Trust and provider rotation

CRISP's encrypted-input and output-callback routes permit 4 MiB JSON to hold the largest supported
hex-encoded DA object; read routes keep smaller defaults. The server uses a multithread Tokio
runtime so expensive validation/round updates do not monopolize the RPC transport's heartbeat
executor; HTTP workers still own their own runtimes. This is an execution boundary, not proof that
all blocking work is absent. [Program-service limits](../../crates/program-server/README.md)
separately describe the unauthenticated runner endpoint, callback filtering, and nondurable
delivery.

The server's signature is a liveness promise that checked bytes are durably held; VectorX supplies
final correctness/availability proof. A compromised signer can attest without retaining bytes and
stall the round, but cannot make different bytes pass finalization. Production needs backed-up
persistent volume, bounded pending storage, protected signer, separate funded Avail account/App ID,
monitored RPC/bridge, and balance/deadline alerts. Example settings: `E3_DURATION=43200`,
`AVAIL_PROOF_LEAD_SECONDS=10800`.

DA binds **per program/round**, not through a protocol-global verifier. CRISP's adapter/verifier is
immutable; ERC-165 admission does not establish that property for arbitrary programs. The adapter
checks `bridge.vectorx() == vectorx` on every call, not just construction. External pointer rotation
fails closed (`InvalidVectorX`) rather than silently changing an in-flight trust root.

Incident response (ZEN2-08): monitor that equality; unregister each affected program to stop **new**
requests (no protocol-wide pause needed); accept that existing rounds remain bound; deploy a new
adapter/program and register it for later rounds. Restoring the old pointer in time can recover old
rounds; otherwise they fail at their existing compute/decryption deadline.

**Accepted unresolved limits (ZEN2-02/08/15):**

- `DataReference{contentHash,blockNumber,leafIndex}` has no provider ID. Only hash is persisted in
  E3; coordinates live in the event. A governed/timelocked pointer switch would make a
  split-provider round's earlier coordinates uninterpretable. Multi-provider support first needs
  persisted provider identity, explicit migration, and review; do not add a settable verifier as a
  convenience.
- There is no extension path. Extending compute alone outlives the frozen accusation horizon and
  collateral hold, yet does not change `FailurePayerLib`'s stage-derived payer. Before
  CiphertextReady, DA outage is requester-paid ComputeTimeout; after it, ciphernode-paid
  DecryptionTimeout without fee-funded DKG compensation. Reallocating loss requires a funded policy
  outside fully allocated service escrow, not a timer/adapter tweak. Never silently skip a pending
  ballot to conclude.
- A permanently unavailable valid bridge proof keeps input pending and eventually fails the round.
  Three-hour margin, server honesty, relay funding, duplicate-cost windows, and nondurable compute
  callback are operational assumptions, not theorem-level liveness.

## Evidence and deployment acceptance

[Avail adapter tests](../../packages/interfold-contracts/test/DataAvailability/AvailVectorX.spec.ts),
[CRISP tests](https://github.com/theinterfold/CRISP/tree/main/packages/crisp-contracts/tests), and
server tests own exact deadline, hash/commitment, job/finality, and quota boundaries. Run
`pnpm evm:test` here and the relevant tests in the CRISP repository. Unit/contract suites do not
reproduce the deployed OpenVM guest. Follow [OpenVM](../../crates/openvm-prover/README.md) and
[provenance](../pages/build/e3-program/verify-compute-provider.mdx): checked worker
commitments/Halo2 code, both gates bound to one identity, the full local Playwright flow of CRISP,
and one real Sepolia Avail Turing/VectorX round. Observe InputCommitted → Avail final →
InputPublished → OpenVM proof → aggregate Avail final → CiphertextOutputReferencePublished →
plaintext completion.
