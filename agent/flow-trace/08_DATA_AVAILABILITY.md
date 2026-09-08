# CRISP Data Availability and Deadlines

## Why this flow exists

Secure BFV public keys and ciphertexts are too large for one Ethereum transaction. CRISP therefore
uses three different transports:

- The committee public key is split into bounded Ethereum event chunks. Its C5 proof commitment is
  already on Ethereum.
- Voter ciphertexts are published to Avail. Ethereum accepts their references only after VectorX
  proves that the exact bytes were included.
- The aggregate ciphertext uses the same Avail and VectorX receipt, after RISC Zero proves the
  computation.

Consumers assemble a complete public-key candidate and check its content hash. They decode the key
with the E3 threshold parameters and compare its C5 commitment with the proven on-chain value.

The application content address is `keccak256(exact serialized bytes)`. Avail's proof API returns
that value as `leaf`. The official bridge hashes `leaf` once more when it checks the submitted-data
Merkle root. The Solidity adapter first requires `leaf == contentHash`, then calls the bridge. Every
reader also re-hashes the retrieved bytes against `contentHash` before use.

The SDK encodes each six-field staging envelope as a flat ABI parameter sequence. The server decodes
that sequence as function parameters, removes the ciphertext, and adds the signed expiry. It returns
a seven-field commitment payload that `CRISPProgram.publishInput` reads through Solidity
`abi.decode`.

## Two-step voter flow

```text
voter creates ciphertext and Noir proof
        |
        v
CRISP server validates the proof and stores the exact bytes durably
        |
        v
server signs InputAvailability(e3Id, inputId, expiresAt)
        |
        v
publishInput(proof, contentHash, commitment, slot, parent, expiresAt, signature)
        |
        +--> verifies the Noir proof and server signature
        +--> reserves the input leaf and index immediately
        +--> increments pendingInputCount
        +--> emits InputCommitted
        |
        v
server submits the stored bytes to Avail
        |
        v
VectorX anchors the Avail range on Ethereum
        |
        v
finalizeInput(tuple, VectorX proof)
        |
        +--> proves availability of the exact contentHash
        +--> marks the reserved input PUBLISHED
        +--> decrements pendingInputCount
        +--> emits InputPublished with Avail coordinates
```

The voter does not stay online for VectorX. On Ethereum mainnet, the voter pays only for the compact
`publishInput` transaction. The server owns the durable Avail and `finalizeInput` job. Sepolia and
local development can relay the compact transaction for the voter.

The leaf is reserved in the first transaction so a revote or mask can name it as its parent while
VectorX is still finalizing. The server that signed the input already has the exact bytes and
indexes them when it sees `InputCommitted`. Other indexers wait for `InputPublished`, retrieve the
bytes from Avail, and verify their hash.

`CRISPProgram.verify` refuses the aggregate proof while `pendingInputCount` is nonzero. A content
hash without an accepted VectorX receipt can therefore never enter the final computation.

The aggregate callback uses the same two-proof order. Before the server spends Avail funds, it calls
`CRISPProgram.verify` as an Ethereum read with the output hash, SAFE commitment, and RISC Zero
proof. Only an output that passes that exact on-chain verifier becomes a durable Avail job. The job
ID excludes the proof seal, so another valid seal for the same output is an idempotent retry instead
of a second paid publication. The server also refuses the job while the input window is open: a
proof over the current root could otherwise become stale after another vote, after the Avail fee was
already paid. The compute server retries a transiently failed callback five times.

## Deadline simulation

The production timeout maxima before a committee key can exist are:

| Phase             |    Maximum | Time since request |
| ----------------- | ---------: | -----------------: |
| Chainlink VRF     |     1 hour |             1 hour |
| Ticket submission | 10 minutes |  1 hour 10 minutes |
| DKG               |    6 hours | 7 hours 10 minutes |

CRISP reserves the final 3 hours of the input window for VectorX. It also guarantees at least 1 hour
in which a voter can create a new proof after a worst-case committee setup:

```text
1h VRF + 10m sortition + 6h DKG + 1h voting + 3h finalization = 40,200 seconds
```

With those production defaults, `E3_DURATION` must be at least 40,200 seconds. A short rehearsal can
use 43,200 seconds (12 hours), which leaves 1 hour 50 minutes for new commitments after the
worst-case key publication. The Interfold DAO launch configuration uses five days. That leaves 4
days 13 hours 50 minutes for new commitments under the same worst case. The server does not
hard-code these totals. At startup, it reads the registry's randomness and sortition windows,
Interfold's DKG window, and CRISP's voting and finalization windows. It refuses to start when
`E3_DURATION` is shorter than their current sum. Test deployments with shorter on-chain windows can
therefore use a correspondingly shorter round.

The three-hour tail is an operating target, not a promise from VectorX. Avail documents a 20-second
block time and says VectorX bridges one range every 360 blocks. One complete range is therefore
about two hours, before proof generation and Ethereum inclusion. The extra hour is normal-case
margin. If that margin is not enough, an already committed input remains recoverable through the
inclusive compute deadline. No new input is admitted during that recovery period.

- [Avail block and finalization timing](https://docs.availproject.org/docs/da/build/turbo-da)
- [VectorX 360-block range](https://docs.availproject.org/docs/da/build/vectorx)

The CRISP request paths currently start the input window 20 or 60 seconds after they read the chain
time. The exact timestamps therefore shift by that small start buffer. The table below uses `T0` as
the input-window start. The contract calculates from the actual request timestamp and actual input
window, so it does not rely on this approximation.

For a 12-hour input window starting at `T0`:

| Boundary                                                      |        Timestamp |
| ------------------------------------------------------------- | ---------------: |
| Worst-case key publication                                    |   `T0 + 25,800s` |
| Last instant before commitment cutoff                         | `< T0 + 32,400s` |
| Input window ends                                             |   `T0 + 43,200s` |
| Compute deadline                                              |  `T0 + 648,000s` |
| Latest decryption deadline after a last-second compute output |  `T0 + 669,600s` |

This is below Interfold's 30-day maximum lifecycle reservation.

The boundaries are intentional:

- `publishInput` requires `timestamp < inputCommitmentDeadline`.
- The availability service signs `InputAvailability(e3Id, inputId, expiresAt)` only after it stores
  the complete ciphertext. The promise expires after 10 minutes if no Ethereum commitment lands. A
  retry receives a new promise only after the old one expires and the server releases its bytes.
- The final 3-hour tail accepts no new proof commitments.
- `finalizeInput` normally completes in that tail. A delayed receipt can recover while the E3 is
  still `KeyPublished` and `timestamp <= computeDeadline`.
- RISC Zero does not start at the input-window end while any input is pending.
- A late `InputPublished` event wakes computation after all pending inputs reach zero.
- The aggregate job starts only when more than 3 hours remain before the compute deadline.
- Interfold accepts the aggregate output only after the input window ends and no later than the
  compute deadline.

Late input finalization is best-effort recovery, not a new seven-day availability promise. The
contract can accept a receipt through `computeDeadline`, but the E3 can complete only if enough of
the compute window remains to produce the RISC Zero proof, publish the aggregate ciphertext to
Avail, wait for its VectorX proof, and submit the output on Ethereum. The server therefore refuses
to start an aggregate Avail job unless more than three hours remain. Operators must alert well
before that cutoff instead of treating `computeDeadline` as a useful finalization target.

The boundary tests use the contract timestamp directly. They cover these cases:

| Case                                                   | Result   |
| ------------------------------------------------------ | -------- |
| Commit at `commitmentDeadline - 1`                     | Accepted |
| Commit at `commitmentDeadline`                         | Rejected |
| Finalize an existing input at `computeDeadline`        | Accepted |
| Finalize at `computeDeadline + 1`                      | Rejected |
| Compute while one input is committed but not finalized | Rejected |
| Compute after the last pending input is finalized      | Allowed  |

The simulation also exposed an RPC race. A wallet transaction can land just before the commitment
cutoff while a load-balanced RPC still returns the older contract state just after the cutoff. The
worker must not conclude that the transaction failed from that mixed view. It now waits for an
Ethereum finalized block at or after the exclusive commitment cutoff and checks `isInputCommitted`
at that block. The same rule applies to input and output publication: a job is marked failed only
after a finalized block strictly after the inclusive compute deadline still lacks the publication.
Until then, the worker keeps the durable job recoverable.

The service does not release an expired promise based on its local clock or an unfinalized chain
head. It waits for an Ethereum finalized block at or after `expiresAt`, then checks the historical
`isInputCommitted` state at that block. A commitment mined before expiry therefore survives even
when the service observes it later. If the finalized state contains no commitment, the service
releases the ciphertext and lets the voter stage the original proof again for a fresh promise.

The old four-hour CRISP duration was unsafe. In the worst case, the input commitment cutoff arrived
before the committee key existed. Both the server and `CRISPProgram.validate` now refuse an unsafe
window. The contract derives the latest key time from the request's frozen DKG timeout and the
request-time Registry VRF and sortition windows. It also accounts for a deliberately delayed input
start, so calling the contract without the CRISP server cannot bypass the rule.

## Restart and failure behavior

- Each ciphernode stores partial public-key assemblies, selected candidates, and unresolved
  ciphertext-output references in a chain-scoped recovery projection. A restart after the event
  snapshot boundary resumes the missing chunks or retrieval instead of waiting for old logs that
  will not replay.
- Every staged object and job state is in the server's persistent Sled database before the server
  signs an input. The object has one content-addressed copy; job metadata does not duplicate it.
- The browser keeps the exact encoded ballot with its durable job pointer. If the server loses its
  job database, the browser re-stages the same commitment instead of creating a second ciphertext
  and leaving the first on-chain commitment unresolved.
- The server checks the one-megabyte object limit before it accepts an input commitment or creates
  an output job. An oversized object cannot reserve a leaf that Avail will always reject.
- The job worker retries every 30 seconds and runs at most four job steps at once. The outer
  eight-minute bound is longer than Avail's internal finality wait, so it stops a hung request
  without cancelling a valid slow submission.
- On restart, the worker resumes proof commitments, Avail submissions, VectorX polling, Ethereum
  finalization, and retrieval from the saved state.
- Ethereum state is checked before each write. A transaction that landed before a crash is not sent
  again.
- A round and voting slot can have only one signed input that is still waiting for its Ethereum
  commitment. The service also refuses new jobs when unfinished objects reach the configured byte
  limit. Failed jobs release their bytes, and successful Avail jobs use Avail as the recovery
  source.
- The browser status endpoint performs a bounded Ethereum reconciliation. If the wallet commitment
  landed before the browser closed, a reload advances the durable job instead of asking the voter to
  sign and submit the same transaction again.
- A deadline failure is conclusive only after the finalized Ethereum state crosses the relevant
  boundary. This prevents a stale RPC read from stranding a transaction that landed on time.
- If a timeout interrupts an Avail submission after broadcast but before its receipt is saved, a
  retry can pay for a duplicate publication. The content hash remains the same, so this affects cost
  but not correctness.
- The server verifies an aggregate RISC Zero proof before it creates an Avail output job. An
  arbitrary caller of the output webhook cannot spend the Avail account on an invalid output.
- The compute server retries a transient callback five times, but this callback is not a durable
  outbox. If that process exits after it receives a proof but before CRISP accepts the callback,
  operators must recover the result or resubmit the computation. The durable Avail worker starts
  only after CRISP receives the callback. This is a pre-existing compute-server recovery limit, not
  an Avail proof bypass.
- If VectorX never produces a valid proof, the input remains pending. CRISP refuses computation and
  Interfold eventually fails the E3 at the compute deadline.
- Input retrieval retries while the round can still compute. References are removed when the
  aggregate ciphertext is published, the round finishes, or Ethereum marks the E3 failed. A retry
  limit during an active round would turn a temporary Avail outage into permanent data loss.

The public HTTP boundary does not expose RPC or database error text. Contract reverts caused by a
ballot return a stable client error. Provider and storage failures return a retryable service error.
Failed admission returns its global relay reservation.

## Remaining trust and operations

VectorX provides the final correctness and availability proof. The server signature is an earlier
liveness promise: it proves that the configured service received and durably stored the exact
ciphertext before Ethereum reserves the leaf.

If the availability signer is compromised, it can sign a hash without retaining the bytes. The
resulting pending input can stop the round until the compute timeout. It cannot make Ethereum accept
different bytes because `finalizeInput` still requires the VectorX proof for the committed hash.

Production therefore needs:

- a persistent, backed-up server volume;
- a pending-object limit sized for the largest supported round and the available disk;
- a protected Ethereum availability-signer key;
- a separate funded Avail account and registered App ID;
- monitored Ethereum, Avail, and bridge API endpoints;
- alerts for pending jobs, signer balance, Avail balance, and the commitment/finalization deadlines;
- `E3_DURATION=43200` and `AVAIL_PROOF_LEAD_SECONDS=10800`.

No fallback changes the data source after its hash is known. Adding such a fallback would require a
new, explicitly bound proof path and a separate review.

## Fast-machine acceptance gates

The normal unit and contract suites do not reproduce the production RISC Zero image. Before this
branch can deploy, use the durable Interfold revision pinned in both support manifests and run the
pinned Docker build. The generated `ImageID.sol` must be reviewed and then used by both the BFV
ciphertext verifier and CRISP program deployment. A native build is not an acceptable substitute.

After the image is rebuilt, run the full local CRISP Playwright flow and one Sepolia round with real
Avail Turing and VectorX. Observe this complete event order:

```text
InputCommitted
  -> Avail finalized
  -> InputPublished
  -> RISC Zero completed
  -> aggregate Avail finalized
  -> CiphertextOutputReferencePublished
  -> plaintext completion
```
