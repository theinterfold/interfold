# Encrypted computation and application input binding

Owners: [compute-provider](../../crates/compute-provider/),
[OpenVM prover](../../crates/openvm-prover/), the
[CRISP program](https://github.com/theinterfold/CRISP/tree/main/program), and the
[CRISP contracts](https://github.com/theinterfold/CRISP/tree/main/packages/crisp-contracts).
Protocol verification creates decryption duty; application verification decides what computation is
valid. Neither can stand in for the other. This path was **not covered** by the scoped Zenith
Solidity audits; [audit scope](../../packages/interfold-contracts/audits/README.md) is narrower than
repository remediation claims.

## Shared computation contract

Every program exports `policy()` beside `fhe_processor`. `InputPolicy` defines a leaf function and
selection over byte-free `InputRecord`s. Shared compute code must guarantee:

- derive leaves from the ciphertexts actually consumed, never accept independent roots/leaves;
- include **every** published input in the tree, in on-chain order, even when not selected;
- process exactly the selected ciphertexts that produced those records.

`InputPolicy::default` uses ciphertext commitment as leaf and selects all inputs, matching the
starter template. CRISP instead selects usable per-slot chains. The crate cannot decide what repeat
input for one participant means for every application.

`SecureProcess` reads one ciphertext at a time. First pass records recomputed commitment, Keccak,
and leaf for every input; selection reads only records; second pass streams selected ciphertexts and
rejects changed hashes (`InputChanged`). Reject short/long input sets (`InputCount`) and processors
that stop early (`Unread`). The caller must still supply the complete on-chain input set. The tree
is the smallest binary Poseidon tree fitting it, minimum depth one, with agreed
leaf/order/zero/depth. `MerkleTreeBuilder::with_leaf_hashes` is test-only, not a production bypass.

Prove the whole round in one guest run. The removed chunk-proof `start_parallel` built a tree of
subtree roots rather than the flat on-chain root. Current batching parallelizes only pure commitment
recomputation; global positions and one selection call remain stable. Without `parallel`, use
sequential execution; guest is single-threaded. Schedule must not change the root.

The host/guest share SecureProcess, but accelerated guest Poseidon2, Keccak, SHA-256, RNS packing,
and power-basis commitments must match native reference behavior. A mismatch does not forge a proof
(contracts rebuild the journal), but prevents producing one and can fail every round. **Gap:** no
Interfold CI job runs the accelerated guest paths (`e3-safe/openvm`, `openvm-hashes`,
`crisp_fhe_optimized`): `openvm_guest` builds only the template guest, and host unit tests build the
non-`openvm` variants. The CI of [CRISP](https://github.com/theinterfold/CRISP) runs the real guest
against the host's journal, but only after CRISP pins a published Interfold release, so a parity
regression on `main` can ship in a release. Guest allocation must free per-input temporaries
(`heap-embedded-alloc`, not a never-free bump allocator); its choice is part of the
executable/application commitments.

## Receipt and output publication

The streamed guest receives domain/parameters/published metadata and ciphertexts, not an input root.
Its journal is nine 32-byte ABI words: chain ID, Interfold address, full E3 ID, scheme ID, committee
public-key hash, output hash, SAFE commitment, parameter hash, and derived input root. It reveals
SHA-256 of those 288 bytes. The worker builds application, recursive, and Halo2 EVM proofs, checks
configured executable/VM commitments, and verifies against the native predicted journal before
returning a seal. Missing configuration or failure cannot choose fake-proof mode. Development mode
is separate.

The request-time scheme verifier reconstructs protocol fields; the request-time program reconstructs
application fields and verifies the same receipt. `OpenVmBfvCiphertextVerifier` authenticates
inputRoot but compares it with **no expected root**. Every program must compare it with its own
on-chain root. Without both derived leaves and that application check, an unpermissioned one-shot
output publisher could prove computation over an unrelated input set; no dispute path repairs it.

`publishCiphertextOutput` requires KeyPublished, inclusive compute deadline, closed input window,
unset output, viable request-time committee, program DA verification, scheme proof, and application
proof. After the mutable `IE3Program.verify` callback, re-read stage and viability: callback
slashing can mark Failed outside the shared publication reentrancy guard. Failure must revert the
complete publication, not overwrite terminal stage/counter/committee cleanup (ZEN2-26).
Ciphertext/plaintext publication share a guard. Store both Keccak output hash and SAFE commitment,
start the frozen decryption window, and emit durable DA reference then CiphertextReady.
[DA](data-availability.md) owns retrieval and availability proof.

SAFE commitment covers **exactly two** ciphertext components c0/c1. `bfv_ciphertext_to_greco`
rejects others; seed compression expands c1 before conversion. Padding a third component otherwise
preserves commitment/root but fails ShareManager decryption, wrongly imposing ciphernode
DecryptionTimeout. Receipt-verifier addresses must have code; a void call to an EOA returning empty
bytes is not success.

Each project's guest and separate `runner/` crate link its own program. The runner calls
`e3_program_runner::run(fhe_processor, policy())`; keeping it separate prevents server dependencies
from entering the guest. `program-runner dev` serves mock proofs; `program-runner openvm` serves the
worker-verified service. Neither creates durable job admission.

Changing processor/policy, allocator, sources, fhe.rs pin, or VM configuration requires rebuilt
executable/keys/application commitments and matching deployed receipt identity. Never reuse a legacy
RISC Zero image ID or another VM configuration's aggregation key. `interfold program compile`
prepares artifacts/config; `program start` checks the selected CPU/CUDA worker (CUDA only after a
successful GPU probe) before accepting work. Worker runs have deadlines; machine-local paths, keys,
proofs, and benchmarks stay outside Git. See
[OpenVM operations](../../crates/openvm-prover/README.md) and
[provenance](../pages/build/e3-program/verify-compute-provider.mdx).

The worker also offers explicit application, aggregate and root checkpoints. Each stage verifies its
proof before saving, and resumption repeats native verification against the configured executable,
VM and exact journal. Manifests bind the pinned OpenVM format and artifact/file digests; they are
corruption/provenance checks, not proof authority. Completion is a manifest published last after
file synchronization. Only final compression produces the existing EVM-verified seal. This local
format does not change guest/receipt identities or protocol counters. It does not make HTTP job
admission durable or automatically resume an interrupted stage; the service still invokes `prove`.
Proof import limits are an operator policy, independent of saving locally generated verified
results. Imported files are bounded and must be regular checkpoint members; the CLI is not a
resource-isolation boundary for untrusted jobs. See the worker guide for limits and file
permissions.

The CLI's `program_support.rs` owns project-root compile/start and cache purge. Development compile
uses `cargo build --bin program-runner`; OpenVM compile runs the embedded
`crates/cli/scripts/openvm-compile.sh` to build guest, keys, receipt identity, worker configuration,
and runner. Start uses the matching mode and forwards absolute `program.openvm` paths as `OPENVM_*`.
Legacy `.interfold/support` projects are refused until they adopt the template runner.

## Ballot proof and selection

CRISP's append-only input leaf is:

```text
sha256(keccak256(exact ciphertext bytes) || commitment || slotAddress || parentIndexPlusOne)
    mod SNARK_SCALAR_FIELD
```

Slot is 20 bytes, parent is uint40 (five bytes) in published metadata. Hashing exact bytes binds
Avail content; SHA-256 outside suits guest acceleration. Rust policy and Solidity must agree byte
for byte. A different content hash, commitment, slot, or parent changes selection authority/root.

Every operation proves `published = addend + ballot`. Private `is_mask_vote` and derived
`keep_previous = is_mask_vote & !is_first_vote` choose current head for a mask, zero for a
vote/revote or empty slot. Do not witness the selector independently: it could double-count an old
ballot or erase one. Both ballot circuits constrain every coefficient/CRT limb with quotient r in
`[-1,1]`. A one-point Fiat-Shamir check over the three plain packed commitments is unsound; a second
opening of the parent can erase its vote. The coefficient-aligned linear relation with equal BIT_CT
packing is the narrow exemption from checked openings, and only while all committed ciphertexts have
bounded openings fixed by validated bytes/upstream constraints. A point check or following only a
stored parent commitment needs injectivity. See [proof contracts](proof-statements.md).

The circuit always returns `sum_ct_commitment`; digest, stored commitment, published ciphertext, SDK
path, and `prepareBallot` server request have one shape for votes/updates/masks. Distinct shape or
request pattern would disclose the private choice. Contract supplies C5-proven round key at
`noirPublicInputs[8]`; ballot circuits bound both key components before commitment generation.
Off-circuit anchors still need injective in-circuit packing.

Plaintext constraints use the full BFV degree D, not message width: option o is `k1[D-1-o]` after
reversal. Zero every non-option coefficient; masks zero the entire polynomial. `check_weight` bounds
coefficient, hinted weight v, and quotient r to `[0,t)`, then verifies `k1 + t*r == Q_MOD_T*v` over
integers. Use the non-centered scale, not `Q_MOD_T_CENTERED`. Weights sum at most the slot bound;
with two options at most one is nonzero. Bounds give `k1_commitment` one opening, so the fold binds
the same plaintext the encryption circuit proves. Regenerate both presets' fold VK constants in the
CRISP repository (`pnpm compute:vk-hash <preset>`, for both presets) and verifiers after
ballot-circuit changes; a deployed program retains its old immutable verifier until replacement.

The tree appends rather than updates because anyone may mask an eligible slot without its owner's
signature. Update-in-place would let a third party erase a counted vote. Each entry names its
parent; in global index order `chain_head_per_slot` accepts it only if bytes reproduce commitment
and its parent is that slot's current head. Keep rejected entries' leaves, but do not select them.
Unusable bytes never become a head/parent, so they cannot leave a slot only their author can open (a
coercion receipt). A mask preserves tally; a revote replaces rather than adds to earlier ballot.

The **first usable sibling wins**. A later sibling/stale parent is dropped, and an attacker can
front-run a revote with a mask. Preferring the later sibling would let an old mask restore a
superseded vote, a silent tally corruption worse than a visible retry. Circuit privacy prevents
telling replacements from adds publicly; changing that rule is not a harmless UX improvement.

`POST /voting/selection` reuses the program's chain rule, answers selected by ancestry (not current
head equality), excluded with reason, or `selection_pending` while a lower index is missing. SDK
joins selection with availability; the CRISP client persists the input identity, marks voted only at
`counted`, and offers reproving before commitment cutoff. It polls until selection persists for 30
minutes after the first selected answer; changed answer/job resets that interval. Indexing is at
chain head, so reorgs can still change it. **Gaps:** no check while client is absent, no retry after
cutoff, lost/multi-instance server indexes can be incomplete, and governance apps do not run this
check. Committed is not counted.

Server cached inputs require a settled, unchanged `_e3:crisp_inputs:{id}` generation.
`modify_inputs` increments started before writing commitment/slot/parent/usability/hash/bytes and
finished afterward; every mutation uses it. Otherwise voters read stale heads and silently build
dropped inputs. `settle_input_generation` repairs counts only at startup before indexing. Failed
writes leave uncached reads until then. Selection costs one read-window unit and refusals do not log
caller identities.

## Tally bounds and census assumptions

TREE_DEPTH 20 gives 2^20 entries, but every operation consumes the round's smaller `inputLimit`, at
most 100,000 (`MAX_INPUTS_PER_ROUND`), on both publish and validation. Every input adds at most one
fresh ciphertext. Both presets set `SEARCH_Z` to 100,000, covering that maximum. Masks require no
voter signature, so anyone with valid proofs/attestations/transactions can fill the limit; no
implemented rate policy makes this impossible.

Every option total must remain below the round's plaintext modulus t (17,000,000 for both presets).
`CRISPProgram.validate` reads that modulus from the request's ABI-encoded `e3ProgramParams`, not a
local preset constant, before initializing the round's limits.

- CONSTANT: reject `credits >= t`; input limit is `min((t-1)/credits,100000)`. Zero credits use
  100,000.
- CUSTOM: freeze token snapshot and divisor ≥ `getPastTotalSupply(snapshot)/t + 1`; requested zero
  chooses the minimum, smaller values reject. Slot bound is past votes divided by that divisor.

CUSTOM assumes summed past votes ≤ past supply. ERC20Votes supplies that contract; the
[escrow-backed BondedVotes gap](voting-power.md#one-token-one-clock-no-duplicate-weight) does not.
The bound still holds only while duplicate-counted FOLD is no greater than nonvoting FOLD. ONCHAIN
mode reads bounds on chain; Merkle census also trusts coordinator leaf weights. Server must read
snapshot and divisor from the same block, in the token's clock units, not infer from metadata. Serve
zero snapshot until clock is known; convert CONSTANT snapshot for block-based discovery. Unreadable
votes/divisor defer discovery durably (`discovery_pending`), not registration; post no one-shot root
missing a voter. Retry discovery while votable; ONCHAIN voting continues meanwhile. Existing
coverage pins durable retry debt, not a live listener with a failing RPC provider.

An all-unusable set produces an empty, undecodable aggregate; it requires no honest input and
follows NoInputsReceived handling. Never silently drop an unfinalized committed input to make a
proof finish.

CRISP keeps a request record from E3Requested and activates only when commitment-validated key
record also exists. Either handler retries convergence; duplicates cannot reset round/output/root or
discard stored census on failed discovery. Ignore other programs' requests before CRISP-specific
calls; only decode tallies for stored rounds with configured program, else complete with empty
tally. Rebuild deadline callbacks after restart; release interrupted/synchronously failed compute
claim to Expired. HTTP submission is at-least-once and can repeat proof work; contract's one-shot
ciphertext gate and callback's terminal preflight prevent a second output.

## Existing guards and acceptance

[SecureProcess tests](../../crates/compute-provider/src/secure_process.rs) cover streamed/held
parity, changed second reads, complete input consumption;
[batching tests](../../crates/compute-provider/src/compute_input.rs) include
`batching_does_not_change_the_root`.
[Leaf vectors](https://github.com/theinterfold/CRISP/blob/main/program/tests/input_leaf.rs) and
[on-chain root agreement](https://github.com/theinterfold/CRISP/blob/main/program/tests/onchain_root_agreement.rs)
pin the cross-language root.
[CRISP contract tests](https://github.com/theinterfold/CRISP/tree/main/packages/crisp-contracts/tests)
include input-tree, ballot, and real OpenVM service boundaries.

Run `cargo test -p e3-compute-provider` here and the relevant tests in the CRISP repository.
Deployment additionally needs real rebuilt guest/worker commitments, checked Halo2 verifier, the
full local Playwright flow of CRISP, and a real Sepolia Avail/VectorX round; native tests are not
equivalent. Pinned Hardhat 3.0.11 / EDR 0.12.0-next.10 can expire subscriptions after five minutes
while WebSocket stays open: use Anvil for long live OpenVM tests. That local listener limit is not a
proof failure.
