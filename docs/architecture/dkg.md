# Distributed key generation

DKG creates a collective BFV key without revealing its secret to one operator. The hot operator
signs protocol messages; delegated collateral ownership does not change that identity.

Owners: [keyshare](../../crates/keyshare/src/threshold_keyshare/),
[proof requests](../../crates/zk/prover/src/proof_request/),
[share verification](../../crates/zk/prover/src/share_verification/),
[public-key aggregation](../../crates/aggregator/src/public_key_aggregation/), and the
[registry](../../packages/interfold-contracts/contracts/registry/).
[Proof statements](proof-statements.md) owns arithmetic and recursive trust;
[threshold decryption](threshold-decryption.md) owns C6/C7.

## Identities and dimensions

There are two proof paths. `insecure-64` (parameter set 0) and `secure-8192` use trBFV; `secure-16384`,
`secure-16384-simd` (parameter set 6), `secure-16384-simd-d6` (parameter set 7), `insecure-simd`
(parameter set 5), and the insecure l-BFV parameter set 4 (`insecure`) use l-BFV.
`insecure-64` and `insecure` have different degrees, and their protocol paths are not
interchangeable. The C1/C5 and singleton C2 descriptions below describe trBFV unless stated otherwise.

- Normalize the finalized committee by ascending parsed EVM address. Runtime, DKG circuit, and
  fold-attestation party IDs are zero-based. Address casing never changes membership or exclusion.
  Only the decryption boundary converts to one-based Shamir coordinates.
- `N` is the complete committee, `H` the selected dealer roster, and `T+1` the reconstruction count.
  Every supported committee has `H < N`. DKG aggregation requires exactly H NodeFold proofs with
  unique, ascending, in-range party IDs and exactly N ordered committee addresses, including
  excluded members. Never reconstruct the complete committee from the reduced keyshare set.
- N-wide C3 recipient-key and C2 share slots use the recipient's full-committee party ID. H-wide C4
  sender slots use the sender's position in the selected fold rows. A non-prefix H-roster makes
  these indices different.
- C2a/C2b are singleton proof bundles for each recipient; C3a/C3b use the configured Shamir
  multiplicities. Derive witness dimensions from the active preset, not incidental vector lengths.

## Exchange and verification boundaries

Recipient bundles contain one C2a and one C2b plus C3a/C3b per **threshold Shamir row**, not per
share-encryption/DKG CRT limb. Shape validation normalizes a DKG preset to its threshold counterpart
before reading row count. Current TrBFV generates one smudging set (Z=1); extending C3b to multiple
sets needs coordinated producer, validator, NodeFold, wire, and circuit changes, not inferred vector
sizes. [Shape tests](../../crates/zk/prover/src/share_verification/workflow_tests/shape.rs) pin that
distinction for both presets.

The trBFV presets `insecure-64` and `secure-8192` use three threshold Shamir rows. The l-BFV path
uses chunked C2/C3 proofs; `secure-16384` and `secure-16384-simd` have five threshold rows.
`secure-16384-simd-d6` has eight threshold rows. Do not infer one path's proof
shape from the other.

The l-BFV C2 chunk size is `c2_chunk_size(degree, n_parties)` in `e3-zk-config`. At degree 16384 it is
8192 coefficients for up to 4 parties and 2048 above. Other degrees use the smaller of 512 and the
degree. A batch holds up to four chunks. The generated `dkg.nr` of `secure-16384`, `secure-16384-simd` and `secure-16384-simd-d6` writes the chunk
size as an expression over the active committee's `N_PARTIES`, so the compiled circuits follow the
same rule. The other presets write fixed values. A non-default `--chunk-size` gives artifacts that
are valid only after the C2/C3/C4 circuits are recompiled against the generated configuration.

| Boundary                                             | Requirement and reason                                                                                                                                                                                                                                                             |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CiphernodeSelected` → initialization                | Read `getDeadlines` and the request-frozen timeout configuration at `CommitteeFinalized`. Retry unavailable RPC; do not substitute a local window. Record the encrypted BFV keypair with flushed `DurableIntent` before using or publishing it.                                    |
| `EncryptionKeyPending` → C0 → `EncryptionKeyCreated` | Sign the proof. Publish own `DKGInnerProofReady` sequence 0 before the created key, so leaving key collection cannot lose C0. C0 intake checks canonical party ownership, signature, key commitment, and request-specific artifacts before verification.                           |
| Key collection → TrBFV generation                    | Keep the first authenticated key per party. Seed rebuilt collectors with expulsions before inputs. Require at least H remaining keys, including this node's key. Early keys in `Init` are recorded and replayed into the collector after timing is known.                          |
| `ThresholdSharePending` → `ThresholdShareCreated`    | Finish and sign C1, C2a, C2b, and every C3a/C3b before any share is published. Each recipient gets its encrypted shares and complete proof bundle. C4–C7 are later phases.                                                                                                         |
| Threshold-share intake                               | Authenticate the complete message before saving it or reserving the claimed dealer's slot. Check E3, dealer, recipient, share bytes, and ordered proof bundle. Rejection leaves the slot free and cannot accuse the claimed dealer.                                                |
| Share verification → signed Ready                    | Validate proof signatures, E3, circuit names, and party ownership; check cross-proof commitments; then run ZK verification. Save verified dealer IDs and exact contribution hashes. Fewer than H locally verified dealers waits outside C4 rather than immediately failing the E3. |
| Accepted roster → C4                                 | Use the saved canonical H-roster, never the lowest H local cache entries. C4 proves decrypted SK/ESM shares match C2 commitments and produces the summed decryption anchors.                                                                                                       |
| `DecryptionKeyShared` → `KeyshareCreated`            | Authenticate the complete C4 message, collect the selected peers, verify C4, and only then authorize keyshare publication.                                                                                                                                                         |

The N-slot C3 fan-out proves every non-own slot. A recipient without a collected C0 key gets a
placeholder encrypted under the sender's C0 key, but receives no share. The sender's own slot is
empty; its plaintext share enters C4 locally. A recipient outside the H-roster needs all H selected
encrypted dealer shares; it cannot replace one with its own plaintext. A selected recipient uses its
plaintext only at its own row.

Whole-message signatures are type-separated. Threshold shares bind the E3 hash (including chain),
dealer, recipient, share hash, and complete bundle hash. C4 binds E3, dealer, node-address hash, and
ordered bundle hash. Hashes cover positional bincode, optional fields, signals, signatures, and
proof order; transport `external` is excluded. Individual proof signatures remain fault evidence. An
unrecoverable or mismatched signer cannot name the claimed dealer in an accusation.

## Timing and collection

The encryption-key hard cutoff is 10% of the frozen DKG window. The threshold-share 75% checkpoint
is **soft**: at H−1 external shares verification can start, but collection remains open; below H−1
it keeps waiting. The checkpoint can occur earlier when every missing dealer had no C0 key when key
collection closed. Such a dealer received no share from this node, so no mutually ready roster can
contain both. Recorded keys count as present, and rebuilt collectors receive the same keyless dealer
set. Only completion or the canonical on-chain DKG deadline ends that collection. C4 collection has
the canonical deadline. Overrides may advance a cutoff, never extend it. Restart uses absolute
remaining time, not a new window.

A restart after the key cutoff but before the DKG deadline applies the cutoff to recorded keys
without a new timer. Peer history sync does not carry missing key documents: reannouncement after
effects resume may be too late, including a key whose C0 check was still pending at cutoff.
Authenticated late inputs can be recorded without entering an expired collector. Local cutoffs omit
missing nodes; they are not evidence that those peers failed to publish.

Collector failures must match the E3 and current phase. Threshold-share failure cannot replace
`ReadyForDecryption`; C4 failure applies there only before verification or publication
authorization. Canonical `CommitteePublished` or `E3StageChanged(KeyPublished)` and later successful
stages supersede all DKG collector failures. A local `PublicKeyAggregated` intent is not canonical
publication. Hydration restores the canonical publication flag before actors start; earlier stages
cannot clear it.

A fatal timeout records immutable `KeyshareState::Failed` stage/reason and redrives the same
`E3Failed` after `EffectsEnabled`. **Gap:** this snapshot write is enqueued, not durably
acknowledged, before publication. The intended commit-before-dispatch property is not established.

## One H-roster, with bounded failover

The active aggregator is the lowest eligible runtime party ID after expulsions, proof-fault
exclusions, and the current phase's unresponsive set. It selects H mutually ready dealers whose
signed Ready reports identify the same contributions. This reuses sortition's aggregator; there is
no second election.

Receivers retain one authenticated roster per proposer and accept only a proposer no later than
their current active party ID. The proposer must have a matching Ready report, local Ready must
contain the roster, and held selected-dealer reports must support it. Expelled proposers or dealers
cannot supply a new accepted roster. Ready growth keeps every unexpelled earlier dealer and adds a
live dealer. An update missing a held dealer can wait for an expulsion that explains it; retain at
most one such update per committee member for each reporter. Reconsider held updates and rosters
after expulsions and restart. A later roster from the same proposer can replace an unsupported held
roster.

Before C4 starts, a lower-ID roster can replace an accepted higher-ID roster; an expelled selected
dealer is no longer honest. Sending decryption-key calculation fixes the roster. Promotion reuses
the accepted list rather than choosing from local arrival order. **Gap:** after restart the store
can reject the write fixing C4's roster as stale. Memory retains it and a later write saves it, but
a second restart before that write can allow a lower-ranked replacement. The existing restart test
does not prove crash durability of that write.

Deriving a valid roster, or receiving a supported roster not yet derivable from all local peer
reports, starts the durable 10-minute roster budget. Acceptance ends that phase and clears its
skips. C5 has a separate readiness-gated 40-minute budget because it also waits for the H node-fold
proofs. Unchanged ready assignment preserves its absolute deadline; promotion gets a new budget.
Re-arm or fire overdue only after effects resume.

This is not Byzantine agreement. An aggregator can choose any qualifying mutually ready H-set or
withhold until failover. On-chain proof verification and single publication prevent two accepted
keys. There is no replacement/rebuild after a selected dealer permanently stops following roster
acceptance; the E3 can fail with other nodes still online. Before canonical key publication,
selected-dealer expulsion/exclusion fails the fixed H-row DKG. After it, every public-key
aggregator, including an incomplete standby, ignores raw DKG removals. Chain failures and T+1
decryption viability still apply.

## C5 and key publication

Every committee member buffers authenticated keyshares and the accepted roster in its persisted
actor state. Once all H keyshares exist, save `VerifyingC1` before
`AggregationInputsReady(PublicKey)`. Only the active aggregator starts effects. A demoted aggregator
that started C1 finishes and publishes, including after restart, but stops when the key is
canonical; late C1 results then change nothing. A result arriving before recovered keyshares is held
once, tied to that roster, never a replacement.

Verify C1 for all H dealers, aggregate their public shares, prove C5, and combine exactly H
NodeFolds. A mixed Some/None NodeFold set is a local test-configuration mismatch: retain inputs, do
not accuse dealers. Local compute errors retain the pending input/correlation for recovery.

`publishCommittee` is permissionless. It requires a viable committee, an unset commitment, mandatory
DKG proof verification, and fold attestations. The request freezes the registry and fold verifier in
`DkgFoldAttestationContextEstablished`. Signers and consumers bind both through EIP-712, including
the frozen verifier as verifying contract. Rotation cannot silently change the attestation domain.
The callback must meet both the inclusive DKG deadline and input-window end; late key publication
cannot turn a committee timeout into requester-paid compute failure.

The on-chain fold verifier requires strictly increasing proof party IDs, binding party IDs, and
attestation party IDs. Each attestation must match its binding and the finalized address-sorted
committee slot. Runtime sorting alone does not replace these contract checks.

Committee hash is Keccak over ordered raw **20-byte** addresses, not padded
`abi.encodePacked(address[])`. Solidity's `CommitteeHashLib`, Rust's `committee-hash`, and Noir must
agree. The wrapper checks its 128-bit limbs; other contextual PK-verifier arguments are not
additional circuit bindings merely because the interface accepts them.

The proven commitment is authority; serialized bytes are transport. Request-time members, including
retained expelled members, can publish canonical 90 KiB chunks of a candidate up to 24 MiB while
`KeyPublished`. Each consumer admits at most the first candidate per publisher and groups chunks by
E3, publisher, and candidate hash. Require a complete sequence, Keccak candidate hash, valid BFV
decode with request-time parameters, and recomputed C5 commitment equality before producing runtime
`CommitteePublished` or storing a client key. An invalid candidate cannot consume another member's
candidate. Terminal stages reject chunks and cannot recreate cleaned-up assemblies. `KeyPublished`
alone does not mean clients have usable key bytes.

**Accepted processing cost (ZEN2-17):** publication accepts dynamic proof/data without wrapper-level
caps. Canonical chunk shape/24 MiB candidate limits bound retained assembly, not total emitted logs:
members may repeat valid chunks while KeyPublished because contracts do not track emitted indices.
Senders pay gas; observers pay processing. Verification failure still reverts atomically. The
transport caps do not establish a bound on every publication's observer cost.

The local writer coalesces publication intents until effects resume and uses chain preflight reads.
An equal commitment published by another aggregator completes that step; a different one is an
error. Restart resends unfinished chunks, then confirmed assembly clears the saved intent. Retry
temporary failures after 30 seconds, not permanent payload/contract errors or RPC request-size
rejection. Peer `PublicKeyAggregated` copies distribute state but cannot create local transaction
intents.

## Recovery and evidence

### l-BFV generation, collection, and publication

The l-BFV path has **no C1 and no C5**. PK and RLK generation row proofs bind the same secret as the
C2a secret root; C2b chunk leaves enforce the lifted smudging bound themselves. For secure-16384 and
secure-16384-simd, generation supplies five ordered PK rows and five ordered RLK rows. For
secure-16384-simd-d6, it supplies eight of each. Aggregation uses the same exact
H ascending parties for PK, RLK D0, and RLK D2, with expected commitments equal to their verified
generation records. Row identity includes family and row; RLK aggregation uses
`component * rows + row`, not only `ProofType`.

Signed manifests bind the E3/session, party, document role, and SHA-256 of each exact contribution
document. Generic document notifications do not initiate a fetch. Versioned requests also bind
attempt number; unavailable and invalid responses are distinct. Persist document bytes before
marking their collection slot durable. Persist the exact-H ready candidate set before verification,
match results to its stable ID, and durably invalidate a failed candidate before selecting another.
Seal the accepted commitments before row aggregation advances. Late noncandidate failures do not
create dishonest-party evidence. Recovery redrives the saved dispatch or sealed set, not a new
arrival-order quorum.

`lbfv_generation_fold` and `lbfv_aggregation_fold` cover the ordered rows. `node_fold_v2` binds the
generation secret to the chunked node's C2a root; `nodes_fold_v2` contains exactly H parties.
`dkg_aggregator_v2` binds independent legacy and V2 VK manifests, the session, accepted set,
committee, and operational key-envelope commitment. The final public-input length is
`39 + 3*H + 3*rows` (60 for secure-16384/minimum and secure-16384-simd/minimum, 69 for
secure-16384-simd-d6/minimum), not the trBFV C5 layout. Aggregator ID is
statement metadata; publication remains permissionless.

Persist both operational keys reconstructed from accepted contribution documents before final V2
proof dispatch. `LbfvPublicKeyAggregated` is a local publication intent, not canonical authority.
The registry writer retains the existing publication gate and attestation bundle. The published
`IFLBFVKE` version-3 envelope carries canonical `LBFVRelinearizationKey` bytes; consumers
reconstruct the level-zero `LBFVPublicKey`, validate fixed CRS/URS material, convert all rows to
reversed, centered circuit CRT form, and recompute the combined PK/D0/D2 commitment. Only equality
with the on-chain `pkCommitment` authorizes encryption or exposing the RLK. A decoded public-key
prefix alone is insufficient.

`secure-16384-simd-d6` (parameter set 7) has the degree, the committees, and the V2 layout of
`secure-16384-simd`. It supports multiplicative depth 6, so it has eight threshold CRT moduli and
eight l-BFV rows. Its version-3 `IFLBFVKE` envelope has 21,381,552 bytes (20.39 MiB). The envelope
is an 18-byte header and the aggregate relinearization key of 21,381,534 bytes. This size is above
the former 16 MiB limit. A separate protocol change raises the cap to 24 MiB for this reason. The
committee public key cap is 24 MiB.

The smudging noise bound of `secure-16384-simd-d6` is 2^382 or more. This value is above the BN254
field. The C2b leaf `esm_share_computation_chunk` therefore proves the bound in two limbs for this
preset. The generated `default/mod.nr` sets `E_SM_WIDE` and the constants `E_SM_WIDE_*`. The witness
gives the low limb, a high limb, and one quotient for each CRT modulus. The high limb is the last
entry of `e_sm_quotients_chunk`, so the circuit input layout does not change. Each term of the
relation stays below 2^251. The narrow presets keep the single-limb check, and their compiled
circuits are byte-identical to the circuits before this change.

Owners include
[l-BFV collection](../../crates/aggregator/src/public_key_aggregation/lbfv_contribution_collection.rs),
[V2 aggregation](../../crates/zk/prover/src/circuits/aggregation/v2.rs), and
[the V2 wrapper](../../packages/interfold-contracts/contracts/verifiers/bfv/BfvPkVerifierV2.sol).
These are protocol requirements, not a claim that mock lifecycle tests verify real row proofs.

During replay, `ThresholdKeyshare` records keys, threshold shares, and C4 shares without starting
collectors or their timers. Both hydrated actors and actors created during replay inherit the
router's `E3Context::effects_enabled`. At `EffectsEnabled`, `resume_in_flight_work` rebuilds
collectors from recorded inputs before work continues.

Randomized successful TrBFV responses are protocol contributions: reuse their exact bytes. Hold
early replayed `GenPkShareAndSkSss`/`GenEsiSss` until prerequisites return; identical replay is
idempotent, conflicting responses fail closed. Failed attempts can retry only before durable
success. A lost BFV secret cannot be repaired by generating and advertising a second key; recovery
abstains when history reveals the earlier key. A pre-existing key already published before that
history arrives remains a risk.

Dealer identity binds public statement (E3, proof type, circuit, signals), not randomized proof
bytes. Replacing a proof plan invalidates all old correlations first. C2/C3 verification outcomes
authorize only their exact dispatch batch, including the first result; growth needs a new verdict.
Save dispatch IDs and bound held early results (64). Even an empty post-precheck batch produces a
saved outcome; later authenticated shares may grow it. Retired batches cannot reopen.

C0 recovery scans the full durable event log for unresolved authenticated inputs and local outcomes,
not just snapshot suffixes. Continue across filtered-empty/byte-limited pages using physical head
and one-record reads for skipped positions; only router-quarantined legacy records explain a gap.
Wrong aggregates, ordering, or other gaps fail startup. Restore party/preset/committee context
before replay; past-DKG lifecycle rejects old/new C0 work even if document dedup suppresses another
fetch. Dispatch only after EffectsEnabled. Local verification errors retry from five seconds to a
60-second cap; request completion cancels them. This recovery is not a durable-general-outbox claim.

Restore C4 collectors from the saved roster and first authenticated peer messages before resuming
proof jobs; completed collection ignores duplicates. Node-fold aggregation records each ordered
inner proof before admitting it to its buffers and records the completed fold before publishing it.
An enqueue failure cannot authorize admission or publication. Metadata and completed output recover
with those inputs; C4 waits for the sequence layout from `ThresholdSharePending`. `KeyPublished` and
terminal events retire that data. Large immutable recovery payloads have separate keys with
length/Keccak references; verify before hydration, retire references before payloads. Inactive
node-fold entries are tombstoned before removing their index entry.

The commitment checker restores its complete verified-proof cache and H-roster before proof
recovery. It checks C1→C2, C2→C3, selected-roster C2→C4, and C1→C5; C0→C3 local-cache absence is not
fault evidence, so each recipient checks its own key. C2→C4 waits for all selected targets and maps
full party IDs to H-row positions. C4→C6 and C6→C7 continue this chain. Save changed checker state
with the triggering event's context, in the same snapshot batch as that event. These ordering rules
do not make snapshot enqueue a durable-flush acknowledgment. **Gap:** failed checker snapshot writes
are logged and retried on the next mutation while processing and publication continue. See
[persistence](persistence-and-replay.md) for the wider snapshot limit.

Representative guards (not a complete protocol proof):

- [Keyshare tests](../../crates/keyshare/src/threshold_keyshare/tests.rs):
  `a_first_c2_c3_result_applies_only_to_the_batch_of_its_dispatch`,
  `a_verdict_of_an_earlier_batch_does_not_complete_a_grown_batch`,
  `canonical_publication_supersedes_collector_failures`, and
  `a_restart_keeps_the_roster_that_its_c4_started_from` cover actor admission/recovery boundaries.
- [Roster helpers](../../crates/keyshare/src/threshold_keyshare/effects/coordinate_roster.rs) test
  outsider completeness and Ready growth. Recursive Noir tests in
  [circuits](../../circuits/bin/recursive_aggregation/) cover non-prefix links and party ordering.
- [DKG publication tests](../../packages/interfold-contracts/test/Registry/DkgPublicationBinding.spec.ts)
  and
  [fold attestation tests](../../packages/interfold-contracts/test/Registry/DkgFoldAttestationVerifier.spec.ts)
  own the contract boundary, not process crash recovery.
- Run `cargo test -p e3-keyshare`, `pnpm evm:test`, and for changed proof statements
  `pnpm rust:test:proofs` plus `pnpm noir:test` with the affected artifacts. Secure-only branches
  need secure witnesses; default insecure proof tests do not establish their completeness.
