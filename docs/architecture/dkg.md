# Distributed key generation

DKG creates a collective BFV key without revealing its secret to one operator. The hot operator
signs protocol messages; delegated collateral ownership does not change that identity.

Owners: [keyshare](../../crates/orchestration/keyshare/src/),
[proof requests](../../crates/zk/prover/src/proof_request/),
[share verification](../../crates/zk/prover/src/share_verification/),
[public-key aggregation](../../crates/orchestration/aggregator/src/public_key_aggregation/), and the
[registry](../../packages/interfold-contracts/contracts/registry/).
[Proof statements](proof-statements.md) owns arithmetic and recursive trust;
[threshold decryption](threshold-decryption.md) owns C6/C7.

## Identities and dimensions

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
  multiplicities. Derive witness dimensions from the saved profile, not incidental vector lengths.

## Exchange and verification boundaries

Admitted SS recipient bundles contain one C2a and one C2b plus C3a/C3b per **threshold Shamir row**,
not per share-encryption/DKG CRT limb. Shape validation derives the row count from the request-time
profile's threshold parameters. Current TrBFV generates one smudging set (Z=1); extending C3b to
multiple sets needs coordinated producer, validator, NodeFold, wire, and circuit changes, not
inferred vector sizes.
[Shape tests](../../crates/zk/prover/src/share_verification/workflow_tests/shape.rs) pin that
distinction for both presets.

Both insecure-64 and secure-8192 use three threshold Shamir rows. Each recipient bundle therefore
contains one C2a, one C2b, three C3a, and three C3b proofs.

The disabled synchronized insecure-64 profile has a separate native SK-share packing rule. A
directed 32-byte PRF key uses 64 low little-endian bits; every higher bit is zero. For native
ascending coefficient j in threshold limb zero, the transport plaintext is
`share[0][j] + key_bit[j] * q_0`. Other limbs are unchanged. All original residues must be canonical
under their own threshold modulus. The synchronized DKG plaintext modulus is twice `q_0`, the
packing limb's modulus; these parameters are not interchangeable with the SS DKG pair. Unpacking
rejects out-of-range packed coefficients and restores SK residues before aggregation. Native round
trips exercise the existing encrypted SK-share transport, not a new key-bearing wire field or
signature. The isolated
[draft C0–C4 leaves](proof-statements.md#isolated-synchronized-dkg-leaves-draft-not-admitted) bind
packed-message openings and directed-key roots/bundles. Native generation, encrypted proof-request
preparation and keyshare planning now carry those keys without an SS smudging lane: synchronized
recipient bundles have one C2a and three C3a proofs; C4 has one SK proof. Keys stay in the existing
encrypted share plaintext, not a new public wire field. Admission remains disabled.

The draft setup context is
`keccak256(abi.encode(keccak256("interfold:sync-dkg-setup:v1"), uint256(chainId), interfold, fullE3Id, committeeHash, cryptoConfigId))`,
split into high/low 128-bit big-endian limbs without reduction. Selection supplies the complete
canonical committee and exact profile parameters/configuration ID; the node supplies its configured
chain deployment. This derivation and the synchronized dealer-identity domain
`interfold:sync-dkg-dealer:v1` are **unratified protocol interfaces**, not deployed contract
bindings.

Synchronized intake authenticates the complete dealer bundle before retention, then checks its C2
context/owner, exact recipient/CRT C3 message commitments and ciphertext commitments. Local planning
decrypts the actual transport plaintexts, opens every selected C2 message, and saves the
incoming/outgoing keys with the aggregate-SK and bidirectional-bundle anchors. Same-owner commitment
links connect C1→C2, C3→C2 and C4→owner-C2 under exact synchronized public layouts. C4 checks every
dealer row against the complete saved verified C2 batch: the SS C2→C4 check's cross-party blame and
partial-cache semantics are not reused. Missing provenance is a local failure, not an accusation.
The generic C3→C2 membership link is supplemented by exact recipient/CRT indexing at intake and in
the dealer join. Pre-slot rejection is not a verified dishonest-peer verdict. A rejected saved C4
input releases its slot and restarts collection with the valid retained inputs; a partial batch
cannot authorize an H verdict.

The disabled definitions now include separate dealer and per-recipient
[provenance joins](proof-statements.md#draft-synchronized-provenance-joins-not-admitted). They bind
all H contributions to each recipient's C0/C4 and expose the aggregate-SK/key-bundle commitments
without SS smudging proofs. Recipients outside H prove their own C2 root without requiring N C4
proofs or changing the accepted dealer roster.

This is not a complete admitted setup protocol. The explicit proof API verifies a supplied canonical
context/roster; it does not establish their chain/signature authority. The isolated
[C5/publication boundary](proof-statements.md#draft-synchronized-c5publication-boundary-not-admitted)
joins H recipient setups to the aggregate key and a common dealer-batch anchor, with native and
Solidity verification against independent expectations, including reopened runtime artifacts. The
separate [registry authority](proof-statements.md#synchronized-registry-authority-unactivated) now
requires every selected recipient's consent and stores distinct SK/key-bundle anchors. Its
request-time context event freezes the synchronized wrapper, not the SS attestation verifier. Native
ingestion joins confirmed request/context, full-authority and publication-proof observations in the
existing shared canonical-key projection, including retained history before snapshot cursors. The
authority is typed separately from SS anchors; it permits dormant DKG byte validation, not
decryption-domain repair or profile admission.

The keyshare consent helper requires an independently aggregated native PK, verified recipient setup
and recovered sealed material. Its read-only #2050 handoff joins the recipient's setup to confirmed
batch/threshold-key authority and checked PK bytes, reopens its sealed keys and checks their bundle.
An outside-H recipient uses its own verified setup for the same batch; it does not acquire an H
publication-consent slot. A setup DTO alone is not a proof verdict: callers must admit the local
worker source/correlation and cryptographic result before either helper.

This remains unactivated: guarded C5/consent/publication actor and writer phases, full-node
synchronized startup and synchronized C6 are absent. The capability replay fixture below does not
enable production admission. Synchronized runtime folding/publication and decryption paths still
refuse the SS implementations. The joins, root/bundle/batch schemas, attestation domain and setup
derivation require human protocol review before consumers freeze them.

Typed local dealer/recipient/publication work uses a separate synchronized executor, not SS fold
requests. Runtime admission rejects the disabled profile before touching proof artifacts; isolated
qualification calls the explicit definition API. The existing shared compute gate waits for
current-boot effects and retires this DKG work at confirmed key publication. Neither the gate nor a
setup response authenticates peer inputs or replaces actor-owned correlation and durable phases.

The node proof collector now has a distinct local dealer phase. It checks the request profile,
configured Interfold controller, finalized committee/local owner, local source and canonical
non-self C3 order, then collects C1–C3 without waiting for C4. The C1/C2 secret commitments must
agree before dispatch. C2 is provisional until each C3 binds its exact recipient/CRT message and the
key from the native fan-out. Up to one alternate per slot stays repairable until a complete batch
qualifies. Its exclusive flushed record fences work dispatch and local output publication. Startup
reads the retained journal, including the snapshotted prefix, for the native key anchors and
provisional alternates without changing the snapshot encoding. It rejects saved plans for chains
without a configured journal. Replay waits for current-boot effects, restart preserves qualified
proof bytes and replaces compute correlations, and confirmed key publication retires the phase.
Local generation errors retain the exact request rather than accusing peers.

Dealer and recipient joins have a separate signed peer envelope, not an extension of the on-chain
fault-attribution roles. Its `InterfoldSynchronizedDkgProof` EIP-712 domain (version `1`) binds the
chain and Interfold controller; the statement binds the full uint256 E3 ID, committee hash,
configuration, party, role and hashes of both proof and public-signal bytes. Dealer/recipient roles
map exclusively to their respective join circuits. Low-S and canonical 27/28 parity are required.
The exact encoding and wire cutover are described in [upgrades](upgrades.md).

The same node collector owns recipient collection. It authenticates dealer authorship against the
finalized committee before reserving a bounded slot. Early authenticated rows cannot choose a
roster: native keyshare's C4 intent supplies the fixed H roster, verified C2 provenance,
transport-key and SK/bundle anchors. Before that intent, the signed controller domain is provisional
too. Incompatible early rows are discarded when the native intent arrives. C0, own C2 and C4 must
come from local planned slots; all N recipients, including outside H, join exactly those H dealers.
Retained peer rows are authenticated candidates; `NodesFold` recursively verifies their proofs, and
the executor verifies the join. Proof bytes or genealogy can repair a candidate without changing its
fixed statement. During a join, each dealer slot holds one alternate at most. Only a matching
reported failure can promote a compatible repair and retire its correlation, within a per-boot
budget per dealer. Neither new bytes nor local worker retries invalidate a running join. A join
failure is not a localized peer-invalid verdict. PK/batch expectations are derived from those dealer
rows; this collector does not independently compare native PK shares. Its exclusive record flushes
before work or output, preserves completed output, replaces restart correlations, and retires at
canonical DKG termination. A peer setup is never a local recipient verdict. Only the correlated
local worker result produces the local setup event and signed peer setup. Downstream
consent/publication producers still need to consume these outputs. Admission stays disabled;
below-admission actor tests and real-proof qualification do not admit production effects.

Recipient storage and bus delivery back off independently. Storage retry validates the latest
retained record without dispatching unflushed work. Refused delivery retries from acknowledged
progress without another write. Confirmed retirement cancels both timers.

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
canonical; late C1 results then change nothing. A local C1 result authorizes only the keyshares of
its exact dispatch event ID, never those of a replacement roster; equal verdicts for different
rosters have different delivery IDs. A result arriving before recovered keyshares is held until they
rebuild its request. A local result replayed before `EffectsEnabled` is held the same way and
restores the record that this node started C1, also when replay demotes it.

Verify C1 for all H dealers, aggregate their public shares, prove C5, and combine exactly H
NodeFolds. A mixed Some/None NodeFold set is a local test-configuration mismatch: retain inputs, do
not accuse dealers. Local compute errors retain the pending input/correlation for recovery. A local
C5 proof replayed before `EffectsEnabled` is applied when the C5 phase resumes, if its public inputs
are the commitments of the current honest keyshares: the prover would re-sign the replayed proof
identically, and the bus drops that duplicate. A resumed phase applies a held C1 or C5 result under
a fresh chain-scoped `AggregationResumed`. Each roster member sends its NodeFold once, so hydration
reads received folds back from the event log: folds received before C5 are held only in memory, and
the snapshot can miss folds moved into C5.

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

The proven commitment is authority; shared
[chunk mechanics](../../crates/data-availability/README.md) only validate transport. Request-time
members, including retained expelled members, can publish canonical 90 KiB chunks of a candidate up
to 512 KiB while `KeyPublished`. Each consumer admits at most the first candidate per publisher and
groups chunks by E3, publisher, and candidate hash. Require a complete sequence, Keccak candidate
hash, valid BFV decode with request-time parameters, and recomputed C5 commitment equality before
producing runtime `CommitteePublished` or storing a client key. An invalid candidate cannot consume
another member's candidate. Terminal stages reject chunks and cannot recreate cleaned-up assemblies.
`KeyPublished` alone does not mean clients have usable key bytes.

**Accepted processing cost (ZEN2-17):** publication accepts dynamic proof/data without wrapper-level
caps. Canonical chunk shape/512 KiB candidate limits bound retained assembly, not total emitted
logs: members may repeat valid chunks while KeyPublished because contracts do not track emitted
indices. Senders pay gas; observers pay processing. Verification failure still reverts atomically.
The transport caps do not establish a bound on every publication's observer cost.

The local writer coalesces publication intents until effects resume and uses chain preflight reads.
An equal commitment published by another aggregator completes that step; a different one is an
error. Restart resends unfinished chunks, then confirmed assembly clears the saved intent. Retry
temporary failures after 30 seconds, not permanent payload/contract errors or RPC request-size
rejection. Peer `PublicKeyAggregated` copies distribute state but cannot create local transaction
intents.

## Recovery and evidence

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

The saved randomized threshold-share work plan also retains encrypted own-share rows. A restart
reuses its exact ciphertexts, witnesses and local rows instead of rerunning BFV fan-out.
Synchronized recovery seals directed keys with profile, setup binding and owner inside authenticated
local encryption; H-ordered incoming keys and N-ordered outgoing keys open the saved bundle and
owner's C2 root. It retains compact C2 public statements after the large transport payloads retire.
Context/key/roster substitutions and conflicting successful native responses fail closed. Early C4
records are provisional until the complete C2 batch is available; recheck and discard invalid ones
before collector admission so they cannot reserve a recovered slot against a valid replacement.
These records still use the existing snapshot/payload write boundaries, not a new durable-flush
guarantee.

The private
[disk recovery fixture](../../crates/orchestration/keyshare/src/tests/synchronized/recovery.rs)
stops, flushes and physically reopens three independent stores and keyshare actors with fresh
password-derived ciphers. It checks exact reissued work and saved artifacts, H `[0,2]` including an
outside-H recipient, provisional C4 retirement and authenticated replacement after restart. Its
explicit real-proof variant proves C4 from the restored request, then joins reopened signed
contributions, sealed material and native PK-share bytes through C5/publication verification in Rust
and Solidity. Selected C4 artifacts come from peers' reopened snapshots; the outside-H recipient
uses its disk-restored C4 request and the verified publication's key/batch authority. Native H
signatures then publish the real proof to a locally deployed registry. The fixture checks authority
and PK-chunk readback, reopens the decoded confirmed journal and validates all N sealed setup
handoffs. Its finalized selection and lifecycle controller remain test harnesses.

The complementary
[replay fixture](../../crates/orchestration/keyshare/src/tests/synchronized/recovery/replay.rs)
reopens a commit-log suffix through `EventSystem` and production startup sync into one manually
hydrated keyshare actor. It checks authenticated replacement/deduplication, decreasing-HLC aggregate
sequence, stale boot-control filtering, no pre-enable effects and persisted inputs after an
acknowledged snapshot drain/reopen. Historical EVM/network adapters return empty history. These are
capability-level, orderly recovery checks below disabled production hydration/compute admission, not
whole-node startup, network delivery, hard-crash durability or guarded production publication. See
the [test commands](../../crates/orchestration/keyshare/README.md#tests).

Dealer identity binds public statement (E3, proof type, circuit, signals), not randomized proof
bytes. Replacing a proof plan invalidates all old correlations first. C2/C3 verification outcomes
authorize only their exact dispatch batch, including the first result; growth needs a new verdict.
Save dispatch IDs and bound held early results (64). Even an empty post-precheck batch produces a
saved outcome; later authenticated shares may grow it. Retired batches cannot reopen.

C0 recovery scans the full durable event log for unresolved authenticated inputs and local outcomes,
not just snapshot suffixes. Continue across filtered-empty/byte-limited pages using physical head
and one-record reads for skipped positions; only router-quarantined legacy records explain a gap.
Wrong aggregates, ordering, or other gaps fail startup. Restore party/profile/committee context
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

The checker owns the `CommitmentLink` interface in `e3-slashing`; `e3-zk-prover` supplies concrete
public-signal extraction/comparison. `ProofType` and signed proof payloads stay in events. Static
circuit identity and layout selection belong to `e3-zk-config`, not to the transport pipeline.

Representative guards (not a complete protocol proof):

- [Keyshare tests](../../crates/orchestration/keyshare/src/tests.rs):
  `a_first_c2_c3_result_applies_only_to_the_batch_of_its_dispatch`,
  `a_verdict_of_an_earlier_batch_does_not_complete_a_grown_batch`,
  `canonical_publication_supersedes_collector_failures`, and
  `a_restart_keeps_the_roster_that_its_c4_started_from` cover actor admission/recovery boundaries.
- [Roster helpers](../../crates/orchestration/keyshare/src/effects/coordinate_roster.rs) test
  outsider completeness and Ready growth. Recursive Noir tests in
  [circuits](../../circuits/bin/recursive_aggregation/) cover non-prefix links and party ordering.
- [DKG publication tests](../../packages/interfold-contracts/test/Registry/DkgPublicationBinding.spec.ts)
  and
  [fold attestation tests](../../packages/interfold-contracts/test/Registry/DkgFoldAttestationVerifier.spec.ts)
  own the contract boundary, not process crash recovery.
- Run `cargo test -p e3-keyshare`, `pnpm evm:test`, and for changed proof statements
  `pnpm rust:test:proofs` plus `pnpm noir:test` with the affected artifacts. Secure-only branches
  need secure witnesses; default insecure proof tests do not establish their completeness.
