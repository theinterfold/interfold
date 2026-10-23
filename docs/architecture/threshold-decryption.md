# Threshold decryption

Owners: [keyshare](../../crates/keyshare/src/threshold_keyshare/),
[plaintext aggregation](../../crates/aggregator/src/plaintext_aggregation/),
[canonical key projection](../../crates/request/src/canonical_key.rs), and
[EVM canonical authority](../../crates/evm/src/canonical_key.rs). [DKG](dkg.md) defines the accepted
H-roster and zero-based committee identities.

## Authority before work

The decryption domain is Keccak of ABI-encoded
`(chainId, Interfold address, e3Id, committeeHash, ciphertextOutputHash, committeePublicKey)`. Every
secret-bearing C6 proof carries it; recursive folding requires one common domain. The final wrapper
compares its 128-bit limbs with the domain Interfold recomputes, compares the SAFE ciphertext
commitment saved at publication, and uses e3Id separately to resolve registry-backed DKG anchors.
Keccak of serialized ciphertext and the SAFE commitment are different bindings.

`CanonicalKeyProjection` derives authority only from confirmed chain observations:
`CommitteeProofPublished` retained as `EvmLogObserved`, the request's preset and committee, and the
configured Interfold deployment. It recovers the ordered committee, selected party IDs, key
commitment, and SK/ESM anchors. It updates before domain delivery and rebuilds from the full
retained log before hydration, including history before snapshot cursors. Chunk history supplies
commitment-checked bytes. Neither gossip nor registry/head-state RPC populates this authority; the
shared router performs no blocking key-authority reads or retry waits.

Keyshare admits `PublicKeyAggregated` only when its commitment and both rosters match this
projection and its decoded bytes reproduce the commitment. Keep the first matching key. Early peer
bytes are bounded candidates, not authority. Ciphertext may wait in `Decrypting` for first canonical
key admission; repeating an already-retained matching key is a no-op.

Before proof-intent deduplication, repair retained C6 public key, domain, preset, and committee size
from canonical authority. Before compute dispatch or response reuse, `ComputeEffectGate` checks
logged C6 requests against it. Missing authority defers admission; a mismatch must not reserve a
party slot or dedup key that blocks corrected work. Pre-v0.19 state is not repaired: that release
resets to schema 8.

## Shares and exact batches

`CalculateDecryptionShare` uses the saved summed SK and ESM with the canonical ciphertext. C6 proves
that calculation and binds the full d polynomial into Fiat-Shamir. Its signed proof accompanies each
`DecryptionshareCreated`, broadcast to all committee members. Admission checks:

- finalized sender/party ownership and accepted-roster membership;
- signature, full E3 identity, proof type, and every ciphertext position;
- each raw share's equality to its C6 commitment;
- the canonical C6 domain and matching ciphertext hash.

Reject unauthenticated input without occupying or excluding the claimed party. Keep the first
admitted bundle for each party. Persist accepted inputs on standbys as well as the active
aggregator.

Start verification at **T+1 distinct roster shares**, not H (Small: 10 rather than 14). Save
`VerifyingC6` before `AggregationInputsReady(Plaintext)`, which starts that phase's durable
10-minute failover budget. Shares arriving during verification become durable backups; they do not
mutate the in-flight batch. A failed proof or raw-share check can use backups and verify another
batch. Wait for replacements while T+1 eligible roster parties can still succeed; fail only when
that becomes impossible.

Local verification outcomes authorize their exact dispatch event ID, including the first result.
Equal verdicts for different batches have different delivery IDs. Standby/replayed outcomes persist
but only the active aggregator, or a demoted node that dispatched them, can apply them after effects
resume. A fresh chain-scoped `PlaintextVerificationResumed` gives recovered results a writable
sequence; never write under the earlier result sequence or chain-independent `EffectsEnabled`
context.

The active aggregator reconstructs from exactly T+1 verified shares. C7 witness construction refuses
any other share/party count. Sort runtime IDs and convert **once** to one-based Shamir coordinates
`party_id + 1`; zero, duplicate, unordered, and out-of-range coordinates fail. The wrapper subtracts
one to locate registry slots. C7 proves every plaintext coefficient, including claimed zeros.

C7 admission binds the exact selected C6 commitments, ordered party IDs, ciphertext index, and
plaintext. Deduplicate by request, not merely E3. Replacing a batch invalidates all old worker
correlations and regenerates matching proofs. Each final job folds its C6 leaves, checks C7, and
surfaces the common domain, selected coordinates, and DKG anchors. Missing proofs or a final
proof-count mismatch follows `DecryptionInvalidShares`, not a silent local trap.

## Failover and publication

Only the active party starts aggregation. A node demoted after starting C6 finishes and submits its
local result; after restart it can resume from `Computing`, `GeneratingC7Proof`, or `Complete`. A
demoted restart still in C6 verification does not resume that work; the promoted aggregator does.
First valid on-chain output wins. Local infrastructure failure retains the exact input and
correlation; it is not proof that a peer supplied invalid shares.

`PlaintextAggregated` is a **local durable publication intent**, never a gossip artifact or
canonical completion. The writer admits final domain limbs against confirmed key authority and
retained ciphertext hashes before deduplication. Missing authority retains one history sequence
range per E3, not payload queues. Read bounded pages only when that E3's authority arrives;
unrelated E3s do not rescan it. Reject mismatches and allow corrected intents. Confirmed terminal
stages retire pending work and reject later intents; local completion alone does not prove that the
result landed.

After `EffectsEnabled`, the writer checks chain state, coalesces the first admitted local intent,
and calls permissionless `publishPlaintextOutput`. The contract requires `CiphertextReady`,
inclusive decryption deadline, currently viable request-time committee, and mandatory final
verification. Complete then credits pull rewards and emits
`PlaintextOutputPublished`/`E3StageChanged(Complete)`. Temporary write failures retry; neither
failover demotion nor request cleanup may erase unfinished publication. Reward and settlement
details belong to [failure settlement](failure-settlement.md).

## Restart and redelivery limits

Hydration validates saved signed C6 shares and retained inputs in every phase, including `Complete`.
Invalid work clears verification outcomes and derived C7/final proofs, then rebuilds collection from
authenticated history with effects disabled. Corrected shares can use released slots. Valid C6 work
survives a stale C7; regenerate only C7/final proofs when its binding differs.

Restore deferred ciphertext and shares from the full retained log, not only the post-snapshot
suffix. A missing plaintext actor rebuilds authenticated collection before effects run. A saved
actor with no canonical authority remains dormant without replacing its snapshot or aborting
startup. Retain one history range and one current-boot effects signal; recover in pages of 1,024
events/16 MiB, allowing one larger event so the cursor advances. Global verifiers restore the
canonical party-slot map before replay, and the per-E3 consistency checker restores its cache and
roster.

Keyshare coalesces share calculation and C6 intent per process. Hydration clears dispatch markers;
repeated key/ciphertext observations do not create extra work. A late share response after leaving
`Decrypting` is ignored. Local retries use the same live request. A phase missing its result for
five minutes redelivers at most six times: a fresh calculation correlation or a fresh random C6
`redelivery` token. Proof completion carries that token so EventBus dedup permits redelivery.
Terminal events stop it at once. The compute gate answers all waiting correlations and only resends
a ten-minute-old missing outcome when no copy remains queued/running. Its buffers are not a durable
external-effect outbox.

Network share retransmission backs off from 60 seconds to 10 minutes, stops at failure/completion,
and lasts at most eight hours. Fresh transport delivery IDs preserve the embedded stable event ID.
Replay schedules local retransmissions in log order, only after replay finishes. Chain-terminal
memory is bounded to the last 1,024 E3s, so a round ended while offline can be reannounced until its
chain history arrives. See [network delivery](network-delivery.md) for loss and durability limits.

## Existing guards and limits

- [Workflow tests](../../crates/aggregator/src/plaintext_aggregation/workflow_tests.rs):
  `small_starts_verification_with_up_to_four_missing_roster_members` and
  `duplicate_shares_do_not_count_or_replace_an_in_flight_batch` pin T+1 admission and stable
  batches.
- [Hydration tests](../../crates/aggregator/src/ext.rs), including
  `plaintext_dependencies_use_chain_rosters_across_restart`, and
  [keyshare tests](../../crates/keyshare/src/threshold_keyshare/tests.rs), including
  `retained_c6_work_recovers_key_bytes_in_every_decryption_phase`, cover recovery admission.
- [Effect-gate tests](../../crates/multithread/src/effect_gate.rs), including
  `replayed_c6_compute_requires_canonical_public_inputs`, guard logged request release.
- [BfvDecryptionVerifier tests](../../packages/interfold-contracts/test/BfvDecryptionVerifier.spec.ts)
  own on-chain domain/anchor checks. Use `cargo test -p e3-aggregator`, `pnpm evm:test`, and
  `pnpm rust:test:proofs` for changed recursive statements; unit hydration is not a full crash test.

The [persistence gaps](persistence-and-replay.md) still apply. Do not infer exactly-once effects,
full replay/snapshot equivalence, or crash-safe snapshots from these focused guards.
