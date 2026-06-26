# DKG Crash Recovery — Live Reproduction Findings

Status: 2 of 3 issues fixed and verified live; 1 open (design needed).
Companion to [`DKG_RESTART_SAFETY.md`](./DKG_RESTART_SAFETY.md), which covers the actor-level
restart-safety work (correlation IDs, checker rehydration, resync). This note records what a
**live, on-chain reproduction** surfaced when a committee node is `kill -9`'d mid-DKG and restarted.

## Test methodology

Local CRISP stack: `anvil` + 5 ciphernodes (`cn1`–`cn5`, `cn1` is the bootstrap — never kill it).
`examples/CRISP/target/debug/cli init` requests an E3; `check-e3-ready --e3id N` returns `true`
iff on-chain `E3Stage == KeyPublished`. The committee (N=3, H=2) is selected per E3; party 0 is the
aggregator that publishes the committee key on-chain.

Repro: request an E3, wait for a target committee member to enter C3
(`STARTING MULTITHREAD zk_share_encryption`), `kill -9` it, immediately restart it, then poll
`check-e3-ready` and grep logs for accusations / stall points.

Success criteria: on-chain `KeyPublished == true`, **0** `CommitmentConsistencyViolation`, **0**
`proposeSlash`.

Two scenarios matter and behave differently:
- **Aggregator (party 0) killed** — the killed node is the collector; peers wait for it.
- **Non-aggregator (party 1/2) killed** — peers actively verify the killed node's shares and the
  aggregator must collect its late contributions.

---

## Issue 1 — Gossip mesh fails to re-form after restart  ✅ FIXED

### Symptom
Restarted node reconnects at the TCP/QUIC level but every gossip publish fails with
`InsufficientPeers`; peers never receive its `KeyshareCreated` / fold markers / resync requests;
the E3 stalls. The restarted node *receives* inbound gossip fine — only outbound fails.

### Root cause
gossipsub exchanges topic subscriptions **only on the first connection to a peer**
(`other_established == 0`; rust-libp2p `gossipsub::Behaviour::on_connection_established`, and the
`publish()` recipient set is gated on *known* subscriptions even with `flood_publish` + explicit
peers). When a node restarts with the **same PeerId** while the surviving peers still hold the
**stale connection** to its dead process, the rejoin is *not* a first connection, so peers never
re-send their subscriptions. The rejoining node therefore believes no peer is subscribed to the
topic and `publish()` returns `InsufficientPeers`.

Confirmed with gossipsub debug logging: the survivors never logged a fresh `Peer disconnected` /
`Peer connected` for the restarted node, and the rejoining node's `peer_topics` for the topic stayed
empty.

### Approaches that did NOT work (recorded so we don't retry them)
- **`idle_connection_timeout`** bump — stopped the *connection* churn (0 disconnects) but not the
  subscription problem; a longer timeout actually *prolongs* the stale connection that blocks the
  re-handshake.
- **`add_explicit_peer`** for connected peers — explicit peers are still gated on known subscription
  state, so publish still failed.
- **`unsubscribe()` + `subscribe()` re-advertise toggle** on the survivor — gossipsub delivers the
  resulting `UNSUBSCRIBE`/`SUBSCRIBE` **out of order** (verified: receiver logged `Subscribe` then
  `Unsubscribe`), so the `Unsubscribe` lands last and *wipes* the subscription. Fundamentally racy.

### Fix (`crates/net/src/net_interface.rs`)
On `ConnectionEstablished`, track connection ids per peer. When a **second** connection to an
already-connected peer appears (the signature of a same-PeerId rejoin over a stale connection),
`disconnect_peer_id()` the peer entirely and trigger a Kademlia bootstrap so it redials. The redial
is then a genuine **clean first connection** → gossipsub does its normal, correct, single
subscription exchange. Guarded by a 15s per-peer cooldown so two healthy nodes that dial each other
simultaneously can't ping-pong disconnects. Also: QUIC `max_idle_timeout = 15s` + `keep_alive = 5s`
(evict dead peers promptly), gossipsub `heartbeat_interval` 10s → 1s (faster mesh heal), modest
swarm `idle_connection_timeout`.

### Verified
Aggregator (party 0) killed mid-C3 → restarted → on-chain `KeyPublished == true`, all nodes
complete, 0 accusations. Debug logs show `force re-handshake` + `received subscriptions` + 0
`InsufficientPeers`.

---

## Issue 2 — Equivocation / false-slash when a non-aggregator regenerates its secret  ✅ FIXED

### Symptom
Non-aggregator killed mid-C3, restarts cleanly (gossip fix above works for it too), but the
aggregator raises `CommitmentConsistencyViolation` on the restarted node's `C3aSkShareEncryption`,
reaches accusation quorum, and issues `proposeSlash` (which reverts on-chain with a custom error
because the node is actually fine). The E3 stalls; the node is marked dishonest but came back —
split-brain.

### Root cause
`crates/keyshare/src/actors/threshold_keyshare.rs` resume path (`resume_in_flight_work`,
`KeyshareState::GeneratingThresholdShare` arm): when the node crashed mid-generation with an
**incomplete** `source`, it re-issues `GenPkShareAndSkSss` **from scratch**. That regenerates the
BFV threshold **secret with fresh randomness** (`multithread.rs` →
`trbfv::gen_pk_share_and_sk_sss` → `SecretKey::random(rng)`), producing a different C0→C3 chain than
the one peers already recorded. The code comment claimed "safe to re-issue from scratch... before
anything was broadcast" — false: by mid-C3 the node has already broadcast commitments derived from
its *original* secret.

The earlier deterministic-encryption work (`derive_share_encryption_seed`) only made the **C3
encryption randomness** deterministic; the **secret itself** (and the ESM Shamir sharing in
`gen_esi_sss`) were still freshly sampled on re-issue. Aggregator restart didn't hit this because
its shares weren't being verified by others at that point.

### Fix (deterministic secret generation — RFC-6979 style, mirrors the existing C3 seed)
- `crates/keyshare/src/domain/share_generation.rs`: add `derive_secret_gen_seed(e3_id_bytes,
  sk_bfv_raw)` — SHA-256 over a domain tag + e3_id + the node's persisted BFV secret key.
- `crates/trbfv/src/gen_pk_share_and_sk_sss.rs` and `gen_esi_sss.rs`: add `secret_seed: [u8;32]`
  (`#[serde(default)]`) to the request; drive all secret sampling from `ChaCha20Rng::from_seed`.
  All-zero seed ⇒ fall back to the entropic RNG (back-compat / non-resumable callers).
- `threshold_keyshare.rs`: derive the seed from the persisted, stable, private `sk_bfv`
  (+ e3_id; domain-separated `esi-sss:` tag for the ESM stream) and pass it into both requests.

Because `sk_bfv` is generated once (encryption-key phase), carried forward, and persisted, the seed
is identical across restart ⇒ re-issuing reproduces a **byte-identical** secret/shares ⇒ identical
C0→C3 ⇒ no equivocation.

### Security note — REQUIRES CRYPTO-OWNER REVIEW
The threshold secret is now a deterministic function of `sk_bfv` (one-way SHA-256 seed). No entropy
reduction: `sk_bfv` is full-entropy and already persisted encrypted at rest, and the derivation is
one-way. Same trust model as the accepted `derive_share_encryption_seed`. Cross-node threshold
security is unaffected (both secrets already live on the same node). Flagged in code doc-comments.

### Verified
Non-aggregator (party 2) killed mid-C3 → restarted → `CommitmentConsistencyViolation: 0`,
`proposeSlash: 0`, `accusations: 0` (previously 2 violations + slash attempts).

---

## Issue 3 — Aggregator stalls waiting for a keyshare that never arrives  ✅ FIX 2 resolves the common case; FIX 3 backstop added

> **Update after implementing Fix 2.** The "honest-set race" framing below was largely a
> *consequence* of the equivocation/slash (Issue 2). Once Fix 2 stops the false slash, the rejoined
> node's keyshare delivers and the E3 completes normally — verified across multiple clean
> fresh-deploy runs (non-aggregator killed mid-C3 + restarted → on-chain `KeyPublished`, **0
> accusations**, ~25s). The slash + accusation churn was disrupting the mesh and the honest-set
> bookkeeping; remove it and the restart path works.
>
> The genuine residual issue is narrower: the `PublicKeyAggregator` waits for **all N** keyshares
> (`add_keyshare`, `unique_parties >= n`) with **no timeout** — the `project_aggregator_no_timeout`
> class. If a committee member is capped out of the honest roster (or genuinely offline) its keyshare
> never comes and the aggregator waits forever.
>
> **Fix 3 (added):** a keyshare-collection timeout on the `PublicKeyAggregator` (mirrors the
> `ThresholdPlaintextAggregator` decryption-share timeout). On expiry, if at least `threshold_m + 1`
> keyshares were collected (a viable honest set), it force-transitions `Collecting → VerifyingC1`
> with the collected majority (`PublicKeyAggregation::force_verifying_c1`); C1 + canonical
> lowest-`H` capping then selects the deterministic honest roster. Default 300s, env override
> `E3_KEYSHARE_COLLECTION_TIMEOUT_SECS`. Files: `aggregator/src/actors/publickey_aggregator.rs`,
> `aggregator/src/domain/publickey_aggregation.rs`.
>
> **Status of Fix 3:** implemented, builds, and the mechanism is verified to fire and to correctly
> *bail* when too few keyshares are present. It is **correct-by-construction** but I could not
> deterministically force the exact trigger where it *drives* completion: with Fix 2 the keyshare now
> delivers (completes normally), and a permanently-offline member is **expelled** (which lowers the
> live `N` so the aggregator no longer waits for it). So Fix 3 is a defensive backstop for the
> residual flaky-delivery / not-yet-expelled window.
>
> **⚠️ Tuning risk:** the timeout value affects *correctness*, not just liveness — too short and a
> slow-but-honest node whose keyshare is still being proved gets excluded from the committee key.
> Keyshares were observed arriving ~38s after the aggregator starts collecting (proof-bound);
> the 300s default leaves wide margin, but prod must size it above worst-case proof latency.

### Original (pre–Fix-2) analysis — kept for reference

### Symptom
With Issues 1 & 2 fixed, a non-aggregator killed mid-C3 no longer gets slashed — but the E3 **still
doesn't reach `KeyPublished`**. All nodes sit at `CommitteeFinalized`; the cross-node fold never
emits `PublicKeyAggregated`.

### Evidence (e3 #0, cn3/party 2 killed)
- The aggregator received cn3's threshold share **late** (after restart) and **included** it in
  C2/C3 verification (`Dispatching C2/C3 share verification ... (2 parties)`).
- But the later phase ran with **`Dispatching C4 share verification ... (1 parties)`** and
  `KeyshareCreated` was collected only from `{party 0, party 1}` — party 2 was **dropped** from C4 /
  keyshare / fold.
- Some aggregator events show `honest_parties: {}`. The DKG fold buffers early markers from parties
  0/1/2 but never completes → no `PublicKeyAggregated`.

### Root cause (hypothesis)
The DKG decides the **honest set per collection phase**. A node absent during one window and back for
the next gets **inconsistent membership across phases** (in C2/C3 but out of C4/keyshare/fold). The
phases then disagree on the roster and the fold can't converge. This is independent of the resume
path and of equivocation — it's the honest-set *lifecycle* under churn.

### Fix direction (not yet implemented)
Make honest-set membership **consistent across all DKG phases** (C2/C3 → C4 → keyshare → fold).
Two candidate designs:
- **(a) Commit the honest set once** at a defined cutoff and apply it uniformly downstream. A node
  that missed the window is simply excluded for *this* E3 (fine for H < N); it must also learn it's
  excluded and stop publishing conflicting artifacts. Simpler, safer.
- **(b) Cleanly re-admit a returning node across all phases** (re-run its C4/keyshare collection).
  More complete but more moving parts and more churn-sensitive.

Open questions: the threshold-share collection cutoff timing vs realistic restart latency; how the
returning node is told its membership decision; interaction with the slashing timeout window.

---

## Summary

| # | Issue | Status | Key files |
|---|-------|--------|-----------|
| 1 | Gossip mesh won't re-form after same-PeerId restart | ✅ fixed, verified | `net/src/net_interface.rs` |
| 2 | Secret regenerated on resume ⇒ equivocation ⇒ false slash | ✅ fixed, verified | `trbfv/src/gen_pk_share_and_sk_sss.rs`, `gen_esi_sss.rs`, `keyshare/src/domain/share_generation.rs`, `keyshare/src/actors/threshold_keyshare.rs` |
| 3 | Aggregator waits for all N keyshares with no timeout (stalls if one never arrives) | ✅ Fix 2 resolves common case; Fix 3 backstop added | `aggregator/src/actors/publickey_aggregator.rs`, `aggregator/src/domain/publickey_aggregation.rs` |

All three fixes are independent and worth landing. Aggregator-restart and non-aggregator-restart now
both complete end-to-end on a fresh deploy (`KeyPublished`, 0 accusations). Fix 3 is a defensive
keyshare-collection timeout for the `project_aggregator_no_timeout` class; correct-by-construction
but its drive-completion path is rarely hit now (Fix 2 makes the keyshare deliver; offline members
get expelled). **Two review items before landing:** (a) crypto-owner review of Fix 2's deterministic
secret; (b) prod sizing of `E3_KEYSHARE_COLLECTION_TIMEOUT_SECS` above worst-case proof latency.
