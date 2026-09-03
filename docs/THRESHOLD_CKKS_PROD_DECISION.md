# Threshold CKKS on Interfold — state of the build and path to production

Date: 2026-09-02. Branches (local, uncommitted): `fhe.rs` `feat/ckks-encryption`,
`interfold` `feat/ckks-user-data-encryption`. Every number below is MEASURED
unless marked ⚠ extrapolated. Source data: `fhe.rs/crates/fhe/BENCHMARKS_TRCKKS.md`
(JSON in `/tmp/trckks-bench/`), live `ckks_timing` tables in `/tmp/hybrid-wiring/`,
e2e reports `/tmp/ckks-auction-e2e-report.json`.
Machine: Apple M3 Pro 11c / 36 GiB.

## 1. What exists and is verified live

| Layer | Status |
|---|---|
| fhe.rs `ckks` + `trckks` | Threshold CKKS (CRP DKG, Shamir sk + e_sm, flooding calculator, share projection), leveled relin keys, **hybrid key switching** (single-key + 2-round multiparty), wire formats, zeroize/redacted Debug. 187 lib tests, clippy clean. |
| Ciphernode integration | Program-bound scheme dispatch; DKG over BFV transport with deterministic wide-preset escalation; relin ceremony (chunked ≤8 MiB documents, keccak integrity, durable chunk log, mid-ceremony recovery); R1 deferred past pk consensus; `RelinCeremonyPlan` + `CkksProofPosture` derived from the param set (no env opt-ins); `ckks_timing` instrumentation. INVARIANTS §Threshold CKKS + flow-trace updated. |
| Proofs | C2a/C2b (DKG, scheme-agnostic), C6/C7-CKKS (canonical set), Greco ct0+ct1 per param set (0/2/3), **app validity legs** (auction bid ≤ Merkle balance + sender binding; salary range), C8 per-level (proven), C8-hybrid (proven at small shape). |
| Browser proving | `examples/ckks-common` WASM (fhe.rs compiles to wasm32 unmodified); Chrome: encrypt 0.2–2 s, ps3 legs 1.5 s, ps2 38-limb Greco legs ~13 s each. |
| Apps | `examples/ckks-salary-survey` (server relays; E2E PASS) and `examples/ckks-auction` (wallet-bound; E2E PASS through real Chrome on 5 nodes: over-balance rejected at proving in 105 ms, 4 bids × 3 Honk proofs verified on-chain ~12.7 M gas, duplicate replay reverts, winner correct, opened output only ±1). |

## 2. Cost model — demo shape (N=512), live 5 nodes

| phase | per-level keys (24) | **hybrid (1 key)** |
|---|---|---|
| DKG → pk share published | ~1.5 s | ~1.5 s |
| ceremony wall (R1 gen → keys written) | ~30 s (22 s R1 + 95 s R2 on slow DHT runs) | **1.8 s** |
| ceremony bytes / party | 60–100 MB | **2.8 MB** |
| sign-extraction eval (12 iters, 6 pairs) | 1.6 s | 1.6 s |
| threshold decrypt | <1 s | <1 s |

## 3. Cost model — 128-bit secure parameters

DKG (dealt shares travel as BFV plaintexts; `8·N·L` bytes per recipient per poly):

| shape | n | DKG CPU/party | dealt out/party | committee dealt |
|---|---|---|---|---|
| N=32768, L=20 (805-bit Q) | 5 | 2.9 s | 40 MiB | 200 MiB |
| N=32768, L=20 | 10 | 5.6 s | 90 MiB | 900 MiB |
| N=65536, 38-limb sign ladder (1525-bit Q) | 5 | 9.5 s | 152 MiB | 760 MiB |

Relin ceremony — the term that decides everything:

| shape | n | per-level up/down per party | **hybrid up/down per party** | CPU RNS → hybrid | relin err RNS → hybrid |
|---|---|---|---|---|---|
| N=32768 L20 | 5 | 1.77 / 7.07 GiB | **145 / 578 MiB** | 8.7 s → 0.4 s | 0.135 → 2.5e-4 |
| N=32768 L20 | 10 ⚠ | 1.77 / 15.9 GiB | 145 MiB / 1.3 GiB | — | — |
| N=65536 ladder | 5 | 14.4 / 57.6 GiB | **693 MiB / 2.7 GiB** | 82 s → 1.8 s | 0.103 → 4e-4 |

Depth-4 chain at secure N: per-level RNS keys give relative error 1–6 (garbage);
hybrid 5e-6. **Per-level keys are not merely slow at secure parameters, they are
incorrect; hybrid is required, not optional.**

Threshold decryption at secure N: share 3–12 MiB, combine 0.9–3.2 s (n=5), error
~2e-4 — fine. Ciphertexts: 6.3 MiB (N=32768) / 24 MiB (N=65536) fresh, shrinking
with level.

Per-user cost (client): encrypt + 3 proofs in the browser — survey ~6 s, auction
~45–60 s (38-limb Greco legs dominate); on-chain verification ~12.7 M gas per
submission (3 Honk verifies). This is independent of N (proof size is fixed);
what grows with N is the Greco circuit itself (not yet built at N=32768 — see §5).

## 4. Recommendation

1. **Shallow policies (statistics, aggregates, linear scoring, one square) at
   N=32768 / L≈20 are production-shaped now**: DKG < 6 s, hybrid ceremony
   < 1 s CPU and ~150 MiB up / ~0.6 GiB down per node at n=5 (a one-time
   per-committee cost, minutes on a 100 Mbit/s link), decrypt seconds.
2. **Winner-mode sign extraction at 128-bit needs N=65536** (1525-bit Q for
   12 iterations). With hybrid keys it is feasible as a one-time setup:
   ~0.7 GiB up / 2.7 GiB down per node at n=5 (⚠ ~6 GiB down at n=10). Reduce
   further with: seeded `a_j` (halves round-2 bytes), 6 iterations (4 %
   resolution, fits N=32768), only-needed levels are already implicit with
   hybrid.
3. Committee size: bandwidth is linear in n for download; n=5–10 is comfortable,
   n=20 is ~10–12 GiB down per node on the ladder — acceptable only as a
   one-time setup.
4. Bootstrapping / deep ML: out of reach without bootstrapping; do not plan on it.

## 5. Open items before a secure deployment (ordered)

1. **Security bound on Q·P**: the N=32768 hybrid row used 3×60-bit special
   primes (Q·P = 985 bits > 881 allowed). Use ≤2×38-bit specials or drop L to
   ~17; re-run that row. The N=65536 ladder at k=3 is 1705 < 1772 ✓ (Lattigo /
   OpenFHE extrapolation of the HE standard table — state as such).
2. **Greco + app circuits at secure N**: the client-side circuits are built for
   N=512 shapes. At N=32768 the ct0/ct1 legs are ~64× the polynomial size —
   expect proving minutes, not seconds, in the browser; needs measurement and
   likely a folding/recursive or server-assisted proving design (CRISP's fold
   circuits are the template).
3. **C8-hybrid at full shape** (ceremony share well-formedness): OOMs at
   `nargo compile` for 39+3 limbs. Needs per-digit sub-circuits bound by shared
   s/u commitments (same three-leg pattern as the app circuits). Until then the
   ceremony's posture is verify-by-determinism (documented in INVARIANTS).
   Also open: C8 emission/verification wiring in the nodes; fhe.rs
   `CkksHybridRelinKeyGenerator::{round_1_extended,u_poly}`.
4. **Proof postures on non-canonical param sets**: C0 over the wide transport
   and C6 for sets 2/3 are proof-free (no compiled circuits for those shapes).
   Compile per-set C0/C6 variants (mechanical, same codegen path as Greco ps2/ps3).
5. Findings explicitly deferred by the user during the review wave: C6-CKKS
   commitment anchoring to the DKG, pk-share rogue-key (C1-CKKS). Both are
   gaps in the "malicious committee member" model, not the "honest committee,
   malicious users" model the demos assume.
6. Relin ceremony transport: seeded `a_j` compression and rate-limited chunk
   publication for n>10.

## 6. How to run

```bash
# auction (browser-proven, wallet-bound bids; ~45-60 s proving per bid)
cd examples/ckks-auction && pnpm install && pnpm build:server && pnpm dev:up   # :5173
pnpm test:e2e            # headless Chrome, full assertion suite
# salary survey (server relays; ~6 s proving per submission)
cd examples/ckks-salary-survey && pnpm install && pnpm stage:circuits && cargo build --release && ./scripts/dev.sh   # :5174
# raw node-level winner run + timing table
cd tests/integration && CKKS_TOOLS_PROFILE=release INTERFOLD_BIN=$PWD/../../target/release/interfold ./ckks-auction-winner.sh
scripts/ckks-timing-report.sh tests/integration/.interfold/data/cn*/ciphernode.jsonl
# benchmarks (fhe.rs)
cargo run --release --example trckks_dkg_bench -- --preset secure32768-L20 --parties 5 --keyswitch hybrid --special-primes 2 --chain-compare
```
One stack at a time (shared anvil/ports). Wipe `tests/integration/.interfold/data/cn*/db` between runs.
