# Threshold CKKS on Interfold — handover

**Status:** feature-complete demo stack, uncommitted, on two local branches.
**Read this first; the four companion documents carry the detail.**

| document | what it holds |
|---|---|
| `docs/THRESHOLD_CKKS_DKG_REVIEW_HANDOUT.md` | for cryptographers: the protocol, what is reused from BFV, five numbered claims to confirm/refute |
| `docs/THRESHOLD_CKKS_PROD_DECISION.md` | measured cost tables at demo and 128-bit parameters, prod recommendation |
| `docs/THRESHOLD_CKKS_PROVEN_PIPELINE_AT_SECURE_N.md` | proof-circuit scaling curve, two-track plan (big boxes vs folding), C8 round-2 spec |
| `fhe.rs/crates/fhe/BENCHMARKS_TRCKKS.md` | raw benchmark methodology + every measured row, incl. §6 secure sets |

Branches (LOCAL, nothing committed): `fhe.rs` → `feat/ckks-encryption`;
`interfold` → `feat/ckks-user-data-encryption` (~119 dirty files, all wanted).

---

## 1. What was built

### 1.1 fhe.rs — threshold CKKS
- **`ckks/`**: parameters, encoder (slot + coefficient encoding), keys, ciphertext ops
  (add, mul, plaintext-mul, rescale, mod-switch), relinearization keys, wire formats.
- **`trckks/`**: multiparty DKG from a common random polynomial (eprint 2020/304 Protocol 1),
  Shamir layer over each RNS prime (eprint 2024/1285), two-round relinearization-key
  ceremony (Protocol 2), threshold decryption with smudging, and the noise-bound calculator.
- **Hybrid key switching** (`ckks/hybrid.rs`, `trckks/hybrid_gen.rs`) — special primes `P` +
  digit decomposition, so ONE relin key serves every level. Technique originates with
  Gentry–Halevi–Smart; the RNS form we follow is Han–Ki (eprint 2019/688, which generalises the
  full-RNS CKKS variant to cut the number of temporary key-switching moduli) as implemented in
  Lattigo/Bossuat et al. This is the single most consequential change in the whole effort (§4).
- **Secure parameter sets** (`ckks/secure_presets.rs`) with the HE-Standard budget asserted in tests.
- **App-feasibility matrix** (`trckks/app_feasibility.rs`) — the flooding bound per app × committee size.
- 199 lib tests, fmt + clippy clean.

### 1.2 Interfold — protocol integration
- CKKS runtime alongside BFV, program-bound scheme dispatch.
- DKG over the BFV transport, with deterministic escalation to a wide preset when a CKKS
  modulus exceeds the standard transport plaintext modulus.
- Relin ceremony in the ciphernodes: chunked (≤8 MiB documents), keccak integrity, durable
  chunk log, mid-ceremony recovery, deferred until after public-key consensus.
- Proof postures resolved per param set from artifact availability, **fail closed**.
- Committee-side proofs: C1-CKKS (pk share), C6-CKKS (decryption share), C7-CKKS (aggregation),
  C8-CKKS (relin round 1, per digit), each generated per param set.
- On-chain verification of the committee key and the decrypted output by real Honk verifiers (§5).

### 1.3 Six full-stack demo apps (CRISP-shaped: actix+sled server, program crate, Vite React client)

| app | port | what the network computes | depth | committee work |
|---|---|---|---|---|
| **auction** (`examples/ckks-auction`) | 5173 / 8090 | iterated sign extraction → sealed-bid winner, only ±1 signs revealed | 37 | DKG + hybrid ceremony + decrypt |
| **salary survey** (`examples/ckks-salary-survey`) | 5174 / 8091 | sum + sum-of-squares → mean, variance, std-dev | 1 | DKG + 1-level ceremony + decrypt |
| **credit scoring** (`examples/ckks-credit-scoring`) | 5175 / 8092 | σ(⟨w,x⟩+b) on the encrypted logit, per-user masked | 2 | DKG + 2-level ceremony + decrypt |
| **private matching** (`examples/ckks-matching`) | 5176 / 8093 | ⟨a,b⟩ of two parties' private vectors (coefficient encoding, masked cross terms); only the score opens | 1 | DKG + level-0 ceremony + decrypt |
| **treasury risk** (`examples/ckks-treasury-risk`) | 5177 / 8094 | Σ_a w_a·(Σ_i x_{i,a})² over n DAOs' private books — aggregate FIRST, then one ct×ct; one scalar opens (7 proof legs per DAO) | 1 | DKG + level-0 ceremony + decrypt |
| **federated averaging** (`examples/ckks-federated-averaging`) | 5178 / 8095 | Σ_i n_i·g_i with PRIVATE sample counts n_i (ct×ct per client); the weighted mean opens | 1 | DKG + level-0 ceremony + decrypt |

The last three share **ParamSet 5** (three 36-bit limbs, Δ=2⁴⁰, opens at level 1) and a
**coefficient-encoded** output (`OutputLayout::Coefficients`, first 64 coefficients at 4
decimals): inner products of two encrypted vectors need rotations in slot encoding (Galois keys the
committee has no ceremony for), whereas `forward(a)·reversed(b)` puts `−⟨a,b⟩` on coefficient 0
with one ct×ct under the level-0 key. Cross terms are hidden by an additive uniform mask
ciphertext (demo hiding ratio 2¹⁰). Design record and per-app pitfalls:
`docs/PS5_APPS_SHARED_DECISIONS.md`.

All six: **client-side encryption in the browser** (fhe.rs compiled to WASM, unmodified),
**client-side proving** (Greco ct0/ct1 + an app-specific validity circuit), wallet-bound
submission verified on-chain, server never sees plaintext.

---

## 2. Theory — why this works (for cryptographers)

The full argument, with file:line pointers and five numbered claims to confirm or refute, is in
`docs/THRESHOLD_CKKS_DKG_REVIEW_HANDOUT.md`. In brief:

**The DKG is scheme-generic and reused from BFV unchanged.** Steps: sample `s_i` (CBD, σ²=0.5 —
literally the same sampler as BFV), Shamir-share it coefficient-wise mod each RNS prime, deal the
shares encrypted under a BFV transport key (proven well-formed by the existing C2a/C2b circuits),
aggregate. The joint public key is non-interactive from a CRP: `pk = (Σ_i(−a·s_i + e_i), a)`.
IND-CPA security rests on RLWE over `(N, Q, χ)`; CKKS's approximate *encoding* plays no role
there — which is precisely why IND-CPA is **not** the right target for CKKS, and why the
opening below needs flooding (§ "Where CKKS genuinely differs"). This is Protocol 1 of
Mouchet et al. (eprint 2020/304); the paper states it for a generic RLWE scheme and
instantiates a multiparty **BFV**, the CKKS instantiation being Lattigo's, not the paper's.

**Level projection is exact.** A share at level ℓ is the level-0 share with the rows of dropped
primes removed — shares are independent per-prime sharings, so this is a subset operation, never
a division.

**Where CKKS genuinely differs: the opening.** Threshold decryption yields
`c0 + c1·s + e_sm = Δ·m + e_ct + e_sm`, which *is* the plaintext — no BFV-style rounding. The
security notion in play is therefore **IND-CPA-D** (Li–Micciancio, Eurocrypt'21): decrypting an
approximate ciphertext hands the adversary `e_ct`, which is key material, so every opened share
must be flooded. Smudging noise consequently lands **in the result**, and BFV's single decode
wall at `Q/(2t)` is replaced by *two* correctness walls, on top of the *same* security floor
both schemes share:
- security floor `B_sm ≥ 2^λ·B_C` — the standard smudging lemma (Asharov–Jain–López-Alt–
  Tromer–Vaikuntanathan–Wichs, Eurocrypt'12, via AJW'11 Lemma 2.1); a statistical-distance
  argument, not a DP one. Li–Micciancio Eurocrypt'21 is the attack that makes it mandatory;
  Li–Micciancio–Schultz–Sorrell Crypto'22 gives the tight DP/Gaussian-mechanism alternative
  with near-matching upper *and lower* bounds ("Noah's Ark", eprint 2023/815, is the same
  statistical route we take; OpenFHE implements this rule).
- no wrap-around mod `Q_ℓ`, and a precision ceiling — both CKKS-specific.

The dealt smudging share is **single-use per ciphertext**, enforced in the node by pinning the
served ciphertext hash (`threshold_keyshare_ckks/machine.rs:1535`; reuse would subtract to
`c1·s`-dependent material).

**The relinearization ceremony** is Protocol 2 of the same paper, run over the *same* `s_i` — no
new secret material is dealt. The hybrid variant runs it over `Q·P` with the digit gadget; RLWE
must then be assessed at modulus `Q·P`, not `Q`.

**The one gating open question (claim C-5 in the handout).** Our flooding calculator uses a
worst-case sup-norm noise model where `B_C` grows ×N per multiplication level. At N=32768 that is
~15 bits/level, and with λ=50 **no app closes all three walls at any 128-bit parameter set** —
depth-1 statistics alone demands 101 smudging bits; the credit app's depth-2 shape demands 112.
Every measured row runs at the demo's 20 bits. Production libraries (OpenFHE, Lattigo) bound noise
in the canonical embedding (average-case, ≈√N per level) and the literature permits Rényi λ/2.
**Nothing is "secure" until a cryptographer signs off on the noise model.** Three candidate
relaxations are written out in the handout.

⚠️ **Caveat that narrows those relaxations.** LMSS Crypto'22 §"dynamic noise estimates" proves
that flooding noise tailored to *a given ciphertext's* error, rather than to worst-case error, is
**vulnerable to IND-CPA-D attacks** — they show the intuitive claim that smaller noise suffices
for schemes with accurate per-ciphertext noise estimates is false. That does not by itself kill an
average-case/canonical-embedding `B_C` (which is still a *static*, circuit-derived bound, and is
what OpenFHE/Lattigo ship), but it does mean the relaxation must stay a function of the circuit
only, never of the observed ciphertext — and it is the strongest argument in the literature
against relaxing this bound casually. Put this in front of the cryptographers with C-5.

---

## 3. Performance — CKKS vs BFV, and what it costs

### 3.1 Same ring, same sizes
At identical `(N, L)` the key and ciphertext sizes are identical: sk ~N small coefficients,
pk and fresh ct `2·N·L·8` bytes. There is no CKKS "overhead" at rest.

### 3.2 Where they diverge

| | BFV | CKKS |
|---|---|---|
| arithmetic | exact integers mod t | approximate reals, fixed-point via Δ |
| multiplication | needs relin; steep noise growth | needs relin; **rescale** manages noise, ~2–4× cheaper per mult (literature) |
| ciphertext over a computation | constant size | **shrinks** with each rescale (39 limbs ≈160 KB → 2 limbs ≈8 KB) |
| depth budget | plaintext-modulus bound | one ~40-bit prime per multiplication ⇒ depth picks N |
| division / mean / variance | painful | native |
| threshold flooding | under the decode wall, invisible | lands in the result (§2) |
| our stack | never multiplied ⇒ no ceremony was ever built | ceremony is the dominant setup cost |

**Honest note:** the *linear* credit variant (v1) needed no ct×ct at all — BFV could have served it
equally well. CKKS earns its place the moment the network must compute something nonlinear without
opening intermediates.

### 3.3 The hybrid key-switching win (measured)

| | per-level RNS keys | **one hybrid key** |
|---|---|---|
| demo ladder, ceremony bytes/party | 115 MiB | **5.4 MiB** (÷21) |
| N=32768 L20, up/down per party | 1.77 / 7.07 GiB | **145 / 578 MiB** (÷12) |
| N=65536 ladder, up/down per party | 14.4 / 57.6 GiB | **693 MiB / 2.7 GiB** (÷21) |
| N=65536 ceremony CPU/party | 80 s | **1.8 s** |
| depth-4 chain error at secure N | **1–6 (garbage)** | 5e-6 |
| live 5-node ceremony wall time | ~122 s | **1.8 s** |

That last error row is the point: per-level keys are not merely slower at secure parameters, they
are **incorrect**. Hybrid is a correctness requirement, not an optimisation.

### 3.4 Secure-parameter cost (16 measured rows, Apple M3 Pro)

Sets: **S1** = N=32768, 60+17×40-bit, k=2 → log₂(Q·P)=860 ≤ 881, depth 17.
**S2** = N=65536, 60+37×40-bit, k=3 → 1720 ≤ 1772, depth 37.
(6-iteration comparisons do NOT fit S1 at 128-bit — 940 > 881; five do.)

Full chain (DKG → ceremony → app eval → threshold decrypt), wall time:

| set | app | n=3 | n=5 | n=10 | n=20 |
|---|---|---|---|---|---|
| S1 | stats / poly4 / cmp5 | ~40 s | ~72 s | ~205 s | 313 s (stats) |
| S2 | stats / poly4 / cmp6 | ~55 s | — | — | — |
| S2 | cmp12 (the auction shape) | 64 s | 101 s | 241 s | — |

Reference row (S1, stats, n=3): DKG 1.15 s/party, 18 MiB dealt; ceremony 0.31 s CPU,
121 MiB up / 242 MiB down; user ct 5.8 MiB; eval 0.50 s; decrypt share 2.7 MiB, combine 0.32 s;
relative error 4.4e-5.

**Reading:** compute is a non-issue everywhere. Bandwidth is a one-time per-committee setup cost and
is now modest. Wall time grows ~linearly in n (the O(n²) dealing showing through). **Shallow apps at
N=32768 are production-shaped today**; the 12-iteration auction needs N=65536 and is the premium tier.

### 3.5 Client and chain cost per user

| app | browser encrypt + prove | on-chain gas |
|---|---|---|
| credit (5 legs, ps4) | ~5 s | ~5 M |
| survey (3 legs, ps3) | ~6 s | ~3 M |
| auction (3 legs, ps2, 38 limbs) | ~40–60 s | ~12.7 M |

Committee-key verification adds 9.1 M gas once per E3 (n=3, one C1 proof per party); the decrypted
output adds 2.9 M once.

---

## 4. What is verified, and what is trusted

**Verified on-chain, real Honk proofs:**
- every application: Greco ct0 + ct1 (the ciphertext is a well-formed encryption of the committed
  message) + an app-specific validity leg (bid ≤ attested balance / salary in range / features
  Merkle-attested and logit correctly formed), bound to `msg.sender`, deduplicated by `u_commitment`;
- the committee public key: one C1-CKKS proof per party;
- the decrypted output: one C7-CKKS aggregation proof.

**Verified peer-to-peer between ciphernodes:** C1 before public-key aggregation (rogue-key
protection), C6 anchored to the DKG commitments through the commitment-link registry, C8 per-digit
proofs gating each party's relin contribution.

**Trusted — the honest list:**
1. **Program correctness.** No RISC0 proof that the E3 program computed the policy it claims
   (`MockCiphertextVerifier` remains registered, by explicit decision). A malicious program could
   publish a different output ciphertext.
2. **The decode step.** The C7 proof binds `u_global` — the reconstructed ring element — but NOT the
   published plaintext bytes. Recovering the published values requires centering mod a ~144-bit Q,
   dividing by Δ, and an inverse FFT over ℂ for slot-encoded sets: none of it EVM-tractable. A
   malicious aggregator could prove a correct reconstruction and publish unrelated bytes.
   *Fix:* a circuit exposing `keccak256(encode_fixed_point_output(decode(u_global)))` as a public
   input. Notably far cheaper for coefficient-encoded outputs (no FFT).
3. **Aggregate key ≠ proven sum of shares on-chain.** The circuit commits with Poseidon over limb
   coefficients, the chain with keccak over serialised bytes — not inter-recomputable in the EVM.
   Enforced off-chain by the aggregator; closing it needs a C5-CKKS circuit.
4. **The flooding bound** (§2, claim C-5) — the gating item.

**Closed by the 2026-09-05 audit (were open when this document was first written):**
- ~~C7 CRT glue was vacuous~~ — `crt_quotients` was an unconstrained witness, so the field identity
  accepted ANY `u_global` (confirmed empirically: honest 42, claimed 1 000 000, accepted). Now
  range-constrained in `verify_crt_reconstruction_ckks` (`u_global < Q`, `r_l < Q/q_l`) so
  `u_global` is the unique canonical lift; Noir regression tests prove the forged and
  non-canonical lifts are rejected. **The BFV C7 shares this bug and is deliberately NOT fixed
  here** — see `docs/BFV_C7_CRT_SOUNDNESS_FINDING.md` (claim C-6).
- ~~C6→C7 link structurally broken~~ — C6-CKKS hashed all N=512 coefficients into `d_commitment`,
  C7-CKKS hashed the BFV sparse window of 100; the two could never match. C7 now binds the full
  ring (`DECRYPTED_SHARES_AGGREGATION_CKKS_N`), with a zk-helpers test asserting C6's commitment
  equals C7's `expected_d_commitments`.
- ~~No domain binding on C7~~ — C7-CKKS now exposes `domain_hi/lo` (the same E3 decryption
  domain C6-CKKS binds) and `CkksDecryptionVerifier` checks them against Interfold's on-chain
  derivation; a spec proves the proof is rejected under any other E3's domain.
- ~~C6 fail-open~~ — under a PROVEN posture, proof-less shares were aggregated unverified and the
  node degraded to publishing them whenever it had missed the gossiped `PublicKeyAggregated`.
  Both arms now `bail!`; the decryption domain is also set from the chain-observed
  `CommitteePublished`, which every node sees.
- ~~e_sm pin published-before-persisted~~ — the machine snapshot is now written BEFORE command
  dispatch, so a crash between publishing a decryption share and persisting `Decrypting
  { served_ct_hash }` can no longer lead to the same smudging share flooding a second ciphertext.
- ~~Flooding bound omitted relinearization noise~~ — `circuit_noise_bound` now charges the
  key-switch term per level (RNS-key or hybrid, chosen from the params), and rejects a
  non-finite `mult_operand_bound` instead of casting NaN to 0 and shrinking the bound.

---

## 5. What is missing, and how to close it

Ordered by what I would do first.

1. **Flooding-bound sign-off** (blocks any "secure" claim). Needs a cryptographer's answer on the
   noise model, then a calculator change: average-case/canonical-embedding `B_C`, optionally Rényi
   λ/2, optionally opening at doubled scale. No new machinery, ~days of work after the decision.
2. **Decode binding** (item 2 above). An in-circuit decode for the coefficient-encoded case
   (moderate). Slot-encoded decode needs an in-circuit inverse FFT — expensive; consider moving
   apps to coefficient-encoded outputs instead.
3. **C5-CKKS** (aggregate-key binding, item 3). One circuit, mirrors the BFV C5.
4. **BFV C7 soundness** (`docs/BFV_C7_CRT_SOUNDNESS_FINDING.md`) — its own change, its own VK
   regeneration, cryptographer sign-off first.
5. **Proofs at secure N.** All committee circuits are instantiated at N=512 shapes. The measured
   scaling is exactly linear in N·L (C1 78·N, C6 100·N, C8-digit 164·N constraints; `bb prove`
   ~10–17 s and ~5.5 GiB per million constraints), so S1 extrapolates to C6 ≈20 M constraints,
   ~5.6 min, ~108 GiB — feasible on a 256 GiB box (**Track A**, ~1.5 h per party per E3). S2 needs
   350–660 GiB per leaf ⇒ **Track B**, the limb-row kernel split. The compile step, not proving, is
   the wall: `nargo compile` RAM grows ×1.7–2.9 per doubling. Full plan and effort estimate
   (~30–35 eng-days to "fully proven at S1") in the pipeline doc.
6. **C8 round 2 has no circuit anywhere.** Specified in the pipeline doc (per Q·P limb:
   `h0' = h0_agg·s + e0'`, `h1' = h1_agg·(u−s) + e1'`, bound to the round-1 and C1 commitments,
   ~31 constraints per coeff-limb). Until it exists, ceremony round 2 is verify-by-determinism.
7. **Client proving at secure N is unmeasured.** Greco circuits are N=512-shaped; at N=32768 they
   are ~64× larger. Expect minutes in-browser; likely needs folding/IVC or server-assisted proving
   with a privacy story. **This determines the product shape more than anything else left** —
   measure it before committing to a launch.
8. **RISC0 program-correctness** (item 1) — deliberately deferred; re-scope when wanted.

---

## 6. What we can build next (and why it fits)

Depth is the currency: each multiplication costs one ~40-bit prime, and when the limbs no longer fit
the security budget you must double N (which doubles every artifact). Depth is paid at setup, not per
reveal — a deep policy still opens a small ciphertext.

| tier | apps | depth | N @128-bit | status |
|---|---|---|---|---|
| **1 — ready** | statistics, filtered aggregates, histograms/quantiles, correlations, OLS regression, DP-noised releases | 0–1 | 16384–32768 | pattern proven by the survey app |
| **2 — ready** | linear/logistic scoring, credit risk, similarity/recommendation, kNN | 1–3 | 16384–32768 | proven by the credit app; per-user masked opening included |
| **3 — feasible** | small MLPs / tabular nets with polynomial activations, LeNet-scale CNNs | 6–10 | 32768 (S1) | needs models retrained with poly activations |
| 4 — no | transformers, deep CNNs, anything needing bootstrapping | — | — | say no honestly |

**Cheaper auction designs** (the current 12-iteration ladder is the expensive way to compare):
- *masked max* — multiply differences by a committee-generated positive random mask before opening;
  reveals only the sign, exactly, at **depth 1**. Tournament ⇒ log₂(n) opening rounds.
- *bucketed one-hot* — applicants encrypt a one-hot bucket vector; the histogram is **depth 0**
  (additions only), winner = top occupied bucket, Vickrey second price = next one. Leaks the
  winner's bucket rather than the full ordering — arguably *better* privacy than today.
- *minimax sign polynomial* (Cheon–Kim–Kim) — same ±1 output as today at depth ~9 instead of 37.

**Bigger levers on parameters:** 30-bit rescale primes instead of 40-bit buy depth 27 at S1 instead
of 17 (precision study needed per app); accepting ~112-bit instead of 128-bit lets the 6-iteration
ladder fit N=32768 and avoids the N=65536 cliff entirely.

**Where TFHE would be the better tool:** unbounded-depth, branchy, exact integer logic on few values.
Threshold TFHE needs a joint bootstrapping-key ceremony (an open research area, heavier than ours).
A middle path worth knowing: CKKS↔FHEW/TFHE scheme switching (Chimera, PEGASUS) — vector arithmetic
in CKKS, exact comparisons in TFHE — which needs a threshold switching key, i.e. the same ceremony
problem.

---

## 7. How to run everything

```bash
# one-time
cd ~/Documents/zk/interfold
cargo build --release --bin interfold
bash scripts/stage-ckks-circuits.sh          # stages every CKKS circuit for the nodes
cargo test -p e3-zk-prover --release --test ckks_staged_artifacts -- --ignored --nocapture
#   → all four param sets must print c0..c7=proven ceremony=proven

# credit scoring  (:5175 client, :8092 server)
cd examples/ckks-credit-scoring && pnpm install && pnpm -r build && pnpm dev:up
# private matching (:5176 / :8093), treasury risk (:5177 / :8094), federated averaging (:5178 / :8095)
cd examples/ckks-matching && pnpm install && pnpm -r build && pnpm dev:up
cd examples/ckks-treasury-risk && pnpm install && pnpm -r build && pnpm dev:up
cd examples/ckks-federated-averaging && pnpm install && pnpm -r build && pnpm dev:up
# offline proof smoke for any of the three (no chain): node scripts/prove-node.mjs  → PROVE-NODE OK
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node scripts/e2e.mjs --window 600

# salary survey (:5174) and auction (:5173) — same shape, one stack at a time (shared anvil/ports)
cd examples/ckks-salary-survey && ./scripts/dev.sh
cd examples/ckks-auction       && pnpm dev:up && pnpm test:e2e

# node-level auction winner run + ceremony timing table
cd tests/integration
CKKS_TOOLS_PROFILE=release INTERFOLD_BIN=$PWD/../../target/release/interfold ./ckks-auction-winner.sh
scripts/ckks-timing-report.sh tests/integration/.interfold/data/cn*/ciphernode.jsonl

# benchmarks (fhe.rs) — §6 of BENCHMARKS_TRCKKS.md lists one command per row
cd ~/Documents/zk/fhe.rs
cargo run --release --example trckks_secure_feasibility        # flooding matrix
bash crates/fhe/scripts/trckks_secure_rows.sh                  # all 16 secure rows
```

**Gotchas that cost time (all now fixed, but know them):**
- `pnpm build:circuits` compiles **in place** under `circuits/bin`; building the wide DKG preset
  leaves `dkg/pk` in a 2-limb shape and breaks standard-preset consumers. `stage-ckks-circuits.sh`
  now restores it.
- The on-chain committee config (`ActiveCryptoConfig.sol`) and `scripts/utils.ts` must agree;
  regenerate with `--committee minimum` if `setCommitteeThresholds` reverts.
- Only one demo stack at a time (shared anvil and ports). Wipe
  `tests/integration/.interfold/data/cn*/db` between runs — it grows tens of GiB.
- Probe contracts with the **compiled artifact ABI**, never a hand-written one: three "bugs" during
  this work were my own wrong ABIs (`request` vs `requestE3`, 6- vs 9-field request struct).
