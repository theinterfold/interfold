# Threshold CKKS on Interfold — DKG review handout

**Audience:** cryptographers reviewing the claim that the CKKS distributed key
generation reuses the BFV DKG unchanged and is sound in doing so.
**Ask:** confirm or refute the four claims in §5; everything else is context
and pointers so you can check them against source, not prose.

Source of truth: `fhe.rs` (branch `feat/ckks-encryption`) —
`crates/fhe/src/trckks/{mod.rs, keygen.rs, relin_gen.rs, hybrid_gen.rs,
smudging.rs, README.md}`, `crates/fhe/src/ckks/{keys.rs, hybrid.rs}`;
Interfold (branch `feat/ckks-user-data-encryption`) —
`crates/keyshare/src/threshold_keyshare_ckks/`, `crates/fhe-params/src/ckks_presets.rs`,
`agent/INVARIANTS.md` §Threshold CKKS.

---

## 1. The claim, stated precisely

The threshold-CKKS key material is produced by **exactly the same
distributed protocol** as threshold-BFV on Interfold:

1. Each party `i` samples a secret contribution `s_i` and a smudging-noise
   contribution `e_sm,i` (only the *distributions* are scheme-specific, §2).
2. `s_i` and `e_sm,i` are Shamir-shared coefficient-wise, mod each RNS prime
   `q_j` of the ciphertext modulus `Q`, and dealt to the other parties
   **encrypted under a BFV "transport" key** (the same encrypted-DKG the BFV
   flow uses). Dealt shares are proven well-formed by the existing C2a/C2b
   circuits (Shamir share consistency / commitment), unchanged.
3. Each party aggregates the shares it received: `[s]_i = Σ_k share_k(i)`,
   giving an additive-then-Shamir sharing of the joint secret `s = Σ_i s_i`
   (and likewise for `e_sm = Σ_i e_sm,i`).
4. The joint public key is produced non-interactively from a CRP `a`:
   party `i` publishes `pk0_i = −a·s_i + e_i`; `pk = (Σ_i pk0_i, a)`.

Steps 1–3 are scheme-agnostic (they never touch a ciphertext). The only
scheme-specific parts are the distributions in step 1, the modulus chain the
shares live over, what happens at decryption (§3), and the additional
relinearization ceremony CKKS needs for multiplication (§4).

The reasoning for why this is sound is not ours: it is Mouchet–Troncoso-
Pastoriza–Bossuat–Hubaux, *Multiparty Homomorphic Encryption from RLWE*
(eprint 2020/304), whose Protocols 1 and 2 are stated for a generic RLWE
scheme — the paper itself instantiates a multiparty BFV; the CKKS
instantiation is Lattigo's, not the paper's — plus the Shamir
layer of Urban–Rambaud (eprint 2024/1285), also RLWE-generic.

## 2. What is scheme-specific in key generation

| item | BFV (`trbfv`) | CKKS (`trckks`) | why it differs |
|---|---|---|---|
| secret distribution | CBD, variance 0.5 (ternary-ish) | **same**: `CkksSecretKey::SK_VARIANCE = 0.5`, `sample_vec_cbd_f32` (`ckks/keys.rs:48-59`) | none — identical sampler |
| pk noise `e_i` | discrete Gaussian / CBD per params | same sampler family, `CkksParameters::variance()` (default 10 ⇒ σ≈3.2) | none |
| modulus the shares live over | plaintext `t`-agnostic; ciphertext `Q` | ciphertext `Q = Π q_j` (levels drop primes) | CKKS ciphertexts shrink by rescaling; a share at level ℓ is the level-0 share with rows for dropped primes **removed** (`TRCKKS::project_share_to_level`, `mod.rs:298`) — never divided. Shares are independent per-prime Shamir sharings, so dropping rows is exact. |
| DKG transport bound | dealt share coefficients `< t_dkg` of the BFV transport preset | **same** constraint; when a CKKS prime exceeds the standard transport `t` (ParamSet 2: 45-bit base prime) the node escalates deterministically to `InsecureDkgWide512` (`t = 0x3fffffff6401`, 46-bit) | shares are `mod q_j` values and must fit the transport plaintext space; this is a *packaging* constraint, not a security one |
| special primes `P` (hybrid KS) | n/a | public parameters; **sk shares are never over P** — `CkksHybridRelinKeyGenerator` extends locally (`hybrid_gen.rs`) | nothing extra is dealt |

**Consequence:** the DKG transcript (what travels, what is proven, what is
committed) is byte-for-byte the same protocol as BFV with a different
modulus chain. The C2a/C2b circuits are reused with no changes.

## 3. What is genuinely different: decryption and flooding

This is the part where "CKKS is basically BFV" is *false* and where the
security argument has to be re-done — and it was.

Threshold decryption of `(c0, c1)` at level ℓ: party `j` publishes
`d_j = c0 + c1·[s]_j + [e_sm]_j`; Lagrange reconstruction over any `t+1`
parties gives `c0 + c1·s + e_sm = Δ·m + e_ct + e_sm` — which **is** the CKKS
plaintext (no BFV rounding step). Two consequences:

1. **The smudging noise lands in the result.** In BFV, `e_sm` must stay under
   the decode wall `Q/(2t)` and is otherwise invisible. In CKKS it is an
   additive error of `n·B_sm/Δ` on the decoded reals. The calculator
   (`trckks/smudging.rs`, `CkksSmudgingBoundCalculator`) therefore enforces
   *two* correctness walls in place of BFV's single decode wall, on top of
   the security floor both schemes share:
   - security floor (same as BFV): `B_sm ≥ 2^λ · B_C` — the standard
     smudging lemma (Asharov–Jain–López-Alt–Tromer–Vaikuntanathan–Wichs,
     Eurocrypt'12, via AJW'11 Lemma 2.1), a statistical-distance argument.
     Li–Micciancio Eurocrypt'21 is the attack it defends against;
     Li–Micciancio–Schultz–Sorrell Crypto'22 is the tight DP/Gaussian
     alternative (not the source of this bound), and "Noah's Ark"
     eprint 2023/815 takes the same statistical route we do;
   - no wrap-around: `Δ·B_msg + B_C + n·B_sm < Q_ℓ/2`;
   - precision: `n·B_sm ≤ precision_loss · Δ` (application-declared).
   If the walls conflict, the parameters cannot support secure threshold
   decryption for that circuit and the calculator errors out — the fix is a
   larger `Q_ℓ` at the opening level or a smaller circuit bound.
2. **Single use.** The dealt `e_sm` sharing floods exactly one decryption;
   reusing it for a second ciphertext subtracts to `c1·s`-dependent
   material (Li–Micciancio again). The node pins the served ciphertext's
   hash in the `Decrypting` phase and refuses a different ciphertext
   (`threshold_keyshare_ckks/machine.rs`, test `..._refuses_second_ciphertext`),
   and `TRCKKS::decryption_share` documents the requirement.

So the *DKG* is the same; the *opening* has a CKKS-specific correctness
analysis layered on the same security bound.

## 4. The CKKS-only addition: the relinearization ceremony

BFV threshold flows on Interfold never multiply ciphertexts, so no
key-switching key was ever generated. CKKS apps do (variance, sign
extraction), so the committee runs a second protocol after the DKG:

- **Protocol 2 of eprint 2020/304 (`RelinKeyGen`)**, two rounds over a CRP,
  with each party's `s_i` and an ephemeral `u_i`. Implemented per-level in
  `relin_gen.rs` and — the production path — with the **hybrid gadget**
  (Han–Ki eprint 2019/688; Kim–Polyakov–Zucca eprint 2021/204 for noise) in
  `hybrid_gen.rs`: rows `(−a_j·s + P·g_j·s² + e_j, a_j)` over `Q·P`, one key
  for every level.
- Inputs: the *same* `s_i` from the DKG (the generator takes the party's
  secret contribution, not a fresh secret), so the relin key is for the
  joint `s` whose pk was published. No new secret material is dealt.
- Security accounting: RLWE hardness must be evaluated on `Q·P`, not `Q`.
  Interfold's ParamSet 2 uses 3×60-bit special primes at N=512 (demo); the
  bench's N=32768 row overshoots the 128-bit budget and is flagged in the
  prod doc as *to be re-run with smaller specials*.
- Verification: the ceremony is deterministic given the public round
  messages — every party derives the identical key, and a mismatch is
  attributable. Per-digit well-formedness proofs (C8) exist and are being
  wired; see §6.

## 5. Claims to confirm

Please mark each **confirm / refute / needs-condition**:

**C-1.** *Reusing the RLWE-generic DKG (Protocols 1 of 2020/304 + Shamir layer
of 2024/1285) for CKKS with the same secret distribution (CBD σ²=0.5) and the
same pk-noise distribution introduces no CKKS-specific weakness in key
generation.* Our reading: the security reduction of the joint key is
RLWE over `(N, Q, χ)` regardless of encoding; CKKS's approximate decoding
plays no role until decryption.

**C-2.** *Projecting a level-0 Shamir share to level ℓ by dropping the RNS
rows of removed primes is exact and leaks nothing beyond the level-0 share.*
Our reading: shares are independent sharings per prime; the level-ℓ share is
a strict subset of published/dealt values.

**C-3.** *The decryption-share flooding bound `B_sm ≥ 2^λ·B_C` with the two
CKKS correctness walls (no wrap mod `Q_ℓ`; bounded precision loss) is the
right condition, with λ ≥ the same floor BFV uses (`MIN_SECURE_LAMBDA`), and
the single-use rule on `e_sm` closes the Li–Micciancio channel in the
threshold setting.* Specific question: is a *statistical* λ (we default to
the BFV value) sufficient, or does the CKKS-D setting warrant a larger λ
given that the decrypted result is *published* (not just used internally)?

**C-4.** *Deriving the relinearization key from the same `s_i` via Protocol 2
(hybrid gadget over `Q·P`) does not weaken the joint key beyond the usual
key-switching-key circular-security assumption, provided RLWE is assessed at
modulus `Q·P`.* Specific question: any concern with the ephemeral `u_i`
being sampled from `Poly::small` (CBD, variance 10 ⇒ bound 6) rather than
the ternary key distribution? **Context for that question:** this is NOT a
CKKS deviation — the shipped BFV reference (`fhe::mbfv::relin_key_gen.rs:94`)
samples `u` from exactly the same `Poly::small(ctx, par.variance)`, and the
CKKS generator was ported from it. So the question applies to both schemes'
Protocol-2 realisations; a "no" answer means changing BFV too.

**C-6 (found by audit, fixed for CKKS, OPEN for BFV).** *The CRT-glue check
`u_crts[l] + r_l·q_l == u_global` in `decrypted_shares_aggregation.nr`
(shared C7 body) constrains nothing when the quotient witness `r_l` is
range-free: over the scalar field `r_l = (u* − u_crts[l])·q_l⁻¹` satisfies it
for ANY `u*`.* Empirically confirmed with `nargo` (honest 42, claimed
1 000 000, accepted). Consequences: CKKS C7 was fully vacuous (nothing follows
the glue); BFV C7 is partially so (`verify_decoding` follows and is
many-to-one). The CKKS branch fixes its own circuit by range-constraining
`u_global < Q` and `r_l < Q/q_l` (`verify_crt_reconstruction_ckks`,
regression tests `test_ckks_aggregation_rejects_forged_u_global` /
`_rejects_noncanonical_lift`); the BFV circuit is byte-identical to `main`
and documented in `docs/BFV_C7_CRT_SOUNDNESS_FINDING.md`. Questions: (i) is
the CKKS bound `BIT = L·BIT_D_NATIVE` with `Q < p` sufficient for the field
identity to imply the integer one? (ii) how exploitable is the BFV residual
freedom (a different `u_global` in the same decode class) given nothing
on-chain binds `u_global` for BFV?

**C-5 (the one that decides deployability).** *The flooding calculator's
noise model is worst-case sup-norm: `B_C` grows by ×N per multiplication
level. At N=32768 that is ≈15 bits/level, and with λ=50 NO app closes all
three walls at any 128-bit set (`trckks/app_feasibility.rs`; e.g. depth-1
statistics requires 101 smudging bits, precision wall fails). Production
threshold-CKKS implementations (OpenFHE, Lattigo) bound noise in the
canonical embedding (average-case, ≈√N per level) and the literature's
Rényi-divergence argument permits λ/2.* Questions: (i) is an average-case /
canonical-embedding `B_C` acceptable for the flooding bound in the
published-result (CKKS-D) setting, and under what independence assumptions
on the evaluation? (ii) is Rényi λ/2 acceptable here? (iii) is opening at a
doubled scale (skipping the final rescale, +40 bits of `Q_ℓ` headroom) a
sound way to relax the precision wall? **Counter-evidence you should weigh
first:** LMSS Crypto'22 proves that noise tailored to a *given ciphertext's*
error rather than worst-case error is vulnerable to IND-CPA-D attacks — they
explicitly refute the claim that accurate per-ciphertext noise estimates
justify smaller flooding. We read that as permitting a static, circuit-derived
average-case bound (what OpenFHE/Lattigo ship) but forbidding any bound that
reads the observed ciphertext; confirm or refute that reading. Every measured
row so far uses the demo value of 20 smudging bits and is marked
`used/required` in the report; we will not call any deployment secure until
this bound closes.

## 6. Known gaps (so you don't rediscover them)

Being closed now, all committee-side, none in the DKG itself:

- C1-CKKS (pk-share well-formedness) verified before aggregation — closes
  the rogue-key shortcut of the *last* party choosing `pk* − Σ others`.
- C6-CKKS `expected_sk_commitment` anchored to the DKG commitment via the
  link registry (BFV has this through C4; CKKS links C1/C2a → C6 directly,
  since all three use the same Poseidon commitment over `s_i`).
- Per-param-set C0/C6/C7 artifacts (no proof-free postures).
- C8 per-digit proofs wired into the ceremony.

Outside the DKG: Greco/app circuits are built at N=512 shapes only;
secure-N client proving is unmeasured.

## 7. Parameters in use

| set | N | Q primes | Δ | use | transport |
|---|---|---|---|---|---|
| 0 | 512 | 2×36-bit | 2^26 | canonical / tests | standard |
| 2 | 512 | 45 + 38×40-bit, +3×60-bit special (hybrid, dnum 13) | 2^40 | auction sign extraction (12 iter) | wide (46-bit t) |
| 3 | 512 | 3×36-bit | 2^40 | salary survey (one square) | standard |

All three are **insecure demo shapes** (N=512). Measured secure-shape
costs (N=32768/L20, N=65536 ladder) are in
`fhe.rs/crates/fhe/BENCHMARKS_TRCKKS.md` and
`interfold/docs/THRESHOLD_CKKS_PROD_DECISION.md`.
