# Cryptographic proof contracts

The synchronized-decryption branch changes the C2/C3/C4 and C6/C7 leaf interfaces. Its
[migration status](threshold-decryption.md#synchronized-decryption-migration-status) distinguishes
local real leaf/recursive/contract evidence from still-unqualified secure presets and deployment.
The statements below describe the synchronized source, not compatibility with deployed pre-migration
verifiers; do not use them to claim this branch is deployment-ready.

Owners: [Noir library](../../circuits/lib/src/),
[recursive circuits](../../circuits/bin/recursive_aggregation/),
[Rust configuration](../../crates/zk/config/) and [witness preparation](../../crates/zk/witness/),
and [BFV wrappers](../../packages/interfold-contracts/contracts/verifiers/). These constraints
survive implementation refactors. A passing witness is not a soundness argument, and a code citation
or audit remediation is not completeness evidence.

## Statement chain

| Proof | Statement                                                                                                                                                                                             |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C0    | BFV share-encryption public key is correctly generated.                                                                                                                                               |
| C1    | Threshold public share derives from SK; outputs commit to SK and PK.                                                                                                                                  |
| C2a   | Correct Shamir splitting of SK linked to C1, with outgoing-key commitments and packed-message commitments.                                                                                            |
| C3a   | Correct recipient encryption under the C0 key, binding recipient/limb, transported key bits and C2's packed message.                                                                                  |
| C4a   | The H selected received messages open C2 commitments; key bits are stripped before the normalized SK sum; incoming keys are committed in selected-dealer order.                                       |
| C5    | Aggregate PK derives from exactly the H canonical dealer shares.                                                                                                                                      |
| C6    | The share is `lambda*c1*SK + fresh_noise + PRF_mask`, bound to owner, designated set and canonical E3 domain. Full `d` enters Fiat-Shamir; the C7-facing commitment binds the configured native tail. |
| C7    | Exactly T+1 distinct ordered, already-weighted shares plus c0 reconstruct every claimed message coefficient, including zeros, without a second interpolation.                                         |

[DKG](dkg.md) defines identities, multiplicity, and roster links;
[threshold decryption](threshold-decryption.md) defines the domain and final verifier checks. Both
final verifiers are mandatory. The runtime `skip_proof_aggregation` setting works only with
`test-only-skip-proof-aggregation`; production rejects it. Test placeholders retain roster/domain
fields but production verifiers reject their proof bytes. There is no request-level bypass.

The release workflow puts the proof-skip feature only in
`interfold-test-only-skip-proof-aggregation-linux-x86_64`. Every release archive checks its compiled
`rev --features` against its declared build features. The install script and `interfold update`
select normal platform archives, never the test-only archive. It is for tests/CI, not production.

## Integer constraints inside a field

A relation `lifted = residue + quotient * q` alone binds nothing: q is invertible in the proof
field. Bound the lifted integer, residues, quotients, and all other operands so their sum cannot
wrap the field. Put bounds on the quantity they describe, not a representation with a smaller range.

C6 bounds each signed fresh-noise coefficient before relating it to every CRT residue with bounded
quotients. On secure presets the integer smudging bound exceeds every CRT prime, so checking only
residues against that bound is vacuous. The former shared-ESM C1/C2b chain is retired; its lesson
from IF-005 remains: a per-residue check cannot replace a bound on the lifted integer.

ct0 and C3 use `e0` directly in the reduced identity, with bounded reduction quotients and operands.
DKG `error1_variance <= 16` keeps `e0_bound = 2 * variance` (20 for both presets) below every
`q_i/2`; witness generation asserts this. Raising it enters a different uniform-sampler bound and
requires reconsidering the assumption. C3 and user-data-encryption `k1` are non-centered `[0,t-1]`
residues; Rust witnesses, Noir equations, and asymmetric quotient bounds must agree. The workspace
now pins fhe.rs **v0.5.1** (the pre-migration pin was v0.4.2); sampler assumptions need validation
against that release, not older v0.4.1 labels. The additive smudging contract is
`2^(lambda+1) * degree * B_C`, with preset/committee-specific bounds generated from the matching
Rust sampler. The preset search (`crates/fhe-params/src/search`) sizes `q` with the same smudging
bound and, for `b == 20`, `b_chi == 1`, and tabulated `d`, a lattice-estimator 128-bit ceiling
(`search::security`). Other inputs use the formula fallback and print a warning; see
[`crates/fhe-params/README.md`](../../crates/fhe-params/README.md) for the limitation;
`search_reproduces_secure_presets` and `search_reproduces_insecure_presets` keep its moduli,
plaintext moduli, and `ERROR1_VARIANCE` equal to the preset constants.

Every prover-chosen modular quotient needs a bound. Division/rounding are verified with a quotient
bound plus the unique remainder interval, not trusted because a hint computed them. In particular:

- `ModU64::div_mod` must check `result * divisor == dividend (mod modulus)` (IF-001).
- Full-field `ModU64::reduce_field` proves integer reduction, not only a scalar congruence. For
  production moduli it bounds the quotient by `B=floor((p-1)/q)`, requires `0<=r<q`, and, at
  quotient B, requires `r<=(p-1)%q`. The last condition excludes the alias `quotient*q+r=n+p`. The
  bounds derive from a checked byte reduction of p-1; tiny moduli use checked byte/limb reduction
  directly. An unconstrained division supplies witnesses only.
- `ModU128::reduce_mod` does **not** constrain the quotient and so does not pin a prover-controlled
  remainder. It currently serves constant-only `bin/config`; `Polynomial::eval_mod` has no callers.
  Use `reduce_mod_bounded`/`inv_mod_bounded` for witness inputs, or repair and propagate bit widths
  through the primitive's arithmetic first. A remainder interval alone is insufficient.
- C7 derives u through a bounded sum of weighted partials plus c0 and Garner reconstruction, not
  witnessed `u_global` or CRT quotients. Its inverse and reduction hints are bounded.
  `rounded_decode` constrains quotient and remainder and compares every message coefficient
  (IF-002/IF-012).
- The C7 rounded decode `round(t*u/Q)` with t mapped to zero must remain equivalent to the modular
  reference decode `-Q^-1 * (t*u mod Q) mod t`. Keep the boundary assertions; historical exhaustive
  comparison across 44 parameter pairs is evidence for that reformulation, not every future tuple.

Reducing identities modulo `X^N+1` deletes the cyclotomic quotient; it does not delete the need for
real integer bounds. `negacyclic_kernel` evaluates the reduced product at one point without
witnessing the product. Bounds may transfer through an injective opening rather than be repeated.
C4's centered reduction uses one bounded division and a q-wide centered interval, with carry bounded
by H (`AGGREGATION_BIT_CARRY = 8`, H < 256). It avoids assumptions that all moduli straddle the same
power of two. C5's sum quotient uses `SUM_BIT_CARRY = 8` with H <= 128; its aggregate key still
needs an explicit bound.

## Commitments, packing, and Fiat-Shamir

Packing uses shared carriers `acc = acc * radix + (v + base)`. A digit overflowing its slot can
cancel into its neighbor and preserve the carrier. Therefore one hash can have several coefficient
openings unless every digit fits its slot. A `u64` cast is not enough when `base` leaves less than
64 usable bits (the old C2b case).

**Injectivity is not canonicality.** `pack_checked` pins `digit < radix`; it transfers an upstream
creating circuit's canonical bound because the opening must equal the committed value. It does not
create a canonical bound where no upstream statement proves one. C1's originating `pk0` and C5's
unanchored `pk0_agg` need explicit centered bounds. C5's per-party keys and C4's received C2 shares
can inherit them through checked openings. C4 normalizes its derived aggregate in circuit; it does
not need a second opened-witness bound. Run the binding check **before** commitment comparison.

The review class is **every prover-chosen witness entering the sponge**, not only commitments opened
from another circuit. C2a/C2b, C4, C5, and three C6 openings were the IF-011 class. IF-013
additionally found direct `flatten` inputs (C6 d and C3 ciphertexts) and commitments created inside
ct0/ct1. Use `flatten_checked`/checked commitment helpers unless another constraint already makes
packing injective. Creating a commitment is not an exemption.

Once the transcript uniquely fixes the witness before gamma, the polynomial evaluation argument can
force a value to equal a canonical identity. That is why C6 d needs injectivity rather than another
explicit bound. C1 pk0 and C5 aggregate pk0 are not determined that way. A reduced integer identity
still needs genuine bounds on its operands; the two arguments are not interchangeable.

C6 absorbs already-checked SK/ciphertext commitments plus its PRF-key and round bindings rather than
paying again to absorb all their coefficients. This is sound only while those openings stay checked.
Keep the native-tail witness binding: deriving it caused an unexplained Noir
`bug: Brillig function call isn't properly covered by a manual constraint` diagnostic. A solved
witness, including under `--silence-warnings`, does not make that diagnostic acceptable. C3's scaled
rounding carry z is a prover witness with `BIT_Z` and `[0,t)` checks, not an in-circuit unchecked
hint; retain negative tests for inflated/deflated carries. The committed insecure-64 and secure-8192
configurations now disable the scaled-quotient branch after the DKG t=2q parameter change. The
generic optimization retains separate test coverage; a reused archive must be checked independently.
Secure bounds and witness sizes still need secure-parameter coverage.

The CRISP ballot relation is a narrow exception: plain packing can preserve a coefficient-aligned
linear relation across equal-width carriers when all commitments have bounded openings fixed
elsewhere. [CRISP](encrypted-computation.md#ballot-proof-and-selection) explains why a one-point
check or following a parent's commitment without its bytes destroys that exemption. Do not
generalize it.

Checked packing rejects group size one: it saves no sponge absorption and still pays range checks.
Plain packing permits that layout for already-bounded wide values such as C6's 129-bit secure
quotients. It preserves the shifted carrier encoding used by Rust rather than silently changing the
Fiat-Shamir payload to raw coefficients; it provides no compression in that case. Keep
`pack`/`pack_checked` equivalence tests because they duplicate layout arithmetic. Never replace a
missing circuit constraint with a comment claiming another circuit established it.

## Rust configuration and preparation

`e3-zk-config` owns static bounds, widths, parity, and public layouts. `Configs::new` retains an
existing BFV parameter owner; constructors check the ring, CRT basis, and sampler profile. C3 and
user encryption share derived `k0is` across bounds, rendering, and preparation. Configuration needs
no witness, sample, secret key, or prover.

`e3-zk-witness` owns production inputs, commitments, preparation, and canonical Noir JSON. Workers
pass concrete configurations through `Provable::Config`, reusing C6/C7 configurations across
ciphertext indices. User encryption prepares from the exact typed ciphertext and intermediates;
`encrypt_and_prepare` encrypts once and returns both ciphertext and Inputs. Preserve lifted-e0 ct0
correction and separate `r`/`r_ct1` JSON quotients.

The unpublished `e3-zk-samples` owns artificial inputs. Production consumers use dev-dependencies;
the unpublished benchmark runner is the only normal-dependency exception. `pnpm check:repository`
enforces aliases and target-specific tables. The builder depends on witness/config, not samples.

C7 host preparation checks the canonical committee, exactly T+1 shares, strictly increasing
one-based recipient IDs, and level-zero contexts. Small uses 10 C7 shares, not C5's H=14.
Preparation reads/pads the configured native ascending message prefix; Noir owns the weighted-share
sum and CRT reconstruction. Host validation is not a substitute for those circuit constraints.

## Recursive trust and exported values

Sequential C3, C6, and nodes folds keep `(leaf, fold, genesis)` VK hashes constant across
predecessors. The first step verifies genesis; continuation verifies the fold; the final consumer
binds the declared fold hash to the verified VK. Node-fold covers C0/C1/C2/C4, the C3 fold and its
nested keys. DKG aggregation requires one node-tree hash across every selected row.

C6's PRF expands exactly `T` peer pairs, selected from the ordered designated set with the owner
removed. A witness-dependent branch inside a full-N loop does not skip circuit constraints and must
not be mistaken for runtime work avoidance. Each key absorbs its key and the two-element context
digest, then squeezes `L * ceil(N/3)` field elements under
`fhe.rs/trbfv/prf/poseidon2/eval-x3`. Successive integer division by that limb's modulus splits
each element into three residues in `[0, q)`. The last element of a limb contributes only
`N mod 3` coefficients when `N` is not a multiple of 3. The third residue is statistically short
of 128 bits for a modulus near 60 bits; the first two are not. A raw 64-bit window is not a
substitute. The context digest, under `fhe.rs/trbfv/prf/poseidon2/ctx-cmt`, absorbs the designated
set, level 0, the two components, `L`, `N`, and the checked ciphertext commitment already verified
against the opened ciphertext. It does not absorb the raw coefficients again. These domains do
not verify masks produced by the previous `ctx` and `eval` labels. The fixed-array squeeze path
requires the sponge to be at a permutation boundary and validates the declared output count
against the IO pattern. It performs the same full-rate blocks and final partial block as
streaming SAFE; a zero-length squeeze performs no permutation. It must not reset the domain/tag,
truncate the stream, or silently accept a partially consumed rate window.

The trust tree uses ordered SAFE `DS_VK_HASH` hashing:

```text
C3 chain   = hash(c3_fold, c3_fold_kernel, C3)
node tree  = hash(C0, C1, C2a, c3_fold, C3 chain, C4a)
nodes tree = hash(nodes_fold, nodes_fold_kernel, node_fold, node tree)
C6 tree    = hash(c6_fold, c6_fold_kernel, C6)
```

Final public input zero is the complete nodes/C6 tree, pinned immutably from `.vk_tree_hash`, not
the immediate `.vk_hash`; public input one separately pins C5/C7. A prover-declared unanchored hash
does not establish trust. [Circuit artifacts](circuit-artifacts.md) owns generation and deployment.

`node_fold::assert_c3_recipient_keys` must pin every non-self recipient limb to limb zero and match
C3 in each slot. DKG links the exported limb-zero key to that recipient's C0. Checking only the
first limb lets later limbs encrypt under another key (IF-014). The own slot is exempt because its
key comes from C0. The missing constraint was established by source review and a negative test, not
an end-to-end threshold bypass demonstration.

Before BFV verification, wrappers require canonical BN254 field encodings; message coefficients must
also fit 64 bits. The output width is exactly 50 u64 coefficients across Noir
`MAX_MSG_NON_ZERO_COEFFS`, `e3-zk-config`, and Solidity `MESSAGE_COEFFS_COUNT`. The builder emits
the Noir value from the Rust constant; its shared-material test compares rendered Noir/Solidity
widths with that constant. C6/C7 preparation uses the same native ascending prefix selected by
`config.max_msg_non_zero_coeffs`; a nondefault host width requires matching ABIs and consumers.
Canonical field checks do not prove parameter-specific plaintext-modulus bounds because the wrapper
does not store t.

## Evidence and change review

- [Noir helpers](../../circuits/lib/src/math/) and
  [recursive circuit tests](../../circuits/bin/recursive_aggregation/) own range, packing,
  recipient, and recursion constraints. `pnpm noir:test` exercises the selected configuration; use
  real secure witnesses and unit branches for secure-only paths. Scan execution output for `bug:` as
  well as exit failures. Compilation alone is not a proof check.
- [BFV wrapper tests](../../packages/interfold-contracts/test/BfvDecryptionVerifier.spec.ts),
  [PK tests](../../packages/interfold-contracts/test/BfvPkVerifier.spec.ts), and
  [VK integration](../../packages/interfold-contracts/test/BfvVkBindingIntegration.spec.ts) own
  contract anchors. `pnpm rust:test:proofs` exercises real recursive proofs with prepared artifacts.
- Measure gate changes at every committee size, not only H=2: constant work and H-scaled work can
  trade places. Rebuild the intended preset after a gate sweep; restoring source config does not
  restore `target/` or compiled artifacts and can produce misleading ABI length failures.
- CRISP browser proving has `srsSize: 2**21`. Crossing 2,097,152 gates stops proving, not merely
  slows it. Measure ct0 and ballot circuits before shipping added constraints; soundness repairs
  cannot be dropped to meet the ceiling.

[History](protocol-history.md) retains finding IDs and evidence scope, not current audit assurance.
The compute path, Rust witnesses, OpenVM guest/prover, and receipt verifiers were not covered by the
two scoped Zenith Solidity audits. See
[audit scope](../../packages/interfold-contracts/audits/README.md).
