# Cryptographic proof contracts

Owners: [Noir library](../../circuits/lib/src/),
[recursive circuits](../../circuits/bin/recursive_aggregation/),
[Rust configuration](../../crates/zk/config/) and [witness preparation](../../crates/zk/witness/),
and [BFV wrappers](../../packages/interfold-contracts/contracts/verifiers/). These constraints
survive implementation refactors. A passing witness is not a soundness argument, and a code citation
or audit remediation is not completeness evidence.

## Statement chain

| Proof   | Statement                                                                                                                                                                                 |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C0      | BFV share-encryption public key is correctly generated.                                                                                                                                   |
| C1      | Threshold public share derives from SK; integer smudging bound is enforced; output commits to SK, PK, and ESM residues.                                                                   |
| C2a/C2b | Correct Shamir splitting of SK/ESM, linked to C1 secrets.                                                                                                                                 |
| C3a/C3b | Correct recipient encryption of those shares under the C0 key, linked to C2 messages.                                                                                                     |
| C4a/C4b | The H selected received shares open their C2 commitments and form the normalized summed SK/ESM anchors.                                                                                   |
| C5      | Aggregate PK derives from exactly the H canonical dealer shares.                                                                                                                          |
| C6      | The decryption share derives from the anchored SK/ESM and ciphertext, in one canonical E3 domain. Full `d` enters Fiat-Shamir; the C7-facing commitment binds the configured native tail. |
| C7      | Exactly T+1 distinct ordered shares reconstruct every claimed message coefficient, including zeros.                                                                                       |

This table names the trBFV chain. l-BFV has no C1/C5: PK/RLK row generation and aggregation replace
them, linked to C2a's secret root, and C2b chunk leaves prove their own lifted ESM bound.
[DKG](dkg.md#l-bfv-generation-collection-and-publication) describes the V2 chain and key envelope.

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

C1's smudging bound belongs on `e_sm_lifted`; on secure presets it exceeds every CRT prime, so
checking each residue against it is vacuous. Residues use `(q_i-1)/2`; quotients also have bounds.
C1 commits to the residues C2b splits, not the lift. The shared `PK_GENERATION_BIT_E_SM` and
`SHARE_COMPUTATION_E_SM_BIT_SECRET` use the same modulus width. A per-residue bound cannot replace
the lifted integer check (IF-005), even if an optimization branch predates that repair.

ct0 and C3 use `e0` directly in the reduced identity, with bounded reduction quotients and operands.
DKG `error1_variance <= 16` keeps `e0_bound = 2 * variance` (20 for both presets) below every
`q_i/2`; witness generation asserts this. Raising it enters a different uniform-sampler bound and
requires reconsidering the assumption. C3 and user-data-encryption `k1` are non-centered `[0,t-1]`
residues; Rust witnesses, Noir equations, and asymmetric quotient bounds must agree. The workspace
uses the locked fhe.rs `dev` revision; do not infer sampler behavior from older release labels. The
additive smudging contract is `2^(lambda+1) * degree * B_C`, with preset/committee-specific bounds
generated from the matching Rust sampler.

Every prover-chosen modular quotient needs a bound. Division/rounding are verified with a quotient
bound plus the unique remainder interval, not trusted because a hint computed them. In particular:

- `ModU64::div_mod` must check `result * divisor == dividend (mod modulus)` (IF-001).
- `ModU128::reduce_mod` does **not** constrain the quotient and so does not pin a prover-controlled
  remainder. It currently serves constant-only `bin/config`; `Polynomial::eval_mod` has no callers.
  Use `reduce_mod_bounded`/`inv_mod_bounded` for witness inputs, or repair and propagate bit widths
  through the primitive's arithmetic first. A remainder interval alone is insufficient.
- C7 derives u through bounded interpolation and Garner reconstruction, not witnessed `u_global` or
  CRT quotients. Its inverse and reduction hints are bounded. `rounded_decode` constrains quotient
  and remainder and compares every message coefficient (IF-002/IF-012).
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

C6 absorbs already-checked SK/ESM/ciphertext commitments rather than paying again to absorb all
their coefficients. This is sound only while those openings stay checked. Keep the native-tail
witness binding: deriving it caused an unexplained Noir
`bug: Brillig function call isn't properly covered by a manual constraint` diagnostic. A solved
witness, including under `--silence-warnings`, does not make that diagnostic acceptable. C3's scaled
rounding carry z is a prover witness with `BIT_Z` and `[0,t)` checks, not an in-circuit unchecked
hint; retain negative tests for inflated/deflated carries. Branch selection is generated per preset;
the default insecure artifacts do not establish secure-only branch coverage. Check a reused archive
independently and exercise secure bounds with secure-parameter witnesses.

The CRISP ballot relation is a narrow exception: plain packing can preserve a coefficient-aligned
linear relation across equal-width carriers when all commitments have bounded openings fixed
elsewhere. [CRISP](encrypted-computation.md#ballot-proof-and-selection) explains why a one-point
check or following a parent's commitment without its bytes destroys that exemption. Do not
generalize it.

`packing_layout` rejects group size one: it saves no sponge absorption and still pays range checks.
Keep `pack`/`pack_checked` equivalence tests because they duplicate layout arithmetic. Never replace
a missing circuit constraint with a comment claiming another circuit established it.

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

Those quotient names describe unchunked trBFV. Chunked user encryption retains `r1is`/`p1is`, full
lifted `e0`, and PK/ciphertext component commitments. Do not replace that witness shape with the
unchunked API while moving crates. All CRISP ballots use the chunked tree, including secure-8192
ballots; the generic SDK selects the tree by the requested protocol path.

The unpublished `e3-zk-samples` owns artificial inputs. Production consumers use dev-dependencies;
the unpublished benchmark runner is the only normal-dependency exception. `pnpm check:repository`
enforces aliases and target-specific tables. The builder depends on witness/config, not samples.

C7 host preparation checks the canonical committee, exactly T+1 shares, strictly increasing
one-based recipient IDs, and level-zero contexts. Small uses 10 C7 shares, not C5's H=14.
Preparation reads/pads the configured native ascending message prefix; Noir owns interpolation and
CRT reconstruction. Host validation is not a substitute for those circuit constraints.

## Recursive trust and exported values

Sequential C3, C6, and nodes folds keep `(leaf, fold, genesis)` VK hashes constant across
predecessors. The first step verifies genesis; continuation verifies the fold; the final consumer
binds the declared fold hash to the verified VK. C3ab covers both complete C3 chains. Node-fold
covers child folds and their nested keys. DKG aggregation requires one node-tree hash across every
selected row.

The trust tree uses ordered SAFE `DS_VK_HASH` hashing:

```text
C2 tree    = hash(C2a, C2b)
C3 chain   = hash(c3_fold, c3_fold_kernel, C3)
C3 tree    = hash(C3a chain, C3b chain)
C4 tree    = hash(C4a, C4b)
node tree  = hash(C0, C1, c2ab_fold, C2 tree, c3ab_fold, C3 tree, c4ab_fold, C4 tree)
nodes tree = hash(nodes_fold, nodes_fold_kernel, node_fold, node tree)
C6 tree    = hash(c6_fold, c6_fold_kernel, C6)
```

Final public input zero is the complete nodes/C6 tree, pinned immutably from `.vk_tree_hash`, not
the immediate `.vk_hash`; public input one separately pins C5/C7. A prover-declared unanchored hash
does not establish trust. [Circuit artifacts](circuit-artifacts.md) owns generation and deployment.

`node_fold::assert_c3_recipient_keys` must pin every non-self recipient limb to limb zero and match
C3a/C3b in each slot. DKG links the exported limb-zero key to that recipient's C0. Merely matching
the two C3 chains lets later limbs encrypt under another key (IF-014). The own slot is exempt
because its key comes from C0. The missing constraint was established by source review and a
negative test, not an end-to-end threshold bypass demonstration.

Before BFV verification, wrappers require canonical BN254 field encodings; message coefficients must
also fit 64 bits. The output width is exactly 50 u64 coefficients across Noir
`MAX_MSG_NON_ZERO_COEFFS`, `e3-zk-config`, and Solidity `MESSAGE_COEFFS_COUNT`. The builder emits
the Noir value from the Rust constant; its shared-material test compares rendered Noir/Solidity
widths with that constant. C6/C7 preparation uses the same native ascending prefix selected by
`config.max_msg_non_zero_coeffs`; a nondefault host width requires matching ABIs and consumers.
Canonical field checks do not prove parameter-specific plaintext-modulus bounds because the wrapper
does not store t.

## Evidence and change review

### l-BFV and user-encryption recursive anchors

For l-BFV, the legacy manifest has 15 entries with no C1, and the independent V2 manifest has 11. Do
not equate corresponding legacy/V2 VKs. Each row kernel starts at row zero; a fold accepts only the
next row, and terminal consumers require the final configured row. Generation PK rows open fixed CRS
commitments; RLK rows open fixed URS and CRS commitments and bind both output components. All
prover-chosen secret, error, quotient, and key data must reach the transcript before challenge
derivation. Aggregation opens the creator's range-checked packed carriers and normalizes their sum
in circuit; checked openings and canonical carry windows remain necessary.

Every chunked user-encryption descendant VK reaches an anchor: identity outputs the leaf hash; the
leg manifest hashes `(identity, leaf, pk_ct)` in that order; the wrapper exports
`hash(top_level, manifest)` for each leg. Consumers compare both chains, not just top-level VKs. The
wrapper requires one shared `u` root. ct0 rebuilds the complete `k1` root before exporting its
whole-polynomial commitment. Leaves, identity circuits opening private `u`, and the ct0 top-level
opening private `k1` require the ZK recursive target. The trBFV single encryption circuit has no
recursive children, shares one `u`, and hard-codes the CRS `pk1`; restoring a `pk1is` witness would
require a checked opening again.

The l-BFV wide C7 follows bounded interpolation and mixed-radix Garner reconstruction, not unbounded
CRT quotient witnesses. Secure-16384 decode uses U384 for the numerator, including `u = Q-1`; U256
or field arithmetic silently loses the required integer width.

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
