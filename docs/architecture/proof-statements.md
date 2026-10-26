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
| C2a/C2b | Correct Shamir splitting of SK/ESM, linked to C1 secrets. Proven as a chunk chain whose final proof keeps C2's commitments.                                                               |
| C3a/C3b | Correct recipient encryption of those shares under the C0 key, linked to C2 messages.                                                                                                     |
| C4a/C4b | The H selected received shares open their C2 commitments and form the normalized summed SK/ESM anchors. Proven one CRT limb per proof under a final proof that keeps C4's commitment.     |
| C5      | Aggregate PK derives from exactly the H canonical dealer shares.                                                                                                                          |
| C6      | The decryption share derives from the anchored SK/ESM and ciphertext, in one canonical E3 domain. Full `d` enters Fiat-Shamir; the C7-facing commitment binds the configured native tail. |
| C7      | Exactly T+1 distinct ordered shares reconstruct every claimed message coefficient, including zeros.                                                                                       |

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
pins fhe.rs **v0.4.2**; do not infer current sampler behavior from older v0.4.1 labels. The additive
smudging contract is `2^(lambda+1) * degree * B_C`, with preset/committee-specific bounds generated
from the matching Rust sampler. The preset search (`crates/fhe-params/src/search`) sizes `q` with
the same smudging bound and, for `b == 20`, `b_chi == 1`, and tabulated `d`, a lattice-estimator
128-bit ceiling (`search::security`). Other inputs use the formula fallback and print a warning; see
[`crates/fhe-params/README.md`](../../crates/fhe-params/README.md) for the limitation;
`search_reproduces_secure_presets` and `search_reproduces_insecure_presets` keep its moduli,
plaintext moduli, and `ERROR1_VARIANCE` equal to the preset constants.

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
hint; retain negative tests for inflated/deflated carries. The committed insecure-64 and secure-8192
configurations both enable the scaled-quotient branch. Tests using the current insecure artifacts
can enter it; a reused archive must be checked independently. Secure bounds and witness sizes still
need secure-parameter coverage.

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

The unpublished `e3-zk-samples` owns artificial inputs. Production consumers use dev-dependencies;
the unpublished benchmark runner is the only normal-dependency exception. `pnpm check:repository`
enforces aliases and target-specific tables. The builder depends on witness/config, not samples.

C7 host preparation checks the canonical committee, exactly T+1 shares, strictly increasing
one-based recipient IDs, and level-zero contexts. Small uses 10 C7 shares, not C5's H=14.
Preparation reads/pads the configured native ascending message prefix; Noir owns interpolation and
CRT reconstruction. Host validation is not a substitute for those circuit constraints.

## Recursive trust and exported values

Sequential C6 and nodes folds keep `(leaf, fold, genesis)` VK hashes constant across predecessors.
The first step verifies genesis; continuation verifies the fold; the final consumer binds the
declared fold hash to the verified VK. C3ab covers both complete C3 chains.

`c6_fold_kernel` and `c6_fold` verify four C6 proofs per step (`lib::math::c6_fold`), which costs
about half as much per leaf as one leaf per 2^21 step. Every leaf must carry the chain's domain. A
place with nothing to fold carries the sentinel slot `T + 1` and repeats a real leaf of the step;
the decryption aggregator requires the ciphertext commitment in every slot, so no slot stays empty.
`nodes_fold` still takes one node per step because the aggregator streams it one
`NodesFoldStepRequest` per node.

C3 chains run over Chonk (`lib::math::chonk`). A stack is `c3_chonk_app`, which verifies
`C3_CHONK_LEAVES` C3 proofs, then the init, tail and hiding kernels; `c3_chonk_tube` verifies the
stack's Chonk proof as a rollup proof, and `c3_chonk_accumulate` merges an accumulator or tube on
the left with a tube on the right. `c3ab_fold` verifies each chain's last accumulator as a root
rollup, which closes its IPA claim. Every stage verifies against a witness key and appends that
key's hash to the data it passes on, so each tube or accumulator exposes seven key hashes: its own,
the tube, the hiding kernel's Chonk key, then C3, app, init and tail. Merging requires equal keys on
both sides; `c3ab_fold` hashes each chain's seven keys into the C3 tree, which the anchor pins. The
Chonk and Mega key hashes are Barretenberg's Poseidon2 hash of the key fields, which the builder
writes beside `write_vk --scheme chonk` output. A chain has at least two stacks, so it ends on an
accumulator.

Every slot index is public. A place with nothing to verify carries the sentinel slot `C3_SLOTS` and
writes nothing; its proof position repeats a real leaf of the stack, so it is verified but adds no
row. Within a stack every written slot must be empty, and merging rejects a slot filled on both
sides, so no row is overwritten or duplicated. Node-fold covers child folds and their nested keys.
DKG aggregation requires one node-tree hash across every selected row.

The trust tree uses ordered SAFE `DS_VK_HASH` hashing:

```text
C2a chain  = hash(sk_share_computation_chain, sk_share_computation_chain_last)
C2b chain  = hash(e_sm_share_computation_chain, e_sm_share_computation_chain_last)
C2 tree    = hash(C2a, C2a chain, C2b, C2b chain)
C3 chain   = hash(c3_chonk_accumulate, c3_chonk_tube, hiding kernel, C3, app, init, tail)
C3 tree    = hash(C3a chain, C3b chain)
C4 chain   = hash(share_decryption_limb_0, share_decryption_limb_1, share_decryption_limb_2)
C4 tree    = hash(C4a, C4 chain, C4b, C4 chain)
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

## Chunked C2

C2 is split by coefficient range so its proofs stay near 2^21 gates at large committees. Each share
commitment is one SAFE sponge over the share's packed coefficients, highest degree first. A chunk
runs C2's per-coefficient checks (Shamir finite differences, share ranges, the `sk` column equal
across limbs) and continues every party's sponge from a carried `(state, absorb_pos)`. SAFE merges
consecutive ABSORB words into one tag, so the chain computes exactly the unchunked commitment and
C1, C3, C4 and the node fold are unchanged. A full chunk holds whole packing carriers and whole
sponge blocks, so every chunk starts each sponge at a known position; only the last may end on a
partial carrier. At degree 8192 C2a takes five chunks and C2b, which also hashes every secret limb,
six; each fills at most 2^22 at 39 parties.

Each chunk proves `h_out` from `h_in`, hashes of every carried sponge
(`DS_SHARE_COMPUTATION_CHAIN_STATE`). The final `sk_share_computation` or `e_sm_share_computation`
circuit verifies every chunk, pinning each key by place (the last place takes the last-chunk key,
every other place the full-chunk key), links them, starts the chain from fresh sponges, ends it on
the commitments it returns, and opens C1's secret commitment exactly as the unchunked C2 did. The
chunks also absorb the secret column into a chain sponge (`DS_SHARE_COMPUTATION_CHAIN_SECRET`), and
the final circuit requires the opened secret to hash to that digest, so the shares are dealt from
C1's secret.

The final proof exposes the hash of the two chunk keys as its last public field. `c2ab_fold` folds
it into the VK tree above. A peer verifying a C2 proof directly must compare it with its own chunk
keys (`zk_verify_share_proof_bundle`); the proof alone does not pin them.

## Chunked C4

C4's openings and sums are independent per CRT limb, and the aggregate commitment C6 reads is one
SAFE sponge over the normalized limbs in order. So limb `l`'s proof runs C4's statement for that
limb (`aggregate_limb`: open every honest party's limb-`l` share commitment with checked packing,
sum, reverse and center) and continues the aggregate sponge from the state limb `l - 1` left; the
last limb squeezes the unchunked C4 commitment. Each limb packs into its own carriers and can start
mid-block, and its start position follows from the limb index, so each limb has its own circuit.

The final `share_decryption` circuit verifies the three limb proofs, each with its own key, links
them from the fresh aggregate sponge (`DS_SHARE_DECRYPTION_CHAIN_STATE`), and returns the aggregate
commitment then the hash of the limb keys. `c4ab_fold` folds that hash into the VK tree; a peer
verifying a C4 directly compares it with its own limb keys.

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
