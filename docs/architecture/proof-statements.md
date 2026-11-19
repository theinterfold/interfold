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
| C0      | BFV share-encryption public key is committed, and every coefficient is centred modulo its `q_i`. Key generation is deliberately not proven; see the note below.                           |
| C1      | Threshold public share derives from SK; integer smudging bound is enforced; output commits to SK, PK, and ESM residues.                                                                   |
| C2a/C2b | Correct Shamir splitting of SK/ESM, linked to C1 secrets.                                                                                                                                 |
| C3a/C3b | Correct recipient encryption of those shares under the C0 key, linked to C2 messages.                                                                                                     |
| C4a/C4b | The H selected received shares open their C2 commitments and form the normalized summed SK/ESM anchors.                                                                                   |
| C5      | Aggregate PK derives from exactly the H canonical dealer shares.                                                                                                                          |
| C6      | The decryption share derives from the anchored SK/ESM and ciphertext, in one canonical E3 domain. Full `d` enters Fiat-Shamir; the C7-facing commitment binds the configured native tail. |
| C7      | Exactly T+1 distinct ordered shares reconstruct every claimed message coefficient, including zeros.                                                                                       |

**C0 does not prove key generation.** A party can publish a bounded key it holds no secret for, such
as a copy of another party's key or zero. That key only receives the shares dealt to its owner:
dealers draw fresh encryption randomness per recipient and limb, C4 aggregates plaintext shares
pinned to C2 commitments rather than decrypting in-circuit, and accusations come only from failed
proofs or cross-proof commitment mismatches, never from a recipient failing to decrypt. A bad key
therefore exposes or loses only its owner's shares, which a corrupt party could publish or withhold
anyway. If encryption randomness is ever shared across recipients or recipients can blame dealers
for undecryptable shares, C0 must prove `pk0 = -pk1 * s + e` with `s` and `e` bounded as key
generation samples them; the equation alone holds for `s = 0`, `e = pk0`.

[DKG](dkg.md) defines identities, multiplicity, and roster links;
[threshold decryption](threshold-decryption.md) defines the domain and final verifier checks. Both
final verifiers are mandatory. The runtime `skip_proof_aggregation` setting works only with
`test-only-skip-proof-aggregation`; production rejects it. Test placeholders retain roster/domain
fields but production verifiers reject their proof bytes. There is no request-level bypass.

The table above describes the admitted SS chain. The isolated synchronized leaves below do not
replace its statements or authorize synchronized execution.

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
pins fhe.rs **v0.6.0**, with both native decryption features compiled but synchronized profile
admission disabled; do not substitute synchronized partials or local noise for the SS statement. The
additive smudging contract is `2^(lambda+1) * degree * B_C`, with preset/committee-specific bounds
generated from the matching Rust sampler. The preset search (`crates/bfv/params/src/search`) sizes
`q` with the same smudging bound and, for `b == 20`, `b_chi == 1`, and tabulated `d`, a
lattice-estimator 128-bit ceiling (`search::security`). Other inputs use the formula fallback and
print a warning; see [`crates/bfv/params/README.md`](../../crates/bfv/params/README.md) for the
limitation; `search_reproduces_secure_presets` and `search_reproduces_insecure_presets` keep its
moduli, plaintext moduli, and `ERROR1_VARIANCE` equal to the preset constants.

Every prover-chosen modular quotient needs a bound. Division/rounding are verified with a quotient
bound plus the unique remainder interval, not trusted because a hint computed them. In particular:

- `ModU64::div_mod` must check `result * divisor == dividend (mod modulus)` (IF-001).
- `ModU128::reduce_mod` does **not** constrain the quotient and so does not pin a prover-controlled
  remainder. It currently serves constant-only `bin/config`; `Polynomial::eval_mod` has no callers.
  Use `reduce_mod_bounded`/`inv_mod_bounded` for witness inputs, or repair and propagate bit widths
  through the primitive's arithmetic first. A remainder interval alone is insufficient.
- C7 derives u through bounded interpolation and Garner reconstruction, not witnessed `u_global` or
  CRT quotients. Its inverse and reduction hints are bounded. `rounded_decode` constrains quotient
  and remainder and compares every message coefficient (IF-002/IF-012). Every input to those helpers
  needs a quotient under `BIT_K` or valid inputs cannot be proven: the Lagrange products are reduced
  after every factor, so each quotient stays below the largest party id. Unreduced, the product of
  the other ids reaches `n!/(n-T)!` (about 2^35 at 19 parties).
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

When every other operand of an identity is exactly bounded, the integer identity already fixes its
quotient; the quotient's bound only has to rule out wraparound. C1's `r` and `e_sm` CRT quotients,
C6's `r`, and the user-encryption legs' `r` use the window `[-2^BIT, 2^BIT)`, one assert per
coefficient. Their generated bound arrays then only document the honest range, and `bin/config`
checks that each `BIT` covers its array. Bound-1 witnesses (C1 `sk`, C3 and user-encryption `u`) use
`c^3 = c`.

## Synchronized PRF and draft Minimum C6

The [isolated Noir gadget](../../circuits/lib/src/core/synchronized/prf.nr) consumes native
power-basis rows. `pnpm test:sync-prf` checks individual owners' masks against the locked `fhe.rs`
implementation with deterministic ciphertexts, keys and sets. The caller must select the correct
incoming/outgoing keys from the authenticated bundle. SAFE uses zero-padded
`fhe.rs/trbfv/prf/poseidon2/ctx` and `fhe.rs/trbfv/prf/poseidon2/eval` labels. The context absorbs
the designated count, sorted one-based IDs, level and component count, then each component's
CRT/ring dimensions and every native power-basis coefficient in ascending order, CRT-major.
Synchronized ciphertexts have two components at level zero. Keys map from all 32 little-endian bytes
modulo the BN254 scalar field. Evaluation squeezes one full field element per output coefficient,
reduced as a canonical integer under that CRT modulus; it does not extract three residues from each
field.

Full-field quotient hints must reconstruct an integer in `[0, p-1]`, not just the same scalar-field
value. At the maximal quotient, the remainder must also be at most `(p-1) % q`; ordinary quotient
and remainder ranges alone would admit an alias offset by p. Deferring per-peer mask reductions must
retain accumulator and final-quotient bounds. Neither optimization changes the PRF transcript.

This PRF context does not authenticate the Interfold E3 or DKG key provenance. The admitted C1–C7
chain and deployed verifier interfaces remain SS-only; neither native transport tests nor isolated
DKG leaves establish a synchronized proof chain or qualify secure-profile or repeated-decryption
behavior.

The disabled
[`sync-insecure-64/minimum` C6](../../circuits/bin/synchronized/threshold/share_decryption/src/main.nr)
opens the full C4 SK and bidirectional H-wide bundle. It derives the one-based PRF/Shamir set from
the first T+1 rows of the public, strictly ordered zero-based H roster. Only a designated owner may
contribute. C6 opens both components of the level-zero ciphertext and directly checks every native
coefficient of `d = λ · c1 · sk + e + mask` in the negacyclic ring. The direct product and integer
widths are for degree 64 only. One bounded integer per coefficient supplies the same noise across
every CRT limb. Its bound comes from the profile's native noise calculator; this does not prove how
or when the host sampled it.

The draft public fields are
`(setup[2], owner, roster[H], E3 decryption domain[2], aggregate SK, key bundle, ciphertext)`
followed by `(d commitment, c0 component commitment)`. The new `d` anchor covers **all** native
ascending coefficients, not the SS prefix. The c0 anchor is the component hash already inside the
ciphertext commitment, in centered descending order.

The disabled
[Minimum C7](../../circuits/bin/synchronized/threshold/decrypted_shares_aggregation/src/main.nr)
exposes exactly T+1 **complete C6 public rows**, in order, followed by the published native
plaintext coefficients. Row `i` must belong to `roster[i]`; setup, full H roster, E3 domain,
ciphertext and c0 must match across rows. Each raw share opens its own C6 `d` commitment; the single
c0 opens the common component commitment. C7 sums native residues with c0 once, then uses the
existing Garner reconstruction and rounded decode. All coefficients enter the openings even though
only the protocol's plaintext prefix is published.

`pnpm rust:test:sync-dkg:proofs` includes a real native C4/C6/C7 case. It compares the C7 public
prefix byte-for-byte to independently verified C6 proofs and rejects a substitution from another
independently proved set on the same ciphertext.

The isolated
[Minimum decryption aggregator](../../circuits/bin/synchronized/recursive_aggregation/decryption_aggregator/src/main.nr)
directly verifies both designated C6 proofs and the C7 proof. Each `noir-recursive` ZK leaf is
verified against its slice of one public C7 statement; there is no separately supplied copy of the
C6 rows. The two public child-key pins use bb's Poseidon2 hash of the actual VK fields. The final
`evm` proof exposes `(C6 VK hash, C7 VK hash, complete C7 statement)`. These are the only
descendants: this definition uses neither the SS sequential fold nor any SS VK.

The [native verifier](../../crates/zk/prover/src/synchronized/decryption.rs) compares both pins with
local synchronized artifacts; it checks the roster, setup, domain, ciphertext, designated SK/bundle
anchors and plaintext against independent expectations before verifying the outer proof. A generated
Honk verifier alone authenticates no chain state. An application wrapper must enforce those pins and
obtain the expected context and anchors from the confirmed request and synchronized DKG authority
before activation.

At `sync-insecure-64/minimum`, bb 6.0.0 measured 2,242,265 gates for the outer circuit. Its
generated Solidity verifier (solc 0.8.28) accepted the real 76-field statement and rejected a
changed plaintext coefficient. To export the public inputs, proof and VK for verifier testing, run
the ignored `threshold_decryption::` test in `synchronized_dkg` with `E3_SYNC_DECRYPTION_EXPORT` set
to a new directory path. This evidence covers the disabled Minimum definition only.

### Isolated synchronized DKG leaves (draft, not admitted)

`circuits/bin/synchronized/` defines C0–C5 and draft setup/publication joins only for
`sync-insecure-64/minimum`. C0 and C3 reuse the SS arithmetic with the separate transport
parameters. C1 proves a bounded threshold-key contribution without SS's dealt smudging branch. C2
proves the existing degree-T sharing relation, then commits the native packed messages and an N-wide
outgoing-key root. C4 opens those packed messages, extracts incoming keys, and commits the centered
sum of unpacked SK residues plus a bidirectional H-wide key bundle. **C4 does not prove a BFV
decryption equation.**

Public fields flatten in declaration order; return values follow inputs:

| Leaf | Public inputs                                                                                                  | Public outputs                                               |
| ---- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| C0   | none                                                                                                           | transport PK commitment                                      |
| C1   | setup binding `[2]`, zero-based dealer                                                                         | SK, threshold PK commitments                                 |
| C2   | setup binding `[2]`, dealer, expected SK commitment                                                            | packed message commitments `[N][L_threshold]`, outgoing root |
| C3   | expected transport PK, packed message commitments                                                              | ciphertext commitment                                        |
| C4   | setup binding `[2]`, recipient, dealer IDs `[H]`, expected outgoing root, expected messages `[H][L_threshold]` | aggregate SK, key-bundle commitments                         |

The profile ID is the profile/committee crypto-config ID split into high/low 128-bit big-endian
limbs, compiled into these packages. `SetupBinding = [u128; 2]` is an opaque **caller-supplied**
context: the leaves only bound it, not derive or authenticate it. The draft `interfold:sync-dkg:v1`
SAFE domain uses a leading absorbed role (directed key 1, outgoing root 2, bundle 3, C1 challenge 4,
dealer batch 5). Key commitments absorb all 32 bytes as separate fields, not the PRF's lossy
key-to-field map. Directed keys bind profile, context, N, key width, dealer and recipient. The root
orders all N recipients. The bundle binds its owner, aggregate SK, exact sorted H dealer IDs and
both key directions for each; outgoing keys are indexed by full-committee ID, not roster position.
Own incoming/outgoing keys must agree. H is not trimmed to the designated T+1 set. The generic C4
opening supports H≤N, while the current recursive joins require H<N. The supported profile fixes N=3
and H=2; H=N is not an admitted configuration. Broadening that boundary requires new recursive and
publication qualification, not just the generic C4 constraint.

Before runtime use, reviewed recursive joins must authenticate the canonical E3-derived context and
H-roster, connect C1's SK to C2, C2's exact recipient/CRT message to C3 and C4, C3's key to C0 and
ciphertext to the signed transport, and the owner's C2 outgoing root to C4. C6 must open the same
aggregate SK and bundle. A consistent context/dealer substitution can produce a valid isolated leaf
with different public fields/outputs; it is not evidence of authentication. Canonical context
derivation now has a [draft native owner](dkg.md#exchange-and-verification-boundaries), and keyshare
checks signed transport and complete C2-batch openings. The draft joins below add recursive
enforcement of child consistency, not chain authority or registry publication authorization. The
draft Minimum C6 consumes the two C4 commitments without an ESM placeholder. The joins,
root/bundle/batch schema and setup derivation require protocol review before consumers freeze them.

`pnpm rust:test:sync-dkg:proofs` exercises the actual typed encoders and native encrypted transport,
including non-prefix H, self/outside-H recipients, real private-input leaf and join/publication
proofs, altered public fields and malformed witnesses. Its provenance child verifies independently
valid but mismatched children before checking their rejection by the parent. The publication case
also checks the real EVM proof through the draft Solidity wrapper. It does not qualify registry
publication/attestations, recovery, secure-profile, replacement-set or repeated-decryption behavior.

The [keyshare preparation proof test](../../crates/orchestration/keyshare/README.md#tests)
additionally starts from production native generation and encrypted runtime work plans, exercises
the C1/C2/C4 request adapters, and verifies their leaf proofs, including self/outside-H recipients.
Native keyshare tests cover saved key/bundle validation, exact work-plan reload and authenticated
rejection before slot reservation. The explicit recovery qualification also joins reopened runtime
artifacts through C5/publication verification in Rust and Solidity, comparing independently
recovered/native C1/C4/key/batch expectations. Its complementary durable-log replay case uses
synthetic statements. Neither qualifies hard-crash recovery, whole-node startup or live registry
execution of the synchronized protocol.

### Draft synchronized provenance joins (not admitted)

The synchronized `NodeFold` is a **dealer join**, not the SS C0–C4 node fold. It verifies C1, C2 and
exactly `(N−1)×L_THRESHOLD` ZK C3 proofs in recipient/CRT order, omitting self without a dummy
proof. It joins C1's SK to C2, every non-self C2 message to C3, and every encrypted CRT row to the
same recipient key. It exports context/dealer, descendant VK hash, threshold PK, outgoing root,
N-wide messages, recipient keys and ciphertexts. Self C3 slots are zero; self C2 messages remain
present.

The synchronized `NodesFold` is a **per-recipient setup join**, not an SS sequential accumulator or
the C5/publication wrapper. It verifies H dealer joins plus that recipient's C0, C2 and C4. Its
public inputs are the expected descendant-tree hash, setup binding, recipient and exact sorted
H-roster. Each H-row's C2 message at the full-committee recipient slot must equal C4's opening for
every threshold CRT row. Every non-self dealer's C3 key must equal the recipient's C0; the dealer
join has already constrained this across all encrypted rows. C4's outgoing root must equal the
recipient's own C2, including for recipients outside H. A selected recipient's own C2 messages/root
must also equal its dealer join. The return is H threshold-PK commitments, aggregate-SK commitment
and bidirectional key-bundle commitment, together with a commitment to the complete H ordered dealer
public rows. That batch anchor includes the exact C2 messages/roots and C3 key/ciphertext
commitments; a matching threshold PK alone does not identify the successful randomized fan-out. Its
SAFE payload is
`[5, profile[2], setup_binding[2], N, KEY_BITS, H, L_THRESHOLD, flatten(H complete dealer public rows)]`
in the existing DKG domain. Proof bytes are not hashed: reproving the same public contribution does
not replace the batch. Those commitments are a draft handoff, not a C6 witness.

For the current definition, dealer IO is **3 inputs/24 outputs**; recipient IO is **6/5**. These
layouts are profile-specific; no identity enum discriminant or SS layout changes. The complete
genealogy is `dealer = VK_HASH(C1,C2,C3)` and `setup = VK_HASH(NodeFold,dealer,C0,C2,C4)`. All H
dealer hashes must agree, and the recipient circuit compares the complete setup hash with input
zero. The verifier derives that expected hash from its local artifact keys, never from the received
proof. Pinning only NodeFold's VK would leave its private leaf VKs unanchored. The C0 commitment
authenticates neither a recipient identity nor possession of its secret key. The runtime must
independently admit the recipient's signed C0 under its full-committee owner; recipient execution
must use its locally planned C0 slot. Recursive consistency with a caller-supplied C0 alone is
insufficient.

The explicit prover API checks request-derived binding, recipient, roster, exact field layouts and
genealogy before returning verified setup commitments. It also requires the caller's previously
admitted C4 aggregate-SK/bundle, dealer-batch and selected C1/C5 threshold-key commitments to match;
candidate outputs cannot supply their own authority. It does **not** authenticate those expected
values or caller-supplied chain context/roster, or replace signature admission. A different
consistently selected setup is not rejected without canonical external authority. These joins prove
neither C4's BFV decryption equation nor publication authority. The runtime still refuses
synchronized folding/publication; human protocol review, guarded actor/writer integration, full-node
replay and on-chain decryption authority binding remain open.

The typed local definition executor reuses these proof/verification owners. Recipient results must
match independently supplied setup/owner and C1/C4/batch anchors; publication results must also
match the independently aggregated native PK. Invalid context, witness inputs or independent
expectations are permanent parameter errors, including malformed external child-proof shapes against
the loaded ABI. Incompatible locally generated proof shapes or a loaded ABI with the wrong canonical
fan-out are local failures. Independent statement mismatches take precedence over local genealogy
failures. Unusable local VK fields or inconsistent verifier-key genealogy, missing artifacts/process
failures, malformed generated public signals and cryptographic rejection of a locally generated
proof remain local generation failures, not peer-invalid verdicts. Runtime requests still fail
disabled-profile admission before artifact access; real qualification invokes the definition API
explicitly, without a production bypass flag.

### Draft synchronized C5/publication boundary (not admitted)

C5 reuses the bounded public-key aggregation statement with the synchronized profile's threshold
parameters and CRS. The final `DkgAggregator` verifies exactly H recipient setup proofs in the
selected dealer order and one C5 proof. All recipient rows must name the same context, roster,
complete descendant tree, threshold keys and **dealer batch**; C5 opens those exact ordered keys. It
needs no N-wide C4 set and no SS smudging placeholder.

The full setup pin is `VK_HASH(NodesFold, setup-descendants)`; C5's non-ZK VK is pinned separately.
The final EVM public inputs are these two pins, setup binding `[2]` and dealer IDs `[H]`. Outputs
are batch, threshold keys `[H]`, aggregate SK anchors `[H]`, key bundles `[H]` and aggregate PK
commitment: **6 inputs/8 outputs** at H=2, or **6+4H** total fields. No ESM lane is reinterpreted.

Rust verification compares the native expected PK commitment, admitted C1/C4/batch anchors and
canonical context/roster before returning a read-only handoff. The isolated
`SynchronizedDkgPublicationVerifier` recomputes the setup binding from chain ID, configured
Interfold/configuration ID, full E3 ID and raw-address committee hash, checks the expected roster,
batch/PK and complete VK pins, then verifies the EVM proof. Its constructor accepts only the
disabled synchronized insecure-64/minimum identity and canonical N/H. The caller still authenticates
the request-frozen facts. This contract is deliberately not an `IPkVerifier` route and is absent
from deployments. The separate registry entry below supplies authority; the SS registry's ESM field
cannot stand in for a bundle.

### Synchronized registry authority (unactivated)

`publishSynchronizedCommittee` uses the request's frozen controller, configuration ID, full
canonical committee and proof wrapper, never publication-supplied deployment facts or the registry's
current global SS attestation verifier. A final proof alone is insufficient: **all H selected
recipients**, not a T+1 shortcut or all N members, must sign the same setup, ordered roster, dealer
batch and aggregate PK, each with its own full-committee party ID and SK/key-bundle anchors. Every
signer must still be active at publication. The roster is strictly increasing full-committee IDs;
H-row positions do not replace them. The batch binds the proof's complete selected contributions and
threshold-key rows.

The EIP-712 domain is `InterfoldSynchronizedDkgAttestation`, version `"1"`, with chain ID and the
request-frozen proof-wrapper address as `verifyingContract`. The struct additionally binds the
registry, **full uint256 E3 ID**, configuration ID and setup binding.
`rosterHash = keccak256(abi.encode(uint256[] partyIds))`, including ABI offset and length, not a
packed address hash. Exact field types/order are owned by
[`SynchronizedDkgAttestationLib`](../../packages/interfold-contracts/contracts/lib/SynchronizedDkgAttestationLib.sol);
no SS signature/domain or ESM commitment is reused.

At request time `SynchronizedDkgContextEstablished` supplies that domain from the frozen request
wrapper, separately from the SS context event. Native EIP-712 encoding has an independent ethers
digest/signature vector with an E3 ID above 2²⁰⁰, and rejects high-S/non-EVM signature encodings
rather than normalizing them.

The registry stores
[Authority v1](../../packages/interfold-contracts/contracts/interfaces/ISynchronizedDkgPublication.sol)
in append-only storage, with the three commitment columns in selected H order, and emits the full
authority for replay. Version zero means absent, including for SS publications. The existing
canonical-key callback still enforces lifecycle deadlines; its rejection atomically rolls back
authority and key writes. The ordinary SS entry rejects the synchronized identity. SS publication
checks, anchors and existing ERC-165 identities are preserved; linked `DkgPublicationLib` owns both
publication paths to fit EIP-170 under the normal compiler settings.

The shared native projection requires confirmed request/context, authority and proof observations to
agree on configuration, setup binding, ordered roster, batch and every commitment column. It does
not reverify a confirmed chain proof or obtain authority from gossip, an aggregation intent or an
opportunistic registry read. Terminal history removes the retained setup/context and key bytes, with
the existing snapshot-hydration roster exception. Unsupported context/authority versions fail
recovery and signal fatal event-pipeline health live, closing subsequent admission without creating
authority. This does not synchronously cancel fanout of the already-admitted event.

Mock-proof registry tests establish consent/rollback/storage behavior, not proof soundness. The
prepared recovery suite also uses an actual generated verifier and a locally deployed registry, with
native H signatures, authority readback, chain PK chunks and a reopened confirmed journal. The
finalized selection/controller lifecycle are test harnesses below disabled request admission, and
proofs are driven explicitly. This is not a guarded production actor/writer workflow, whole-node
startup, reorg/hard-crash assurance, C6 or a source-bound release. Admission stays disabled. The
domain, authority schema and deployment/rollback decisions remain unratified protocol interfaces
requiring human cryptographic and compatibility review.

## Commitments, packing, and Fiat-Shamir

Packing uses shared carriers `acc = acc * radix + (v + base)`. A digit overflowing its slot can
cancel into its neighbor and preserve the carrier. Therefore one hash can have several coefficient
openings unless every digit fits its slot. A `u64` cast is not enough when `base` leaves less than
64 usable bits (the old C2b case).

**Injectivity is not canonicality.** `pack_checked` pins `digit < radix`; it transfers an upstream
creating circuit's canonical bound because the opening must equal the committed value. It does not
create a canonical bound where no upstream statement proves one. C1's originating `pk0` and C5's
unanchored `pk0_agg` need explicit centered bounds. C0 bounds its key, so C3 opens it checked and
inherits the bound; an out-of-range key fails its owner's C0, not every dealer's C3. C0 does not
prove correct key generation or possession of a secret key. C5's per-party keys and C4's received C2
shares likewise inherit through checked openings. C4 normalizes its derived aggregate in circuit; it
does not need a second opened-witness bound. Run the binding check **before** commitment comparison.

User encryption has no upstream circuit for its key. ct0 opens `pk0` with checked digits, which
rules out wraparound but not a non-canonical key; the exact centred bound comes from C5 only through
the committee-key anchor. Any program accepting `user_data_encryption` proofs must compare their
`pk_commitment` with the committee key, as CRISP does. ct1 hard-codes `pk1` as the CRS that C5
commits as `pk1_agg`, so only keys on the default-seed CRP, which every committee key is, can be
proven. Both legs read one `u` witness: ct0 bounds and commits it, and ct1 reuses that commitment
(`execute_with_u_commitment`), which is sound only with the commitment of the same `u` it reads.

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

`e3-zk-config` owns static bounds, widths, and public layouts. `Configs::new` retains an existing
BFV parameter owner; constructors check the ring, CRT basis, and sampler profile. C3 and user
encryption share derived `k0is` across bounds, rendering, and preparation. Configuration needs no
witness, sample, secret key, or prover.

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

Sequential C3, C6, and nodes folds keep `(leaf, fold, kernel)` VK hashes constant across
predecessors. The kernel proves the chain's first leaf at that leaf's slot; every fold step carries
its predecessor's rows forward, the kernel's included, and adds one leaf to an empty slot. A chain
of `n >= 2` leaves is one kernel and `n - 1` fold proofs. The first step verifies the kernel;
continuation verifies the fold; the final consumer binds the declared fold hash to the verified VK.
C3ab covers both complete C3 chains. Node-fold covers child folds and their nested keys. DKG
aggregation requires one node-tree hash across every selected row.

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
  slows it. Measure `user_data_encryption` and ballot circuits before shipping added constraints;
  soundness repairs cannot be dropped to meet the ceiling.

[History](protocol-history.md) retains finding IDs and evidence scope, not current audit assurance.
The compute path, Rust witnesses, OpenVM guest/prover, and receipt verifiers were not covered by the
two scoped Zenith Solidity audits. See
[audit scope](../../packages/interfold-contracts/audits/README.md).
