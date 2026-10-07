# Invariants — Cryptography / circuits

Scope: `circuits/`, `crates/zk-prover`, `crates/zk-helpers`, `crates/trbfv`, `crates/fhe-params`,
the BFV and OpenVM receipt verifier contracts, `crates/compute-provider`, and the CRISP example.
Committee config sync, Noir/Barretenberg compatibility, DKG and threshold structure, proof binding
and domain separation, and E3 program input rules.

Read `00_INDEX.md` first: it carries the meta-invariants and the open-issues list that apply to
every section.

## Cryptography / circuits

### Committee config sync (the `check:committee` gate)

- Committee `(N, T, H)` and each complete BFV parameter tuple must stay synchronized.
  `scripts/check-committee.sh` fails when these copies disagree: committee values in
  `circuits/lib/src/configs/committee/<name>/mod.nr`,
  `crates/zk-helpers/src/ciphernodes_committee.rs`, `ActiveCryptoConfig.sol`, and
  `packages/interfold-contracts/scripts/utils.ts`; the threshold BFV tuple in
  `packages/interfold-contracts/scripts/protocol/constants.ts`,
  `crates/fhe-params/src/constants.rs`, and
  `circuits/lib/src/configs/{insecure,secure}/threshold.nr`; and the configuration IDs in
  `utils.ts`, `ActiveCryptoConfig.sol`, `tasks/interfold.ts`, `packages/interfold-sdk/src/utils.ts`,
  and `crates/evm-helpers/src/contracts.rs`. Drift means a deployment can register parameters that
  ciphernodes or circuits do not implement. Write the generated values only with
  `pnpm build:circuits` or `pnpm build:circuits sync-config --preset <name> --committee <name>`. The
  committed generated selection is `insecure-512/minimum`: the CI circuits job rebuilds with the
  defaults and fails on a diff. `circuits/bin/.active-preset.json` is a local cache; a mismatch only
  prints a note. `scripts/circuit-constants.ts` also holds committee values, and the gate does not
  compare it.
- Canonical sizes: `minimum` (3,1,2) · `micro` (9,4,5) · `small` (19,9,14) — must mirror `mod.nr`
  and `CiphernodesCommitteeSize::values()`. — `scripts/circuit-constants.ts`
- Each supported `(preset, committee)` pair has its own `BfvPkVerifier` (public-input layout set by
  H) and `BfvDecryptionVerifier` (layout set by T). `BfvPkVerifierRouter` and
  `BfvDecryptionVerifierRouter` dispatch by public-input length and VK anchors, and their routes are
  fixed at construction. Selecting another committee needs no redeployment if the installed verifier
  mappings already support that pair. Otherwise, register matching verifiers, and deploy any missing
  wrappers or replacement routers first. A changed circuit or VK needs new wrappers and, where a
  router is used, a new router and new `setPkVerifier` / `setDecryptionVerifier` calls. —
  `protocol/deployContracts.ts`; `BfvPkVerifierRouter.sol`
- Parity matrices (`parity_{insecure,secure}.nr`) are derived artifacts regenerated from preset
  `QIS` + committee `(N, T)`. Do not hand-edit them. `scripts/check-committee.sh` regenerates and
  diffs them only when `target/release/generate_parity_matrices` and `nargo` exist; the Agent
  Harness CI job skips that step. The CI circuits job catches edits to the committed selection
  through its rebuild diff.
- The C1 and C2 bound globals (`PK_GENERATION_*`, `SHARE_COMPUTATION_*`) are derived artifacts of
  the preset and committee. The build regenerates them for the selected pair and replaces each whole
  declaration, array bounds included. It rejects a declaration with its config file's prefix that
  the generator does not emit, because the pair source hash ignores those declarations. The C1
  `e_sm` quotient bounds grow with the committee, so an array kept from another committee makes
  honest C1 proofs fail. The committed configs hold the `minimum` values. —
  `scripts/build-circuits.ts` (`committeeBoundUpdates`); `scripts/circuit-artifacts.test.ts`

### Noir / Barretenberg compatibility

- Treat Nargo, the Rust Noir crates, witness serialization, Barretenberg, circuit release archives,
  verification keys, and generated Solidity verifiers as one compatibility unit. The current unit is
  Nargo and Rust Noir `1.0.0-beta.26` with Barretenberg `5.1.0`. The same pins also appear in the
  SDK's `@noir-lang/noir_js` and `@aztec/bb.js`. No script checks that these pins agree. —
  `.github/workflows/ci.yml` and `releases.yml`; `crates/zk-prover/versions.json`;
  `crates/zk-prover/Cargo.toml`; `packages/interfold-sdk/package.json`
- Rust-generated witnesses must use `WitnessStack::serialize()`. Do not serialize a witness stack
  with `bincode`; Barretenberg 5 accepts the beta.26 MessagePack format markers, not the legacy
  marker. — `crates/zk-prover/src/witness.rs`
- Rebuild and publish circuit archives with the pinned Nargo version before changing
  `required_circuits_version`. Regenerate all dependent verification keys and Solidity verifiers
  with the pinned Barretenberg version. A release archive from an older serialization format can
  pass checksum verification but fail during ACIR decoding or proof generation.
- `required_circuits_version` must equal the Interfold release version, without the `v` prefix. The
  release workflow rejects a different value because the ciphernode resolves both the GitHub release
  tag `v{version}` and `circuits-{version}.tar.gz` from this field.
- A circuit release archive that supports current deployments must include every
  `insecure-512/{minimum,micro,small}` and `secure-8192/{minimum,micro,small}` pair. Each pair has a
  build stamp with the exact preset, committee, and source hash. `checksums.json` and `SHA256SUMS`
  must cover the archive artifacts. Nodes select the artifact directory from the E3's on-chain
  parameter set and committee size. `download_circuits` checks the archive SHA-256 against
  `ZkConfig::circuits_checksums[required_circuits_version]` before extraction. Missing pins fail
  closed. Both download and local archive installation require a nonempty SHA-256 `checksums.json`,
  verify each entry, and reject uncovered artifact files before replacement. Download and local
  archive installation require every pair in `crates/zk-prover/supported-configurations.json` by
  default. Release tooling uses the same matrix. A local or CI caller can request a nonempty subset
  through `download_circuits_for_configurations` or `install_circuits_archive_for_configurations`.
  The CLI accepts repeated `--circuits-configuration` options only with `--circuits-archive`.
  Required pairs never depend on archive contents. Each required or included pair must contain every
  path in `crates/zk-prover/required-artifacts.json`, with a verified manifest entry. The release
  tooling's `requiredArtifactMarkers` uses that same inventory. Root manifests, `SOURCE_HASH`, and
  build stamps are metadata, not required prover artifacts. Validation failure preserves the
  installed circuits and `version.json`. Installation errors trigger best-effort rollback and remain
  the returned error even if rollback fails. Each rollback failure logs its source and target paths.
  If restoration of the previous circuits fails, the installer retains the staging directory and
  logs its path for recovery. — `crates/zk-prover/src/backend/download.rs`
- Archive pins ship with the binary; neither the archive nor its download endpoint supplies the
  expected digest at runtime. The 0.18.0 pin comes from the published GitHub asset digest. Local
  archive installation trusts the operator's file and does not require a release pin. Release
  packaging supplies `E3_CIRCUITS_ARCHIVE_SHA256` before binary and ciphernode image compilation.
  `build.rs` validates the digest, and `ZkConfig::default` binds it to the crate version. Other pins
  remain in `versions.json`. The workflow retains the same archive bytes for publication.
  `SOURCE_HASH` identifies circuit sources, not archive bytes, and cannot replace this check.
- Artifact identity must cover every source that compiles into an artifact. `computeSourceHash`
  (`scripts/build-circuits.ts`) includes shared Noir logic, the library entry point and dependency
  manifest, and shared configuration constants. It normalizes the active preset selector because
  each pair already identifies its preset. A library-only change invalidates every affected pair.
  Rebuild and push those pairs before release.
- The pair source hash ignores generated C1/C2 bound values and includes the Rust sources that
  generate them, without their `#[cfg(test)]` modules. Switching the active committee or editing a
  test module must not change another pair's source hash.
- The source hash reads `Cargo.lock` for external crate pins only: name, version, source, and
  checksum. A workspace version bump or a dependency edit inside the workspace must not make the
  published artifact matrix stale. — `scripts/build-circuits.ts`
- Restamp published artifacts only when the branch records the source hash that the current tree
  produced under the previous hash scheme. Artifacts from another tree need a rebuild. —
  `scripts/circuit-artifacts.ts`

### DKG / threshold structure

- Plaintext collection starts verification at **T+1** distinct accepted-roster shares, not at H.
  Every selected raw share must match its C6 commitment for each ciphertext output. Bad early shares
  must not prevent the use of valid backups while T+1 roster parties remain possible. A local C6
  result authorizes only its exact dispatch batch. Share admission checks the signed sender, E3,
  proof type, raw bytes, and ciphertext position before reserving a party slot. — `flow-trace/04`

- SK splits into N shares; exactly **T+1** shares feed the recursive decryption proof. —
  `flow-trace/04`
- Runtime `party_id` derives from the finalized committee normalized by ascending address and is
  zero-indexed. DKG circuit party IDs and fold-attestation slots use the same zero-based index. Only
  decryption uses one-based Shamir coordinates, `party_id + 1`, which must be strictly increasing;
  `BfvDecryptionVerifier` subtracts 1. Convert once, at that boundary. The active aggregator is the
  lowest eligible runtime `party_id` after exclusions and the current phase's durable
  unresponsive-party set. — `ARCHITECTURE.md`; `flow-trace/04`
- Every committee member persists validated aggregation inputs. Failover starts only after
  `AggregationInputsReady` confirms that the phase can resume from durable state. Standbys keep
  their local C6 outcomes for failover. Only the active party can launch aggregation effects. Only
  it applies their results, except that an aggregator demoted by failover finishes the work that it
  started (public key: C1 verification onward; plaintext: C6 verification onward) and publishes the
  result; the first valid result on chain wins. A demoted public-key aggregator stops once a key is
  on chain, and a C1 result after key publication changes nothing. — `flow-trace/04`; INDEX concerns
  #42, #68
- The active aggregator proposes a canonical H-dealer DKG roster only after it derives `H` mutually
  ready dealers from signed Ready reports; a promoted aggregator reuses an already accepted roster.
  A receiver keeps one authenticated roster per proposer. It accepts a roster only from a proposer
  whose party ID is at most the active party ID from `AggregatorChanged`, and only when its local
  Ready state supports that roster. Before C4 starts, a roster from a lower party ID replaces an
  accepted roster from a higher one, and an expelled dealer of an accepted roster is not an honest
  party; after C4 starts, the accepted roster is fixed. **Gap:** after a restart, the store can
  refuse the write that fixes it as stale; memory keeps it and the next state write saves it, but a
  second restart before that write lets a lower-ranked roster replace the roster that C4 used.
  Accepting a roster ends only the DKG-roster failover phase. Public-key aggregation receives a new
  readiness-gated failover budget. —
  `crates/keyshare/src/threshold_keyshare/effects/coordinate_roster.rs`; `flow-trace/04`; INDEX
  concerns #42 and #52
- DKG dealer identity binds the public proof statement, not randomized proof bytes. Replacing a
  same-E3 proof plan must invalidate every prior correlation ID before the replacement can accept
  responses. — `flow-trace/04`
- A DKG dealer slot accepts only a message authenticated by that finalized committee member.
  Threshold-share signatures bind the E3 (including chain ID), dealer, recipient, share bytes, and
  complete C2/C3 bundle. C4 signatures bind the E3, dealer, node address, and complete proof bundle.
  Individual proof signatures remain the evidence for proof failures. An unrecoverable signature or
  a mismatched signer cannot name the claimed dealer in an accusation. —
  `crates/events/src/interfold_event/{threshold_share_created,decryption_key_shared}.rs`;
  `crates/keyshare/src/threshold_keyshare/effects/coordinate_collectors.rs`; `flow-trace/04`
- A local C2/C3 result counts only for the share batch that its dispatch carried. A result of an
  earlier batch must not count a dealer that only a later, grown batch holds as verified. —
  `crates/keyshare/src/threshold_keyshare/effects/verify_threshold_shares.rs`; `flow-trace/04`
- DKG aggregation receives **exactly H** canonical honest NodeFold proofs (unique in-range party
  IDs) and **exactly N** ordered committee addresses; every supported committee size has `H < N` —
  never assert `H == N`. A mixed Some/None NodeFold set is a local test-configuration mismatch.
  Preserve the aggregation inputs and do not report invalid committee shares. — `ARCHITECTURE.md`;
  `flow-trace/04`
- The `dkg_aggregator` circuit requires strictly ascending, in-range H-party IDs. The on-chain
  fold-attestation verifier repeats that check, so both proof consumers use the same roster order. —
  `flow-trace/04`
- In the DKG aggregator, C3 key slots and C2 share slots use the selected recipient's full-committee
  `party_id`. C4 expected-commitment slots use the sender's position in the H-row fold. These
  indices differ when the selected H-subset skips a committee member. — `flow-trace/04`
- **A key the fold exports must be constrained across every slot it stands for, not just the slot it
  is read from.** `node_fold` reduces each recipient's C3 key to one value by taking limb zero, and
  `dkg_aggregator` links only that value to the recipient's C0 key. Asserting `pk_a == pk_b` per
  slot is not enough: a prover puts the real key in limb zero and a different one in a later limb,
  matching across C3a and C3b, and the exported key stops representing what the other limbs
  encrypted to. `assert_c3_recipient_keys` now pins every limb to limb zero. A comment asserting an
  invariant ("same DKG key across all moduli") is not a constraint — this gap was exactly that
  comment being believed. — `flow-trace/04`
- A recipient outside the selected H dealers builds C4 from all H encrypted dealer shares. It must
  not replace a selected dealer share with its own plaintext share. A selected recipient uses its
  plaintext share only at its own row. — `flow-trace/04`
- Proof multiplicity: C2a/C2b singleton per recipient; C3a/C3b follow configured Shamir
  multiplicities. Witness dimensions come from the **active preset**, never incidental vector sizes.
  — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`
- fhe.rs v0.4.1 derives additive smudging bounds as `2^(lambda + 1) * degree * B_C` and uses
  sampler-specific encryption error bounds. The C1/C2 Noir bit widths must use the same bounds as
  the Rust sampler for each preset and committee. Regenerate them with `pnpm build:circuits`;
  rebuild the matching verifier artifacts before deploying a protocol-version-7 node. —
  `flow-trace/04`; `scripts/build-circuits.ts`
- fhe.rs v0.4.1 passes plaintext-scaled ballot coefficients as non-centered residues. Both CRISP
  vote circuits must check `Q_MOD_T`, rather than `Q_MOD_T_CENTERED`, against those coefficients. —
  `examples/CRISP/circuits/bin/{crisp,crisp_onchain}/src/main.nr`
- The C3 and user-data-encryption `k1` witnesses use non-centered residues in `[0, t - 1]`. Their
  Noir equations and asymmetric quotient bounds must match the Rust witnesses. —
  `circuits/lib/src/core/dkg/share_encryption.nr`; `crates/zk-helpers/src/circuits/`
- Mainnet secure parameter-set index 1 contains the old tuple. Version 7 registers the new tuple at
  index 2 and must not reinterpret old index-1 E3s as version-7 secure requests. — `flow-trace/07`;
  `crates/fhe-params/src/presets.rs`; `ActiveCryptoConfig.sol`
- The local C1, C2a, C2b, and every C3a and C3b proof must complete and be signed before any
  `ThresholdShareCreated` is published. C4 through C7 belong to later phases. —
  `crates/zk-prover/src/proof_request/effects/publish_threshold_shares.rs`; `flow-trace/04`
- The decrypted plaintext is exactly 50 u64 coefficients in every layer: `MAX_MSG_NON_ZERO_COEFFS`
  in Noir (`configs/default/mod.nr`, written by `scripts/build-circuits.ts`) and in `zk-helpers`,
  and `MESSAGE_COEFFS_COUNT` in `BfvDecryptionVerifier.sol`. **Gap:** no gate compares these copies.
- A CRT consistency equation of the form `lifted[j] == limb[i][j] + quotient[i][j] * q_i` constrains
  nothing on its own: `q_i` is invertible modulo the proof-system prime, so every limb admits a
  quotient that satisfies it. It binds the witnesses only when the lifted value, the limbs **and**
  the quotients all carry range checks that keep the term sum far below the prime, which is what
  makes the equation hold over the integers. C1's `e_sm` lift relies on all three bounds. ct0 and C3
  use `e0` directly in reduced encryption identities. Their reduction quotients and all operands
  carry bounds that prevent field wraparound. — `flow-trace/04`
- Apply a bound where the quantity it describes actually lives. The smudging bound `e_sm_bound` is
  an integer bound and belongs on C1's lifted `e_sm_lifted` witness; on secure presets it exceeds
  every `q_i`, so checking a CRT residue against it is satisfied for free. Limbs carry the modulus
  bound `(q_i - 1) / 2` instead. — `flow-trace/04`
- C1 commits to the `e_sm` **residues**, not the lifted value, so C2b keeps hashing what it
  Shamir-splits. The integer bound reaches C2b through that commitment: C1 proves the limbs are
  bounded and hash to it, C2b proves its own limbs hash to the same value. `PK_GENERATION_BIT_E_SM`
  and `SHARE_COMPUTATION_E_SM_BIT_SECRET` are the same modulus width and must move together. —
  `flow-trace/04`
- A circuit that re-opens a commitment from a private witness must constrain that witness, because
  the commitment packs `BIT`-wide coefficients into shared carriers
  (`acc = acc * radix + (v + base)`). An unbounded coefficient overflows its slot and cancels
  against the next one, leaving the carrier — and so the commitment — unchanged, so one commitment
  has many openings and the prover chooses which the circuit sees. — `flow-trace/04`
- **Injectivity is not canonicality, and only injectivity transfers.** Asserting each packed digit
  fits its slot (`pack_checked`, one `assert_max_bit_size::<nibble_bits + 4>()`) makes the opening
  unique, so the opened coefficients must _equal_ the ones the creating circuit committed — its
  canonical bound carries over and need not be repeated. That is all an opener needs: C5's per-party
  `pk0` (bounded by C1) and C4's shares (bounded by C2) rely on it, at half the cost of a two-sided
  range check. A value that no upstream commitment bounds still needs its own bound: C1's `pk0`,
  because C1 originates it and the key equation absorbs `+q` against `r1`; and C5's `pk0_agg`,
  because `verify_pk_for_basis` pins it only modulo `q_l`. — `flow-trace/04`
- Every prover-chosen modular quotient needs a bound. This includes C1's `e_sm` CRT lift and the
  reduced encryption quotients in ct0, ct1, and C3. Bounds on the other operands must also prevent
  field wraparound. — `flow-trace/04`
- C7 derives `u` through bounded interpolation and `garner_reconstruct`; it accepts neither
  `u_global` nor CRT reconstruction quotients as witnesses. `reduce_mod_bounded` and
  `inv_mod_bounded` constrain every reduction and inverse hint used by that path. The rounded decode
  constrains its own quotient and remainder. — `flow-trace/04`
- **`ModU128::reduce_mod` does not pin its remainder; use `reduce_mod_bounded` for anything a prover
  controls.** It asserts `n == q * quotient + remainder` with `remainder < q` but never bounds the
  quotient, and the equation is over the field — so a prover picks any `remainder` in `[0, q)` and
  solves for a matching quotient. Verified: the constraint set accepts `(2, 50)` and
  `((250 - 51) / 100, 51)` alike for `250 mod 100`. Same unbounded-quotient shape as IF-012. It is
  unreachable today only because its one production caller, `bin/config`, is `fn main()` with no
  inputs, so every value it reduces is a `pub global`; `Polynomial::eval_mod` has no callers at all.
  `reduce_mod_bounded` / `inv_mod_bounded` bound the quotient and stand beside it for witness use.
  If `ModU128` ever gains a caller with a prover-supplied input, that caller must use the bounded
  pair or the primitive must be fixed — which means threading a bit width through `add`, `sub`,
  `mul_mod`, `div_mod` and `inv_mod`. — `flow-trace/04`
- **Division and rounding are verified, never computed.** Noir has neither, and neither is needed:
  `round(a / b)` is `floor((a + (b-1)/2) / b)`, and a floor is a hint plus two constraints — bound
  the quotient, and put the remainder in `[0, b)`. That pair is unique for a given numerator and
  divisor, so a wrong hint cannot satisfy both. Every hint in the reduced circuits follows this
  shape (`reduce_mod_bounded`, `inv_mod_bounded`, `rounded_decode`), and an `unsafe` hint without
  both checks is a defect. A quotient bound may be loose — the remainder interval is what pins the
  result — but it must never be absent. — `flow-trace/04`
- **Reducing an identity modulo `X^N + 1` removes the cyclotomic quotient, and the bounds that
  replace it must be real, not injectivity.** `negacyclic_kernel` evaluates `a * u mod X^N + 1`
  without the product entering the witness, which deletes the quotient witness and its range check.
  What the reduced form then needs is a genuine bound on every coefficient it reads, because it is
  checked at one point and the field equality only implies the integer one when nothing can wrap.
  Those bounds make the plain packing injective as a side effect, which is why the IF-013 digit
  asserts came back out of ct0/ct1/C3/C7 rather than stacking with them. — `flow-trace/04`
- **The enumeration axis is "every prover-chosen witness that reaches the sponge", not "every
  commitment opened from elsewhere".** Fiat-Shamir is only sound while `gamma` is independent of the
  witness, and that holds exactly while the packing carrying the witness into the sponge has one
  opening. Enumerating the narrower class missed four members: C6's `d` and C3's `ct0is` / `ct1is`
  reach the transcript through `flatten` directly, and ct0 / ct1 reach it through commitments they
  _create_ rather than open. A witness absorbed by `flatten`, or committed by a circuit that creates
  the commitment, needs `flatten_checked` / the checked helper unless something else already bounds
  it — creating a commitment is not a reason to skip the check. — `flow-trace/04`
- **Injectivity restores Schwartz-Zippel, and Schwartz-Zippel then bounds the value for free.** Once
  the transcript binds a witness uniquely, the evaluation check forces it to equal the identity's
  right-hand side _as a polynomial_, and that value is already canonical — so a witness the
  circuit's own identity determines needs injectivity and never an explicit bound. C6's `d` and C3's
  ciphertext are of this kind; C1's `pk0` and C5's `pk0_agg` are not, because no identity inside
  their circuit determines them. Ask "does anything outside this circuit's own identity depend on
  this value's magnitude?" rather than "was it bounded before?". — `flow-trace/04`
- **Supply a quotient as a witness, not as an in-circuit hint.** Every quotient in these circuits is
  prover-supplied and pinned by constraints, and C3's rounding carry `z` now follows that: a `BIT_Z`
  bound plus the `[0, t)` window that exactly one `z` satisfies. Computing it in-circuit through
  `__compute_mod_reduction` instead drew the "Brillig call isn't properly covered" diagnostic for
  identical constraints. The witness form is cheaper to reason about, matches the rest of the
  codebase, and keeps the hint in the generator where the rest of them live. A prover-supplied value
  needs a `should_fail` test in each direction, since nothing else stops it being wrong. —
  `flow-trace/04`
- **A path gated off for one preset is the path CI exercises least, and usually the one that
  ships.** C3's scaled quotient is generated-false on insecure-512, which is the default preset and
  the only one `rust:test:proofs` and `local_e2e_tests` run. So the production path gets no
  end-to-end proof coverage from them: it needs its own `nargo execute` against a real secure-8192
  witness, plus a unit test that enters the branch. Before C3 added one, every C3 test exercised the
  fallback. — `flow-trace/04`
- **Grep `nargo execute` output for `bug:`, not just for failure.** Noir's "Brillig function call
  isn't properly covered by a manual constraint" diagnostic prints even under `--silence-warnings`,
  and a witness that solves says nothing about it. It is call-site sensitive: `reduce_mod_bounded`
  draws it from one C6 context while C7 calls the same helper four times cleanly, and widening the
  quotient bound made it worse, so the trigger is not understood. Treat it as blocking on a
  soundness-critical circuit rather than reasoning past it -- C6's `d_native_trunc` derivation was
  dropped for this, at a measured cost of 1,950 gates. — `flow-trace/04`
- **A bound already transferred by a checked opening must not be re-asserted when reducing an
  identity.** Reducing modulo `X^N + 1` means every coefficient the identity reads needs a real
  bound, but "real" includes one inherited through an injective opening -- it does not have to be
  checked again locally. C6 reads `ct0`, `ct1`, `sk` and `e_sm`, all opened through checked packing
  from the ciphertext commitment and C4's aggregates, so they arrive bounded; adding `centered()`
  calls for them (as `feat/secure-circuit-optimizations` does, because its base predates IF-011)
  would cost about 786k and make the reduction a net loss. Ask what already bounds a witness before
  bounding it again. — `flow-trace/04`
- **A witness opened from a checked commitment enters the transcript through that commitment.** C6
  absorbs `sk`, `e_sm` and the ciphertext as their commitments, not their coefficients: each is
  opened with checked packing, so the commitment has one opening and fixes the witness before
  `gamma`. Absorbing the coefficients as well pays twice for the same binding (415k gates for C6's
  ciphertext). The condition is the checked opening, not the commitment: a commitment opened with
  plain packing has second openings and does not bind. — `flow-trace/04`
- **An optimisation branch that predates a fix will silently undo it; diff against the fix, not the
  optimisation.** `feat/secure-circuit-optimizations` forked before IF-005, so its C1 replaces
  `e_sm_lifted` / `e_sm_quotients` with a per-residue `centered()` check. Per-residue bounds do not
  bound a CRT-reconstructed integer -- each residue under `(q_l - 1) / 2` still permits `~Q/2` --
  which is IF-005 exactly. It reads as an optimisation because against _its own_ base it was a
  tightening. Before porting any part of that branch, check whether the code it replaces was
  introduced by a finding on this branch: `git log -S` on the deleted identifier answers it. Only
  the negacyclic reduction was taken for C1. — `flow-trace/04`
- **Renaming a generated config global needs the declaration seeded by hand first.**
  `build-circuits.ts` splices `pub global NAME: ...;` into `configs/{secure,insecure}/*.nr` **by
  name**. It throws `Missing NAME` if the target does not already declare a generated global, and it
  throws `NAME ... is not generated` if the target keeps a prefixed global that the generator no
  longer emits. So a rename is: edit both config files to declare the new name, drop the old, then
  run codegen to fill the authoritative value. `sync-config` does not regenerate bounds at all — it
  only switches the active preset. — `flow-trace/04`
- **A circuit-size change must be measured at every committee size before it is called a win.** Cost
  splits into a part that scales with the committee (`H*L*N` work, such as per-share commitment
  openings) and a part that does not (`L*N` work, such as the aggregate's normalisation). A change
  that trades one for the other therefore has a break-even `H`, and a single measurement cannot show
  it. `feat/secure-circuit-optimizations` does exactly this in C4: its own benchmark reads -26.8% at
  `minimum` (H=2) and **+4.6% at `micro`** (H=5), with `small` (H=14) never run. Our committees span
  H=2 to H=14, so a benchmark at `minimum` alone says little about the size that matters. Fit
  `A + B*H` across at least two committees and state which half of the change each term is. —
  `flow-trace/04`
- **A gate-count sweep leaves compiled artifacts at whatever preset it last built, and that breaks
  tests that load them.** `scripts/test-circuits.sh` and any ad-hoc `bb gates` loop restore the
  _source_ config through their trap but not `target/` or `dist/circuits`. Anything reading compiled
  artifacts afterwards — `pnpm rust:test:proofs` in particular — then runs the wrong parameter set
  and fails with an ABI `LengthMismatch` naming an `L` that does not match the data. That failure is
  an artifact of the sweep, not of the change under test: rebuild with `pnpm build:circuits` before
  believing it. — `flow-trace/04`
- A soundness fix can be blocked by the browser prover, and the ceiling is a cliff rather than a
  slope. CRISP proves ct0 in-browser against a hardcoded `srsSize: 2**21` (2,097,152); the checked
  pk and ciphertext commitments put ct0 at 2,229,363, which stops browser proving rather than
  slowing it. The soundness fix landed first and the pending arithmetic optimisation restores the
  margin, but the two must ship together: ct0 has to be re-measured against 2,097,152 before CRISP
  ships. Measure ct0 against that number before adding any constraint to it. — `flow-trace/04`
- Anchoring a value off-circuit still needs an injective packing in-circuit. ct0/ct1 bound the
  public-key components before commitment generation. `CRISPProgram` supplies the registry's
  C5-proven committee key as `noirPublicInputs[8]`. This binds the ballot to the round's key only
  because the packing has one opening. Non-injective packing defeats a chain-supplied anchor as it
  defeats an in-circuit commitment comparison. The same requirement applies to the `u`-commitment
  equality in the `user_data_encryption` fold. — `flow-trace/04`
- The class is "every circuit that opens a commitment it did not create", and it has seven members:
  C2a, C2b, C4, C5 and C6 (three). All open through `pack_checked`. A new commitment opened from
  elsewhere joins that list and needs either the checked helper or its own bound. Naming the class
  matters: the first two instances were found while optimising the circuits that held them, and the
  other five only by enumerating the pattern. CRISP's ballot circuits also open commitments they did
  not create (the parent's and the ballot's ciphertexts) and keep plain `pack`: `verify_slot_update`
  checks a relation that is linear and aligned coefficient by coefficient across ciphertexts packed
  with the same `BIT_CT`, so an opening that keeps the carriers proves the same relation for the
  committed coefficients. With the checked helper on the three commitments, the secure `crisp`
  circuit measured 2,520,034 gates, above the browser ceiling. The exemption holds only for that
  shape of relation, and only while every commitment in it has a bounded opening that something else
  fixes: the ballot through the range checks of `user_data_encryption_ct0/ct1`, and the parent and
  the published result because `chain_head_per_slot` takes an entry only when its bytes reproduce
  its commitment and it extends the selected head. A check at one point over those commitments, or a
  Secure Process that follows a parent by its stored commitment without its bytes, needs injective
  openings: chained masks could then carry a coefficient past the radix and shift a plaintext
  coefficient by a carry. — `flow-trace/04`
- A bound that is not tight enough for the slot is no bound for this purpose. C2b's `as u64` cast
  limited coefficients to `2^64` while the slot was `radix = 2^64` with `base = 2^60`, so a digit
  could still overflow. — `flow-trace/04`
- A derived value that the circuit reduces itself needs no opened-witness bound. C4's aggregate is
  canonicalised by `normalize_aggregated`, and `reduce_mod` pins its quotient to `u64`, which stays
  sound for sums far above the slot width. — `flow-trace/04`
- `packing_layout` rejects `group == 1`. At one value per carrier, packing saves no sponge
  absorption while still charging the range checks that make it injective — measured +82% gates
  against absorbing directly. — `flow-trace/04`
- `pack` and `pack_checked` duplicate the layout arithmetic, so the equivalence tests in
  `math/helpers.nr` must keep passing: if they drift, commitments created on one path stop matching
  those opened on the other. — `flow-trace/04`
- Order matters: a check that makes a commitment binding must run **before** the commitment
  comparison, not after. — `flow-trace/04`
- Do not document a bound the circuit does not enforce. C4's `compute_aggregated_shares` claimed its
  inputs were in `[0, q_l)` "by C2 range checks" for a value C2 never constrained on this path; the
  comment stood in for the missing check. — `flow-trace/04`
- DKG error terms need no CRT decomposition: `error1_variance <= 16` puts `e0_bound` at
  `2 * variance` (20 secure, 6 insecure), far below every `q_i / 2`, so the centered residue equals
  `e0`. C3 uses `e0` directly. Raising DKG `error1_variance` past 16 switches `Bounds::compute` to
  the uniform branch and breaks that assumption — witness generation asserts it. — `flow-trace/04`

### Proof binding / domain separation (audit-fix invariants — do not regress)

- **Recursive trust reaches every descendant VK.** Sequential folds keep their leaf, fold, and
  genesis hashes constant across predecessor proofs. A consumer binds the declared fold hash to the
  verified VK. C3ab includes both complete C3 chains, and node-fold includes the child-fold VKs and
  their nested hashes. The final DKG aggregator requires one node-tree hash across every row. Public
  input zero commits to the complete nodes or C6 tree. Deployment pins that value from the pair's
  `.vk_tree_hash`, not from its immediate `.vk_hash`. A prover-supplied hash without this immutable
  anchor does not establish trust. — `math/recursive_vk.nr`; `flow-trace/04`
- **PK domain binding (C-08):** `publishCommittee` sets
  `committeeHash = CommitteeHashLib.hash(c.topNodes)`: keccak256 over the ordered raw 20-byte
  addresses, not `abi.encodePacked(address[])`, which pads each address to 32 bytes.
  `BfvPkVerifier.verify` compares its 128-bit limbs with the proof's public inputs, binding the
  proof to the specific committee. `crates/committee-hash` must produce the same bytes. —
  `CommitteeHashLib.sol`; `flow-trace/04`
- **Decryption-proof replay prevention (C-03):** every secret-bearing C6 proof commits to the domain
  `(chainId, Interfold address, e3Id, committeeHash, ciphertextOutputHash, committeePublicKey)`;
  folding requires one common domain; the wrapper rejects any domain differing from the contract's
  recomputed value and checks per-party SK/ESM commitments against registry-stored DKG anchors.
  Keyshare and plaintext aggregation use the chain commitment, ordered finalized committee, and DKG
  anchor party IDs. A `PublicKeyAggregated` must match these facts and open the key commitment.
  Keyshare retains the first matching key. Before hydration and replay, confirmed event history
  rebuilds authority and commitment-checked key bytes. Retained C6 intents are repaired before
  deduplication; logged compute requests must pass canonical admission before release. No registry
  storage RPC supplies this authority. Plaintext admission checks each C6 domain before reserving a
  party slot. Hydration checks signed shares and retained C6 inputs in every phase, including
  `Complete`. Invalid work is rebuilt from signed history before verification or publication
  resumes. State written before v0.19 is not repaired because the release requires a store reset to
  schema 8. The EVM writer checks final-proof domain limbs against confirmed key authority and
  ciphertext hashes before intent deduplication. Missing authority defers admission; a mismatch
  discards the intent and permits a corrected result. C7 intent deduplication binds to the exact
  request. Live and retained C7 results must match the selected C6 commitments, ordered party IDs,
  and plaintext. A replacement batch invalidates earlier worker correlations and regenerates
  matching proofs. — `crates/aggregator/src/plaintext_aggregation/effects/recovery.rs`;
  `crates/request/src/canonical_key.rs`; `crates/evm/src/canonical_key.rs`; `flow-trace/04`; INDEX
  concern #34
- **Ctx-witness binding (C-04, commit `cd7cbceea`):** the off-chain SAFE ciphertext commitment is
  stored at ciphertext publication, propagated as a final-proof public input, and compared on-chain
  (no BFV decoding/Poseidon2 in Solidity); C3/C6 commitments are checked against their ciphertext
  witnesses. — INDEX IF-004
- **Ciphertext-duty proof (Zenith #15):** each E3 snapshots the protocol verifier for its encryption
  scheme at request time. Before `CiphertextReady`, this verifier checks a zkVM receipt that binds
  the chain, Interfold address, E3 ID, scheme ID, BFV parameter hash, committee public key, output
  hash, and SAFE commitment. The E3 program verifies application rules separately and cannot create
  a decryption duty by itself. — `flow-trace/04`; INDEX Z-15
- **The compute path carries no external audit.** Neither Zenith protocol audit (2026-08-17, six
  Solidity files; 2026-09-08, a scoped review of 14 Solidity files) covered Rust, the OpenVM guest
  and prover, `crates/compute-provider`, `crates/zk-helpers`, or the OpenVM receipt verifiers
  (`OpenVmBfvCiphertextVerifier.sol`, `OpenVmReceiptVerifier.sol`). Treat changes there as
  unaudited. — `packages/interfold-contracts/audits/README.md`
- **A Secure Process derives its input root; it never receives it.** `ComputeInput` holds
  `fhe_inputs` and per-input `published` data, never a root, and `ComputeInput::process` derives one
  leaf from each supplied input through the E3 program's `InputPolicy`. The protocol verifier
  authenticates the input root in the receipt but does not compare it with any expected root, so the
  E3 program's comparison against its own on-chain root is the only check — and that comparison is
  worthless if the guest can be handed leaves that disagree with the ciphertexts it consumed.
  Publication is unpermissioned and one-shot, with no dispute path, so any party could otherwise
  publish a tally over ciphertexts that were never submitted. `MerkleTreeBuilder::with_leaf_hashes`
  is `#[cfg(test)]` to keep it out of that path. — `flow-trace/04`
- **Every E3 program must compare the proof's input root against its own root.**
  `OpenVmBfvCiphertextVerifier` authenticates the receipt's `inputRoot` but compares it with
  nothing. A program that skips the comparison accepts a result computed over any input set. —
  `flow-trace/04`
- **A Secure Process derives its leaves; it never receives them, and never drops one.**
  `SecureProcess` computes one leaf per supplied input, in the supplied order whatever the batching
  schedule, through the program's `InputPolicy::leaf`, including inputs that the policy does not
  select for computation. The caller must supply the complete input set in on-chain order: a
  received root can disagree with the data it claims to describe, and a missing leaf changes the
  root and makes the result unpublishable. — `crates/compute-provider/src/secure_process.rs`;
  `flow-trace/04`
- **A CRISP input is committed before it is finalized, but computation requires both.**
  `publishInput` verifies the Noir proof and the configured service's EIP-712 storage attestation,
  then reserves the leaf and index so a later input can name it as its parent. `finalizeInput` must
  prove VectorX availability for the exact committed content hash. The input tuple cannot change
  between the calls, and `CRISPProgram.verify` must reject while any committed input remains
  pending. — `flow-trace/08`
- **CRISP input envelopes use one flat ABI parameter sequence.** The SDK uses `encodeAbiParameters`
  for the six fields. The server uses parameter decoding for that sequence and parameter encoding
  for the signed commitment payload that Solidity reads through `abi.decode`. Treating the envelope
  as one wrapped struct adds a leading tuple offset and breaks the boundary. — `flow-trace/08`
- **Avail-backed CRISP rounds leave a usable voting interval.** `CRISPProgram.validate` derives the
  worst-case key time from the E3 timeout snapshot and the request-time Registry windows. The
  commitment cutoff must be at least one hour after both that time and the configured input start.
  The server repeats the production minimum as an early configuration check, but it is not the
  security boundary. — `flow-trace/08`
- **Avail references name exact application bytes.** The application content hash is
  `keccak256(rawBytes)`, which is also the `leaf` returned by Avail's proof API. The official bridge
  hashes that value once more when it verifies the submitted-data Merkle root. Solidity binds the
  proof API leaf to `contentHash`, and every reader hashes retrieved raw bytes again before decoding
  or proving over them. An App ID or RPC response is not a correctness proof. — `flow-trace/08`
- **The leaf layout and input selection are the E3 program's, not the crate's.** They are supplied
  as an `InputPolicy`, because a leaf must match whatever that program builds on chain and no two
  programs need agree, and because "what does a second input for the same participant mean?" has no
  universal answer. `InputPolicy::default` is the historical behaviour — leaf is the ciphertext's
  own commitment, every input counts — which matches the starter template. Every E3 program exports
  `policy()` beside `fhe_processor`. — `flow-trace/04`
- **The Secure Process holds one ciphertext at a time and checks its second pass.** It reads every
  ciphertext once for its leaf, selects over records without bytes, then reads the selected
  ciphertexts again and refuses one whose Keccak hash differs from the first read. The host and the
  guest run the same `SecureProcess`, but the guest build swaps in accelerated code the host does
  not run: OpenVM's Poseidon2 (`e3-safe/openvm`), Keccak and SHA-256 (`openvm-hashes`), and the
  power-basis commitment and RNS packing (`crisp_fhe_optimized`). The host's predicted journal is
  the guest's only while each accelerated path matches its reference. Unit tests compare them, and
  CI runs the real guest against the host's journal on an insecure and a secure fixture
  (`pnpm openvm guest-parity`). A mismatch cannot make a false proof, because contracts rebuild the
  journal from chain state, but no proof can then be made and every round fails. — `flow-trace/04`
- **CRISP binds bytes, commitment, slot and parent into its leaf, and selects the end of each slot's
  chain.** `CRISPProgram.inputLeaf` is
  `sha256(keccak256(bytes) || commitment || slot || parentIndexPlusOne) mod SNARK_SCALAR_FIELD` and
  `e3_user_program::policy` rebuilds it byte for byte; a divergence makes every root mismatch and
  nothing else would catch it, so both sides pin the same vector (`program/tests/input_leaf.rs`,
  `tests/input-leaf.test.ts`) and `onchain_root_agreement.rs` asserts Rust reproduces a root a real
  contract produced. The tree is append-only because the mask path checks no signature, so anyone
  can write to any census member's slot and update-in-place would let a third party erase a counted
  vote. — `flow-trace/04`
- **A slot's head must be openable by anyone, so selection follows a parent chain rather than a
  mutable pointer.** `chain_head_per_slot` takes an entry only when its bytes reproduce its
  commitment _and_ the entry it names is that slot's current head. `CRISPProgram` cannot check the
  first — the commitment is a Poseidon sponge over CRT limbs and the circuit never sees the
  serialization — so with one mutable head per slot, anyone could publish a valid proof beside
  unusable bytes and leave a head only they can open. A slot nobody can mask is a slot where every
  later input is provably its owner voting again, which is a coercion receipt. Because an unusable
  entry is never the head, it is never a valid parent, and the next honest input names the same
  parent it did.

  The rule takes the **first** usable entry to extend a parent, so a later sibling is dropped and an
  input can be front-run into not counting. Keep it that way: a stale parent cannot be told apart
  from a sibling built a moment earlier, because only the circuit knows whether an entry replaces
  the slot or adds to it. Preferring the later sibling would let a mask on a superseded ciphertext
  restore it over a vote — a silent tally corruption, against a dropped re-vote the voter can see
  and retry.

  A committed input is not a counted input, and clients must not report it as one. The voter sees a
  drop through `POST /voting/selection`, which replays the chain with the same rule and answers
  `selected` by ancestry, so a later mask or re-vote on top of the input does not read as a drop; it
  answers `selection_pending` while a lower tree index is missing from the server's index. **Gap:**
  a drop is visible only while a client checks, there is no retry after the commitment deadline, the
  answer depends on the server holding every indexed input, and the governance apps do not run the
  check. — `flow-trace/04`

- **Every change to the inputs of a CRISP round is counted in the round's input generation.**
  `state/previous-ciphertext` and `POST /voting/selection` read the inputs through a cache in the
  server process (`indexed_inputs`). A read is cached only while the generation under
  `_e3:crisp_inputs:{id}` has as many changes finished as started, and it is served only while the
  generation stays the same. A write to `input_commitments`, `input_slots`, `input_parents`,
  `input_usable`, `input_ciphertext_hashes` or `ciphertext_inputs` must go through `modify_inputs`,
  which counts the change as started before the record write and as finished after it. Another write
  leaves the cache with the old inputs: voters then build on a stale head, and the Secure Process
  drops their inputs. `settle_input_generation` may make the counts equal only at startup, before
  the indexer runs. — `flow-trace/04`

- **CRISP's three ballot operations prove one relation and publish one shape.** Voting, updating,
  and masking all prove `published = addend + ballot`, with the addend selected by the private
  `is_mask_vote` and derived as `keep_previous = is_mask_vote & !is_first_vote`. The circuit returns
  `sum_ct_commitment` on every path, the SDK has one code path, and `CrispSDK.prepareBallot` makes
  the same server request either way. Branching any of these apart — a different published
  ciphertext, a different commitment for the digest, a different request — makes the three
  distinguishable on chain, which is what masks exist to prevent. Deriving the selector rather than
  witnessing it is what stops a voter counting their old ballot twice and a masker erasing a vote. —
  `flow-trace/04`
- **CRISP proves the slot update at every coefficient.** The function `verify_slot_update` in
  `crisp_lib::ciphertext_addition` asserts `published = ballot + addend + q_i * r` for each
  coefficient, with each `r` in `[-1, 1]`, for both ballot circuits. A check at one Fiat-Shamir
  point derived from the three commitments is unsound: the point is known before the prover picks
  the parent opening and the quotients, and a second opening of the parent commitment let a mask
  publish its ballot alone and drop the slot's vote
  (`a_second_opening_of_the_parent_cannot_erase_the_slot`). The fold circuits pin the ballot
  circuits through `CRISP_FOLD_EXPECTED_KEY_HASH_*` and `CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_*`, so
  a change to either ballot circuit must regenerate those constants (`pnpm compute:vk-hash`, both
  presets) and the generated verifiers; a deployed `CRISPProgram` keeps the circuit its verifier was
  built from. — `flow-trace/04`
- **A CRISP tally coefficient is exact only below the plaintext modulus.** Every ballot coefficient
  is 0 or 1, and the tally adds one ballot per selected slot, so each decrypted coefficient counts
  the ballots that set that bit of that option. The committee decrypts it modulo the plaintext
  modulus `t` of the round's BFV parameters: 100 at insecure-512 and 17,000,000 at secure-8192.
  Voting power does not change the bound, because a ballot adds at most 1 to each coefficient. A
  tally format that is not one bit per coefficient per ballot needs a new bound. **Gap:**
  `CRISPProgram` does not limit the slots of a round. When `t` or more ballots in one round set the
  same bit, `decodeTally` reads the residue and the count is wrong with every proof valid. That
  takes 100 ballots at insecure-512 and 17 million at secure-8192. — `flow-trace/04`
- **CRISP constrains every coefficient of the ballot plaintext, at the real BFV degree.** The
  witness generator reverses the message over the full degree, so the payload starts at
  `D - MAX_MSG_NON_ZERO_COEFFS + (MAX_MSG_NON_ZERO_COEFFS mod num_options)` with the options back to
  front; `crisp_lib::utils::ballot_layout` derives that offset, both checkers use it, and no code
  may hand-code it. Each coefficient inside an option segment encodes one bit as 0 or `q_mod_t`,
  everything outside the ballot region must be zero, and a mask's plaintext must be zero everywhere.
  Indexing as if the polynomial were the message width makes both checks read only padding: every
  vote passes any balance bound, and a mask — which needs no signature and may be written to any
  eligible slot — can carry an arbitrary payload into someone else's ballot. Tests must build `k1`
  at the compiled degree, not at `MAX_MSG_NON_ZERO_COEFFS`. — `flow-trace/04`
- **The SAFE ciphertext commitment requires exactly two components.** It covers `c[0]` and `c[1]`
  only, matching the Noir circuit, so `bfv_ciphertext_to_greco` rejects any other component count. A
  padded ciphertext would otherwise share a commitment with its two-component prefix while threshold
  decryption rejects it, failing the round as a `DecryptionTimeout` billed to the ciphernodes. —
  `flow-trace/04`
- **Client PK commitment binding (C-01):** Serialized PK event bytes are an untrusted transport
  hint. Consumers decode the bytes with the request-time threshold BFV parameters. Consumers store
  the key only when its recomputed commitment equals the on-chain (C5-proven) value. Proof-backed
  committee publication never accepts key bytes. Public-key candidates are bounded and gated to
  request-time committee members while the E3 remains in `KeyPublished`. Retained expelled members
  can still repair transport, but their bytes receive no extra trust. Terminal E3s cannot create new
  durable assemblies after cleanup. Consumers accept at most one candidate per member, so an invalid
  candidate cannot block a valid candidate from another member. — INDEX concerns #33, Z-31
- **No proof-disabled bypass (C-02):** both final verifier calls are mandatory in production;
  `skip_proof_aggregation` works only under the `test-only-skip-proof-aggregation` Cargo feature;
  mock placeholders carry the final roster or canonical decryption domain fields, but production
  verifiers reject their C5/C7 proof bytes. — INDEX concern #32
- Circuit soundness fixes to preserve: `ModU64::div_mod` verifies
  `result*divisor == dividend (mod modulus)` (IF-001); C7 compares **every** decoded coefficient,
  including zeros, to the claimed message (IF-002).
