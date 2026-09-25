# Invariants — Cryptography / circuits

Scope: `circuits/`, `crates/zk-prover`, `crates/zk-helpers`, `crates/trbfv`, `crates/fhe-params`.
Committee config sync, Noir/Barretenberg compatibility, DKG and threshold structure, proof binding
and domain separation.

Read `00_INDEX.md` first: it carries the meta-invariants and the open-issues list that apply to
every section.

## Cryptography / circuits

### Committee config sync (the `check:committee` gate)

- Committee `(N, T, H)` and each complete BFV parameter tuple must stay synchronized. The tuple is
  defined for deployment in `packages/interfold-contracts/scripts/protocol/constants.ts`, for
  ciphernodes in `crates/fhe-params/src/constants.rs`, and for circuits in
  `circuits/lib/src/configs/{insecure,secure}/threshold.nr`. Committee values also appear in
  `circuits/lib/src/configs/committee/active.nr`, `packages/interfold-contracts/scripts/utils.ts`,
  `crates/zk-helpers/src/ciphernodes_committee.rs`, and
  `packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol`. The generated Solidity and
  TypeScript values bind the BFV parameter-set hashes and configuration IDs. The gate verifies the
  tuple, the circuit error bound, and every runtime configuration-ID copy. The local
  `circuits/bin/.active-preset.json` cache may differ from the production chain pair. Drift means a
  deployment can register parameters that ciphernodes or circuits do not implement. Regenerate
  configuration constants with `pnpm build:circuits sync-config --preset <name> --committee <name>`;
  switch and build circuits only with `pnpm build:circuits --committee <name>`. Both paths are
  enforced by `scripts/check-committee.sh`.
- Canonical sizes: `minimum` (3,1,2) · `micro` (9,4,5) · `small` (19,9,14) — must mirror `mod.nr`
  and `CiphernodesCommitteeSize::values()`. — `scripts/circuit-constants.ts`
- Wrapper Solidity verifiers (`BfvPkVerifier`, `BfvDecryptionVerifier`) have an `(H, T)`-specific
  public-input layout and must be redeployed on committee change.
- Parity matrices (`parity_{insecure,secure}.nr`) are derived artifacts regenerated from preset
  `QIS` + committee `(N, T)`; hand-edits are caught by regenerate-and-diff.

### Noir / Barretenberg compatibility

- Treat Nargo, the Rust Noir crates, witness serialization, Barretenberg, circuit release archives,
  verification keys, and generated Solidity verifiers as one compatibility unit. The current unit is
  Nargo and Rust Noir `1.0.0-beta.26` with Barretenberg `5.1.0`. — `.github/workflows/ci.yml`;
  `crates/zk-prover/versions.json`; `Cargo.toml`
- Rust-generated witnesses must use `WitnessStack::serialize()`. Do not serialize a witness stack
  with `bincode`; Barretenberg 5 accepts the beta.26 MessagePack format markers, not the legacy
  marker. — `crates/zk-prover/src/witness.rs`
- Rebuild and publish circuit archives with the pinned Nargo version before changing
  `required_circuits_version`. Regenerate all dependent verification keys and Solidity verifiers
  with the pinned Barretenberg version. A release archive from an older serialization format can
  pass checksum verification but fail during ACIR decoding or proof generation.
- `required_circuits_version` must equal the Interfold release tag that publishes its archive. The
  release workflow rejects a different value because the ciphernode resolves both the GitHub release
  and `circuits-{version}.tar.gz` from this field.
- A circuit release archive that supports current deployments must include every
  `insecure-512/{minimum,micro,small}` and `secure-8192/{minimum,micro,small}` pair. Each pair has a
  build stamp with the exact preset, committee, and source hash. `checksums.json` and `SHA256SUMS`
  must cover the archive contents. Nodes select the artifact directory from the E3's on-chain
  parameter set and committee size.
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
  zero-indexed. Circuit-side Shamir coordinates are `party_id + 1` and must be strictly increasing.
  The active aggregator is the lowest eligible runtime `party_id` after exclusions and the current
  phase's durable unresponsive-party set. — `ARCHITECTURE.md`; `flow-trace/04`
- Every committee member persists validated aggregation inputs. Failover starts only after
  `AggregationInputsReady` confirms that the phase can resume from durable state. Only the active
  party can launch aggregation effects or accept their results. — `flow-trace/04`; INDEX concern #42
- The active aggregator proposes the canonical DKG roster only after it can derive `H` mutually
  ready dealers from signed readiness reports. `AggregatorChanged` supplies the active party ID, and
  receivers accept a roster only from that party. A receiver can hold the first authenticated roster
  from a standby until local failover promotes that party. The first accepted roster is durable and
  immutable; a later conflicting roster is ignored. Accepting it ends only the DKG-roster failover
  phase. Public-key aggregation receives a new readiness-gated failover budget. — `flow-trace/04`;
  INDEX concerns #42 and #52
- DKG dealer identity binds the public proof statement, not randomized proof bytes. Replacing a
  same-E3 proof plan must invalidate every prior correlation ID before the replacement can accept
  responses. — `flow-trace/04`
- DKG aggregation receives **exactly H** canonical honest NodeFold proofs (unique in-range party
  IDs) and **exactly N** ordered committee addresses; every preset has `H < N` — never assert
  `H == N`. A mixed Some/None NodeFold set is a local test-configuration mismatch. Preserve the
  aggregation inputs and do not report invalid committee shares. — `ARCHITECTURE.md`;
  `flow-trace/04`
- The `dkg_aggregator` circuit requires strictly ascending, in-range H-party IDs. The on-chain
  fold-attestation verifier repeats that check, so both proof consumers use the same roster order. —
  `flow-trace/04`
- In the DKG aggregator, C3 key slots and C2 share slots use the selected recipient's full-committee
  `party_id`. C4 expected-commitment slots use the sender's position in the H-row fold. These
  indices differ when the selected H-subset skips a committee member. — `flow-trace/04`
- A recipient outside the selected H dealers builds C4 from all H encrypted dealer shares. It must
  not replace a selected dealer share with its own plaintext share. A selected recipient uses its
  plaintext share only at its own row. — `flow-trace/04`
- Proof multiplicity: C2a/C2b singleton per recipient; C3a/C3b follow configured Shamir
  multiplicities. Witness dimensions come from the **active preset**, never incidental vector sizes.
  — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`
- All C0–C7 proofs must complete before `ThresholdShareCreated` is published. — `flow-trace/04`
- A CRT consistency equation of the form `lifted[j] == limb[i][j] + quotient[i][j] * q_i` constrains
  nothing on its own: `q_i` is invertible modulo the proof-system prime, so every limb admits a
  quotient that satisfies it. It binds the witnesses only when the lifted value, the limbs **and**
  the quotients all carry range checks that keep the term sum far below the prime, which is what
  makes the equation hold over the integers. C1 (`e_sm`) and `user_data_encryption_ct0` (`e0`) both
  rely on all three bounds; dropping any one makes the check vacuous. — `flow-trace/04`
- Apply a bound where the quantity it describes actually lives. The smudging bound `e_sm_bound` is
  an integer bound and belongs on C1's lifted `e_sm_lifted` witness; on secure presets it exceeds
  every `q_i`, so checking a CRT residue against it is satisfied for free. Limbs carry the modulus
  bound `(q_i - 1) / 2` instead. — `flow-trace/04`
- C1 commits to the `e_sm` **residues**, not the lifted value, so C2b keeps hashing what it
  Shamir-splits. The integer bound reaches C2b through that commitment: C1 proves the limbs are
  bounded and hash to it, C2b proves its own limbs hash to the same value. `PK_GENERATION_BIT_E_SM`
  and `SHARE_COMPUTATION_E_SM_BIT_SECRET` are the same modulus width and must move together. —
  `flow-trace/04`
- A circuit that re-opens a commitment from a private witness must range-check that witness. The
  commitment packs `BIT`-wide coefficients into shared carriers (`acc = acc * radix + (v + base)`),
  so an unbounded coefficient overflows its slot and cancels against the next one: the carrier, and
  so the commitment, is unchanged. Without the bound one commitment has many openings and the prover
  chooses which the circuit sees. C1/C5 (`pk0`) and C4 (`decrypted_shares`) rely on this; the bound
  must be below the slot width, which the centered residue `(q_l - 1) / 2` and the dealt range
  `[0, q_l)` both satisfy. — `flow-trace/04`
- Order matters: a range check that makes a commitment binding must run **before** the commitment
  comparison, not after. — `flow-trace/04`
- Do not document a bound the circuit does not enforce. C4's `compute_aggregated_shares` claimed its
  inputs were in `[0, q_l)` "by C2 range checks" for a value C2 never constrained on this path; the
  comment stood in for the missing check. — `flow-trace/04`
- DKG error terms need no CRT decomposition: `error1_variance <= 16` puts `e0_bound` at
  `2 * variance` (20 secure, 6 insecure), far below every `q_i / 2`, so the centered residue equals
  `e0`. C3 uses `e0` directly. Raising DKG `error1_variance` past 16 switches `Bounds::compute` to
  the uniform branch and breaks that assumption — witness generation asserts it. — `flow-trace/04`

### Proof binding / domain separation (audit-fix invariants — do not regress)

- **PK domain binding (C-08):** `BfvPkVerifier.verify` checks
  `committeeHash = keccak256(abi.encodePacked(topNodes))` (as 128-bit limbs) against the proof's
  public inputs, binding the proof to the specific committee. — `flow-trace/04`
- **Decryption-proof replay prevention (C-03):** every secret-bearing C6 proof commits to the domain
  `(chainId, Interfold address, e3Id, committeeHash, ciphertextOutputHash, committeePublicKey)`;
  folding requires one common domain; the wrapper rejects any domain differing from the contract's
  recomputed value and checks per-party SK/ESM commitments against registry-stored DKG anchors. —
  `flow-trace/04`; INDEX concern #34
- **Ctx-witness binding (C-04, commit `cd7cbceea`):** the off-chain SAFE ciphertext commitment is
  stored at ciphertext publication, propagated as a final-proof public input, and compared on-chain
  (no BFV decoding/Poseidon2 in Solidity); C3/C6 commitments are checked against their ciphertext
  witnesses. — INDEX IF-004
- **Ciphertext-duty proof (Zenith #15):** each E3 snapshots the protocol verifier for its encryption
  scheme at request time. Before `CiphertextReady`, this verifier checks a RISC Zero receipt that
  binds the chain, Interfold address, E3 ID, scheme ID, BFV parameter hash, committee public key,
  output hash, and SAFE commitment. The E3 program verifies application rules separately and cannot
  create a decryption duty by itself. — `flow-trace/04`; INDEX Z-15
- **The compute path carries no external audit.** The 2026-08-17 Zenith audit covered six Solidity
  files and no Rust. `crates/compute-provider`, the RISC Zero guest, `crates/zk-helpers`, and
  `Risc0BfvCiphertextVerifier.sol` were outside both the audit and its mitigation review, so a
  `Resolved` `Z-` row is this repository's remediation rather than a re-reviewed one. Treat changes
  in these areas as unaudited by default. — `flow-trace/00`;
  `packages/interfold-contracts/audits/README.md`
- **A Secure Process derives its input root; it never receives it.** `ComputeInput` holds only
  `fhe_inputs`, and `ComputeInput::process` derives the leaves from the ciphertexts it processed.
  The protocol verifier takes the input root from the proof envelope and does not constrain it, so
  the E3 program's comparison against its own on-chain root is the only check — and that comparison
  is worthless if the guest can be handed leaves that disagree with the ciphertexts it consumed.
  Publication is unpermissioned and one-shot, with no dispute path, so any party could otherwise
  publish a tally over ciphertexts that were never submitted. `MerkleTreeBuilder::with_leaf_hashes`
  is `#[cfg(test)]` to keep it out of that path. — `flow-trace/04`
- **Every E3 program must compare the proof's input root against its own root.**
  `Risc0BfvCiphertextVerifier` takes no `inputRoot` argument and constrains none. A program that
  skips the comparison accepts a result computed over any input set. — `flow-trace/04`
- **A Secure Process derives its leaves; it never receives them, and never drops one.**
  `MerkleTreeBuilder::compute_leaf_hashes_batched` builds every leaf from the ciphertexts it was
  given, in global index order whatever the batching schedule, and pushes one per on-chain input
  leaf, whatever the E3 program's policy decides about computing over it. Both rules are applied by
  `e3-compute-provider` rather than delegated: a received root can disagree with the data it claims
  to describe, and a missing leaf changes the root and makes the result unpublishable. —
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
  and retry. — `flow-trace/04`

- **CRISP's three ballot operations prove one relation and publish one shape.** Voting, updating,
  and masking all prove `published = addend + ballot`, with the addend selected by the private
  `is_mask_vote` and derived as `keep_previous = is_mask_vote & !is_first_vote`. The circuit returns
  `sum_ct_commitment` on every path, the SDK has one code path, and `CrispSDK.prepareBallot` makes
  the same server request either way. Branching any of these apart — a different published
  ciphertext, a different commitment for the digest, a different request — makes the three
  distinguishable on chain, which is what masks exist to prevent. Deriving the selector rather than
  witnessing it is what stops a voter counting their old ballot twice and a masker erasing a vote. —
  `flow-trace/04`
- **CRISP constrains every coefficient of the ballot plaintext, at the real BFV degree.** The
  witness generator reverses the message over the full degree, so the payload sits at
  `k1[D - MAX_MSG_NON_ZERO_COEFFS ..]` with the options back to front;
  `crisp_lib::utils::ballot_layout` derives that offset and both checkers use it. Coefficients
  inside an option segment must be binary, everything outside the ballot region must be zero, and a
  mask's plaintext must be zero everywhere. Indexing as if the polynomial were the message width
  makes both checks read only padding: every vote passes any balance bound, and a mask — which needs
  no signature and may be written to any eligible slot — can carry an arbitrary payload into someone
  else's ballot. Tests must build `k1` at the compiled degree, not at `MAX_MSG_NON_ZERO_COEFFS`. —
  `flow-trace/04`
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
  production verifiers reject placeholder C5/C7 proofs. — INDEX concern #32
- Circuit soundness fixes to preserve: `ModU64::div_mod` verifies
  `result*divisor == dividend (mod modulus)` (IF-001); C7 compares **every** decoded coefficient,
  including zeros, to the claimed message (IF-002).
