# Invariants — Cryptography / circuits

Scope: `circuits/`, `crates/zk-prover`, `crates/zk-helpers`, `crates/trbfv`, `crates/fhe-params`,
the BFV and RISC Zero verifier contracts, `crates/compute-provider`, and the CRISP example.
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
  fixed at construction. Selecting another supported committee needs no redeployment. A changed
  circuit or VK needs new wrappers and, where a router is used, a new router and new `setPkVerifier`
  / `setDecryptionVerifier` calls. — `protocol/deployContracts.ts`; `BfvPkVerifierRouter.sol`
- Parity matrices (`parity_{insecure,secure}.nr`) are derived artifacts regenerated from preset
  `QIS` + committee `(N, T)`. Do not hand-edit them. `scripts/check-committee.sh` regenerates and
  diffs them only when `target/release/generate_parity_matrices` and `nargo` exist; the Agent
  Harness CI job skips that step. The CI circuits job catches edits to the committed selection
  through its rebuild diff.

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
  must cover the archive contents, and a node must reject an archive without them. Nodes select the
  artifact directory from the E3's on-chain parameter set and committee size. **Gap:**
  `download_circuits` passes `require_checksums=false`, so a node installs an archive without
  `checksums.json` after a warning (`crates/zk-prover/src/backend/download.rs`).
- Artifact identity must cover every source that compiles into an artifact. **Gap:**
  `computeSourceHash` (`scripts/build-circuits.ts`) does not hash `circuits/lib/src/core/**`,
  `circuits/lib/src/math/**`, or `circuits/lib/src/lib.nr`, where the IF-001 and IF-002 fixes live.
  After a change there, rebuild and push every affected pair.
- The pair source hash ignores generated C1/C2 bound values and includes the Rust sources that
  generate them. Switching the active committee must not change another pair's source hash.
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
  their local C6 outcomes for failover. Only the active party can launch aggregation effects or
  apply their results to advance the phase. — `flow-trace/04`; INDEX concern #42
- The active aggregator proposes a canonical H-dealer DKG roster only after it derives `H` mutually
  ready dealers from signed Ready reports; a promoted aggregator reuses an already accepted roster.
  A receiver keeps one authenticated roster per proposer. It accepts a roster only from a proposer
  whose party ID is at most the active party ID from `AggregatorChanged`, and only when its local
  Ready state supports that roster. Before C4 starts, a roster from a lower party ID replaces an
  accepted roster from a higher one; after C4 starts, the accepted roster is fixed. Accepting a
  roster ends only the DKG-roster failover phase. Public-key aggregation receives a new
  readiness-gated failover budget. —
  `crates/keyshare/src/threshold_keyshare/effects/coordinate_roster.rs`; `flow-trace/04`; INDEX
  concerns #42 and #52
- DKG dealer identity binds the public proof statement, not randomized proof bytes. Replacing a
  same-E3 proof plan must invalidate every prior correlation ID before the replacement can accept
  responses. — `flow-trace/04`
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
- A recipient outside the selected H dealers builds C4 from all H encrypted dealer shares. It must
  not replace a selected dealer share with its own plaintext share. A selected recipient uses its
  plaintext share only at its own row. — `flow-trace/04`
- Proof multiplicity: C2a/C2b singleton per recipient; C3a/C3b follow configured Shamir
  multiplicities. Witness dimensions come from the **active preset**, never incidental vector sizes.
  — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`
- The local C1, C2a, C2b, and every C3a and C3b proof must complete and be signed before any
  `ThresholdShareCreated` is published. C4 through C7 belong to later phases. —
  `crates/zk-prover/src/proof_request/effects/publish_threshold_shares.rs`; `flow-trace/04`
- The decrypted plaintext is exactly 100 u64 coefficients in every layer: `MAX_MSG_NON_ZERO_COEFFS`
  in Noir (`configs/default/mod.nr`, written by `scripts/build-circuits.ts`) and in `zk-helpers`,
  and `MESSAGE_COEFFS_COUNT` in `BfvDecryptionVerifier.sol`. **Gap:** no gate compares these copies.

### Proof binding / domain separation (audit-fix invariants — do not regress)

- **PK domain binding (C-08):** `publishCommittee` sets
  `committeeHash = CommitteeHashLib.hash(c.topNodes)`: keccak256 over the ordered raw 20-byte
  addresses, not `abi.encodePacked(address[])`, which pads each address to 32 bytes.
  `BfvPkVerifier.verify` compares its 128-bit limbs with the proof's public inputs, binding the
  proof to the specific committee. `crates/committee-hash` must produce the same bytes. —
  `CommitteeHashLib.sol`; `flow-trace/04`
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
- **The compute path carries no external audit.** Neither Zenith protocol audit (2026-08-17, six
  Solidity files; 2026-09-08, a scoped review of 14 Solidity files) covered Rust, the RISC Zero
  guest, `crates/compute-provider`, `crates/zk-helpers`, or `Risc0BfvCiphertextVerifier.sol`. Treat
  changes there as unaudited. — `packages/interfold-contracts/audits/README.md`
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
  `Risc0BfvCiphertextVerifier` authenticates the receipt's `inputRoot` but compares it with nothing.
  A program that skips the comparison accepts a result computed over any input set. —
  `flow-trace/04`
- **A Secure Process derives its leaves; it never receives them, and never drops one.**
  `MerkleTreeBuilder::compute_leaf_hashes_batched` computes one leaf per supplied input, in the
  supplied order whatever the batching schedule, through the program's `InputPolicy::leaf`,
  including inputs that the policy does not select for computation. The caller must supply the
  complete input set in on-chain order: a received root can disagree with the data it claims to
  describe, and a missing leaf changes the root and makes the result unpublishable. —
  `crates/compute-provider/src/merkle_tree_builder.rs`; `flow-trace/04`
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
  witness generator reverses the message over the full degree, so the payload starts at
  `D - MAX_MSG_NON_ZERO_COEFFS + (MAX_MSG_NON_ZERO_COEFFS mod num_options)` with the options back to
  front; `crisp_lib::utils::ballot_layout` derives that offset, both checkers use it, and no code
  may hand-code it. Each coefficient inside an option segment encodes one bit as 0 or
  `q_mod_t_centered`, everything outside the ballot region must be zero, and a mask's plaintext must
  be zero everywhere. Indexing as if the polynomial were the message width makes both checks read
  only padding: every vote passes any balance bound, and a mask — which needs no signature and may
  be written to any eligible slot — can carry an arbitrary payload into someone else's ballot. Tests
  must build `k1` at the compiled degree, not at `MAX_MSG_NON_ZERO_COEFFS`. — `flow-trace/04`
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
