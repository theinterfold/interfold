# Proposal: canonical BFV configuration and circuit identities

Status: proposed design for [#2197](https://github.com/theinterfold/interfold/issues/2197). This
document specifies intended changes, not implemented guarantees. No parameter change, deployment,
publication, or release-counter change is part of the consolidation.

Implementation is in progress. The parameter crate owns the scheme/version constants and identity
APIs; the builder, node admission, and indexer use them. Shared language bindings, structured
metadata, circuit-identity manifests, mandatory matrix checks, and the CRISP companion remain
planned.

Reviewed Interfold `origin/main`: `354af6bef3b1cdd8fa23c53093feede923125d55`. Reviewed CRISP HEAD:
`735ce8208ecfff425fc22cea2960f6e1b655ef43`.

## Decision

Extend the existing parameter, committee, configuration, and build owners. Generate language
bindings from their Rust APIs and circuit identities from compiled artifacts. Do not introduce
another parameter catalogue, a general code-generation framework, or a runtime configuration
service.

Keep three boundaries distinct:

1. Selected protocol inputs: manually maintained Rust values.
2. Static derivations: parameter hashes, layouts, circuit bounds, and parity matrices.
3. Artifact identities: verification-key hashes and ordered recursive commitments.

The first migration must preserve parameter bytes, configuration IDs, circuit statements, and
admission behavior. A changed verification key is a compatibility finding, not an acceptable side
effect to hide through regeneration.

## Current implementation and gaps

| Area                       | Current owner or evidence                                                                              | Required change                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| BFV presets and search     | `crates/fhe-params/src/{constants,presets}.rs`                                                         | Export structured metadata and complete search recipes. Keep search constraints separate from selected parameters. |
| Committee names and values | `crates/committee/src/lib.rs`                                                                          | Generate consumers from this owner. Do not move its table into `fhe-params`.                                       |
| Protocol hashing           | `crates/fhe-params/src/encoding.rs`                                                                    | Migrate remaining request-helper IDs and other-language consumers with their consistency checks.                   |
| Message width              | `crates/zk/config/src/lib.rs`, generated Noir selector, Solidity wrapper, tests                        | Generate other-language bindings from the ZK owner and remove remaining consumer literals.                         |
| Deployment and SDK values  | `packages/interfold-contracts/scripts/{utils.ts,protocol/constants.ts}`, contract tasks, SDK utilities | Import one generated browser-safe parameter binding.                                                               |
| Decryption layout          | Solidity wrapper/router and deployment utilities                                                       | Replace the independent `61 + 3*T` calculations with generated layout helpers.                                     |
| Circuit generation         | `crates/zk/build`                                                                                      | Extend this Rust owner, not the removed TypeScript builder.                                                        |
| Recursive anchors          | `crates/zk/build/src/vk_tree.rs`                                                                       | Retain the existing SAFE hash procedures and dependency order. Export their results in an identity manifest.       |
| Consistency checks         | `scripts/checks/committee.sh`, builder `check`, verifier tooling                                       | Replace source-parsing ownership checks with generated-output checks and complete artifact validation.             |

The existing builder `check` compares parity files. It does not regenerate every preset declaration
or validate the full identity matrix. CI builds and checks the default pair; release validation
requires six pairs. These are different assurance scopes.

Parameter search already reproduces the selected threshold/DKG pairs in
`search_reproduces_secure_presets` and `search_reproduces_insecure_presets`. Its CLI defaults
already import the canonical secure search inputs. Preserve this work rather than implement a second
search or another CLI-default table.

CRISP is no longer in this repository. Its two fold circuits still contain separate, manually
maintained anchor constants. Completing the original issue requires a companion CRISP change.

## Ownership and dependency direction

| Owner                      | Manually maintained facts or responsibility                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-fhe-params`            | Selected threshold/DKG tuples, variances, security/search inputs, scheme name, circuit-version domain, ABI encoding and configuration-ID derivation. |
| `e3-committee`             | Committee names, serialized order, N/H/T, exact lookups.                                                                                             |
| `e3-zk-config`             | Bounds, parity, selected message width, public-input layout descriptions, coefficient serialization dimensions.                                      |
| `e3-zk-witness`            | Existing SAFE commitment implementation used for ordered VK-tree hashes.                                                                             |
| `e3-zk-build`              | Composition, rendering, tool execution, artifact-derived identities, generated-output inventory, and checks.                                         |
| Contract/deployment policy | Chain admission, production/testnet defaults, and registry/deployment history. These remain policy, not BFV arithmetic.                              |
| CRISP                      | Ballot rules, application keys, application fold commitments, and application verifiers.                                                             |

Normal dependency direction remains `build -> witness -> config -> fhe-params`, with committee facts
supplied by `e3-committee`. Runtime consumers must not depend on the unpublished build crate. Do not
add committee dependencies to the parameter crate solely to assemble an export.

Message width is a circuit statement/layout choice, not a BFV parameter. Keep
`e3_zk_config::MAX_MSG_NON_ZERO_COEFFS` as its Rust owner. The builder composes parameter and
circuit metadata for generated bindings; `fhe-params` must not depend on ZK configuration or
re-export the circuit width.

Runtime request execution belongs to `crates/zk/prover/src/request_execution.rs`
(`execute_zk_request`) and `crates/trbfv/src/request_execution.rs` (`TrBFVRequest::execute`).
`e3-multithread` coordinates admission/retry/publication using `e3-task-pool`; it no longer owns the
circuit/native calculation dispatch. Keep configuration/export code independent of these runtime
adapters and pool APIs. Do not move parameter logic back into the dispatcher.

### Parameter APIs

Keep the current scheme name and `INTERFOLD_BFV_VERSION` in `crates/fhe-params/src/constants.rs`.
Preserve existing public names where callers need them. Circuit message width remains in
`e3-zk-config`.

Extend the optional `abi-encoding` boundary with APIs for:

- The hash of exact ABI parameter bytes.
- A configuration ID from those bytes and an explicit circuit-version domain.
- The current configuration ID for a supported threshold preset.
- Structured export of selected threshold/DKG values, search metadata, and current registry index.

Preserve these formulas exactly:

```text
parameterHash = keccak256(encode_bfv_params(thresholdParameters))
cryptoConfigId = keccak256(abi.encode(
    keccak256("fhe.rs:BFV"), parameterHash, keccak256(circuitVersion)
))
```

The encoded parameter value remains one ABI tuple:
`(uint256 degree, uint256 plaintext_modulus, uint256[] moduli, string error1_variance)`. Do not
replace the tuple encoding with a differently framed argument list.

Historical indexer verification hashes the original registry bytes. It must not decode and re-encode
them before hashing. Keep the indexer's explicit v1 branch and index-0/index-1 limits; sharing a
hash function must not make historical configurations admissible to current nodes.

Export values through typed APIs, not Rust-source parsing. Transfer large integers as decimal
strings, then render exact target-language literals. Use TypeScript `bigint` for moduli and degrees;
retain the exact decimal variance string used by the ABI. Search party counts do not become N.

### Search recipes and security metadata

Keep selected presets authoritative for generation. Do not execute parameter search during binding
generation or replace a selected tuple with a newly searched candidate.

The typed metadata API must distinguish the preset's selected parameters, its reproduction recipe,
and arbitrary user search requests. A complete reproduction recipe includes the existing `n`, `z`,
`k`, `lambda`, `b`, and `b_chi` inputs plus `d`, `insecure`, `mult_depth`, `min_prime_bits`, and
`min_margin`. Extend the existing preset/search APIs to expose these facts; derive shared values
from current owners rather than add another recipe table. Preserve both current preset recipes as
summation-only (`mult_depth = 0`).

Keep search-policy constants in their current search modules. Preserve the two-bit preset margin,
generated-prime pool size/order, table-versus-generated prime selection, and window search order.
Use the existing `search::utils::{variance_uniform_sym, variance_cbd_str}` functions when export
metadata needs those derivations; do not add another variance calculation.

Security metadata must retain its evidence scope. `search::security` uses a lattice-estimator
ceiling for its tabulated dimensions with `b = 20`, `b_chi = 1`, and `m = 2*d` samples. Other inputs
use a formula fallback with a CLI warning. Multiplication/relinearization exposes additional
samples, so a searched depth-positive set needs its own security estimate. Neither a successful
search nor a generated metadata record establishes installed circuit/verifier support. In
particular, a search result at degree 16384 does not add a supported preset or registry route.

## Generated outputs

### Parameter and layout bindings

Generate one shared binding per other language:

| Proposed output                                                                | Consumers                                                                                  |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| `packages/interfold-contracts/bfv.ts`, published as `@interfold/contracts/bfv` | Deployment helpers, contract tasks/tests, SDK, dashboard consumers, external applications. |
| `packages/interfold-contracts/contracts/lib/BfvProtocol.sol`                   | ActiveCryptoConfig, BFV wrappers/routers, program templates, and contract test programs.   |
| `circuits/lib/src/configs/protocol.nr`                                         | The default selector and circuit consumers, through existing re-exports where needed.      |

The TypeScript export contains data and pure layout functions only. It imports no Hardhat, Node
filesystem APIs, prover, WASM, or package root with deployment side effects. Update package exports
and TypeScript compilation inputs, and test the packed package outside the monorepo. SDK CJS output
also needs an import/require smoke test.

Keep `scripts/protocol/constants.ts` and `scripts/utils.ts` exports where callers need them, but
make them imports/re-exports or policy adapters. Stop patching their numeric declarations. Make
ActiveCryptoConfig a stable policy consumer of the generated Solidity library, not another generated
copy of current hashes. Preserve its existing chain rules and error behavior.

Generate committee leaf declarations and language committee tables from `e3-committee` through the
same build operation. Preserve preset/committee names, serialized enum variants, and on-chain
indices. Keep current parameter indices 0 and 2; index 1 remains historical.

Keep `scripts/circuits/build-pairs.json` as build policy and the prover's
`supported-configurations.json` as release requirements. Validate the release subset and resolve
both against canonical metadata. Neither file becomes a second table of numeric parameters.

### Layouts

Extend `crates/zk/config/src/output_layout.rs` with the decryption aggregator's named layout. It
owns the fixed prefix, return prefix, column count, offsets, and encoding size, and references the
same crate's `MAX_MSG_NON_ZERO_COEFFS`. Generate target helpers from this description using small,
explicit renderers. The target-language `MESSAGE_COEFFS_COUNT` binding derives from this ZK
constant, not from `fhe-params`. Do not add a general schema language.

```text
shareCount(T)          = T + 1
partyIdOffset          = 7 + 1
skOffset(T)            = partyIdOffset + shareCount(T)
esmOffset(T)           = skOffset(T) + shareCount(T)
messageOffset(T)       = esmOffset(T) + shareCount(T)
publicInputsLength(T)  = messageOffset(T) + MESSAGE_COEFFS_COUNT
plaintextByteLength    = MESSAGE_COEFFS_COUNT * 8
```

Both Solidity wrapper and router use the same generated helper. Retain the constructor's existing
positive-threshold domain rather than silently restricting it to three committee values. For
supported T values 1, 4, and 9, current application input lengths are 64, 73, and 88.

Independently flatten public parameters and the public return value from the compiled Noir ABI.
Compare named parameters and ordered types/dimensions with the layout contract; anonymous return
tuples have no field names to compare. Compare the VK's public-input count separately: current Honk
verifiers include eight pairing-point fields that callers do not supply. For example, the default
verifier declares 72 inputs but accepts 64 application inputs. Pin and test that backend
distinction; do not infer the application layout from the raw VK count.

Do not generate circuit signatures from the same descriptor used as the expected answer. Keeping the
compiled ABI independent makes the comparison useful.

### Circuit-identity manifest

Generate a versioned `circuits/identities.json` covering every supported build pair. Use a key of
`(preset, committee, group/circuit, proofVariant, hashKind)`. Group-qualified circuit names avoid
collisions. Reject duplicate, missing, and unknown required entries.

Each entry records:

- The typed identity kind and exact 32-byte value.
- The compiled-artifact and VK byte digests and repository-relative artifact paths.
- The selected pair and its source identity, plus pinned Nargo/BB versions.
- Ordered dependency keys for a composite identity.

Keep these kinds separate:

| Kind                             | Derivation                                                                            |
| -------------------------------- | ------------------------------------------------------------------------------------- |
| Parameter/configuration identity | Existing Ethereum ABI/Keccak formulas.                                                |
| BB VK hash                       | Pinned `bb write_vk` result for the exact compiled artifact and verifier target.      |
| Solidity `VK_HASH`               | The EVM verifier generator's result for that key; validate against its actual output. |
| Recursive tree commitment        | Existing ordered SAFE `DS_VK_HASH` composition.                                       |
| Artifact digest                  | SHA-256 of file bytes, for integrity rather than proof identity.                      |

An implementation can share a value between kinds only after the pinned backend establishes their
equivalence. It must not substitute a generic file digest or a guessed Keccak/Poseidon formula.

Retain `.vk`, `.vk_hash`, and `.vk_tree_hash` artifact paths and runtime loading behavior. Those are
already generated inputs, not manually maintained parameter copies. Named deployment adapters select
manifest entries and check their artifact digests; they do not accept a manifest value without its
matching key material.

Ship the manifest, or validated pair slices, with new circuit archives and copy the deployment
metadata into the npm package. Keep it outside its own source-hash input graph. Do not immediately
add it to the runtime installer's mandatory inventory: existing supported release archives lack it.
Requiring it at runtime needs a separate artifact-format compatibility decision.

Keep generated Solidity verifiers self-contained. Inline `VK_HASH` values are permitted generated
outputs, not independent owners. Regenerate and compare each full verifier when its key changes;
centralizing one hash cannot replace its embedded verification key.

## Build order and failure behavior

Use explicit phases inside `e3-zk-build`, with existing compiler/verifier adapters:

```text
Rust parameter + committee APIs
    -> generated protocol bindings, bounds, parity, selected configuration
    -> source identity and leaf compilation
    -> leaf VKs and backend hashes
    -> any compiled-in descendant anchors
    -> dependent folds/aggregators and their VKs
    -> complete recursive tree commitments
    -> final identity manifest and full Solidity verifiers
    -> checksums and qualified artifact output
```

Not every fold embeds a constant anchor. Preserve today's proof construction and tree topology; do
not redesign witness-supplied recursive keys to make the build graph look uniform. Reject a
compiled-in self-dependency instead of hashing the final manifest back into its inputs.

Use staged generated contents for source hashing, including the new protocol module. Preserve the
existing framed source identity policy. Generation inputs must invalidate the affected source
identity; outputs must not create a hash cycle. No archive restamping or source-hash weakening is
authorized by this design.

The current source-hash scope includes all of `crates/fhe-params/src`, including search code. A
search-only change can therefore invalidate pair stamps without changing selected parameters or VKs.
Treat that as a provenance mismatch, not automatic proof incompatibility. Keep its resolution with
#2249 rather than exempt search inputs or relabel archives in this consolidation.

Stage multi-file updates before publication. Write only changed content, in stable order, without
timestamps or absolute paths. Check mode uses isolated copies and never switches live selectors.
Preserve the existing rule that incomplete/failed builds remove both final tree anchors. They must
also invalidate any completion marker for the attempted manifest; an old index cannot qualify
partial new artifacts.

## CRISP integration

Interfold cannot own CRISP's complete fold commitment: one component is a CRISP application key.
Publish Interfold's typed parameter binding and release-matched circuit identities. In a companion
CRISP change:

1. Consume a pinned Interfold release/artifact set, not a mutable branch tip.
2. Build the CRISP ballot leaf circuits.
3. Compute the existing ordered commitments from the matching user-encryption, ballot, ct0, and ct1
   keys, with the current proof variants and SAFE domain.
4. Generate one shared anchor module imported by `fold` and `fold_onchain`.
5. Compile both folds, regenerate both verifiers, and validate application proof acceptance.

The shared module contains distinct constants for each ballot stack and supported preset. Do not
replace those different commitments with one value. Keep CRISP's ten-option policy local and check
that it fits the shared message width; the protocol width does not automatically become the
application's option limit.

Interfold checks its own complete matrix. CRISP checks its application extensions. Closing #2197
requires linked verification evidence from both repositories, not an Interfold check that fetches an
arbitrary CRISP checkout.

## Mandatory consistency gate

Proposed commands, implemented by extending the existing builder:

```text
pnpm generate:crypto-config              # regenerate shared source bindings/configuration
pnpm check:crypto-config --bindings-only # explicit source-only result, not full acceptance
pnpm check:crypto-config                 # full supported-matrix acceptance
```

Generation of parameter bindings must not require compiled artifacts. The final manifest is a later
build output. This separation avoids requiring an old manifest to generate its own inputs.

Full mode requires prepared, source-matched artifacts. It does not silently download, rebuild,
hydrate, or repair them. Missing tools, pairs, variants, checksums, or outputs are failures with
preparation instructions. Report every checked pair and the exact assurance scope.

Full mode must:

1. Regenerate bindings, complete preset declarations, committee declarations, bounds, and parity in
   isolation. Compare every registered generated path, including committed default selectors.
2. Check every build-policy pair and ensure that every release-required pair is included.
3. Verify source identity, tool pins, artifact inventory, and checksums.
4. Re-run the pinned VK generation against the exact compiled artifacts. Compare key bytes and
   hashes, not merely the manifest against neighboring `.vk_hash` files.
5. Recompute ordered tree commitments and regenerate compiled-in anchors. Reject missing
   descendants, wrong variants, noncanonical field values, and reordered dependencies.
6. Regenerate complete Solidity verifiers from their EVM keys and compare their bytes.
7. Check application layouts against compiled ABIs and backend public-input metadata.
8. Check ownership hygiene across consumers. Reject independent scheme/version/config-ID and width
   definitions outside registered owners, generated outputs, and reviewed fixtures/history.

Committed preset files retain their declared canonical committee. Stage other committees'
pair-specific declarations and compare them with the corresponding artifacts, not with one live
preset file. Comparing every pair against the same minimum-committee bounds would be incorrect.

Ownership scanning is a regression guard, not semantic proof. Do not ban every occurrence of `50` or
exempt arbitrary files because their header says generated. Use an explicit output/fixture
inventory, targeted definitions, and tests that a new consumer copy is detected.

Keep `check:committee` as a compatibility entry point into shared source checks while callers
migrate; remove its independent Rust/TypeScript source parsing. Do not reduce existing coverage.

Wire full mode into relevant pre-push checks and required CI. Extend shared path routing for all
canonical owners, templates, generated outputs, the checker, and its tests. Use per-pair isolated CI
preparation/validation and one required aggregate result that fails on a skipped required leg. A
bindings-only result must never satisfy that aggregate result.

Coordinate source-matched artifact preparation with
[#2249](https://github.com/theinterfold/interfold/issues/2249). Current `--latest` hydration can
support development, but cannot satisfy this gate. Keep the existing source-hash policy until that
separate design is approved; do not solve its performance cost by accepting stale artifacts.

## Compatibility and rollout

Classify the intended consolidation as compatible rolling, with unchanged `protocol_version` and
`node_generation`, only after the comparisons below pass. Preserve serialized types, enum order,
contract ABI/storage/events, parameter bytes, hash domains, public-input order, and recursive trust.
Current runtime admission remains current-only; indexer historical handling remains explicit.

New bindings and manifest metadata are additive. A source identity can change because owners or
paths moved even when ACIR/VKs do not. Qualify new artifacts normally; do not relabel older
archives. The consolidation does not authorize governance transactions or replacement verifiers.

If compiled bytecode/VKs change unexpectedly, stop the compatibility claim and investigate. If a key
change is intentional, document supported old/new verifier combinations and obtain a separate
rollout decision. Do not regenerate the real-proof fixture merely to conceal that difference.

For a later parameter, message-width, DKG, or statement update, make an explicit circuit-version and
protocol/node-counter decision. The threshold parameter hash does not directly include DKG
parameters or message width. Do not silently change the configuration-ID formula to address that
limitation. Keep registry entries append-only and deployment history immutable.

Rollback of the behavior-preserving consolidation uses the preceding compatible implementation and
its matching package/artifact set. If evidence requires a protocol cutover instead, follow
[upgrade policy](upgrades.md); this rollback assumption no longer applies.

## Verification plan

| Boundary                     | Evidence required                                                                                                                                                                   |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hash/ABI preservation        | One reviewed fixture set with exact encoded bytes, parameter hashes, current configuration IDs, and historical v1 examples. Rust, ethers/viem, and Solidity independently check it. |
| Parameter export             | Exact large integers, distinct threshold/DKG records, search-vs-selected distinctions, and unsupported-value errors.                                                                |
| Search preservation          | Existing preset-reproduction, estimator-limit, and multiplication-depth tests; exact reproduction recipes and unchanged CLI defaults/warnings.                                      |
| Generated source             | Determinism, no-op regeneration, full preset/committee coverage, read-only checks, and missing-output failures.                                                                     |
| Layouts                      | Current T=1/4/9 counts and offsets, arbitrary supported constructor inputs, compiled ABI flattening, and the Honk pairing-field distinction.                                        |
| Identity graph               | Real backend VK derivation, wrong-pair/variant rejection, ordered SAFE known answers, missing descendants, stale manifests, and incomplete-build invalidation.                      |
| Consumer packaging           | Browser import without Node/prover dependencies, SDK ESM/CJS use, and npm deployment outside the checkout.                                                                          |
| Historical/current admission | Existing indexer historical-key tests and runtime rejection of old/unknown configuration IDs.                                                                                       |
| Proof behavior               | Real recursive proof verification, BFV wrapper acceptance, tampered anchor/input rejection, and the committed fixture without a benchmark override.                                 |

Use `cargo test --locked -p e3-fhe-params --features abi-encoding`, focused committee/config/witness
tests, `pnpm test:circuit-build`, `pnpm test:circuit-tooling`, SDK tests, and affected contract
suites. After prepared artifacts exist, run full `check:crypto-config`, real Rust/SDK proof suites,
and an affected integration scenario. Run CRISP's real-proof paths in its companion change.

Reuse the existing search reproduction tests instead of duplicating them. If a change affects a
runtime parameter consumer, exercise its current ZK/TrBFV request-execution boundary. The prover's
`--lib request_execution::` tests cover request admission, correlations, C5/C7 thresholds, and C6
key validation; they do not replace its prepared real-proof tests. Preserve the shared-pool C0
admission, serial barriers, and cancellation behavior without adding scheduler work to this issue.

Behavioral tests import dimensions, but expected cryptographic answers stay independent. Updating
the reviewed known-answer fixture must be explicit, never an automatic test repair. Refresh
`test/fixtures/bfv_vk_binding/folded_artifacts.json` only when its proof statement actually changes.

Complete a separate protocol/domain review against the actual implementation diff. Record deployed
verifier compatibility, old-data replay, mixed-version admission, results, and remaining limits as
[CONTRIBUTING.md](../../CONTRIBUTING.md#protocol-compatibility) requires.

## Implementation sequence

1. **Parameter owner and frozen evidence.** Capture known answers. Add constants/hash/export APIs.
   Reuse search reproduction coverage and export complete recipes. Migrate Rust callers and preserve
   aliases/historical behavior. No parameter or search-policy changes.
2. **Bindings and consumer migration.** Generate shared language modules and layout helpers. Migrate
   deployment, SDK, contract, template, and test consumers. Consolidate current numerical prose into
   one reference; keep upgrade history explicit.
3. **Identity pipeline.** Generate the manifest from real artifacts, integrate named deployment
   lookup, and validate recursive dependencies/full verifiers. Preserve runtime artifact paths.
4. **Mandatory gates.** Complete isolated generation checks, negative regressions, CI/path routing,
   and local completion checks. Do not report matrix acceptance from the old default-only job.
5. **CRISP companion and acceptance rehearsal.** Migrate application consumers/anchors, run
   cross-repository proof evidence, and measure recurring-update paths.

Each slice needs its own covering checks and review. These are reviewable changes within the issue,
not permission to publish multiple PRs or deploy them.

## Measuring the 25-file target

The original #2195 diff contains 58 tracked paths, including CRISP and generated outputs. The
23-plus-2 estimate in #2197 is unmeasured. Do not claim success from a smaller Interfold-only diff
after CRISP moved out of the repository.

Measure a recurring update after consolidation, separately from the one-time migration:

- Record the baseline commit, exact old/new inputs, commands, and path inventory.
- Count every changed tracked path, including generated bindings, manifests, verifiers, fixtures,
  and documentation. Count replacement paths and companion CRISP paths without exclusions.
- Report source-repository paths separately from artifact-branch/archive/deployment outputs.
- Do not pack unrelated outputs into one file merely to meet the metric.

The proposed output layout retains this provisional recurring-update budget:

| Output group                                                      | Tracked paths |
| ----------------------------------------------------------------- | ------------: |
| BFV decryption verifiers and both CRISP verifiers                 |             8 |
| Secure parity matrices and threshold/DKG Noir configurations      |             5 |
| Canonical Rust parameter/circuit inputs and three shared bindings |             5 |
| Identity manifest and shared CRISP anchor module                  |             2 |
| Reviewed known answers and the real-proof fixture                 |             2 |
| Current parameter reference and explicit upgrade documentation    |             2 |
| Release pin                                                       |             1 |
| **Target maximum, not a measurement**                             |        **25** |

Keeping message width in its ZK owner consumes the original one-file allowance, so this budget has
no spare path after the release pin. It assumes no additional verifier changes. If the actual
dependency graph requires them, count them and report the target as missed. Do not leave a stale DKG
or application verifier to preserve the estimate. Additional CRISP-specific proof fixtures must also
count.

A literal historical replay needs special handling: #2195 changed width 100 to 50, but current
degree-64 circuits cannot accept width 100. Their share-decryption statement requires width <= ring
degree. Do not restore historical presets to current runtime admission for the experiment.

Recommended acceptance method: run the same old-to-new update on a historical-compatible rehearsal
branch with the consolidation adapted to the original degree-512 baseline. Use the original
Interfold-plus-CRISP logical scope. This is a separate, potentially substantial rehearsal, not a
normal current-main build. Keep its changes out of production.

Pin the search implementation and recipe for each historical snapshot as well. Current preset
reproduction tests describe the current selected tuples; do not weaken those tests to make a
historical tuple pass under a different search model.

If maintainers choose a current-main equivalent update instead, agree on valid inputs and the
comparison scope in #2197 before measuring it. Label that result equivalent, not a literal replay.
Preserve the <=25 target as unverified until the agreed experiment passes.

## Decisions needed before implementation is complete

1. Confirm a companion CRISP change is required for issue closure. Recommendation: yes.
2. Approve historical replay versus a specified current-main equivalent for the 25-file metric.
   Recommendation: retain the historical rehearsal for the literal acceptance criterion.
3. Coordinate strict artifact preparation and CI cost with #2249. Recommendation: fail closed with
   source-bound preparation; optimize provenance separately rather than weaken the gate.

## Evidence limits for this proposal

This design comes from source, issue/PR inventories, CI configuration, and CRISP fold inspection.
The latest-main recheck compared the four commits after the original Interfold review, including the
parameter-search and ZK/TrBFV/shared-pool ownership changes. Selected preset constants, ABI
encoding, committees, configuration/witness/build owners, contracts, SDK, and circuit CI/checker
paths are unchanged across that range. CRISP remains reviewed at the separate commit above.

The design review did not run parameter generation, proof campaigns, runtime tests, or the 25-file
rehearsal. Implementation checks are reported separately. The worktree has no installed Node
dependencies or complete circuit-artifact matrix.

Relevant current contracts: [proof statements](proof-statements.md),
[circuit artifacts](circuit-artifacts.md), [upgrades](upgrades.md), and
[design principles](design-principles.md).
