# BFV configuration consolidation: verification record

Issue: [#2197](https://github.com/theinterfold/interfold/issues/2197). Local qualification date:
2026-10-22. This records implementation evidence, not release/deployment authorization or a new
cryptographic audit.

## Qualified scope

The complete build-policy matrix was freshly compiled in isolated source snapshots with the pinned
Nargo beta.26 and BB 5.2.0. All **300 VK byte sequences and backend hashes** matched the preserved
pre-consolidation artifact set. No verifier or known-answer fixture was regenerated to conceal a key
change, and older source stamps were not relabelled.

`pnpm check:crypto-config --artifacts-dir <prepared-output>` passed for all six pairs. This included
complete generated-source/consumer ownership checks, source stamps, required inventory/checksums,
independent backend VK rederivation, ordered SAFE dependencies, complete regenerated Solidity
verifiers, and independently flattened compiled decryption ABIs. Minimum/micro/small expose 64/73/88
application fields and 72/81/96 backend Honk fields respectively, for either preset.

The identity manifest is [the generated output](../../circuits/identities.json), not a second
hand-maintained catalogue. It has six pairs and 354 typed identity entries. Repeated generation
preserved output bytes/mtimes; full checking preserved all output mtimes. The publication worktree
reproduced the qualified manifest exactly. Hashed production/tool/Noir inputs were compared
byte-for-byte across the qualification and publication worktrees; upstream dashboard changes,
stack-CI routing, and test placement do not alter those inputs.

Compiler source maps now canonicalize checkout and Nargo Git-cache paths. Unknown absolute paths
fail. Unit coverage includes Unix/macOS/Windows path spellings, and separate local compilations of
C0, C7, and the DKG aggregator agreed after canonical source-path normalization. This is not a claim
that an independent cross-platform CI run has already passed.

## Covering checks

- Foundation parameter/search/encoding suite: 53 unit and four frozen compatibility tests passed.
- Builder/CLI/metadata suite: 36 tests passed, including the explicitly selected pinned-backend
  regression. The CLI-versus-formatted-build source-hash regression fails before the selector-import
  normalization fix and passes afterward for every pair.
- Circuit tooling/binding/packaging suite: 22 tests passed on the complete implementation.
- Focused protocol/layout/router/installed-package contract suites: 52 tests passed.
- Prepared VK-binding, protocol-deployment, and E3 lifecycle integration suites: 107 tests passed.
  Both folded aggregator proofs in the committed fixture verified without a benchmark override;
  stale wrapper immutables were rejected. Lifecycle tests use the established mock compute boundary,
  not a claim of a live ciphernode fleet run.
- SDK unit tests: 38 passed. Prepared browser-WASM encryption proof suite: seven passed, including
  changed public-input and proof rejection.
- Prepared native C3 and C6 sequential fold proofs and correlated sparse-self-slot node folding:
  three real-proof tests passed. The small-committee runtime C7 test also produced and verified a
  real proof over ten shares.
- Fresh Solidity/TypeScript build and `check:bindings` passed. ABIs, bytecode, deployed bytecode,
  and immutable locations of the five rebuilt tracked CLI artifacts were unchanged; compiler-run
  IDs/AST numbering were kept out of the source change.
- Dashboard tests on the updated main base: 12 passed. Lint and pnpm/license/committee/address/
  repository/documentation-link checks passed, with existing non-fatal lint/license/ethers enum
  fragment warnings.

The native/browser proof suites used the supported provenance-preserving development hydration path
for an earlier, VK-compatible compilation while the final source-hash-only fix was being qualified.
Their archive stamps were retained. Complete acceptance above comes from the separate fresh
source-bound matrix, not from that hydration or from selected-pair checks.

## Separate compatibility/domain review

The actual diff and post-change owners were reviewed against
[proof statements](proof-statements.md), [threshold decryption](threshold-decryption.md),
[artifact provenance](circuit-artifacts.md), and [upgrade policy](upgrades.md), following
[protocol compatibility](../../CONTRIBUTING.md#protocol-compatibility).

Proposed rollout class is compatible rolling, subject to human review. Protocol 8, generation 2,
current BFV tuples/domains/configuration IDs, committee ordering, T+1 versus H meaning, proof
multiplicity, ABI preimages, public-input order, serialized runtime types, storage declarations,
events, and gossip/sync encodings remain unchanged. Current node/client admission still rejects
retired/unknown configurations; the indexer retains explicit historical v1 handling over exact
registered bytes. No state migration, new peer overlay, replacement verifier, or governance action
is introduced. Matching earlier package/artifact sets remain the rollback boundary.

Review findings addressed before qualification were machine-dependent source-map paths and the
formatter moving `protocol` imports across the selected preset's lexical position. Sorting is
limited to the normalized selector's imports; recursive dependency order and repeated proofs are not
sorted or deduplicated. The C7 hint change removes only an unused hinted remainder; its bounded
quotient/remainder constraints and VKs are preserved. There are no remaining actionable findings
from this read-only pass; maintainer approval, live mixed-fleet testing, and audit assurance are
separate requirements.

## Remaining acceptance limits

- The separate CRISP companion is prepared in its own repository/worktree for a release-blocked
  draft, tied to a digest-pinned local candidate. It awaits an immutable published Interfold release
  and final public dependency pins; Interfold CI never fetches an arbitrary CRISP checkout.
- The literal historical #2195 rehearsal has **not** been executed. Original before/after sources,
  the 58-path reference, and an isolated historical baseline have been retained. The <=25 recurring
  tracked-file target remains unmeasured; no Interfold-only count or excluded generated/companion
  paths are offered as a substitute.
- This record does not assert a successful GitHub CI run, production deployment, full live
  mixed-version fleet, accelerated OpenVM guest proof, or complete crash/replay equivalence.

These limits remain tracked in #2197; passing the Interfold matrix alone does not satisfy the
cross-repository release and historical-measurement requirements.
