# Circuit artifacts and deployment provenance

Owners: [Rust circuit builder](../../crates/zk/build/),
[artifact store](../../scripts/circuits/artifacts.ts),
[Rust artifact installer](../../crates/zk/prover/src/backend/download.rs), and
[deployment tooling](../../packages/interfold-contracts/scripts/).
[Circuit Builder usage](../../scripts/circuits/README.md#circuit-builder) owns commands;
[proof contracts](proof-statements.md) owns what the artifacts must prove.

## Generated configuration and pair identity

Use `pnpm build:circuits --committee <name> [--preset <preset>]` and `pnpm check:committee`. Do not
hand-edit generated default/active selectors, parity matrices, C1/C2 bounds, generated TS/Solidity
constants, verifier output, local `.active-preset.json`, or prepared OpenVM identity artifacts.
Canonical committees `(N,T,H)` are minimum `(3,1,2)`, micro `(9,4,5)`, small `(19,9,14)`. Every
preset/committee pair has its own H-shaped PK and T-shaped decryption public-input layout.

`pnpm check:committee` compares committee Noir/Rust/ActiveCryptoConfig/deployment utils, complete
threshold BFV tuples across deployment constants/Rust/preset Noir, and configuration IDs across
contracts, tasks, SDK, and EVM helpers. Drift can register a tuple nodes/circuits do not implement.
The committed default is insecure-64/minimum; CI rebuilds that selection and rejects diffs. Local
active-preset cache mismatch is only a note. **Limits:** the gate does not compare
`scripts/circuits/constants.ts` committee values; manually review those. With Nargo available, the
gate runs `pnpm build:circuits check --committee all`. The Rust owner renders/formats an isolated
library copy and compares generated files without swapping live files. Circuit CI also rejects
committed-selection drift after rebuilding.

C1/C2 `PK_GENERATION_*`/`SHARE_COMPUTATION_*` bounds are derived from preset+committee. Generator
replaces whole declarations including array dimensions and rejects unknown prefixed globals, because
pair source hash ignores generated values. Smudging quotient bounds grow with committee: retaining a
minimum array in another pair can reject honest proofs. A renamed global must first have
declarations seeded in both preset files, removing the old name, then run generation. `sync-config`
updates deployment utils and ActiveCryptoConfig only; it neither switches Noir selectors nor
regenerates bounds. General generated-file policy does not permit guessing new generated values by
hand.

Generated provenance headers retain their original spelling across tooling moves. Changing those
bytes requires a coordinated generated-source refresh; renaming a script alone must not make CI's
source-regeneration comparison fail. Maintained documentation links identify the current owner.

Toolchain is one compatibility unit: Nargo/Rust Noir beta.26, witness serialization, bb 5.2.0,
archive, VKs, SDK noir_js/bb.js, and generated verifiers. **Gap:** no script compares every version
pin across CI, release, `versions.json`, Cargo, and SDK. Rust witness stacks use
`WitnessStack::serialize()` (beta.26 MessagePack), never bincode. A valid archive checksum cannot
make older ACIR/serialization compatible. Rebuild/publish matching archives and regenerate
keys/verifiers before changing required circuit version.

Build and benchmark share exact-version parsing in `crates/zk/build/src/toolchain.rs`. Pair
SOURCE_HASH covers compiling Noir, library entry/dependency manifests, shared constants, pinned
tools, and Rust configuration/witness/build sources and templates. The build manifest contributes
edition/features, not workspace dependency edges or release versions. Cargo.lock contributes only
external name/version/source/checksum. The shared build policy is an input; the release matrix is
not.

`identity.rs` uses the versioned `interfold:zk-source:v2` hash stream. Records carry a type tag,
repository-relative UTF-8 name, content, and explicit name/content lengths. Moving a source between
roots changes its identity. Required files, directories, and tool pins must exist unless the build
supplies that generated file's staged contents. A missing relocated owner fails instead of silently
reducing provenance. Circuit-group order cannot change the same source set's hash.

Normalize active-preset selection and generated bound values; exclude cfg(test) modules and the
build crate's separate tests. Switching pair or editing a test must not stale another pair.
Library-only changes invalidate affected pairs. Cache/release reuse rejects another hash scheme;
development hydration retains the artifact's original identity rather than relabeling it.

Restamp published artifacts only when the branch records the hash produced by the **same source
tree** under the old hash scheme. Another tree needs a rebuild, not a new label.

## Archive bytes are not source or application identity

| Identity                                            | Binds                                                                  | Does not establish                                               |
| --------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------- |
| SOURCE_HASH / pair build stamp                      | Compiling source, tools, preset, committee                             | Exact archive bytes or independent reproducibility.              |
| Compiled version-bound archive SHA-256              | Exact downloaded/installed release archive                             | Correct source or compatible tools merely from checksum success. |
| checksums.json / SHA256SUMS                         | Artifact bytes within archive                                          | An attacker-chosen expected digest.                              |
| Recursive VK tree anchors                           | Complete descendant proof trust for that pair                          | OpenVM application/receipt identity.                             |
| OpenVM application commitments and receipt identity | Guest executable, VM configuration, proving/deployed verifier boundary | Artifact SHA-256 or source reproducibility by itself.            |

`required_circuits_version` equals Interfold release version without v; binary resolves GitHub tag
`v{version}` / `circuits-{version}.tar.gz`. Release workflow rejects mismatch. All six pairs in
[supported-configurations](../../crates/zk/prover/supported-configurations.json) must ship:
insecure-64 and secure-8192 × minimum/micro/small. That matrix is canonical for release/installation
and must be a subset of `scripts/circuits/build-pairs.json` (tooling test). Both Rust and TypeScript
read that build policy. Wildcards preserve its order, not a Cartesian product; an unsupported
explicit pair fails before tools or writes.

Default `store:circuits pull` selects newest first-parent artifact commit with matching source hash,
not necessarily branch tip. Release uses it and `verify-release` checks every pair, stamps,
manifests, and required artifacts before publication. Non-release CI/full-proof integration can use
`pull --latest` without a source match. `--hydrate-bin-only` requires a stamp and markers, reports a
source mismatch, and records the original artifact hash in the active stamp. It never rewrites the
archived stamp. `--skip-if-built` still requires a source match. These development reuse paths do
not supply release-level source provenance; retain strict release qualification.

The expected archive digest ships **with the binary**, never fetched from the archive or endpoint.
0.18.0's pin is the published GitHub asset digest; other version pins live in versions.json. Release
packaging hashes and retains exact bytes, passes `E3_CIRCUITS_ARCHIVE_SHA256` to binary/image
compilation, and build.rs validates it. ZkConfig binds it to crate version. `noir status` checks
binary and ciphernode image against that digest before candidate publication. Both DAppNode packages
extend the checked ciphernode image. Unpinned builds compile, but downloads fail before network
access.

Both download and local install require nonempty SHA-256 checksums.json, verify every entry, reject
uncovered artifacts, and require every path in
[required-artifacts](../../crates/zk/prover/required-artifacts.json) for required/included pairs.
SOURCE_HASH/root manifests/stamps are metadata, not prover artifacts. Required pairs cannot be
chosen by archive contents. Explicit nonempty subsets are available through installer APIs and
repeated `--circuits-configuration` only with `--circuits-archive`. Local archives need the same
version pin unless explicit `--allow-unpinned-archive`; without that flag a missing pin fails closed
too. CI candidate fixtures deliberately use that flag/subsets, not production policy.

Validate before replacement so failure preserves installed circuits/version. Install errors trigger
best-effort rollback but remain the returned error. Log every failed rollback rename source/target;
if previous artifacts cannot restore, retain staging path for operator recovery rather than erase
it.

## Verifier and deployment compatibility

Complete pair builds generate `nodes_fold.vk_tree_hash`/`c6_fold.vk_tree_hash` from all recursive
keys. Subset builds, skip-VK, or any circuit failure remove **both** pair/bin anchors to prevent
stale pins. Cache markers and release validation require both; hydration copies them. Final wrappers
pin these tree hashes at input zero and C5/C7 separately, not an immediate fold VK hash.

Each supported pair has concrete BfvPkVerifier/BfvDecryptionVerifier; immutable routers dispatch by
public-input length and VK anchors. Selecting an already installed matching pair needs no
replacement; missing routes or changed VKs require matching wrappers and replacement routers before
mapping updates. Constructor code checks/nonzero VK anchors are mandatory. Deployment compares
immutables with built artifacts. Generated verifiers must match built VKs: pre-push reads circuit
filter paths and checked-out insecure pair (local committee/default minimum), refusing dirty
relevant files; CI source builds compile/check the selected default pair using the same filter.
Releases require the complete supported matrix. A wrapper name alone does not identify its accepted
statement.

Published `@interfold/contracts` deploys do not require a checkout. Outside the monorepo,
node-release metadata comes from `dist/node-release.json`, written by `compile:ts`, and BFV VK paths
use `INTERFOLD_CIRCUITS_DIR`. The circuits must match the package release. Monorepo deployments
ignore that override and retain repository release files and local artifact selection. See
[npm-package deployment](../../packages/interfold-contracts/README.md#deploying-from-the-npm-package)
for layout and setup.

Storage baselines are committed read-only CI inputs; missing baseline, compiler drift, incompatible
nested layout, and bad gap consumption fail. Creating a baseline is explicit maintainer work, never
an automatic fix. Tracked contract artifacts feed CLI `sol!`; after `pnpm evm:build`,
`pnpm check:bindings` compares fresh ABI and requires regenerated artifacts for changed
functions/events/errors. Size CI reserves >=128 bytes below EIP-170 for Interfold, BondingRegistry,
CiphernodeRegistryOwnable, and canonical insecure-minimum aggregator verifiers. **Limit:** every
variant must fit, but other verifier variants are not measured by that gate. See
[registration](registration-and-bonding.md) for library links.

Configuration writes in deployInterfold/configureLocalSlashingPolicies use `scripts/utils.ts`'s
`send`: await mined receipt, require success, preserve send/mining error cause. Awaiting a setter
alone means sent, not mined. Deployment then reads back references/authorizations before enabling
requests: tokens, treasuries, claim source, reciprocal contracts, BFV bindings, initial program,
reward distributor, transfer whitelist, and fee admission. Add readback with every new reference.
Owner/admin and scalar policy values are different checks; integration base checks committee
thresholds. **Gap:** graph check does not read ERC-1967 implementation/admin slots, so reused or
later-upgraded proxies need separate validation.
[Voting-power deployment](voting-power.md#bonded-history-and-deployment) covers its required
checkpoint attachment, resync, adapter and exclusion probes.

The OpenVM template and CRISP read the deployed receipt identity; no generated Solidity identity
file is tracked. Never commit deployment-local executable/key/proof/input/worker-config/benchmark
artifacts; put them under target or outside source.

## Provenance and checks

The [Rust benchmark owner](../../crates/zk/benchmarks/README.md) validates selected artifact
digests, compiler version, pair, and proof variant while retaining published source stamps. A local
config cache separately binds compiled/VK digests and tool/pair identity. Fresh compilation records
local source identity, not a hydrated archive hash. Protocol children receive the validated BB path
through `E3_CUSTOM_BB`. Replay uses saved folded proofs; missing verifier measurements remain
incomplete.

`pnpm provenance:manifest --project <checkout>` ties source/lockfiles/artifact digests/OpenVM
commitments/worker identity and deployed protocol/receipt/Halo2 verifiers. `--project` names the
clean checkout of the project whose guest the worker configuration describes. Missing fields mean
`complete: false`, not partial "verified" output. Even complete manifests need independent
reproducibility evidence. **Gap:** release workflow does not attach the manifest; a maintainer must
run it manually. See
[verification procedure](../pages/build/e3-program/verify-compute-provider.mdx).

Use `pnpm check:committee`, `pnpm test:circuit-tooling`, `pnpm check:verifiers` after prepared
builds, and `pnpm store:circuits verify-release` for archive release acceptance. Existing
[artifact tooling tests](../../scripts/circuits/artifacts.test.ts),
[deployment artifact selection](../../packages/interfold-contracts/test/Deployment/VerifierArtifactSelection.spec.ts),
and [storage tests](../../packages/interfold-contracts/test/Standards/StorageLayouts.spec.ts) guard
distinct boundaries; none proves cryptographic soundness or every missing pin/width/provenance
comparison.
