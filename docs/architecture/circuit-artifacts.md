# Circuit artifacts and deployment provenance

Owners: [TypeScript circuit builder](../../scripts/build-circuits.ts),
[artifact store](../../scripts/circuit-artifacts.ts),
[Rust artifact installer](../../crates/zk-prover/src/backend/download.rs), and
[deployment tooling](../../packages/interfold-contracts/scripts/). This checkout uses the existing
builder, not a proposed replacement crate stack.
[Circuit Builder usage](../../scripts/README.md#circuit-builder) owns commands;
[proof contracts](proof-statements.md) owns what the artifacts must prove.

## Generated configuration and pair identity

Use `pnpm build:circuits --committee <name> [--preset <preset>]` and `pnpm check:committee`. Do not
hand-edit generated default/active selectors, parity matrices, C1/C2 bounds, generated TS/Solidity
constants, verifier output, local `.active-preset.json`, or prepared OpenVM identity artifacts.
Canonical committees `(N,T,H)` are minimum `(3,1,2)`, micro `(9,4,5)`, small `(19,9,14)`. Every
preset/committee pair has its own H-shaped PK and T-shaped decryption public-input layout.

`check-committee.sh` compares committee Noir/Rust/ActiveCryptoConfig/deployment utils, complete
threshold BFV tuples across deployment constants/Rust/preset Noir, and configuration IDs across
contracts, tasks, SDK, and EVM helpers. Drift can register a tuple nodes/circuits do not implement.
The committed default is insecure-512/minimum; CI rebuilds that selection and rejects diffs. Local
active-preset cache mismatch is only a note. **Limits:** the gate does not compare
`scripts/circuit-constants.ts` committee values; manually review those. Parity regeneration/diff
runs only with `target/release/zk-artifacts` and nargo; Repository Checks can skip it, while
circuits CI catches committed-selection drift by rebuilding.

C1/C2 `PK_GENERATION_*`/`SHARE_COMPUTATION_*` bounds are derived from preset+committee. Generator
replaces whole declarations including array dimensions and rejects unknown prefixed globals, because
pair source hash ignores generated values. Smudging quotient bounds grow with committee: retaining a
minimum array in another pair can reject honest proofs. A renamed global must first have
declarations seeded in both preset files, removing the old name, then run generation. `sync-config`
switches the active preset/committee; it does not regenerate bounds. General generated-file policy
does not permit guessing new generated values by hand.

Toolchain is one compatibility unit: Nargo/Rust Noir beta.26, witness serialization, bb 5.2.0,
archive, VKs, SDK noir_js/bb.js, and generated verifiers. **Gap:** no script compares every version
pin across CI, release, `versions.json`, Cargo, and SDK. Rust witness stacks use
`WitnessStack::serialize()` (beta.26 MessagePack), never bincode. A valid archive checksum cannot
make older ACIR/serialization compatible. Rebuild/publish matching archives and regenerate
keys/verifiers before changing required circuit version.

The builder refuses nargo/bb versions other than pinned values. Pair SOURCE_HASH covers compiling
Noir sources, library entry/dependency manifest/shared constants, pinned Noir tag/bb version, and
Rust bound generation sources (`zk/cli`, fhe-params, committee, polynomial and its FHE adapter),
excluding cfg(test) modules. Normalize active-preset selector and generated bound declarations:
switching pair or editing a test must not stale another pair. Cargo.lock contributes only external
name/version/source/checksum, not workspace version churn. Library-only changes invalidate every
affected pair.

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
[supported-configurations](../../crates/zk-prover/supported-configurations.json) must ship:
insecure-512 and secure-8192 × minimum/micro/small. That matrix is canonical for
release/installation, must match builder pairs (tooling test), and is not itself a SOURCE_HASH
input.

Default `store:circuits pull` selects newest first-parent artifact commit with matching source hash,
not necessarily branch tip. Release uses it and `verify-release` checks every pair, stamps,
manifests, and required artifacts before publication. **Known gap (#2249):** non-release
CI/integration use `pull --latest` without source match; `--hydrate-bin-only` does not check stamp
source hash. Those paths do not supply release-level source provenance. Do not remove strict release
checking to match them.

The expected archive digest ships **with the binary**, never fetched from the archive or endpoint.
0.18.0's pin is the published GitHub asset digest; other version pins live in versions.json. Release
packaging hashes and retains exact bytes, passes `E3_CIRCUITS_ARCHIVE_SHA256` to binary/image
compilation, and build.rs validates it. ZkConfig binds it to crate version. `noir status` checks
binary and ciphernode image against that digest before candidate publication. Support image builds
no CLI/node; DAppNode copies the checked image. Unpinned builds compile, but downloads fail before
network access.

Both download and local install require nonempty SHA-256 checksums.json, verify every entry, reject
uncovered artifacts, and require every path in
[required-artifacts](../../crates/zk-prover/required-artifacts.json) for required/included pairs.
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
relevant files; CI hydrates/compares all supported pairs using the same filter. A wrapper name alone
does not identify its accepted statement.

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

`crates/support/contracts/ImageID.sol` is frozen historical RISC Zero identity: producer guest is
gone, but secureCrisp/validateSecureCrisp still read it. Never regenerate or hand-edit; remove it
only together with those scripts. Current OpenVM template/CRISP read deployed receipt identity; no
generated copy of ImageID.sol is tracked. Never commit deployment-local
executable/key/proof/input/worker-config/benchmark artifacts; put them under target or outside
source.

## Provenance and checks

`pnpm provenance:manifest` ties source/lockfiles/artifact digests/OpenVM commitments/worker identity
and deployed protocol/receipt/Halo2 verifiers. Missing fields mean `complete: false`, not partial
"verified" output. Even complete manifests need independent reproducibility evidence. **Gap:**
release workflow does not attach the manifest; a maintainer must run it manually. See
[verification procedure](../pages/build/e3-program/verify-compute-provider.mdx).

Use `pnpm check:committee`, `pnpm test:circuit-tooling`, `pnpm check:verifiers` after prepared
builds, and `pnpm store:circuits verify-release` for archive release acceptance. Existing
[artifact tooling tests](../../scripts/circuit-artifacts.test.ts),
[deployment artifact selection](../../packages/interfold-contracts/test/Deployment/VerifierArtifactSelection.spec.ts),
and [storage tests](../../packages/interfold-contracts/test/Standards/StorageLayouts.spec.ts) guard
distinct boundaries; none proves cryptographic soundness or every missing pin/width/provenance
comparison.
