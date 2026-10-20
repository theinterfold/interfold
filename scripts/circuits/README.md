# Circuit tooling

## Purpose

Root package commands are the supported entry points. The
[Rust builder](../../crates/zk/build/README.md) owns generation; these scripts own transport,
verifier adaptation, and wrappers.
[Artifact boundaries](../../docs/architecture/circuit-artifacts.md) explain identity and
compatibility.

## Map

| File                                                                               | Responsibility                                                                     |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [Rust build crate](../../crates/zk/build/README.md)                                | Selects pairs, compiles Noir, generates keys, and stages artifacts.                |
| [`build-pairs.json`](build-pairs.json)                                             | Shared build policy, separate from release requirements.                           |
| [`constants.ts`](constants.ts)                                                     | Shared circuit group, variant, preset, and committee metadata.                     |
| [`artifacts.ts`](artifacts.ts)                                                     | Published artifact transport, checksums, and release-inventory validation.         |
| [`verifiers.ts`](verifiers.ts)                                                     | Generates/checks Solidity verifiers and applies contract-specific transformations. |
| [`lint.sh`](lint.sh)                                                               | Noir formatting and compiler checks.                                               |
| [`test.sh`](test.sh)                                                               | Noir tests across the configured preset/committee selections.                      |
| [`artifacts.test.ts`](artifacts.test.ts), [`verifiers.test.ts`](verifiers.test.ts) | Tooling regression tests.                                                          |

## Tests

`pnpm test:circuit-tooling` exercises transport/inventory and verifier transformations.
`pnpm test:circuit-build` checks the Rust generator; `pnpm test:circuit-bench` checks benchmark
orchestration and measurement. Install workspace dependencies first. These tests are separate from
`pnpm noir:test` and real-proof suites. `pnpm noir:lint` runs compiler/format checks, but reports a
skip when Nargo is absent. The commands below describe the pinned tools and prepared artifacts
needed for actual circuit/verifier work.

## Circuit Builder

`pnpm build:circuits` runs `e3-zk-build`. It compiles Noir, generates keys, and stages artifacts.

### Usage

```bash
# Build all circuits (defaults: --preset insecure --committee minimum)
pnpm build:circuits

# Switch the active committee size (regenerates committee/active.nr,
# default/mod.nr, and patches BFV_DKG_H / BFV_THRESHOLD_T in utils.ts atomically)
pnpm build:circuits --committee micro

# Combine preset + committee
pnpm build:circuits --preset insecure --committee small

# Build only specific group (dkg or threshold)
pnpm build:circuits --group dkg

# Skip verification key generation (faster)
pnpm build:circuits --skip-vk

# Dry run to see what would be built
pnpm build:circuits --dry-run

# Get source hash for change detection
pnpm build:circuits hash

# Regenerate protocol hashes and config IDs without compiling circuits
pnpm build:circuits sync-config --preset insecure --committee minimum

# Regenerate static declarations without proving
pnpm build:circuits sync-preset --preset insecure --committee minimum

# Compare generated files in an isolated copy
pnpm build:circuits check --committee all

# Benchmark production preparation and Noir execution with artificial inputs
pnpm bench:circuits run --mode insecure --committee minimum --circuit dkg/pk --leaf-only
```

### Committee sizes

Three sizes are supported, mirroring `e3_committee::CiphernodesCommitteeSize`:

| Committee           | N (parties) | T (threshold) | H (honest) |
| ------------------- | ----------- | ------------- | ---------- |
| `minimum` (default) | 3           | 1             | 2          |
| `micro`             | 9           | 4             | 5          |
| `small`             | 19          | 9             | 14         |

[`build-pairs.json`](build-pairs.json) owns permitted pairs. Both Rust and TypeScript read it.
Wildcards preserve manifest order; unsupported explicit pairs fail before tools or writes. The
release matrix is a separate required subset. The Rust builder calls `e3-zk-config` to generate
Reed-Solomon parity matrices; files on disk are derived artifacts, not hand-tuned data.

The currently-active selection is written to `circuits/bin/.active-preset.json` and checked by
`pnpm check:committee` (pre-push hook) against `active.nr`, `utils.ts`, and the parity files.
Switching committee always goes through `pnpm build:circuits --committee` — never edit `active.nr`,
`utils.ts`, or any `parity_*.nr` by hand; the check will reject pushes where they drift from what
the generator would produce.

### What it does

1. **Discovers circuits** in `circuits/bin/{dkg,threshold,recursive_aggregation}/`
2. **Compiles** each circuit using `nargo compile`
3. **Generates verification keys** using `bb write_vk`
4. **Sanitizes paths** in compiled JSON (removes local filesystem paths for opsec)
5. **Generates checksums** (`SHA256SUMS` and `checksums.json`)
6. **Copies artifacts** to `dist/circuits/`

### Options

- `--preset <name>` - Parameter preset: `insecure` (degree 128, default), `insecure-lbfv` (the same
  artifact archive), `secure-8192`, `secure-16384`, or `all`. Secure-16384 supports minimum, micro,
  and small; its build excludes trBFV-only circuits.
- `--committee <name>` - Committee size: `minimum` (default), `micro`, `small`
- `--skip-utils-patch` - Skip rewriting committee values and BFV configuration hashes in
  `packages/interfold-contracts/scripts/utils.ts`
- `--group <groups>` - Circuit groups (comma-separated: dkg,threshold)
- `--circuit <name>` - Build specific circuit(s)
- `--skip-vk` - Skip verification key generation
- `--skip-checksums` - Skip checksum generation
- `-o, --output <dir>` - Output directory (default: dist/circuits)
- `--dry-run` - Show what would be built
- `--no-clean` - Don't clean output directory
- `--no-clean-targets` - Keep compiler targets during a source build
- `--skip-if-built` - Reuse a source-matched build or hydrate its archived pair
- `--hydrate-bin-only` - Hydrate a stamped pair without compiling

Hydration accepts a different source hash, reports it, and records the original artifact hash in the
active stamp. It never restamps the archive. `--skip-if-built` still requires a source match.

Only a complete build with verification keys writes the `nodes_fold.vk_tree_hash` and
`c6_fold.vk_tree_hash` anchors. A build with `--group`, `--circuit`, or `--skip-vk`, or a build with
a failed circuit, removes both anchors from the pair and from `circuits/bin/`. An old anchor can
hash a key that no longer matches the compiled circuits. Run a complete build before you deploy the
BFV verifiers or aggregate proofs.

`sync-config` updates only `scripts/utils.ts` and `ActiveCryptoConfig.sol`, including deployment
routes and pair admission generated from `build-pairs.json`. Use it when BFV parameter constants
change and the prebuilt circuit artifacts already exist. It does not compile Noir circuits or
regenerate verification keys.

### Prerequisites

- `nargo` - Noir compiler ([install](https://noir-lang.org/docs/installation))
- `bb` - Barretenberg prover (for verification keys)

## Circuit Artifacts

`artifacts.ts` - Push/pull pre-built circuit artifacts via git branch.

`crates/zk/prover/versions.json` pins the circuit archive that a released ciphernode downloads. Its
`required_circuits_version` must equal the release tag without the `v` prefix. The release workflow
checks this before it publishes binaries or `circuits-<version>.tar.gz`.

### Usage

```bash
# Build or hydrate the required circuit pairs, then push them to the git branch
pnpm build:circuits --preset insecure --committee minimum
pnpm build:circuits --preset insecure --committee micro
pnpm build:circuits --preset insecure --committee small
pnpm build:circuits --preset secure-8192 --committee minimum
pnpm build:circuits --preset secure-8192 --committee micro
pnpm build:circuits --preset secure-8192 --committee small
pnpm build:circuits --preset secure-16384 --committee minimum
pnpm build:circuits --preset secure-16384 --committee micro
pnpm build:circuits --preset secure-16384 --committee small
pnpm store:circuits push

# Pull circuits from git branch (used by releases)
pnpm store:circuits pull

# Pull the branch tip without a SOURCE_HASH match (used by CI and the integration tests)
pnpm store:circuits pull --latest
```

### Source hash

`pnpm build:circuits hash` prints the hash that gates the published artifacts. It covers the Noir
circuits, the Noir config for the selected preset and committee, the Rust sources that generate the
C1/C2 bounds and the parity matrices, the circuit build scripts, and the external crate pins in
`Cargo.lock`. It ignores the generated bound values, Rust `#[cfg(test)]` modules, the workspace
release version, and the dependency graph between workspace crates. A change outside that set does
not need a circuit rebuild.

### What it does

- **Push**: Merges local `dist/circuits/` into the `circuit-artifacts` branch, refreshes
  `SHA256SUMS` and `checksums.json`, then pushes to origin
- **Checksums**: `pnpm store:circuits checksums --dir <path>` writes `SHA256SUMS` and
  `checksums.json` for exactly the staged directory. CI runs this before packaging the
  circuit-download fixture
- **Pull**: Fetches `circuit-artifacts` and selects its newest first-parent commit with a matching
  `SOURCE_HASH`. It extracts that build to `dist/circuits/`. A build for another source tree at the
  branch tip does not replace this match. If no match exists, the command fails before it changes
  local artifacts. `verify-release` still checks every required pair and build stamp. With
  `--latest`, the command takes the branch tip and does not check `SOURCE_HASH`. CI and the
  integration tests use `--latest` until the circuit drift workflow is designed (#2249). In that
  period, `--hydrate-bin-only` does not check the stamp's source hash either. It reports a mismatch
  and continues
- **Replace**: `pnpm store:circuits push --replace` rewrites the branch from local `dist/circuits/`;
  use only when intentionally deleting old artifact sets
- **Restamp**: `pnpm store:circuits restamp --expect-source-hash <previous hash>` rewrites the build
  stamps when the hash scheme changed but the artifacts did not. Compute the previous hash from the
  same tree with the previous hash implementation. The command refuses a branch that records another
  hash, and it fails when a rewrite touches a circuit artifact

### Workflow

Circuits are built locally and stored in a git branch:

1. **Local**: Build circuits and push to branch

```bash
pnpm build:circuits --preset insecure --committee minimum
pnpm build:circuits --preset insecure --committee micro
pnpm build:circuits --preset insecure --committee small
pnpm build:circuits --preset secure-8192 --committee minimum
pnpm build:circuits --preset secure-8192 --committee micro
pnpm build:circuits --preset secure-8192 --committee small
pnpm store:circuits push
```

2. **CI**: Pulls from branch during release, attaches to GitHub release

3. **After release**: Circuits live permanently in release assets

The release archive must include:

- `insecure/{minimum,micro,small}` for Sepolia and local rehearsals
- `secure-8192/{minimum,micro,small}` for Sepolia secure-parameter tests and mainnet committees
- `secure-16384/{minimum,micro,small}` for the l-BFV V2 configurations

Nodes download one archive and select the artifact directory from the E3's on-chain BFV parameter
set and committee size.

## Verifier Generator

`verifiers.ts` - Generates (or verifies) Solidity Honk verifier contracts from compiled Noir
circuits.

The generated `.sol` files under `packages/interfold-contracts/contracts/verifiers/bfv/honk/` are
**committed to git**. The root files correspond to `(insecure, minimum)`, which is the development /
CI / benchmark default. Non-canonical pairs are committed under `honk/<preset>/<committee>/`. The
Honk verifiers bake in the recursive VKs of `dkg_aggregator` / `decryption_aggregator`, which are
preset- and committee-dependent. Different BFV parameter sets or `H/T` sizes compile to different
VKs and therefore different `.sol` bytes.

The generator enforces this: both `--check` and `--write` refuse to run unless
`dist/circuits/<preset>/<committee>/.build-stamp.json` exists and reports the requested preset, and
`circuits/bin/.active-preset.json` matches the requested preset and committee. The stamps are
written by [`pnpm build:circuits --preset <preset> --committee <name>`](#circuit-builder) and record
which `(preset, committee)` produced the artifacts. If either dimension drifts, the generator
refuses with a clear fix recipe instead of silently producing the wrong `.sol`.

For non-canonical pairs, pass `--preset <name> --committee <name>`; the verifiers land under
`honk/<preset>/<committee>/` so the canonical `.sol` files committed to git are not clobbered.
`--check` compares that pair with its committed files. CI source builds compile/check the selected
default pair; releases require the complete supported matrix.

The script has two modes:

- **`--check` (used by test and CI flows)** — regenerate in memory and diff against the committed
  files. Exits non-zero on drift without touching the working tree.
  `tests/integration/lib/prebuild.sh`, `pnpm check:verifiers` in CI, and the pre-push hook invoke
  the script this way — so accidental drift between committed verifiers and current circuit VKs
  surfaces as a failure rather than a silent rewrite mid-test.
- **`--write` (default for manual runs)** — regenerate and overwrite the committed files. Use this
  when you intentionally bump the canonical-preset circuits or the Noir/bb toolchain.

### Usage

```bash
# Verify committed verifiers match current circuit VKs (CI/tests use this)
pnpm generate:verifiers --check

# Regenerate (default; equivalent to --write)
pnpm generate:verifiers

# Generate for non-canonical pairs
pnpm build:circuits --preset secure-8192 --committee minimum
pnpm generate:verifiers --preset secure-8192 --committee minimum --write

pnpm build:circuits --preset secure-8192 --committee small
pnpm generate:verifiers --preset secure-8192 --committee small --write

# Generate all circuits in a group, without the root alias's on-chain circuit filter
pnpm exec tsx scripts/circuits/verifiers.ts --group dkg
pnpm exec tsx scripts/circuits/verifiers.ts --group threshold

# Generate for specific circuit(s)
pnpm generate:verifiers --circuits pk
pnpm generate:verifiers --circuits dkg_aggregator,decryption_aggregator

# Clean existing verifier directory first (write mode only)
pnpm generate:verifiers --clean

# Preview what would be generated
pnpm generate:verifiers --dry-run

# Skip auto-compilation (requires pre-built circuits)
pnpm generate:verifiers --no-compile
```

### What it does

Automates the full pipeline from Noir circuits to on-chain Solidity verifiers:

1. **Discovers circuits** in `circuits/bin/{dkg,threshold,recursive_aggregation}/`
2. **Compiles circuits** with `nargo compile` (if not already compiled)
3. **Generates verification keys** using `bb write_vk -t evm`
4. **Generates Solidity verifiers** using `bb write_solidity_verifier`
5. **Post-processes** the generated Solidity:
   - Renames contract from `HonkVerifier` to descriptive name (e.g., `DkgAggregatorVerifier`,
     `DecryptionAggregatorVerifier`)
   - Replaces Apache-2.0 license header with LGPL-3.0-only
   - Runs `prettier-plugin-solidity` so on-disk format matches the rest of the repo (and so
     `--check` doesn't trip on whitespace differences vs. raw `bb` output)
6. **Outputs / verifies** at `packages/interfold-contracts/contracts/verifiers/bfv/honk/`:
   - In `--write` mode: overwrites the committed `.sol` files.
   - In `--check` mode: diffs the freshly generated content against the committed `.sol` and exits
     non-zero on any drift, printing the offending files and a fix recipe.

### When `--check` (or `--write`) fails

There are two distinct failure modes — the error output tells you which one:

**1. Target preset and committee not built** — the generator refuses up front because
`dist/circuits/<preset>/<committee>/.build-stamp.json` is missing or reports a different preset. The
committed verifier root is pinned to `insecure/minimum`; non-canonical pairs use their own
subdirectories under `honk/<preset>/<committee>/`.

To fix:

```bash
pnpm build:circuits --preset insecure --committee minimum
# then retry the original command
```

**2. Drift between committed verifiers and current circuit VKs** — the canonical preset is built but
the bytes don't match. Typical causes:

- You ran `pnpm build:circuits` against a different Noir/bb version than the one that produced the
  committed verifiers (see `crates/zk/prover/versions.json` for the pinned versions).
- A circuit was changed without regenerating the committed Solidity files.

To fix:

1. Verify your `nargo` / `bb` versions match `crates/zk/prover/versions.json`.
2. Run `pnpm build:circuits --preset insecure --committee minimum`.
3. Run `pnpm generate:verifiers --preset insecure --committee minimum --write`.
4. Run the same build and generate commands for each non-canonical pair.
5. Commit the resulting diff under `packages/interfold-contracts/contracts/verifiers/bfv/honk/`.

### Options

The `generate:verifiers` script in package.json passes `--circuits` with the on-chain used list.

- `--check` - Verify committed verifiers match current VKs (no writes). Exits non-zero on drift.
- `--write` - Write/overwrite committed verifiers. Default when neither `--check` nor `--write` is
  passed.
- `--circuits <list>` - Circuit names, comma-separated. Omit to generate all.
- `--group <groups>` - Circuit groups (comma-separated: dkg,threshold,recursive_aggregation)
- `--clean` - Remove existing verifier directory before generating (write mode only)
- `--no-compile` - Don't compile circuits automatically (fail if not already compiled)
- `--no-clean-targets` - Don't delete nargo target dirs before generating verifiers
- `--dry-run` - Show what would be generated without doing anything
- `-h, --help` - Show help message

### Prerequisites

- `nargo` - Noir compiler ([install](https://noir-lang.org/docs/installation))
- `bb` - Barretenberg CLI for proof system operations

### Output Example

```
🔮 Generating Solidity verifiers from Noir circuits...

   Found 2 circuit(s)

   ✓ recursive_aggregation/dkg_aggregator → DkgAggregatorVerifier.sol
   ✓ recursive_aggregation/decryption_aggregator → DecryptionAggregatorVerifier.sol

✅ Generated 2 Solidity verifier(s) in:
   packages/interfold-contracts/contracts/verifiers/bfv/honk/
```

### Integration

Generated verifiers are automatically:

- Compiled with aggressive size optimization (`runs: 1` in Hardhat config)
- Deployed via `pnpm deploy` (integrated into main deployment flow)
- Saved to `deployed_contracts.json`
- Verified on block explorers via `pnpm verify:contracts`

### Notes

- Verifier contracts are large (~24KB) due to pairing cryptography
- Library linking (e.g., `ZKTranscriptLib`) is handled automatically during deployment
- Generated files are excluded from linting (`.solhintignore`)
