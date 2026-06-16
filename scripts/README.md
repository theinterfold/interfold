# Scripts

This directory contains utility scripts for the Interfold project.

## Version Bumper

`bump-versions.ts` - Bumps the versions of all packages and crates in the project.

### Usage

```bash
# Full release (bump, commit, tag, and push)
pnpm bump:versions 1.0.0

# Pre-release version
pnpm bump:versions 1.0.0-beta.1

# Local only (don't push to remote)
pnpm bump:versions --no-push 1.0.0

# Manual git operations (just bump versions)
pnpm bump:versions --skip-git 1.0.0

# Test run (see what would happen)
pnpm bump:versions --dry-run 1.0.0
```

### What it does

**By default, the script performs a complete release:**

1. **Validates** your working directory is clean (no uncommitted changes)
2. **Updates versions** across the entire monorepo:
   - Rust workspace version in root `Cargo.toml`
   - All npm packages in `packages/` and `crates/wasm`
   - Root `package.json`
3. **Updates lock files**:
   - `Cargo.lock` for Rust dependencies
   - `pnpm-lock.yaml` for npm dependencies
4. **Generates changelog** from conventional commits (uses `CHANGELOG.md`)
5. **Commits** all changes with message: `chore(release): bump version to X.Y.Z`
6. **Creates** annotated git tag: `vX.Y.Z`
7. **Pushes** commits and tag to GitHub
8. **Triggers** the automated release workflow

### Examples

```bash
# One-command release (recommended)
pnpm bump:versions 1.2.3
# This bumps everything, commits, tags, and pushes - triggering the full release!

# Pre-release for testing
pnpm bump:versions 1.2.3-beta.1
# Automatically detected as pre-release, published to npm with 'next' tag

# Prepare release locally first
pnpm bump:versions --no-push 1.2.3
# Does everything except push - review first, then: git push && git push --tags

# Just bump versions (old behavior)
pnpm bump:versions --skip-git 1.2.3
# Only updates versions, you handle git operations manually
```

### Options

- `--skip-git` - Skip all git operations (add, commit, tag, push)
- `--no-push` - Perform git operations locally but don't push
- `--dry-run` - Preview what would happen without making any changes
- `--help` - Show help message

### Prerequisites

- Clean working directory (no uncommitted changes)
- Conventional commits for changelog generation
- Valid semver version format

### After Running

Once you run `pnpm bump:versions X.Y.Z` and the tag is pushed, GitHub Actions automatically:

- Builds binaries for all platforms (Linux, macOS)
- Publishes to npm (with `latest` or `next` tag)
- Publishes to crates.io
- Creates GitHub release with changelog and binaries

## License Header Checker

`check-license-headers.sh` - Checks and fixes SPDX license headers in source files.

### Usage

```bash
# Check all files for license headers
./scripts/check-license-headers.sh

# Automatically fix missing headers
./scripts/check-license-headers.sh --fix

# Check only (for CI/CD, exits with code 1 if issues found)
./scripts/check-license-headers.sh --check-only
```

### What it does

- Scans all `.rs`, `.sol`, and `.ts` files in the repository
- Excludes certain files with different licensing (e.g., `ImageID.sol` from RISC Zero with Apache
  license)
- Checks for the required SPDX license header:
  ```
  // SPDX-License-Identifier: LGPL-3.0-only
  //
  // This file is provided WITHOUT ANY WARRANTY;
  // without even the implied warranty of MERCHANTABILITY
  // or FITNESS FOR A PARTICULAR PURPOSE.
  ```
- In `--fix` mode, automatically adds the header to files that are missing it
- Skips files that already have an SPDX header (these need manual review)
- Excludes common build/dependency directories (`node_modules`, `target`, etc.)

### CI/CD Integration

This script is automatically run in GitHub Actions:

- On pull requests: checks headers and comments if any are missing
- On pushes to main/develop: automatically fixes missing headers and commits changes

## Clean Script

`clean.ts` - Removes build artifacts and temporary files from the repository using predefined safe
patterns while providing options to skip specific parts of the codebase.

### Usage

```bash
# Clean build artifacts
pnpm clean

# Dry run to see what would be cleaned
pnpm clean --dry-run

# Clean everything except crates and contracts
pnpm clean --skip-crates --skip-contracts

# Interactive cleaning
pnpm clean --interactive

# Show help message
pnpm clean --help
```

### What it does

- **Uses predefined patterns** to identify safe-to-clean build artifacts and temporary files
- **Safely removes** only files matching known safe patterns (node_modules, dist, target, etc.)
- **Provides granular control** over what gets cleaned via skip options
- **Shows detailed statistics** about what was removed and space freed
- **Prevents accidental deletion** of important files by using a whitelist approach

## Circuit Builder

`build-circuits.ts` - Compiles Noir circuits, generates verification keys, and prepares release
artifacts.

### Usage

```bash
# Build all circuits (defaults: --preset insecure-512 --committee minimum)
pnpm build:circuits

# Switch the active committee size (regenerates committee/active.nr,
# default/mod.nr, and patches BFV_DKG_H / BFV_THRESHOLD_T in utils.ts atomically)
pnpm build:circuits --committee micro

# Combine preset + committee
pnpm build:circuits --preset insecure-512 --committee small

# Build only specific group (dkg or threshold)
pnpm build:circuits --group dkg

# Skip verification key generation (faster)
pnpm build:circuits --skip-vk

# Dry run to see what would be built
pnpm build:circuits --dry-run

# Get source hash for change detection
pnpm build:circuits hash
```

### Committee sizes

Three sizes are supported, mirroring `e3_zk_helpers::CiphernodesCommitteeSize`:

| Committee           | N (parties) | T (threshold) | H (honest) |
| ------------------- | ----------- | ------------- | ---------- |
| `minimum` (default) | 3           | 1             | 2          |
| `micro`             | 9           | 4             | 5          |
| `small`             | 19          | 9             | 10         |

All `(preset, committee)` pairs work because the Reed-Solomon parity matrices in
`circuits/lib/src/configs/committee/<name>/parity_{insecure,secure}.nr` are auto-generated by the
`generate_parity_matrices` Rust binary, invoked from `build-circuits.ts` whenever the committee
changes. The matrix files on disk are derived artifacts.

The currently-active selection is written to `circuits/bin/.active-preset.json` and checked by
`pnpm check:committee` (pre-push hook) against `active.nr`, `utils.ts`, and the parity files.
Switching committee always goes through `pnpm build:circuits --committee` — never edit `active.nr`,
`utils.ts`, or any `parity_*.nr` by hand; the check will reject pushes where they drift from what
the generator would produce.

### What it does

1. **Discovers circuits** in `circuits/bin/dkg/` and `circuits/bin/threshold/`
2. **Compiles** each circuit using `nargo compile`
3. **Generates verification keys** using `bb write_vk`
4. **Sanitizes paths** in compiled JSON (removes local filesystem paths for opsec)
5. **Generates checksums** (`SHA256SUMS` and `checksums.json`)
6. **Copies artifacts** to `dist/circuits/`

### Options

- `--preset <name>` - Parameter preset: `insecure-512` (default), `secure-8192`, or `all`
- `--committee <name>` - Committee size: `minimum` (default), `micro`, `small`
- `--skip-utils-patch` - Skip rewriting `BFV_DKG_H` / `BFV_THRESHOLD_T` in
  `packages/interfold-contracts/scripts/utils.ts`
- `--group <groups>` - Circuit groups (comma-separated: dkg,threshold)
- `--circuit <name>` - Build specific circuit(s)
- `--skip-vk` - Skip verification key generation
- `--skip-checksums` - Skip checksum generation
- `-o, --output <dir>` - Output directory (default: dist/circuits)
- `--dry-run` - Show what would be built
- `--no-clean` - Don't clean output directory

### Prerequisites

- `nargo` - Noir compiler ([install](https://noir-lang.org/docs/getting_started/installation/))
- `bb` - Barretenberg prover (for verification keys)

## Circuit Artifacts

`circuit-artifacts.ts` - Push/pull pre-built circuit artifacts via git branch.

### Usage

```bash
# Build circuits locally, then push to git branch
pnpm build:circuits
pnpm store:circuits push

# Pull circuits from git branch (used by CI)
pnpm store:circuits pull
```

### What it does

- **Push**: Copies `dist/circuits/` to the `circuit-artifacts` orphan branch and pushes to origin
- **Pull**: Fetches the `circuit-artifacts` branch and extracts to `dist/circuits/`

### Workflow

Circuits are built locally and stored in a git branch:

1. **Local**: Build circuits and push to branch

```bash
   pnpm build:circuits
   pnpm tsx scripts/circuit-artifacts.ts push
```

2. **CI**: Pulls from branch during release, attaches to GitHub release

3. **After release**: Circuits live permanently in release assets

## Verifier Generator

`generate-verifiers.ts` - Generates (or verifies) Solidity Honk verifier contracts from compiled
Noir circuits.

The generated `.sol` files under `packages/interfold-contracts/contracts/verifiers/bfv/honk/` are
**committed to git** and correspond to **exactly one `(preset, committee)` pair**:
`(insecure-512, minimum)` (the development / CI / benchmark default). The Honk verifiers bake in the
recursive VKs of `dkg_aggregator` / `decryption_aggregator`, which are preset- and committee-
dependent — different BFV parameter sets or `H/T` sizes compile to different VKs and therefore
different `.sol` bytes. The committed files only match `(insecure-512, minimum)`.

The generator enforces this: both `--check` and `--write` refuse to run unless
`dist/circuits/insecure-512/.build-stamp.json` exists and reports `"preset": "insecure-512"`, and
`circuits/bin/.active-preset.json::committee` matches the requested committee. The stamps are
written by [`pnpm build:circuits --preset <preset> --committee <name>`](#circuit-builder) and are
the only on-disk record of which `(preset, committee)` built `circuits/bin/`. If either dimension
drifts, the generator refuses with a clear fix recipe instead of silently producing the wrong
`.sol`.

For non-canonical committees (e.g. `small`), pass `--committee <name>`; the verifiers land under
`honk/<name>/` so the canonical-committee `.sol` files committed to git aren't clobbered. `--check`
mode skips the diff for non-canonical committees because there's no committed file to diff against —
benchmark and deploy flows already deploy fresh aggregator verifiers from runtime artifacts.

The script has two modes:

- **`--check` (used by test/benchmark/CI flows)** — regenerate in memory and diff against the
  committed files. Exits non-zero on drift without touching the working tree. This is how
  `tests/integration/lib/prebuild.sh`, `circuits/benchmarks/scripts/extract_crisp_verify_gas.sh`,
  and `circuits/benchmarks/scripts/replay_folded_verify_gas.sh` invoke the script — so accidental
  drift between committed verifiers and current circuit VKs surfaces as a failure rather than a
  silent rewrite mid-test.
- **`--write` (default for manual runs)** — regenerate and overwrite the committed files. Use this
  when you intentionally bump the canonical-preset circuits or the Noir/bb toolchain.

### Usage

```bash
# Verify committed verifiers match current circuit VKs (CI/tests use this)
pnpm generate:verifiers --check

# Regenerate (default; equivalent to --write)
pnpm generate:verifiers

# Generate for a non-canonical committee (writes under honk/small/)
pnpm generate:verifiers --committee small --write

# Generate only for specific group
pnpm generate:verifiers --group dkg
pnpm generate:verifiers --group threshold

# Generate for specific circuit(s)
pnpm generate:verifiers --circuit pk
pnpm generate:verifiers --circuit pk --circuit fold

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

**1. Canonical preset not built** — the generator refuses up front because
`dist/circuits/insecure-512/.build-stamp.json` is missing or reports a different preset. The
committed verifiers are pinned to `insecure-512`; nothing under `circuits/bin/` is trusted unless
the build stamp confirms the canonical preset was last built.

To fix:

```bash
pnpm build:circuits --preset insecure-512
# then retry the original command
```

**2. Drift between committed verifiers and current circuit VKs** — the canonical preset is built but
the bytes don't match. Typical causes:

- You ran `pnpm build:circuits` against a different Noir/bb version than the one that produced the
  committed verifiers (see `crates/zk-prover/versions.json` for the pinned versions).
- A circuit was changed without regenerating the committed Solidity files.

To fix:

1. Verify your `nargo` / `bb` versions match `crates/zk-prover/versions.json`.
2. Run `pnpm build:circuits --preset insecure-512`.
3. Run `pnpm generate:verifiers --write`.
4. Commit the resulting diff under `packages/interfold-contracts/contracts/verifiers/bfv/honk/`.

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

- `nargo` - Noir compiler ([install](https://noir-lang.org/docs/getting_started/installation/))
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
