# Release tooling

## Purpose

Prepare synchronized versions and execute release operations with consistent candidate, channel, and
publication checks. [RELEASING.md](../../RELEASING.md) owns the operator procedure and recovery
decisions; this directory contains its executable implementation.

## Map

| File                           | Responsibility                                                                       |
| ------------------------------ | ------------------------------------------------------------------------------------ |
| [`bump.ts`](bump.ts)           | Updates manifests, lockfiles, circuit archive pin, DAppNode metadata, and changelog. |
| [`index.mjs`](index.mjs)       | Dispatches tag, preparation, publication, asset, and promotion commands.             |
| [`version.mjs`](version.mjs)   | Shared package/workspace inventory, version validation, and channels.                |
| [`dappnode.mjs`](dappnode.mjs) | DAppNode upstream pin and wrapper versions for both network packages.                |
| [`git.mjs`](git.mjs)           | Candidate ancestry, release tags, and stable-tag promotion.                          |
| [`npm.mjs`](npm.mjs)           | Package publication and rerun handling using archive integrity.                      |
| [`assets.mjs`](assets.mjs)     | Required archives, checksums, provenance, and release-note assembly.                 |
| [`gates.mjs`](gates.mjs)       | Publication results and structural workflow checks.                                  |
| [`core.mjs`](core.mjs)         | Shared Git, JSON, and error helpers.                                                 |
| [`notes/`](notes/)             | Authored version-specific upgrade notes included in releases.                        |

## Usage

From the repository root with workspace dependencies installed:

```sh
pnpm bump:versions 0.19.1 --dry-run
pnpm bump:versions 0.19.1
```

The second command prepares files, runs required Cargo/pnpm lock updates, and generates/formats
release content. It does not commit or push by default. The release guide documents explicit Git
flags and the separate `pnpm release:tag` command. Publication helpers are also called by
[the release workflow](../../.github/workflows/releases.yml).

## Tests

Run `pnpm test:release`. [`bump.test.ts`](bump.test.ts) uses fixture manifests and injected commands
to check preparation and failure handling. [`index.test.mjs`](index.test.mjs) tests ancestry with
temporary Git repositories, publication with simulated registry responses, and asset/workflow
contracts. Tests do not publish real packages or qualify protocol compatibility.
