# Releasing Interfold

This guide covers the shared Rust workspace/core npm release.
[CRISP releases](https://github.com/theinterfold/CRISP/blob/main/RELEASING.md) are separate.
Publication targets the canonical `theinterfold/interfold` repository; do not rename independent
`gnosisguild` dependencies such as fhe.rs as part of release preparation.

Only perform commit, push, tag, publication, or governance actions with authorization. The commands
below describe their effects; they are not read-only checks unless explicitly labeled.

## Qualify the change

Choose a SemVer and review the
[protocol compatibility decision](CONTRIBUTING.md#protocol-compatibility) before preparing it.
[Upgrade policy](docs/architecture/upgrades.md) owns rolling versus mandatory cutovers, release
counters, state reset/migration, deployed verifiers, and rollback. A version bump does not decide or
perform that governance rollout.

PR review and CI must qualify the commit **before tagging**. The release workflow validates
protected history and builds/publications; it does not rerun the full test suite or infer human
approval from ancestry. The job named “Approve Release Artifacts” is an automated dependency gate,
not a manual approval step. Do not treat a successful build as cryptographic verification.

## Prepare a reviewable release branch

Use a clean release branch based on the intended main history. Preview without changes:

```sh
pnpm bump:versions --dry-run X.Y.Z
```

Choose the write behavior deliberately:

`pnpm bump:versions --help` lists the available options.

| Command                                    | Side effects                                                                            |
| ------------------------------------------ | --------------------------------------------------------------------------------------- |
| `pnpm bump:versions X.Y.Z`                 | Updates versions, lockfiles, changelog and formats release files; no stage/commit/push. |
| `pnpm bump:versions X.Y.Z --commit`        | Same preparation, then stages **release outputs only** and commits locally.             |
| `pnpm bump:versions X.Y.Z --commit --push` | Same preparation/commit, then pushes the release branch to origin.                      |

`--commit` rejects main, dev, detached HEAD, and pending changes. `--push` requires `--commit`. The
former `--skip-git` behavior is now the default; replace the removed `--no-push` flag with
`--commit`. File preparation does not require a clean checkout, so review existing work before
running it. The script does not open a PR, create a release tag, or publish artifacts. Required
Cargo/pnpm lock updates, changelog generation, and release-file formatting fail the command before
staging or committing. Failures leave preparation files for review; they do not roll back files or
authorize bypassing a failed check. This is not just a textual version replacement.

The bumper updates the shared Cargo workspace, selected core npm packages (including wasm),
`required_circuits_version`, lockfiles, and CHANGELOG. It also updates Cargo locks for the separate
template host and guest workspaces that record Interfold dependency versions. For stable releases it
updates DAppNode upstream and bumps the independent wrapper version of both network packages
(Mainnet and Sepolia) according to the upstream major/minor/patch progression. Prereleases skip
DAppNode. [Version validation](scripts/release/version.mjs) defines the exact required files.

Add operator instructions under `scripts/release/notes/<version>.md` when needed; asset preparation
includes them in release notes. Stable notes also include that version's prerelease changelog
sections. Update
[deployment records and published addresses](packages/interfold-contracts/README.md#contract-addresses)
before the release commit: an old manifest can make newly installed nodes sync retired contracts.

Open/review/merge the release PR through the normal contribution process. Do not tag the branch tip
before it merges and qualifies on main.

## Tag the merged main commit

After authorization, update local main to the intended origin/main commit and use:

```sh
pnpm release:tag X.Y.Z
```

This command **creates and pushes an annotated `vX.Y.Z` tag**. It requires clean local main equal to
freshly fetched origin/main, matching release versions, and an absent local/remote tag. On failed
push it removes the local candidate tag. It does not independently verify all PR CI/review outcomes.
The workflow rechecks that tag/event SHA agrees and belongs to protected main history.

Do not reuse an existing version/tag for different bytes. The moving `stable` ref is a tag promoted
by successful stable publication, not the branch on which to prepare a release.

## What publication checks and produces

The canonical flow is [.github/workflows/releases.yml](.github/workflows/releases.yml), implemented
by [scripts/release/](scripts/release/). It serializes release promotions and:

1. Validates candidate ancestry and all shared version values.
2. Pulls the newest source-matching circuit artifact revision, not an unrelated branch-tip build.
   `verify-release` requires all six supported pairs, build stamps, and checked manifests.
3. Packages circuits once and hashes the **exact archive bytes** before compiling binaries and the
   ciphernode image. `E3_CIRCUITS_ARCHIVE_SHA256` binds that archive to the binary's release
   version; binary/image `interfold noir status` checks must match. Do not repack it afterward.
4. Requires qualified binaries/circuits before publishing the versioned ciphernode image and core
   npm packages. Stable releases also require the DAppNode packages; prereleases skip them.
5. Requires every publication, assembles binary/circuit archives, address `manifest.json`, checksums
   in release notes, and `release-provenance.json` (candidate/source hash/tag/workflow run).
6. Promotes container aliases and the stable tag where applicable, then creates the GitHub release.

Rust workspace crates are not published to crates.io by this workflow. Both DAppNode packages extend
the checked ciphernode image; the workflow builds them but does not upload them to the DAppNode
registry. Asset inventory and npm retry semantics are owned by the release scripts, not a second
checklist of package versions here.

The separately named `interfold-test-only-skip-proof-aggregation-linux-x86_64` CLI archive enables
proof skipping for tests/CI only. Normal platform archives have no proof-skip feature; the workflow
checks each binary's `rev --features` before packaging. Install/update commands select normal
platform archives, not this test-only archive. Never use it as a production fallback.

Do not confuse SOURCE_HASH (compiling source/tool identity), archive SHA-256 (bytes), recursive VK
anchors, and OpenVM application/receipt commitments.
[Circuit artifacts](docs/architecture/circuit-artifacts.md) owns their checks and limitations. The
small `release-provenance.json` is **not** the full compute-provider provenance record. A maintainer
must separately prepare/validate the OpenVM guest, keys, worker and deployed verifiers and generate
the [compute-provider manifest](docs/pages/build/e3-program/verify-compute-provider.mdx). Current
release CI cannot attach a complete one; `complete: false` is not accepted evidence of identity or
reproducibility. No guide command substitutes for an independent rebuild where required.

## Channels and recovery

| Publication       | Stable `X.Y.Z`           | Prerelease, conventionally `X.Y.Z-dev.N` |
| ----------------- | ------------------------ | ---------------------------------------- |
| npm dist-tag      | latest                   | dev                                      |
| Container aliases | latest **and dev**       | dev                                      |
| GitHub release    | Stable; moves stable tag | Prerelease; stable tag unchanged         |

Thus container `dev` means most recently published release, including a stable one. npm `dev`
changes only on prerelease publication. `interfold update --version dev` selects the most recently
published GitHub release, stable or prerelease; older releases without `interfold update` use the
install script. These channel meanings are not promises of protocol compatibility.

On a failed publication inspect the failed job and already-published artifacts before retrying the
same immutable candidate. npm tooling skips already-published packages only when bytes and dist-tag
match the candidate; do not force new bytes under them or bypass a failing gate. Partial publication
is possible before the final GitHub release exists. A bad published release needs an explicitly
reviewed new version and the
[monotonic counter/rollback procedure](docs/architecture/upgrades.md#rollback-and-evidence), not
moving an immutable version tag backward.

An authorized publisher can also deprecate an affected npm package version, for example:

```sh
npm deprecate @interfold/sdk@1.0.0 "Critical bug, use 1.0.1"
```

Deprecation changes npm metadata, not deployed contracts or node state. Qualify and release the
replacement through the same procedure above.

`pnpm test:release` tests release tooling (tag ancestry, version checks, publication
retries/assets/gates). It neither publishes nor replaces candidate protocol/integration
qualification. Release implementation commands such as `prepare-assets`, `publish-npm`, and
`promote-stable` write state or publish; they are workflow internals, not operator dry runs.
