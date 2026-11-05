# Repository checks

## Purpose

Use the root `pnpm check:*` commands. `repository.sh` checks Cargo feature/sample containment,
application/node dependency boundaries, ciphernode Docker workspace membership, production Compose
shutdown grace, startup proof-guard presence, and the `.do_send(` line-count ceiling. It is static
configuration validation, not runtime/proof assurance. The grace check accepts the maintained
two-space service / four-space integer-second `stop_grace_period` layout and requires exactly one
budget above 60 seconds per service. It rejects duplicate, missing, quoted, or non-integer-second
fields; it is not a general YAML/Compose validator (aliases and other valid duration notations are
not supported).

## Map

| File                                                               | Responsibility                                                                                                 |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| [`repository.sh`](repository.sh)                                   | Runs configuration, startup proof-guard, and send-count checks.                                                |
| [`repository-baselines.env`](repository-baselines.env)             | Owns the send-count ceiling; increases need explicit call-site review.                                         |
| [`cargo-feature-containment.py`](cargo-feature-containment.py)     | Checks proof-skip features and dev-only ZK sample/benchmark dependencies, including aliases and target tables. |
| [`cargo-dependency-boundaries.py`](cargo-dependency-boundaries.py) | Keeps application execution and the node binary from linking each other's packages.                            |
| [`ciphernode-docker-members.py`](ciphernode-docker-members.py)     | Compares workspace members with Docker manifest copies.                                                        |
| [`committee.sh`](committee.sh)                                     | Compares cross-language committee and BFV configuration.                                                       |
| [`addresses.ts`](addresses.ts)                                     | Checks published addresses and classified consumers against the deployment manifest.                           |
| [`cli-bindings.ts`](cli-bindings.ts)                               | Compares tracked ABIs with freshly built contract artifacts.                                                   |
| [`license-headers.sh`](license-headers.sh)                         | Checks SPDX headers and optionally adds missing headers.                                                       |
| [`pnpm.sh`](pnpm.sh)                                               | Checks the package-manager version against the root pin.                                                       |
| [`shell-syntax.mjs`](shell-syntax.mjs)                             | Parses shell sources individually.                                                                             |
| [`changed-format.mjs`](changed-format.mjs)                         | Checks supported files changed between two Git revisions.                                                      |
| [`doc-links.mjs`](doc-links.mjs)                                   | Checks relative Markdown/MDX file targets, exact case, and heading/explicit-ID anchors without network access. |

## Usage

Run commands from the repository root after `pnpm install --frozen-lockfile` for TypeScript checks
and formatting. Cargo manifest checks need Python 3.11+ or `tomli`; the shell checks need Bash.
`check:bindings` requires `pnpm evm:build` first. Committee parity comparison additionally needs the
Rust generator and Nargo; the command reports when that comparison is skipped.

Until the acknowledged event pipeline in
[#2266](https://github.com/theinterfold/interfold/issues/2266) is complete, retain the send-count
ratchet and startup `validate_proof_aggregation_mode` checks. `repository-baselines.env` holds the
ceiling. Lower it when calls disappear; do not increase it without reviewing new call sites. The
count includes test sources and measures matching lines, not acknowledgment safety. The startup
check verifies the guard and its configuration call exist; the entrypoint's behavior tests still own
proof-skip rejection.

### Dependency boundaries

`cargo-dependency-boundaries.py` enforces the application-execution/node-runtime separation
discussed in [#2375](https://github.com/theinterfold/interfold/pull/2375), which folder placement
alone cannot. Its package lists are the intended graph, so changing them is a boundary decision for
review:

- **Application execution** is the program packages (Secure Process, OpenVM types and host, program
  server and runner), the OpenVM worker, and the default template's program, runner, and guest. It
  may link only itself and the reviewed shared libraries: the BFV client and parameters and the
  ZK-configuration/witness, polynomial, committee, parity-matrix, and SAFE libraries below them.
  General utilities are not shared libraries; `e3-utils`, for example, brings Actix and Alloy.
- **The node binary**, `e3-cli` (the `interfold` executable), may not link application execution.
  Its project commands build and run the project's own runner binary, so the project's pinned
  program crates process its data, and the node carries no OpenVM or program-service dependencies.
- Other packages are not constrained: the SDK may decode application types, and system tests may
  combine both sides.

Edges are transitive normal and build dependencies in every target table, by package name through
`package =` aliases and workspace inheritance. Optional dependencies count, because any consumer can
enable a feature. Dev-dependencies are exempt: they build only the declaring package's tests,
examples, and benchmarks. Only this repository's packages are checked, not third-party crates, and
the check reads manifests rather than a resolved Cargo graph. A violation is reported once, on the
shortest chain to the first package that crosses. Fix the owning package instead of widening the
lists; a renamed listed package fails until the lists are updated.

`pnpm check:shell` parses each tracked shell source and Husky hook separately, choosing `sh` for
POSIX shebangs and Bash otherwise. Local untracked, nonignored scripts are included too.

`pnpm check:links [files...]` checks inline/reference Markdown links and images in indexed and
untracked, nonignored Markdown/MDX. It validates relative targets, ATX heading anchors, repeated
heading suffixes, and explicit literal HTML IDs. Fenced/inline code and footnote labels are not file
targets. It skips external URLs and absolute site routes, does not parse HTML/JSX attributes, and
does not validate rendered MDX semantics. CI and pre-push run it without changing files. The
[protocol review requirement](../../CONTRIBUTING.md#protocol-compatibility) remains a separate
semantic check by the reviewer.

`pnpm check:license [--check-only|--fix]` checks tracked JS/JSX, Noir, Rust, Solidity, and TS/TSX.
Other SPDX licenses are retained and reported, never replaced. `--fix` adds missing headers after an
executable shebang without changing mode. CI is read-only: PR failures are reported; pushes use the
workflow's continue-on-error policy. It does not fix or commit headers on main.

`.husky/pre-commit` uses `pnpm exec lint-staged` and the root Prettier **check** configuration.
lint-staged hides unstaged portions of partially staged files while checking the index content. Rust
workspace formatting stays in the existing pre-push `pnpm lint` checks. PR CI checks supported
changed files with `changed-format.mjs <base-sha> <head-sha>` and never formats or stages them.
Legacy files outside the diff are not a new formatting gate.

## Tests

Run `pnpm test:scripts` for syntax, license-fix, configuration, formatting, and cleanup regressions.
They use temporary repositories and malformed fixtures to exercise failure paths. Run the relevant
`pnpm check:*` command separately to check this checkout's configuration.
