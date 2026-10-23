# Repository checks

## Purpose

Use the root `pnpm check:*` commands. `repository.sh` checks Cargo feature/sample containment,
ciphernode Docker workspace membership, production Compose shutdown grace, startup proof-guard
presence, and the `.do_send(` line-count ceiling. It is static configuration validation, not
runtime/proof assurance. The grace check accepts the maintained two-space service / four-space
integer-second `stop_grace_period` layout and requires exactly one budget above 60 seconds per
service. It rejects duplicate, missing, quoted, or non-integer-second fields; it is not a general
YAML/Compose validator (aliases and other valid duration notations are not supported).

## Map

| File                                                           | Responsibility                                                                                                 |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| [`repository.sh`](repository.sh)                               | Runs configuration, startup proof-guard, and send-count checks.                                                |
| [`repository-baselines.env`](repository-baselines.env)         | Owns the send-count ceiling; increases need explicit call-site review.                                         |
| [`cargo-feature-containment.py`](cargo-feature-containment.py) | Checks proof-skip features and dev-only ZK sample/benchmark dependencies, including aliases and target tables. |
| [`ciphernode-docker-members.py`](ciphernode-docker-members.py) | Compares workspace members with Docker manifest copies.                                                        |
| [`committee.sh`](committee.sh)                                 | Compares cross-language committee and BFV configuration.                                                       |
| [`addresses.ts`](addresses.ts)                                 | Checks published addresses and classified consumers against the deployment manifest.                           |
| [`cli-bindings.ts`](cli-bindings.ts)                           | Compares tracked ABIs with freshly built contract artifacts.                                                   |
| [`license-headers.sh`](license-headers.sh)                     | Checks SPDX headers and optionally adds missing headers.                                                       |
| [`pnpm.sh`](pnpm.sh)                                           | Checks the package-manager version against the root pin.                                                       |
| [`shell-syntax.mjs`](shell-syntax.mjs)                         | Parses shell sources individually.                                                                             |
| [`changed-format.mjs`](changed-format.mjs)                     | Checks supported files changed between two Git revisions.                                                      |
| [`doc-links.mjs`](doc-links.mjs)                               | Checks relative Markdown/MDX file targets, exact case, and heading/explicit-ID anchors without network access. |

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
