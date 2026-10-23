# Workspace cleanup

## Purpose

Remove rebuildable workspace output while preserving source files and application state.

## Map

- [`clean.ts`](clean.ts): derives a deletion plan from indexed manifests and executes or previews
  it.
- [`clean.test.ts`](clean.test.ts): temporary-repository coverage for tracked files, state,
  symlinks, nested repositories, dry runs, and skip flags.

## Usage

`pnpm clean [--dry-run|-n] [--interactive|-i] [--skip-node] [--skip-crates] [--skip-contracts]`
removes rebuildable outputs beside **indexed** package, Cargo, and Hardhat manifests:

- Node: `node_modules`, `dist`, `.pnpm-store`.
- Rust: `target`. Test fixtures are not cleanup inputs.
- Contracts: `artifacts`, `cache`, `out`, `types`.

The Git index protects tracked files (including newly staged ones) and their parent directories.
Safe untracked outputs alongside them can still be removed. A symlink used as an output root is
preserved. Inside a physical output tree, untracked symlinks are unlinked without following their
targets; pnpm dependency links therefore do not leave a partially deleted `node_modules` tree.
Indexed links and their ancestors, nested Git repositories, `.interfold`, `database`, `broadcast`,
`ignition`, and `deployments` are preserved. This is not a node reset or deployment purge; use the
product's explicit reset/purge commands for operator state.

Run from the root with workspace dependencies installed. Preview with `pnpm clean --dry-run` before
deleting. Stop builds and other writers first; the plan is not a filesystem lock against concurrent
changes.

## Tests

`pnpm test:scripts` exercises deletion only in temporary Git repositories. To run this suite alone:
`pnpm exec tsx --test scripts/dev/clean.test.ts`.
