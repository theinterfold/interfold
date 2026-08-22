# Interfold — Project Context

What this project is, how the monorepo is laid out, and how to build/test it. For working rules see
`RULES.md`; for things you must not break see `INVARIANTS.md`.

## What Interfold is

Interfold is an open-source protocol for **confidential coordination** via **Encrypted Execution
Environments (E3)**. It combines **FHE** (threshold BFV), **ZK proofs** (Noir / Barretenberg Honk),
and **MPC** (DKG, Shamir secret sharing) so that integrity and privacy are rooted in cryptography
and economics rather than trusted hardware. Committees of **ciphernodes** are selected by sortition,
jointly generate a threshold BFV key (DKG), compute over encrypted inputs, and threshold-decrypt the
output — every step backed by ZK proofs verified on-chain.

- Docs: https://docs.theinterfold.com · License: LGPL-3.0-only
- Unified version across all crates and npm packages (currently 0.4.0)
- Reference app: **CRISP** (`examples/CRISP`, excluded from the workspace)

## Terminology

| Term         | Meaning                                                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| E3           | Encrypted Execution Environment — one confidential computation instance (`e3Id`)                                                |
| Ciphernode   | Node operator running keyshare/DKG/decryption actors in a committee                                                             |
| Committee    | Ciphernodes serving an E3. Sizes `(N, T, H)`: `minimum` (3,1,2), `micro` (9,4,5), `small` (19,9,10)                             |
| DKG          | Distributed key generation — joint threshold public key, no party holds the full secret                                         |
| BFV / TrBFV  | Brakerski–Fan–Vercauteren FHE scheme / its threshold (publicly verifiable) variant                                              |
| Preset       | BFV parameter set: `insecure-512` (dev/CI default) or `secure-8192`                                                             |
| C0–C7        | ZK circuit IDs across the DKG/decryption pipeline (map below)                                                                   |
| Sortition    | Random committee selection (`crates/sortition`)                                                                                 |
| Slashing     | Fault attribution, accusation quorum, commitment consistency (`crates/slashing`)                                                |
| Aggregator   | Role that recursively aggregates DKG/decryption proofs (`crates/aggregator`)                                                    |
| FOLD / tFOLD | `InterfoldToken` (ciphernode bonding) / `InterfoldTicketToken` (non-transferable collateral-backed tickets) — see flow-trace 02 |
| IMT          | Incremental Merkle Tree used for on-chain node registration — see flow-trace 01                                                 |
| CRT          | Chinese Remainder Theorem moduli used by BFV presets and share aggregation (C7)                                                 |

## Monorepo map

| Path                 | Contents                                                                                                                                                                            |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/`            | Rust workspace (~46 crates, prefix `e3-`): CLI, actors, crypto, TrBFV, networking (libp2p), EVM, ZK proving, persistence                                                            |
| `packages/`          | npm packages (prefix `@interfold/`): `interfold-contracts` (Hardhat Solidity + Honk verifiers), `interfold-sdk`, `interfold-react`, `interfold-mcp`, `interfold-config`, dashboards |
| `circuits/`          | Noir circuits: `lib/` (shared package), `bin/dkg/`, `bin/threshold/`, `bin/recursive_aggregation/`                                                                                  |
| `scripts/`           | Build/check tooling (`build-circuits.ts`, `check-committee.sh`, verifier generation, release bump)                                                                                  |
| `tests/integration/` | End-to-end integration tests (`pnpm test:integration [name]`)                                                                                                                       |
| `agent/`             | This harness: rules, context, invariants, architecture, flow-trace                                                                                                                  |
| `docs/`              | Nextra docs site; `deploy/`, `dappnode/` deployment; `examples/`, `templates/` scaffolding                                                                                          |

Notable crates: `events` (event taxonomy, `CircuitName`, `ProofType`), `zk-prover` (`versions.json`
pins nargo/bb), `zk-helpers`, `trbfv`, `keyshare`, `aggregator`, `sortition`, `slashing`, `evm`,
`net`, `data` (sled persistence), `sync`, `cli`.

## Key commands

Run from repo root via pnpm scripts — not raw cargo/nargo/hardhat.

| Task                        | Command                                                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Install / build all         | `pnpm i` · `pnpm build`                                                                                            |
| Build Rust                  | `pnpm rust:build` (cargo `--locked --release`; prebuilds EVM fixtures)                                             |
| Test everything             | `pnpm test` (evm → rust → sdk → noir)                                                                              |
| Test one layer              | `pnpm evm:test` · `pnpm rust:test` · `pnpm sdk:test` · `pnpm noir:test`                                            |
| Integration tests           | `pnpm test:integration [name]` (`--no-prebuild` to skip binary build)                                              |
| Lint / format               | `pnpm lint` · `pnpm format` / `pnpm format:check`                                                                  |
| Build circuits              | `pnpm build:circuits [--preset …] [--committee …]` (needs `nargo` + `bb`; `interfold noir setup` installs them)    |
| Start the support app       | `interfold program start` (`--linux-network-host-mode` uses Docker host networking and is Linux-only)              |
| Generate Solidity verifiers | `pnpm generate:verifiers [--check\|--write]`                                                                       |
| Circuit artifact cache      | `pnpm store:circuits push\|pull` (orphan branch `circuit-artifacts`)                                               |
| Consistency checks          | `pnpm check:committee` · `check:docs` · `check:invariants` · `check:ciphernode bond` · `check:pnpm` · `check:size` |
| Release bump                | `pnpm bump:versions X.Y.Z`                                                                                         |

## Conventions

- **Commits:** Conventional Commits, types `feat` / `fix` / `chore` only, optional scope, `!` for
  breaking, description ≤ 72 chars (hook regex `^(feat|fix|chore)(\(.+\))?(!)?: .{1,72}$`).
- **PRs:** small and focused; 1 approval required; squash merge with a cleaned-up body of meaningful
  conventional commits; breaking PRs merge only alongside a breaking release; docs changes get the
  `documentation` label. CI validates commit messages.
- **Branches:** `main` = latest (feature-flagged); `v*.*.*` tags; `stable` = latest stable.
- **Pre-push hook (husky):** `pnpm lint`, `check:pnpm`, `check:ciphernode bond`, `check:committee`,
  `check:docs` (harness-doc drift gate — escape with `[skip-doc-sync]` in a commit message when no
  documented behavior changed), `check:invariants` (grep-enforced invariants: `do_send` ratchet,
  skip-proof feature containment — baselines in `scripts/invariant-baselines.env`).
- **Docs MCP server:** `.mcp.json`, `.codex/config.toml`, and `opencode.json` expose
  `@interfold/mcp` (`interfold-docs`) to their respective agents. The launch configs run the
  TypeScript source through the workspace toolchain; `pnpm mcp:build` builds the publishable
  package.
- **License headers:** every `.rs`/`.sol`/`.ts` file needs the SPDX `LGPL-3.0-only` header
  (CI-enforced).

## Tech stack

Rust 1.91.1 (pinned, edition 2021, wasm32 target) · pnpm 10.7.1 · TypeScript 5.8.3 · Noir/nargo +
Barretenberg `bb` (versions pinned in `crates/zk-prover/versions.json`) · FHE via
`gnosisguild/fhe.rs` fork · Hardhat + alloy · libp2p 0.56 · tokio + actix · sled for persistence ·
opentelemetry/tracing.

## Circuit map (IDs ↔ `CircuitName` in `crates/events`)

- **DKG** (`circuits/bin/dkg/`): C0 `pk` (PkBfv) · C2a `sk_share_computation` · C2b
  `e_sm_share_computation` · C3 `share_encryption` · C4 `share_decryption`
- **Threshold** (`circuits/bin/threshold/`): C1 `pk_generation` · C5 `pk_aggregation` · P3
  `user_data_encryption_ct0/ct1` (+ wrapper) · C6 `share_decryption` · C7
  `decrypted_shares_aggregation`
- **Recursive aggregation** (`circuits/bin/recursive_aggregation/`): fold kernels (`c2ab_fold`,
  `c3_fold`, `c6_fold`, `node_fold`, `nodes_fold`, …) and the top-level `dkg_aggregator` /
  `decryption_aggregator`, which produce the on-chain Honk verifiers (committed only for
  `(insecure-512, minimum)`).
- `config` circuit validates preset constants (CRT moduli, bounds, parity matrices). Parity matrices
  are generated by the Rust `generate_parity_matrices` binary — never hand-edit.
