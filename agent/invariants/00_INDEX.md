# Interfold — Invariants

Things that must remain true. Breaking any of these is a protocol bug, a soundness bug, or a
data-loss bug — not a style issue. Each entry cites where it is enforced or documented. When editing
code near one of these, re-read the cited source first; when a change necessarily violates one,
treat it as a protocol migration (versioning + compatibility tests), never a silent edit.

Some entries are mechanically enforced and will fail pre-push: committee sync
(`pnpm check:committee`), harness-doc drift (`pnpm check:docs`), and the `do_send` ratchet +
skip-proof feature containment (`pnpm check:invariants`, baselines in
`scripts/invariant-baselines.env`). The rest are review-enforced — the `invariant-reviewer` agent
(`/invariant-review`) checks a diff against these files.

An entry is a requirement or review claim, not proof that the implementation satisfies it. Verify
the cited contract, test, schema, and runtime path. If a higher-authority source contradicts these
files, preserve the higher-authority behavior and correct the file in the same change. A target
design citation alone does not establish current runtime behavior.

## How to read this directory

Read this index, then **only** the section file that covers the code you touch. The sections are
independent: a contracts change does not need the circuit invariants, and a crate change does not
need the token invariants.

| Changed path                                      | Read                                            | Lines |
| ------------------------------------------------- | ----------------------------------------------- | ----- |
| `packages/interfold-contracts/contracts/`         | `01_PROTOCOL_ONCHAIN.md`                        | ~400  |
| `packages/interfold-contracts/{scripts,tasks}/`   | `01_PROTOCOL_ONCHAIN.md` + `04_BUILD_CONFIG.md` | ~460  |
| `circuits/`                                       | `02_CRYPTO_CIRCUITS.md`                         | ~230  |
| `crates/{zk-prover,zk-helpers,trbfv,fhe-params}/` | `02_CRYPTO_CIRCUITS.md`                         | ~230  |
| `crates/` (actors, events, persistence, net, evm) | `03_ACTOR_RUNTIME.md`                           | ~160  |
| build scripts, committee or preset files          | `04_BUILD_CONFIG.md`                            | ~60   |

Read the whole directory only when the change spans layers (contracts ↔ Rust ↔ circuits) or when
you are asked for a full invariant audit.

## Review budget

Invariant review is **one sequential reviewer pass**. Do not spawn a subagent per invariant or per
section — the sections are short enough to read directly, and per-invariant fan-out costs far more
than it finds. Spawn parallel reviewers only when the user explicitly asks for a per-invariant or
per-section audit.

Verify a cited source when the diff touches its subject. Do not open every citation in a section you
loaded.

## Meta-invariants

These apply to every section.

- **Sources of authority, descending:** (1) deployed contract behavior and protocol/circuit
  invariants, (2) compatibility/e2e tests, (3) durable event/snapshot schemas, (4) `flow-trace/` +
  `CRATES_ARCHITECTURE.md`, (5) `ARCHITECTURE.md` (target design). When docs disagree with
  contracts/tests, fix the docs. — `ARCHITECTURE.md` §Sources of Authority
- **A cleanup must never silently change:** committee ordering, threshold meaning, proof
  multiplicity, hashing, signatures, circuit witness shape, event identity, or replay semantics. —
  `ARCHITECTURE.md`

## Known open issues (check before assuming current behavior is correct)

The authoritative list is the "Verified Bugs & Protocol Concerns" table in `flow-trace/00_INDEX.md`.
Known residual gaps:

- `gracePeriod` is dead code in timeout checks (concern #3).
- CLI `activate` actually calls `register` and reverts for registered operators (#4).
- Live EventBus subscriber fan-out still includes unacknowledged `do_send` edges (#11). EventStore
  replay is paged through bounded temporary runs and uses an acknowledged fan-out barrier.
- `ComputeEffectGate` is in-memory only — no durable external-effect outbox yet.
- Residual runtime risks: `e3-evm` in-process nonce serialization without a durable tx outbox or
  full reorg rollback; accusation votes/timers lack complete durable reconstruction;
  `e3-program-server` test endpoint is unauthenticated (never a production boundary); cancellation
  ownership is not uniform across crates. — `CRATES_ARCHITECTURE.md` §Subsystem contracts
