# Switch Committee — Canonical Procedure

Tool-neutral body for the switch-committee command/skill. Tool adapters point here — edit THIS file
to change the procedure.

Input: a committee name `minimum` | `micro` | `small`, optionally
`--preset insecure | secure-8192 | secure-16384`. Supported pairs live in
`scripts/circuit-constants.ts`.

Rules — read `agent/invariants/02_CRYPTO_CIRCUITS.md` §Committee config sync first:

1. NEVER hand-edit the synced files (`circuits/lib/src/configs/committee/active.nr`,
   `circuits/bin/.active-preset.json`, `packages/interfold-contracts/scripts/utils.ts`, parity
   matrices). The only legal mechanism is the build script.
2. Run `pnpm build:circuits --committee <name> [--preset <preset>]`. This requires `nargo` and `bb`
   on PATH (`interfold noir setup` installs a matching toolchain) — if they're missing, stop and
   tell the user rather than improvising.
3. Verify with `pnpm check:committee` and report its output.
4. Remind the user of the operational consequences: wrapper Solidity verifiers (`BfvPkVerifier`,
   `BfvDecryptionVerifier`) have an `(H, T)`-specific public-input layout; each supported preset and
   committee pair has committed verifier artifacts. A deployment whose verifier mappings or routers
   already support the pair needs no redeployment. Otherwise, register matching verifiers, and
   deploy any missing wrappers or replacement routers first; `crates/zk-helpers`
   `CiphernodesCommitteeSize` must agree (`check:committee` covers this).
5. If artifacts are needed without a local rebuild, `pnpm store:circuits pull` fetches the cached
   ones from the `circuit-artifacts` branch.
