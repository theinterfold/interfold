# Working on protocol contracts

Keep protocol rules in their contract/library owner; deploy scripts and Hardhat
tasks adapt them. [README.md](README.md) owns imports, application examples,
deployment, and address operations.

- Storage layout, initializer behavior, ABI/event signatures, and signed/hash
  preimages are compatibility boundaries. For upgradeable changes, compile and
  run `validate:upgrade`; never refresh production storage baselines merely to
  silence drift. See [upgrade policy](../../docs/architecture/upgrades.md) and
  `scripts/validateUpgrade.ts`.
- Change Solidity sources or canonical generators, then regenerate artifacts,
  TypeChain bindings, Honk verifiers, and deployment manifests as needed; do not
  hand-patch outputs. ABI changes need root `pnpm check:bindings` after
  `pnpm evm:build` for Rust consumers.
- Keep operator docs, dashboard, DAppNode, and CRISP consumers in step with a
  redeploy. Follow [address generation](README.md#contract-addresses); a clean
  address scan does not validate wiring.
- BFV fixture refresh has
  [automatic benchmark inputs and a manual override](test/fixtures/bfv_vk_binding/README.md).
  Mock lifecycle tests and a refreshed fixture are not evidence of real verifier
  acceptance. Preserve [audit scope](audits/README.md) when describing changed
  or newly generated code.

From this package, use `pnpm test <test-file>` or the focused `test:interfold`,
`test:ciphernodeRegistry`, `test:bondingRegistry`, or `test:slashing` scripts.
Lifecycle changes need `pnpm test:integration`; proof changes additionally need
matching real-proof coverage. Follow this package's formatter/linter
configuration, including generated-file exclusions, rather than changing
exclusions or baselines to bypass a failing check.
