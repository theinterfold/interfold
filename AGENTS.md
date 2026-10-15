# Working in Interfold

Interfold implements encrypted execution across contracts, circuits, and asynchronous nodes. READMEs
own usage and public contracts; the nearest `AGENTS.md` owns change guidance, and domain documents
own cross-component rules, rationale, and limits.

## Working agreement

- Preserve unrelated work. Confirm the checkout and branch before editing; coordinate concurrent
  work in separate, durable worktrees. Keep scratch files outside tracked source.
- Commit, push, open or publish PRs, mark them ready, merge, tag, or release only when requested. Do
  not bypass failing checks; report failures and missing prerequisites.

## Development and style

- **KISS:** use the smallest cohesive solution. Avoid speculative frameworks, compatibility layers
  without callers, and unrelated cleanup.
- **SOLID:** give modules clear responsibilities and interfaces their callers need. Extend the
  existing domain owner instead of copying a rule. Add abstractions for real boundaries, not
  symmetry.
- **Clean Architecture is the design direction:** domain rules and deterministic workflows stay
  independent of runtime and I/O. Actors coordinate work; effects/adapters perform it; composition
  roots wire dependencies. Organize by capability, not a mandatory hierarchy of layer folders.
  Existing code has exceptions; see [design principles](docs/architecture/design-principles.md).
- Follow nearby code and repository formatter/linter configuration. Format changed files only. Write
  concise comments that explain why; match documentation style and preserve exact interface text.

## Protocol and artifact changes

- Cleanup does not authorize changes to cryptographic statements, deployed verifiers, durable
  encodings, replay, or actor ordering. Consult the affected
  [domain document](docs/architecture/AGENTS.md) and verify its claims against code and tests.
- Migrations need explicit compatibility, release-counter, rollout, and rollback decisions for human
  review. Follow [Protocol compatibility](CONTRIBUTING.md#protocol-compatibility).
- Use canonical generators for committee/preset outputs, parity matrices, verifiers, constants, and
  deployment manifests. Preset switches change shared files: coordinate them. See
  [Circuit Builder](scripts/README.md#circuit-builder) and
  [contract addresses](packages/interfold-contracts/README.md#contract-addresses).
- Release preparation and publication follow [RELEASING.md](RELEASING.md); commands may commit or
  push.

## Verification

- Use root [package scripts](package.json) for their setup; focused `cargo test -p` and
  `cargo check -p` are also supported. Start with the smallest covering check. Cross-layer changes
  need the affected integration scenario; proof changes need real-crypto coverage, not only mocks.
- Test observable behavior at its owner boundary. A bug regression should fail before the fix and
  pass afterward. Avoid duplicate coverage, implementation-copying tests, and tests of instruction
  wording.
- Review the actual diff, correct documentation made false, and report commands, results, and
  verification limits. A successful compile is not proof verification or a successful CI run.
