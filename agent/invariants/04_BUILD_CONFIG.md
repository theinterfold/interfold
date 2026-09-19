# Invariants — Build / config sync

Scope: build scripts, generated files, committee and preset selection, release provenance, contract
storage baselines.

Read `00_INDEX.md` first: it carries the meta-invariants and the open-issues list that apply to
every section.

## Build / config sync

- Committee four-file sync (above) — `scripts/check-committee.sh`, pre-push + CI.
- **Never hand-edit generated files:** parity matrices, `utils.ts` H/T values, verifier contracts
  (`generate-verifiers.ts` output), `.active-preset.json`, `crates/support/contracts/ImageID.sol`,
  `crates/support/tests/Elf.sol`.
- **Generated verifiers must match the built VKs** — pre-push checks the canonical pair. CI hydrates
  and compares every supported preset and committee pair. A drift means a deployed verifier accepts
  a different circuit from the tree.
- **`Elf.sol` is never committed.** `crates/support/methods/build.rs` writes it with a machine-local
  guest ELF path, so it is generated per checkout and `.gitignore`d.
- **A release publishes a complete provenance manifest** — `pnpm provenance:manifest`. It ties
  source commit, lockfile digests, pinned revisions, RISC Zero version, builder image tag **and
  digest** (the builder tag is mutable and `RISC0_DOCKER_CONTAINER_TAG` overrides it), guest ELF
  SHA-256, image ID, and the deployed verifier to one record. The generator reports
  `complete: false` with the unresolved fields rather than emitting a partial record that reads as
  verified. The ELF SHA-256 is **not** the image ID: SHA-256 checks binary integrity, the image ID
  is computed from the loaded memory image. Procedure:
  `docs/pages/verifying-the-compute-provider.mdx`.
- Upgradeable-contract storage baselines are committed and CI-gated (missing baselines, compiler
  drift, layout incompatibility, bad gap consumption all fail); baseline creation is an explicit
  maintainer command. — INDEX concern #27
- Contracts CI fails a release if `Interfold` / aggregator-verifier runtime bytecode is within 256
  bytes of the EIP-170 limit. — INDEX concern #22
- BFV circuit-verifier and RISC Zero receipt-verifier constructors require deployed verifier
  contracts. BFV circuit wrappers also require nonzero recursive VK hashes. — INDEX concerns #21,
  Z-15
- CLI secrets are passed over **stdin only** — never argv or environment; private keys are never
  stored in plaintext. — `flow-trace/00`, `01`
- **Deployment writes must be mined, not only sent.** Every configuration transaction in
  `scripts/deployInterfold.ts` goes through the `send()` helper in `scripts/utils.ts`, which awaits
  the receipt and fails on a missing receipt or a non-success status. `send()` also labels a
  rejection from the send or the mining stage and keeps the original error as its `cause`. A bare
  `await contract.setX(...)` resolves when the transaction is dispatched, so on a real network a
  dropped write leaves the reference at `address(0)` while the script still exits zero.
- **A deployment must end with a verified wiring graph.** After configuration, `deployInterfold.ts`
  reads back every cross-contract reference (Interfold, CiphernodeRegistry, BondingRegistry,
  InterfoldTicketToken, SlashingManager, E3RefundManager, FOLD as the BondingRegistry ciphernode
  bond token) plus the BondingRegistry reward-distributor authorization for Interfold, and throws
  with the full list of mismatches. Add a read-back for each new cross-contract setter.
- **A deployment must also enable bonded voting.** `protocol/deployContracts` deploys
  `BondedCheckpoints` (bound to the BondingRegistry **proxy**, not the implementation) and the
  governance batch calls `setBondedCheckpoints` after `initialize`. `BondedVotes` comes later, from
  `--action activate-voting`: its constructor asks the registry which token it bonds, so it cannot
  be built until that batch has executed. `protocol/validate` reads back
  `bonding.bondedCheckpoints()` and `bondedCheckpoints.registry()`, and adds `bondedVotes.token()`,
  `bondedVotes.checkpoints()` and `bondedVotes.registry()` once the adapter exists. Upgrading an
  existing deployment through `upgrade/safeProxyUpgrade` deploys and attaches the pair when none is
  attached yet, and appends a `resyncBondedCheckpoint` call for each `bondedResyncOwners` entry —
  attaching does not backfill, so owners that bonded earlier read as zero until then. Without the
  attachment the upgrade silently ships a disabled feature: the sync is a no-op while unconfigured.
