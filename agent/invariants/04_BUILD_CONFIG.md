# Invariants — Build / config sync

Scope: build scripts, generated files, committee and preset selection, release provenance, contract
storage baselines.

Read `00_INDEX.md` first: it carries the meta-invariants and the open-issues list that apply to
every section.

## Build / config sync

- Committee config sync: see `02_CRYPTO_CIRCUITS.md` §Committee config sync.
  `scripts/check-committee.sh` runs in pre-push and in the Agent Harness CI workflow.
- **Never hand-edit generated files:** parity matrices, `configs/default/mod.nr`,
  `configs/committee/active.nr`, the generated C1/C2 bounds, the generated constants in `utils.ts`,
  `ActiveCryptoConfig.sol`, verifier contracts (`generate-verifiers.ts` output), the ignored local
  file `.active-preset.json`, and prepared OpenVM identity artifacts.
- **`crates/support/contracts/ImageID.sol` is frozen.** It records the RISC Zero image ID that the
  existing CRISP deployments verify. The guest build that generated it is gone, so it cannot be
  regenerated, and the secure CRISP upgrade scripts (`scripts/upgrade/secureCrisp.ts` and
  `validateSecureCrisp.ts`) still read it to check those deployments. Never edit it; delete it
  together with those scripts.
- **Generated verifiers must match the built VKs.** When a pushed branch changes a path in
  `.github/filters/circuits.yml`, pre-push checks `insecure-512` with the committee in the local
  `.active-preset.json` (default `minimum`). The check reads the checked-out tree, so the hook stops
  the push of a branch that differs from HEAD in a path of that file. CI reads the same file to
  start `build_circuits`, which hydrates and compares every supported preset and committee pair. A
  drift means a deployed verifier accepts a different circuit from the tree.
- Complete artifact pairs include `nodes_fold.vk_tree_hash` and `c6_fold.vk_tree_hash`. The builder
  derives them from the recursive leaf VKs and non-ZK fold VKs after a complete build with keys.
  Every other build (a `--group` or `--circuit` subset, `--skip-vk`, or a failed circuit) removes
  both files from the pair and from `circuits/bin/`, because an old anchor can hash a key that the
  build replaced. Hydration copies both files into `circuits/bin/`. Build-cache markers and release
  validation require both files. Deployment uses them as public-input-zero pins and retains the
  separate C5/C7 VK pins. — `scripts/build-circuits.ts`; `scripts/circuit-artifacts.ts`;
  `scripts/utils.ts`
- `pnpm store:circuits pull` selects the newest first-parent `circuit-artifacts` commit whose
  `SOURCE_HASH` matches the current source tree. A different build at the branch tip must not
  replace it. The release workflow archives the branch tip and fails if the tip's hash differs.
  Release verification still checks the source hash, every required pair, and each pair's build
  stamp. `crates/zk-prover/supported-configurations.json` owns the release matrix that archive
  installation and release verification require. Each listed pair must be a build pair in
  `scripts/circuit-constants.ts`, and a tooling test checks this. The matrix file is not a
  `SOURCE_HASH` input. CI download fixtures explicitly request the two `minimum` pairs. CI local
  archive setup selects `insecure-512/minimum` with `--circuits-configuration`. `SOURCE_HASH`
  includes the shared Noir library and its dependency manifest (see `02_CRYPTO_CIRCUITS.md` §Noir /
  Barretenberg compatibility).
- Network circuit installation requires a version-bound archive SHA-256 compiled into the binary.
  `download-circuits` in `.github/workflows/releases.yml` hashes the exact archive that it uploads.
  Binary and ciphernode image builds depend on that job and pass `E3_CIRCUITS_ARCHIVE_SHA256` to
  `crates/zk-prover/build.rs`, including through the Docker build argument. `ZkConfig::default`
  binds this pin to `CARGO_PKG_VERSION` and retains the other pins from `versions.json`. Builds
  without this input work, but downloads for unpinned versions fail before network access. Each
  binary build checks the pin reported by `noir status` before the release-candidate gate can pass.
  The ciphernode Docker build checks the same report. The support image compiles no CLI or
  ciphernode, and DAppNode copies the checked ciphernode image. CI generates a manifest for exactly
  the staged fixture before packaging and hashing it. — `02_CRYPTO_CIRCUITS.md` §Noir / Barretenberg
  compatibility
- **Deployment-local OpenVM artifacts are never committed.** Keep executable files, proving keys,
  proofs, inputs, worker configurations, and benchmark reports under `target/` or outside source.
- **A release publishes a complete provenance manifest** — `pnpm provenance:manifest`. It ties
  source commit, lockfile and artifact digests, OpenVM application commitments, worker identity
  validation, and the deployed protocol, receipt, and Halo2 verifiers to one record. The generator
  reports `complete: false` with the unresolved fields rather than emitting a partial record that
  reads as verified. An artifact SHA-256 is **not** an application commitment or receipt identity.
  A complete record does not establish source reproducibility; retain independent rebuild evidence.
  Procedure:
  `docs/pages/build/e3-program/verify-compute-provider.mdx`. **Gap:** the release workflow does not
  generate or attach this manifest (`.github/workflows/releases.yml`); a maintainer runs
  `pnpm provenance:manifest` by hand.
- Upgradeable-contract storage baselines are committed and CI-gated (missing baselines, compiler
  drift, layout incompatibility, bad gap consumption all fail); baseline creation is an explicit
  maintainer command. — INDEX concern #27
- The contract artifacts that git tracks under `packages/interfold-contracts/artifacts/` are the
  source of the CLI's `sol!` bindings (`crates/cli/src/ciphernode/context.rs`). CI compares their
  ABI with a fresh build (`pnpm check:bindings`, after `pnpm evm:build`, in the lib unit-test job):
  an added, removed or changed function, event or error fails until the regenerated files are
  committed. — `scripts/check-cli-bindings.ts`
- Contracts CI requires at least 128 bytes below the EIP-170 limit for `Interfold`,
  `BondingRegistry`, `CiphernodeRegistryOwnable`, and the canonical `insecure-512/minimum`
  aggregator verifiers. Every deployed verifier variant must fit, but CI does not measure the other
  variants. — `scripts/checkContractSize.ts`; INDEX concern #22
- BFV circuit-verifier and OpenVM receipt-verifier constructors require deployed verifier
  contracts. BFV circuit wrappers also require nonzero recursive VK hashes. — INDEX concerns #21,
  Z-15
- CLI secrets enter through **stdin or hidden prompts**, never argv or the environment. Wallet keys
  are never stored in plaintext. `password set`, `wallet set`, and `ciphernode setup` reject
  secret-value options and name the stdin or prompt alternative. Repository callers pipe secrets
  into the CLI. — `crates/cli/src/{main,password,wallet}.rs`, `crates/cli/src/ciphernode/`,
  `crates/cli/tests/cli_secrets.rs`; `flow-trace/01`
- **Deployment writes must be mined, not only sent.** Every configuration transaction in
  `scripts/deployInterfold.ts` and `scripts/configureLocalSlashingPolicies.ts` goes through the
  `send()` helper in `scripts/utils.ts`, which awaits the receipt and fails on a missing receipt or
  a non-success status. `send()` also labels a rejection from the send or the mining stage and keeps
  the original error as its `cause`. A bare `await contract.setX(...)` resolves when the transaction
  is dispatched, not when it is mined.
- **A deployment must end with a verified wiring graph.** After configuration, `deployInterfold.ts`
  reads back every reference that it sets to another contract, a token, a treasury, or the FOLD
  claim source (constructor and initializer arguments and setter values, including the BFV verifier
  bindings and, with ZK verification, the BFV wrappers' circuit verifiers), and every authorization
  that it grants (the BondingRegistry reward distributor, the FOLD transfer whitelist, the initial
  E3 program, the fee-token admission). It throws with the full list of mismatches before it enables
  requests. Owners and admins (the deployer) and configuration values (committee thresholds,
  parameter sets, slash policies, the node release, timing and pricing amounts) are not references;
  the integration check in `tests/integration/base.sh` covers the committee thresholds. Add a
  read-back for each new reference or authorization. **Gap:** the check does not read the ERC-1967
  implementation and admin slots of the proxies. A fresh deployment passes each new implementation
  to the proxy constructor in the same `deployAndSave` helper, but a proxy that a helper reuses from
  the deployment record, or that its admin upgraded later, is not checked.
- **A deployment must also enable bonded voting.** `protocol/deployContracts` deploys
  `BondedCheckpoints` (bound to the BondingRegistry **proxy**, not the implementation) and the
  governance batch calls `setBondedCheckpoints` after `initialize`. `BondedVotes` comes later, from
  `--action activate-voting`: its constructor asks the registry which token it bonds, so it cannot
  be built until that batch has executed. `protocol/validate` reads back
  `bonding.bondedCheckpoints()` and `bondedCheckpoints.registry()`, and adds `bondedVotes.token()`,
  `bondedVotes.checkpoints()` and `bondedVotes.registry()` once the adapter exists. Those read-backs
  cannot tell an adapter from before bonded delegation from a current one, because both take the
  same constructor arguments. `hasBondedDelegation` probes the code instead: `activate-voting`
  refuses such a recorded adapter, `validate` prints a `--` line for it, and
  `deployAndSaveBondedVotes` deploys a replacement. Upgrading an existing deployment through
  `upgrade/safeProxyUpgrade` deploys and attaches the pair when none is attached yet, and appends a
  `resyncBondedCheckpoint` call for each `bondedResyncOwners` entry — attaching does not backfill,
  so owners that bonded earlier read as zero until then. Without the attachment the upgrade silently
  ships a disabled feature: the sync is a no-op while unconfigured.
