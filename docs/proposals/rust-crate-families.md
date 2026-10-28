# Rust capability families: layout proposal

Status: **proposed, not implemented**. This is the design portion of
[#2326](https://github.com/theinterfold/interfold/issues/2326), under
[#2319](https://github.com/theinterfold/interfold/issues/2319). It asks reviewers to agree names and
relocation boundaries; it does not authorize a repository-wide move or change a public contract.

## Refreshed baseline

The map was checked against fetched `main` at
[`26023af50`](https://github.com/theinterfold/interfold/tree/26023af50c6774eb87086d47a304b3adce16dec8)
on 2026-10-28, using Cargo metadata, manifests, owner READMEs, and concrete callers. It has **57
root workspace packages**, not the original review's 55: `task-pool` was added, and `test-helpers`
was replaced by `test-support` and `bfv-test-support`. The excluded OpenVM worker is additional.

Compute ownership from #2321 and fixture ownership from #2325 are implemented on this baseline. The
pending #2320, #2322, #2323, and #2324 work is not treated as merged. In particular, the event crate
still defines committee membership and circuit identity here; this proposal neither repeats those
extractions nor makes relocation a prerequisite for them. #2257 retains its builder scope.

This is a dated decision aid, not another live domain specification. Cargo manifests and
[component READMEs](../../crates/README.md) remain the current inventory; the
[domain references](../architecture/AGENTS.md) own protocol rules and limits.

## Recommended organization

Group packages when their capability gives a developer a useful place to start. Keep package
boundaries, crate names, binary names, features, and exports unchanged in mechanical relocations.
New family directories need no `Cargo.toml`, nested workspace, coordinating runtime crate, or
mandatory actor/workflow/effects hierarchy. Existing ZK and polynomial boundaries stay intact.

| Family           | Navigation benefit and boundary                                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `node/`          | Find command/startup/composition/control and node dispatch together; shared libraries inside it remain independently importable.                                         |
| `state/`         | Find persistence, event-system assembly, replay, and per-E3 routing together; this is not a claim of I/O-free domain code. The event pipeline itself remains flat below. |
| `participation/` | Follow formation → keyshare → aggregation/attribution without confusing those workflows with parameter or execution owners.                                              |
| `program/`       | Follow an application's Secure Process through host/framing/server/runner, separately from ciphernode ZK/TrBFV scheduling.                                               |
| `bfv/`           | Discover parameter, client, threshold-calculation, and runtime-adapter boundaries together without merging them or absorbing general cryptography/math.                  |
| `diagnostics/`   | Pair passive logging and read-only dashboard projections; neither becomes canonical event history or command execution.                                                  |
| `testing/`       | Find existing cross-suite infrastructure and the system harness; owner-local fixtures stay with their production owner.                                                  |
| `evm/`, `zk/`    | Coordinate with #2322's EVM proposal and preserve the implemented ZK family; no competing binding/execution extraction here.                                             |

### How to read the map

Paths are relative to `crates/`; links point to **current** owner documentation, not nonexistent
destinations. An unchanged destination is deliberate. Consumer examples are direct normal Cargo
dependencies unless marked `dev:` or `tool:`; they are not the complete transitive graph. Template
and external consumers are identified separately.

`default` means the manifest does not prohibit registry publication; **it does not mean the crate is
published or currently publishable**. `no` means `publish = false`. All `e3-*` rows below are root
workspace members; publication flags do not change with their proposed directory.

### Node operation

| Cargo package / publish           | Current → proposed path                                                                     | Responsibility and real consumers                                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-cli` / default                | [cli](../../crates/cli/README.md) → `node/cli`                                              | Operator and project command orchestration; tool: the installed `interfold` binary, root scripts, and generated-project workflows.     |
| `e3-entrypoint` / default         | [entrypoint](../../crates/entrypoint/README.md) → `node/entrypoint`                         | Node/process lifecycle entrypoints and fencing; consumed by `e3-cli`.                                                                  |
| `e3-config` / default             | [config](../../crates/config/README.md) → `node/config`                                     | Runtime/operator configuration and release policy; consumed by `e3-data`, `e3-request`, and `e3-ciphernode-builder`, not just the CLI. |
| `e3-ciphernode-builder` / default | [ciphernode-builder](../../crates/ciphernode-builder/README.md) → `node/ciphernode-builder` | Full/bootstrap node composition and recovery wiring; consumed by `e3-cli` and `e3-entrypoint`.                                         |
| `e3-multithread` / default        | [multithread](../../crates/multithread/README.md) → `node/compute-dispatch`                 | Node-wide admission policy, replay/retry gating, and correlated dispatch; consumed by `e3-keyshare` and `e3-ciphernode-builder`.       |
| `e3-daemon-server` / default      | [daemon-server](../../crates/daemon-server/README.md) → `node/daemon-server`                | Loopback command transport, not authorization or command execution; consumed by `e3-cli` and `e3-entrypoint`.                          |

`compute-dispatch` is a proposed directory name only: `e3-multithread`, `Multithread`, and its
caller API do not change. The generic pool stays flat; node dispatch must not become the application
OpenVM runner or a second ZK/native executor. Console output is also kept separate below.

### Events and state

| Cargo package / publish     | Current → proposed path                                                    | Responsibility and real consumers                                                                                                                    |
| --------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-events` / default       | [events](../../crates/events/README.md) → `events` (flat)                  | Event identity, rich payloads, and durable transport; consumed by `e3-data`, `e3-config`, and participation/runtime crates.                          |
| `e3-data` / default         | [data](../../crates/data/README.md) → `state/data`                         | Persistence, repositories, snapshots, and log storage adapters; consumed by `e3-request`, `e3-sortition`, and `e3-event-system`.                     |
| `e3-event-system` / default | [event-system](../../crates/event-system/README.md) → `state/event-system` | Event/store/replay runtime assembly; consumed by `e3-ciphernode-builder` and `e3-entrypoint`; dev: participation suites.                             |
| `e3-sync` / default         | [sync](../../crates/sync/README.md) → `state/sync`                         | Historical reconciliation, recovery preflight, and replay coordination; consumed by `e3-event-system`, `e3-ciphernode-builder`, and `e3-entrypoint`. |
| `e3-request` / default      | [request](../../crates/request/README.md) → `state/request`                | Per-E3 routing/lifecycle, dependency hydration, and canonical-key authority; consumed by `e3-keyshare`, `e3-aggregator`, and `e3-evm`.               |

Keep `events/` flat in this plan. At the baseline it alone has **125 tracked files**, before caller,
manifest, and documentation updates; a whole-package move cannot meet a fewer-than-100-file PR
budget. Its cross-family transport contract also merits a visible owner, not a misleading `types` or
pure `core` folder. The future `state/README.md` should link to it. Reconsidering its path needs a
separate, justified scope/budget decision, not temporary forwarding modules or alias crates.

### Protocol participation

| Cargo package / publish   | Current → proposed path                                                      | Responsibility and real consumers                                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-sortition` / default  | [sortition](../../crates/sortition/Readme.md) → `participation/sortition`    | Eligibility, formation, finalized slots, and aggregator failover; consumed by `e3-aggregator`, `e3-evm`, and `e3-ciphernode-builder`. |
| `e3-keyshare` / default   | [keyshare](../../crates/keyshare/README.md) → `participation/keyshare`       | DKG collection and secret-share lifecycle; consumed by `e3-aggregator`, `e3-ciphernode-builder`, and `e3-entrypoint`.                 |
| `e3-aggregator` / default | [aggregator](../../crates/aggregator/README.md) → `participation/aggregator` | Public-key/plaintext aggregation workflows and publication intents; consumed by `e3-ciphernode-builder` and `e3-entrypoint`.          |
| `e3-slashing` / default   | [slashing](../../crates/slashing/README.md) → `participation/slashing`       | Accusation admission/quorum and cross-proof consistency; consumed by `e3-zk-prover` and `e3-ciphernode-builder`.                      |

This preserves the current crates, not a new committee-formation service. #2324 decides aggregation
dependencies and formation ownership; #2320 moves specific shared definitions. Shared committee
parameters and domain hashes remain outside the runtime participation folder.

### Application computation

| Cargo package / publish         | Current → proposed path                                                                  | Responsibility and real consumers                                                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-compute-provider` / default | [compute-provider](../../crates/compute-provider/Readme.md) → `program/compute-provider` | Deterministic Secure Process, input policy, and provider boundary; consumed by `e3-openvm-host`, `e3-program-server`, and the template guest. |
| `e3-openvm-types` / default     | [openvm-types](../../crates/openvm-types/README.md) → `program/openvm-types`             | Shared host/guest stream and public journal encoding; consumed by `e3-openvm-host` and the template guest.                                    |
| `e3-openvm-host` / default      | [openvm-host](../../crates/openvm-host/README.md) → `program/openvm-host`                | Native/guest parity and external worker execution adapter; consumed by `e3-program-runner`.                                                   |
| `e3-program-server` / default   | [program-server](../../crates/program-server/README.md) → `program/program-server`       | Application compute-job HTTP service and bounded execution; consumed by `e3-program-runner`.                                                  |
| `e3-program-runner` / default   | [program-runner](../../crates/program-runner/README.md) → `program/program-runner`       | Project-supplied processor/policy in dev or OpenVM service mode; consumed by generated `runner/` packages, including the template and CRISP.  |

The additional [`interfold-openvm-prover`](../../crates/openvm-prover/README.md) package remains at
`openvm-prover/`, **excluded from the root workspace**, with its own manifest/lock and separately
documented Rust/OpenVM CPU/CUDA prerequisites. It is executed as a worker by the host, not imported
as a root Cargo dependency. Its manifest leaves publication at the default, independently of the
root packages. Moving it to `program/openvm-prover` is an unsettled follow-up, gated on the
worker/provenance/path audit; it is not needed to group the five root packages. The separate
template host/runner and guest workspaces remain separate too.

### BFV and its adapters

| Cargo package / publish   | Current → proposed path                                            | Responsibility and real consumers                                                                                                         |
| ------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-fhe-params` / default | [fhe-params](../../crates/fhe-params/README.md) → `bfv/fhe-params` | Canonical BFV presets, validation, and configuration identity; consumed by `e3-bfv-client`, `e3-zk-config`, and `e3-trbfv`.               |
| `e3-bfv-client` / default | [bfv-client](../../crates/bfv-client/README.md) → `bfv/bfv-client` | Client encryption, circuit-compatible commitments, and plaintext conversion; consumed by `e3-wasm`, `e3-sdk`, and `e3-trbfv`.             |
| `e3-trbfv` / default      | [trbfv](../../crates/trbfv/README.md) → `bfv/trbfv`                | Native threshold-BFV calculations, request execution, and typed results; consumed by `e3-keyshare`, `e3-multithread`, and `e3-zk-prover`. |
| `e3-fhe` / default        | [fhe](../../crates/fhe/README.md) → `bfv/fhe`                      | Runtime FHE operations and per-request parameter/CRP hydration; consumed by `e3-keyshare`, `e3-aggregator`, and `e3-ciphernode-builder`.  |

The family does not make these four packages interchangeable. Client encryption continues to use the
witness owner for commitments; local secret-at-rest encryption is not BFV; algorithm libraries are
not moved into this folder merely because one BFV/ZK caller uses them. #2197 retains identity
ownership and #2323 retains chunk-transport consolidation.

### Diagnostics and testing

| Cargo package / publish    | Current → proposed path                                                                  | Responsibility and real consumers                                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-logger` / default      | [logger](../../crates/logger/README.md) → `diagnostics/logger`                           | Passive protocol summaries and bounded operational logging; consumed by `e3-ciphernode-builder`, `e3-cli`, and `e3-dashboard`.         |
| `e3-dashboard` / default   | [dashboard](../../crates/dashboard/README.md) → `diagnostics/dashboard`                  | Read-only event/network/log projections and operator UI; consumed by `e3-cli`.                                                         |
| `e3-test-support` / no     | [test-support](../../crates/test-support/README.md) → `testing/test-support`             | Seeded RNGs, scoped tracing, and tool discovery without internal-crate dependencies; dev: `e3-events`, `e3-trbfv`, and `e3-zk-prover`. |
| `e3-bfv-test-support` / no | [bfv-test-support](../../crates/bfv-test-support/README.md) → `testing/bfv-test-support` | Shared artificial ballot/encryption/summation fixtures; dev: `e3-trbfv` and `e3-tests`.                                                |
| `e3-layout-lock` / no      | [layout-lock](../../crates/layout-lock/README.md) → `testing/layout-lock`                | Encoded-layout regression support; dev: `e3-net`, `e3-slashing`, and `e3-zk-prover`.                                                   |
| `e3-tests` / no            | [tests](../../crates/tests/README.md) → `testing/tests`                                  | Cross-capability/system scenarios, composition, and test binaries; tool: root Rust/integration scripts and CI.                         |

No fixture extraction is added to #2325's result. Event runtime fixtures stay in event-system,
cryptographic samples stay in ZK, and single-owner fixtures stay local. A testing folder is not
permission to add normal production dependencies on these packages or to make lower-level fixtures
depend on the ciphernode builder.

### EVM coordination and existing ZK

| Cargo package / publish    | Current → proposed path                                                  | Responsibility and real consumers                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-evm` / no              | [evm](../../crates/evm/README.md) → `evm/runtime` (#2322)                | Ciphernode chain ingestion, projections, transaction writers, and recovery; consumed by `e3-aggregator` and `e3-ciphernode-builder`.                          |
| `e3-evm-helpers` / default | [evm-helpers](../../crates/evm-helpers/README.md) → `evm/client` (#2322) | Application contract clients, listeners, retries, and nonce handling; consumed by `e3-indexer` and `e3-sdk`.                                                  |
| `e3-indexer` / default     | [indexer](../../crates/indexer/README.md) → `evm/indexer` (#2322)        | Application projections and applied-block cursor policy; consumed by `e3-sdk`.                                                                                |
| `e3-zk-config` / default   | [zk/config](../../crates/zk/config/README.md) → `zk/config`              | Static BFV bounds, parity, rendering, and public layouts; consumed by `e3-zk-witness`, `e3-zk-prover`, and `e3-zk-build`.                                     |
| `e3-zk-witness` / default  | [zk/witness](../../crates/zk/witness/README.md) → `zk/witness`           | Deterministic production witness preparation and Noir encoding; consumed by `e3-bfv-client`, `e3-zk-prover`, and `e3-zk-build`.                               |
| `e3-zk-prover` / default   | [zk/prover](../../crates/zk/prover/README.md) → `zk/prover`              | Noir/BB execution, verification, folding, recovery, and artifact installation; consumed by `e3-multithread`, `e3-ciphernode-builder`, and `e3-zk-benchmarks`. |
| `e3-zk-build` / no         | [zk/build](../../crates/zk/build/README.md) → `zk/build`                 | Circuit/configuration build, source identity, staging, and hydration; consumed by `e3-zk-benchmarks`; tool: `pnpm build:circuits`.                            |
| `e3-zk-samples` / no       | [zk/samples](../../crates/zk/samples/README.md) → `zk/samples`           | Artificial ZK test/development inputs; consumed by the private benchmark runner; dev: `e3-zk-witness` and `e3-zk-prover`.                                     |
| `e3-zk-benchmarks` / no    | [zk/benchmarks](../../crates/zk/benchmarks/README.md) → `zk/benchmarks`  | Leaf/protocol/verifier-gas benchmarks and saved replay; tool: `pnpm bench:circuits`, not a runtime library.                                                   |

#2322 owns whether/how to introduce the shared `evm/contracts` package, its concrete Cargo name, and
any public client/package rename. Those are not a fourth existing package in this inventory or
approved extractions here. Keep application listener/indexer cursor policy separate from the
ciphernode journal. Preserve the [ZK dependency contract](../../crates/zk/README.md).

### Intentionally unchanged shared capabilities and public surfaces

| Cargo package / publish       | Current → proposed path                                                                            | Responsibility and real consumers                                                                                                                          |
| ----------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `e3-committee` / default      | [committee](../../crates/committee/README.md) → `committee`                                        | Canonical committee parameters shared across runtime and circuits; consumed by `e3-zk-config`, `e3-events`, and `e3-aggregator`.                           |
| `e3-committee-hash` / default | [committee-hash](../../crates/committee-hash/README.md) → `committee-hash`                         | Canonical EVM DKG/decryption domain hashes; consumed by `e3-events`, `e3-request`, and `e3-zk-prover`.                                                     |
| `e3-crypto` / default         | [crypto](../../crates/crypto/README.md) → `crypto`                                                 | Local secret-at-rest encryption and password sources, not threshold math; consumed by `e3-events`, `e3-trbfv`, and `e3-cli`.                               |
| `e3-polynomial` / default     | [polynomial](../../crates/polynomial/README.md) → `polynomial`                                     | Exact integer polynomials and CRT containers; consumed by `e3-zk-config`, `e3-zk-witness`, and `e3-polynomial-fhe`.                                        |
| `e3-polynomial-fhe` / default | [polynomial/fhe-adapter](../../crates/polynomial/fhe-adapter/README.md) → `polynomial/fhe-adapter` | fhe-math/RNS conversion adapter, separate from integer arithmetic; consumed by `e3-zk-config`, `e3-zk-witness`, and `e3-zk-prover`.                        |
| `e3-parity-matrix` / default  | [parity-matrix](../../crates/parity-matrix/README.md) → `parity-matrix`                            | Reed-Solomon parity construction; consumed by `e3-zk-config`, without making a reusable algorithm a ZK runtime package.                                    |
| `e3-safe` / default           | [safe](../../crates/safe/README.md) → `safe`                                                       | SAFE commitment algorithm shared with guest/circuit consumers; consumed by `e3-zk-witness` and the template guest.                                         |
| `e3-net` / default            | [net](../../crates/net/README.md) → `net`                                                          | Peer admission, gossip, document delivery, and historical sync transport; consumed by `e3-ciphernode-builder`, `e3-dashboard`, and `e3-entrypoint`.        |
| `e3-data-availability` / no   | [data-availability](../../crates/data-availability/README.md) → `data-availability`                | Content-addressed data and Avail/VectorX adapters; consumed by `e3-evm`, without assigning shared application transport to its current sole root consumer. |
| `e3-sdk` / default            | [sdk](../../crates/sdk/README.md) → `sdk`                                                          | Feature-gated application facade over existing owners; external Rust clients and dev: `e3-tests`.                                                          |
| `e3-wasm` / default           | [wasm](../../crates/wasm/README.md) → `wasm`                                                       | JS/WASM BFV facade and Node/browser packaging; consumed by the separate `@interfold/wasm` npm/SDK surface.                                                 |
| `e3-init` / default           | [init](../../crates/init/README.md) → `init`                                                       | Project/template scaffolding; consumed by `e3-cli`, but not a node-lifecycle responsibility.                                                               |
| `e3-fs` / default             | [fs](../../crates/fs/README.md) → `fs`                                                             | Async physical/in-memory VFS transformations; consumed by `e3-init`, not a node-specific filesystem service.                                               |
| `e3-hamt` / default           | [hamt](../../crates/hamt/README.md) → `hamt`                                                       | Immutable key/value maps with structural sharing; consumed by `e3-data` for cheap in-memory store snapshots.                                               |
| `e3-console` / default        | [console](../../crates/console/README.md) → `console`                                              | Destination-independent command output/capture and drain handles; consumed by `e3-cli` and `e3-daemon-server`, not a structured logger.                    |
| `e3-task-pool` / default      | [task-pool](../../crates/task-pool/README.md) → `task-pool`                                        | Reusable bounded admission and cancellation resources; consumed by `e3-multithread`, `e3-zk-prover`, and `e3-ciphernode-builder`.                          |
| `e3-utils` / default          | [utils](../../crates/utils/README.md) → `utils`                                                    | Mechanical byte/decoding, channel, retry/receipt, path, and formatting helpers; consumed by `e3-events`, `e3-data`, and `e3-evm-helpers`.                  |
| `e3-utils-derive` / default   | [utils-derive](../../crates/utils-derive/README.md) → `utils-derive`                               | Byte-serde proc macro; consumed by `e3-utils` and its downstream derive users.                                                                             |

These paths remain stable because the capabilities have distinct contracts/audiences or are small
reusable owners, not because flatness implies purity. In particular, `utils` already has runtime and
EVM adapter dependencies; it is not a dependency-free vocabulary layer.

Keep mechanical helpers at those owners: byte/serde machinery and its derive stay paired; resource
primitives stay in task-pool while memory/retry/E3 policy stays in dispatch; command output stays in
console; VFS copying stays in fs; immutable maps stay in hamt. Test-support stays limited to
independent RNG/tracing/discovery consumers. Do not expand `utils`, create a new general
`helpers`/`support` family, or move capability-specific rules into them to conceal a dependency.

## Dependency direction, not folder layering

The normal package graph remains authoritative. Selected **current** edges are:

```text
e3-cli                -> e3-entrypoint, e3-ciphernode-builder
e3-ciphernode-builder -> participation crates, e3-multithread, e3-task-pool
e3-keyshare           -> e3-multithread, e3-request, e3-fhe
e3-multithread        -> e3-task-pool, e3-zk-prover, e3-trbfv
e3-zk-prover          -> e3-slashing, e3-zk-witness, e3-zk-config, e3-task-pool
e3-zk-build           -> e3-zk-witness, e3-zk-config
e3-bfv-client         -> e3-zk-witness, e3-zk-config, e3-fhe-params
e3-openvm-host        -> e3-openvm-types, e3-compute-provider
e3-program-runner     -> e3-program-server, e3-openvm-host, e3-compute-provider
e3-sdk                -> e3-bfv-client, e3-fhe-params, e3-evm-helpers, e3-indexer (features)
e3-data               -> e3-config, e3-events
e3-config             -> e3-events
```

Thus `node/config` can be consumed by `state/data`, and participation can consume node dispatch.
Families cannot be topologically ordered as architectural layers; no family-root crate is needed to
hide these edges. #1022's earlier pure `core/` tree is context, not evidence that events,
repositories, request routing, or current actors are I/O-free. Use the
[design principles](../architecture/design-principles.md) for incremental boundary improvements.

Preserve focused feature graphs, not only a unified workspace build: normal entrypoint/CLI builds
must exclude test helpers and proof-skip behavior; ZK samples remain dev-only except in their
private benchmark consumer; minimal/BFV-only SDK builds must not acquire EVM/indexer defaults. Keep
the root [feature-containment check](../../scripts/checks/cargo-feature-containment.py) aligned with
relocated paths without weakening its assertions.

## Mechanical relocation and downstream compatibility

Directory grouping is not a Cargo package or Rust API rename. Keep `cargo -p` selectors, import
paths, binary names, SDK aliases, npm exports, features, and default selections stable. Update local
path dependencies; Git consumers selecting a package by name must still find it in the root
workspace. Path-based downstream checkouts must update their manifest paths at the new revision; old
pinned revisions remain usable. Do not leave permanent forwarding packages, symlink trees, or two
implementations as a transition mechanism.

The [release workflow](../../RELEASING.md#what-publication-checks-and-produces) does **not** publish
Rust crates to crates.io. Nine root packages explicitly disable publication, and a `default` flag is
not proof of a registry-ready dependency closure: for example, `e3-aggregator` normally depends on
private `e3-evm`. If registry publication is requested separately, resolve normal/build package
dependencies and publish prerequisites before dependents, audit packaged file inclusion and path
versus version dependencies, and decide private-package exposure first. Folder order is not release
order; this proposal changes no flags and authorizes no publication.

Any public package/API rename, especially the EVM client name, needs its own SemVer, consumer
migration, release-order and bounded-transition decision in #2322. There is no such rename or
compatibility alias crate proposed here.

### Path-sensitive migration checklist

Each relocation PR must update the affected sources and their consumers atomically, including:

| Surface                     | Evidence and required check                                                                                                                                                                                                                                                                                                                                                               |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cargo/workspaces            | Root members/workspace dependency paths, direct paths in every affected manifest, exclusions, template host/guest/runner manifests and locks; compare locked metadata and normal/build/dev feature selections. Do not add the excluded worker to root membership or merge its SDK/feature/lock setup into the root workspace.                                                             |
| Build/embedded inputs       | Audit `CARGO_MANIFEST_DIR`, repository-root discovery, `include_str!`/`include_bytes!`, build scripts and Solidity/Noir fixture paths; a new nesting depth can change these even with unchanged package names.                                                                                                                                                                            |
| Circuit source identity     | The canonical [identity owner](../../crates/zk/build/src/identity.rs) hashes framed repository-relative paths, including FHE/parameter and math owners. Relocation can change SOURCE_HASH with identical algorithms. Update all required roots and hash tests, prove no input disappeared, and record per-pair before/after provenance. Never restamp published artifacts to hide a move. |
| OpenVM identity             | Update [worker launch](../../scripts/openvm/run.sh), [provenance](../../scripts/openvm/provenance.ts), CLI compile/setup paths and generated manifests together where affected. Preserve independent CPU/CUDA targets, worker/guest pins, framing and receipt/executable identities; a folder move is not evidence that the rebuilt guest or deployed verifier is unchanged.              |
| Scripts/CI/Docker           | Audit root package scripts, Rust/Noir test runners, [CI routing](../../.github/workflows/ci.yml), [circuit filters](../../.github/filters/circuits.yml), cache inputs, and [Docker manifest/stub/source copies](../../crates/Dockerfile), including path/depth special cases. Select package IDs rather than assuming every crate is one directory deep.                                  |
| Distribution and navigation | Audit [release version inputs](../../scripts/release/version.mjs), package/archive inclusion, template Git/path rewriting, docs links, blueprint inventory/facts/evidence paths, and root/component READMEs/AGENTS. Keep binary install paths and configured node-state locations unchanged.                                                                                              |

This documentation-only proposal changes no sources, encodings, features, protocol/release counters,
artifact identity, deployment or running state. No migration or operator action is needed; reverting
the document is sufficient rollback. Future moves still need the
[compatibility decision](../../CONTRIBUTING.md#protocol-compatibility) and
[artifact/rollout review](../architecture/circuit-artifacts.md), not a blanket design waiver.
Compatible rolling/no-counter-change is a candidate only when stored/wire/proof compatibility is
verified; otherwise stop and scope the actual migration separately. Keep original matching artifacts
available for binary rollback.

## Review and migration batches

Agree the recommended names and retained-flat paths before implementing relocations. EVM package
names/new bindings stay with #2322; the excluded worker's possible move remains unsettled. These
decisions need not block an independent, already-agreed ownership fix.

After approval, select useful moves independently; this is **not a mandatory all-crate migration**:

| Batch                  | Small relocation units and acceptance boundary                                                                                                                                                                                                                                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Navigation first       | This proposal and the root component-map link only. No speculative empty family directories or source moves.                                                                                                                                                                                                                              |
| Diagnostics            | Logger and dashboard are 17 tracked files combined at the baseline, before caller/path updates; preserve passive observation, redaction, projections and diagnostic versus EventStore cursors.                                                                                                                                            |
| Node operation         | Move one package at a time: daemon/config/dispatch/builder, then entrypoint and CLI independently. CLI and entrypoint already total 102 tracked files before references, so do not combine them. Preserve startup/control profiles and use the affected lifecycle/dispatch/CLI consumer checks; builder behavior changes stay with #2257. |
| State                  | Data, event-system, sync and request can move independently with each package's manifest and callers; exercise affected persistence/replay/hydration scenarios and unchanged layout fixtures. Events stays flat.                                                                                                                          |
| Participation          | One owner per PR, after refreshing against any overlapping #2320/#2324 changes; aggregator plus keyshare already total 102 files. Keep formation, ordered slots, signing/quorum and randomized-output recovery behavior at their existing owners.                                                                                         |
| BFV/source-bound paths | Separate family relocation from formulas, preset switches, artifact regeneration and API changes. Coordinate FHE/FHE-parameter roots with the canonical generator/hash owner; run the affected native/witness/layout and verifier checks and explicitly report real-proof qualification limits.                                           |
| Application            | Move a root package with its template/host/guest/script path consumers, preserving the independent guest workspace and public journal. Verify generated-project compilation and affected host/guest parity; receipt/provenance changes require the prepared acceptance flow. The excluded worker does not move in this batch.             |
| Testing                | Relocate only the four existing shared/system packages, with test runners and graph guards; preserve owner-local fixtures, per-node RNGs and dev-only exposure. No new shared fixture/service layer.                                                                                                                                      |
| EVM                    | Delivery and binding/client naming remain with #2322, separated from semantic ABI extraction where practical; do not add a competing migration stack here. ZK needs no family relocation.                                                                                                                                                 |

Keep each resulting PR below 100 changed files **against its own base**, including renamed files and
all integration/documentation updates. The source counts above are lower bounds, not promises that
caller updates fit. Count the actual diff before publication; defer an oversized move rather than
introduce a half-moved crate, forwarding API, or unrelated source split just to satisfy the budget.
Stack only genuinely dependent slices, and verify each intermediate state independently.

With a family's first actual relocation, add its README containing current member links, why the
family exists, and links to owner/domain contracts. Link still-flat related owners explicitly.
Update the root [component map](../../crates/README.md#find-a-component) to **actual** paths in the
same PR; do not duplicate this dated proposal as another live inventory or copy domain rules into
each family README. Names, source moves, and behavioral/API changes remain separate review units.
