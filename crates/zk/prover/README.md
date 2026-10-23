# e3-zk-prover

## Purpose

Noir witness/proof execution, verification, recursive folding, and artifact installation for
ciphernode protocol proofs. This is separate from the
[OpenVM computation worker](../../openvm-prover/README.md). Static bounds/layouts belong in
[e3-zk-config](../config/README.md), and production input preparation/encoding belongs in
[e3-zk-witness](../witness/README.md).

## Map

| Location                                                                                                 | Responsibility                                                                                            |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| [`backend/`](src/backend), [`config.rs`](src/config.rs)                                                  | Version/checksum admission, downloads, transactional artifact installation, and backend status.           |
| [`witness.rs`](src/witness.rs), [`prover.rs`](src/prover.rs)                                             | Noir execution and bounded/deadlined Barretenberg subprocesses.                                           |
| [`actor_system.rs`](src/actor_system.rs)                                                                 | Node-wide proof actor composition and recovery inputs.                                                    |
| [`request_execution.rs`](src/request_execution.rs)                                                       | Correlated C0–C7, batch verification and recursive request execution, including local witness decryption. |
| [`proof_request/`](src/proof_request), [`proof_verification/`](src/proof_verification)                   | Local proof planning/signing and authenticated key-proof verification/recovery.                           |
| [`share_verification/`](src/share_verification), [`node_proof_aggregation/`](src/node_proof_aggregation) | Signed share bundles, per-batch outcomes, and node-fold accumulation/recovery.                            |
| [`circuits/aggregation/`](src/circuits/aggregation), [`commitment_links/`](src/commitment_links)         | Recursive folds and cross-proof public-value links.                                                       |
| [`tests/`](tests)                                                                                        | Prepared local, recursive-fold, network/download, and proof-to-slash suites.                              |

A capability actor records a proof/verification plan and requests compute work. Shared workers
execute the circuit/prover and return correlated outcomes; actor effects sign/publish complete
results or retain exact retry inputs. Recovery restores canonical context and unresolved work before
current-boot effect readiness. This is distinct from artifact installation, which prepares the
backend before requests are served.

## Backend and public API

`ZkBackend::new(bb_path, circuits_dir, work_dir)` takes `e3_config::BBPath` and artifact/work paths.
`check_status().await` reports setup state; `ensure_installed().await` prepares required
tools/artifacts and may download/install them. Version/checksum requirements come from
[versions.json](versions.json). `with_bb_timeout` bounds each proving process.

`ZkProver::new(&backend)` executes proof generation and verification. Select the matching artifact
directory with `resolve_artifacts_dir(preset, committee)` and use the explicit variant methods where
needed. Verification returns `Result<bool, ZkError>`: infrastructure failure is distinct from
completed invalid verification. `CompiledCircuit`, `WitnessGenerator`, and `input_map` expose
compiled-circuit loading and witness generation (using `noirc_abi::InputMap`) without defining
another circuit parameter table.

`execute_zk_request(prover, cipher, request, record_step)` is the synchronous protocol-request
adapter used by shared workers. It preserves the request's correlation/E3 identity and reports
completed node-fold step timings through the caller's callback. `zk_operation_name` owns the stable
diagnostic labels. This API creates no actor, pool, retry loop or publication side effect; call it
from the node's existing bounded executor. Signature admission remains upstream, and deterministic
witness computation/encoding remains in `zk/witness`.

Node runtimes use `setup_zk_actors` with `ZkActorRecovery`, canonical committees/keys, signer, and
repositories, plus the compute dispatcher's shared `e3_task_pool::TaskPool` and node scope. C0
verification runs off the actor runtime through that pool, preserving serial response/barrier order.
These arguments are required: callers must not create an independent production verification pool.
The [builder wiring](../../ciphernode-builder/src/builder/extensions.rs) shows hydration before
effect-enabled replay. Operators normally use the [CLI Noir commands](../../cli/src/noir.rs), not
manual actor construction. Slashing implementation lives in [e3-slashing](../../slashing/README.md).

`Provable::Config` carries each circuit's concrete configuration into preparation. Workers build it
from their existing BFV parameter owner; C6/C7 reuse it across ciphertext indices. User encryption
prepares from one exact ciphertext and its encryption intermediates, not a second encryption.

## Before running Cargo

`build.rs` runs `scripts/build_fixtures.sh` even for checks. With nargo and required artifacts
available, it compiles the dummy Noir fixture and rewrites tracked fixture JSON using jq. If
required circuit artifacts are absent and bb is available, it can run
`pnpm install --frozen-lockfile` and `pnpm build:circuits` in a separate target directory. Missing
nargo/bb can skip preparation; a successful Cargo command does not establish matching artifacts.

For **compile-only** work:

```sh
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 cargo check --locked -p e3-zk-prover --tests
```

This skips fixture preparation only. It neither skips proof tests nor supplies valid artifacts. The
dependency graph can also need [Solidity fixtures](../../test-helpers/README.md).

## Tests

`cargo test --locked -p e3-zk-prover --lib` runs native/unit and actor suites after the preparation
above. Backend tests cover local archives/install rollback; prover tests use fake processes for
timeout/error classification; witness tests execute the dummy compiled circuit; capability tests
cover plans, signature admission, correlations, and restart inputs. These have different external
requirements from the explicitly selected real-proof suites below.

`zk_actor` tests use controlled fake verification processes to cover actor-runtime progress, shared
pool saturation, serial barriers and node-scoped queued cancellation. They test scheduling and error
classification, not proof correctness.

`cargo test --locked -p e3-zk-prover --lib request_execution::` covers request-kind admission,
request correlation, unavailable-verifier versus invalid-statement classification, C5/C7 threshold
guards and C6 key validation. The ignored
`local_small_c7_request_proves_ten_shares_with_the_canonical_committee` test also lives here; it
requires `E3_CUSTOM_BB` and `E3_TEST_ARTIFACTS_ROOT` for prepared insecure-64/small artifacts.

### Real-proof tests

Prepare pinned nargo and bb, jq, pnpm/workspace dependencies, and circuits/VKs matching the active
preset and committee through the
[circuit build guide](../../../scripts/circuits/README.md#circuit-builder). Then use root
`pnpm rust:test:proofs` for the explicitly selected ignored proof suites, or
`pnpm rust:test:slashing` for proof-to-slash integration. The `integration-tests` feature gates the
separate network/download integration target; enabling it alone is not evidence of proof execution.
Test-only aggregation skipping in the wider harness is never a production fallback.

See [proof statements](../../../docs/architecture/proof-statements.md) and
[artifact compatibility](../../../docs/architecture/circuit-artifacts.md) for required cross-layer
acceptance. Witness generation, process success, checksum matching, and verified statements are
different results. See [AGENTS.md](AGENTS.md) for proof-plan, verification-outcome, and artifact
change rules.
