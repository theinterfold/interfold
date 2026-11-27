# Circuit and protocol benchmarks

## Purpose

`pnpm bench:circuits` runs this crate, `e3-zk-benchmarks`. It is an unpublished development tool: it
links the unpublished `e3-zk-samples` crate as a normal dependency to build artificial cryptographic
material. Samples are not live application inputs. The runner executes production preparation, the
production Noir witness generator, and the production BB adapters.

Run `pnpm bench:circuits --help` for every flag. This page lists the commands and the measurement
rules that the recorded numbers depend on.

## Map

| Location                                                                                     | Responsibility                                                |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [selection.rs](src/circuit_benchmark/selection.rs)                                           | Configured cases, modes, and committee selection.             |
| [inputs.rs](src/circuit_benchmark/inputs.rs), [leaf.rs](src/circuit_benchmark/leaf.rs)       | Samples, production preparation, and measured leaf execution. |
| [artifacts.rs](src/circuit_benchmark/artifacts.rs)                                           | Pair, digest, compiler, and config-cache provenance.          |
| [protocol.rs](src/circuit_benchmark/protocol.rs)                                             | Existing integration and gas child-process orchestration.     |
| [records.rs](src/circuit_benchmark/records.rs), [report.rs](src/circuit_benchmark/report.rs) | Schema-preserving records and metric rendering.               |

## Commands

```bash
pnpm bench:circuits list --mode insecure --committee minimum
pnpm bench:circuits run --mode insecure --committee minimum --circuit dkg/pk --leaf-only
pnpm bench:circuits protocol --mode insecure --committee minimum --multithread-jobs 2
pnpm bench:circuits gas --mode insecure --committee minimum
pnpm bench:circuits replay --input <saved-run-or-summary> --output <new-directory>
pnpm bench:circuits report --input <saved-run> [--output <new-report.md>]
pnpm test:circuit-bench
```

`circuits/benchmarks/config.json` selects the leaf cases and their permitted modes; unknown or
mode-restricted selections fail. Historical result directories and that config stay under
`circuits/benchmarks/`.

## Measurement rules

- Each selected case runs once. The command uses an optimized Cargo profile; run metadata records
  the profile, and a debug-profile run is labeled non-performance data.
- Metrics stay distinct: `production_input_preparation_wall`, `production_noir_execution_wall`, and
  `production_bb_adapter_wall` measure production Rust phases; `external_bb_prove_wall` and
  `external_bb_verify_wall` measure development circuits without a protocol `CircuitName`;
  historical records keep their original `isolated_nargo` label. Integration phases are
  `wall_clock`; overlapping shared jobs are `tracked_job_wall` and never sum to end-to-end latency.
- Sample generation, configuration construction, and artifact loading sit outside the phase timers.
  BB adapter measurements include process startup and file I/O.
- Missing measurements are JSON `null`, never zero. A failed stage fails the run; it does not become
  a successful N/A result. Raw records retain failed-stage durations for diagnostics. Reports show
  failed leaf-phase durations as `N/A` and exclude them from leaf totals; the run remains failed.
- Both UDE legs share one encryption and one prepared witness. The runner measures this shared work
  once, and each leg projects the compiled ABI, including ct1's separate `r_ct1` quotient.

## Artifacts and provenance

The default artifact root is `dist/circuits`; `--artifacts <root>` selects another root. The runner
checks the pair stamp, the manifest digests of the files it reads, the compiled Noir version, and
the proof variant. An artifact source hash that differs from the working tree is accepted and the
original stamp is recorded; the runner never restamps or rebuilds an artifact because Rust source
changed.

The `config` case is not part of the runtime release inventory. Reusing its local cache requires the
artifact-specific `.config-benchmark.json` stamp that binds the selected pair, the compiler version,
the compiled digest, and each cached VK digest; the global active stamp alone is not evidence. Fresh
compilation (`--bench-compile`) hashes the actual local config package and shared Noir library
sources, so a hydrated archive hash never identifies a fresh compile. Select the pair first with the
canonical builder (`pnpm build:circuits`).

## Protocol, gas, replay, and report

For SS, `protocol` runs the `e3-tests` integration target's ignored `benchmark_trbfv_actor` entry in
the release profile with full proof aggregation. `gas` adds the existing Hardhat verifier replay
tool. `run` includes these stages unless `--leaf-only` or `--witness-only` is set. The driver copies
no protocol workflow and implements no EVM: it sets export paths and concurrency controls, then
reads structured JSON exports. The integration child receives the runner's validated canonical BB
path through `E3_CUSTOM_BB`, never a PATH lookup; run metadata records that path and version.

Install workspace dependencies with `pnpm install --frozen-lockfile`. Select a complete archived
node pair before gas collection. Run benchmarks serially: they change shared Noir selectors.

The active preset and committee must match the request, and the driver verifies the runtime artifact
inventory and checksums. To select an archived pair without compiling:

```bash
pnpm build:circuits --preset insecure-64 --committee minimum --hydrate-bin-only
```

Verifier gas and calldata gas stay separate measurements; calldata cost never substitutes for
verifier gas. The gas stage measures the DKG and decryption verifiers. It does not measure the CRISP
user verifier, which the CRISP repository owns. Saved results that contain a user-verifier gas value
keep it in reports.

To measure gas again for saved protocol proofs without another integration run:

```bash
pnpm bench:circuits replay --input <saved-integration-summary> --output <new-directory>
```

Keep the saved integration export and its original metadata unchanged. Replay records new EVM
measurements. It does not repeat protocol proving.

Replay re-verifies saved folded proofs against matching verification keys; it does not regenerate
proofs to hide a mismatch, and an explicit selection that disagrees with the export fails. Report
runs no compiler, prover, integration, or EVM tool, reads schema 1 (historical) and schema 2 (Rust)
records without relabeling, and never overwrites saved output.

Each run writes a new directory under `circuits/benchmarks/runs/` (or `--output`): raw per-case
records, `benchmark_run_meta.json`, `report.md`, protocol exports, and process logs. The runner
refuses to reuse a non-empty directory.

## Synchronized Minimum

Use a source-built
[candidate export](../../../scripts/circuits/README.md#synchronized-decryption-candidates) and the
matching committed manifest. `run` needs its `candidate/` directory; the local request also needs
`dkg-candidate/` in the same export. The runner stages verified bytes privately and does not
activate a preset. Install the workspace dependencies, compile the contract package, and use pinned
bb, solc 0.8.28 and Anvil. For example, with `profile=sync-secure-8192` or `sync-insecure-64`:

```bash
pnpm -C packages/interfold-contracts exec hardhat compile
python3 scripts/circuits/guard-proof-rss.py pnpm bench:circuits run \
  --mode "$profile" --committee minimum --candidate "$export" --output "$runs/graph"
pnpm bench:circuits replay --input "$runs/graph" --candidate "$export" --output "$runs/replay"
python3 scripts/circuits/guard-proof-rss.py pnpm bench:circuits request \
  --mode "$profile" --committee minimum --candidate "$export" --output "$runs/request"
```

- **`run` / `gas`:** one native `19 + 18` ciphertext; recursive C6 for each of `[0,2]`, recursive C7
  over those two verified rows, then the EVM outer. The standalone contract call checks the saved
  proof against the selected child pins and public sample expectations. `--circuit` includes its
  prerequisites; `--leaf-only` stops after C7; `--witness-only` stops at the two C6 witnesses.
- **`request` / `protocol`:** the regular `committee:new` task submits to a private, temporary Anvil
  deployment. The production `Interfold` implementation is linked to a benchmark-only lifecycle
  adapter: it checks the candidate quote and forwards other calls to the normal library. The mined
  request freezes the DKG and decryption wrappers before ticket submission; the decryption default
  then rotates. The signed recovery scenario uses that E3, its registry and finalized committee
  through key chunks, ciphertext publication, aggregator failover and the mined plaintext.
  Production admission stays disabled. The application compute verifier and HTTP DA object service
  are test fixtures.
- **Timing:** `request_receipt.json` records the host monotonic time from the CLI's `request(...)`
  dispatch to the observed plaintext receipt. Incomparable or missing dispatch readings leave those
  durations `null`; the mined transactions and gas remain available. The longer interval from CLI
  invocation includes capacity and fee preflights. Local deployment and circuit builds precede both
  intervals. Anvil advances past the ticket and input windows. Disk reopen, late setup and failover
  are part of the timed workload; this is not a measurement of a fault-free production network.
- **Gas and memory:** the standalone verifier estimate includes transaction intrinsic gas. The
  request records full receipt gas for request, signed DKG publication (excluding key chunks),
  ciphertext and plaintext separately. The guard prints sampled process-tree peak RSS and command
  wall time; run the profiles serially. `report --input <run>` uses saved data only. New request
  runs save the child exit and receipt-validation outcomes separately in `request_outcome.json`; a
  failed run can still have a valid mined receipt.

For the
[SS comparison](../../../circuits/benchmarks/synchronized-decryption.md#optimized-minimum-comparison--2026-11-26),
hydrate the matching SS archive first. Use `mode=insecure` for `insecure-64/minimum` or
`mode=secure` for `secure-8192/minimum` and a fresh output directory for each command:

```bash
python3 scripts/circuits/guard-proof-rss.py pnpm bench:circuits run --mode "$mode" --committee minimum \
  --circuit threshold/share_decryption --circuit threshold/decrypted_shares_aggregation \
  --leaf-only --output "$runs/ss-$mode-leaves"
python3 scripts/circuits/guard-proof-rss.py pnpm bench:circuits gas --mode "$mode" --committee minimum \
  --multithread-jobs 1 --output "$runs/ss-$mode-gas"
python3 scripts/circuits/guard-proof-rss.py pnpm bench:circuits request --mode "$mode" --committee minimum \
  --multithread-jobs 1 --output "$runs/ss-$mode-request"
```

SS `request` runs three full nodes and a local libp2p bootstrap peer on a private Anvil deployment.
The nodes submit tickets, sign and prove DKG, publish the key, fetch one encrypted `19 + 18` result
over HTTP, and submit the decryption proof. The request freezes the real SS verifiers before the
future decryption default rotates. The host observes the last key-chunk and plaintext receipts over
RPC. All SS nodes remain online; the timed SyncDec request includes failover and reopen. Standalone
verifier estimates replay the mined calls after the timing interval.

## Focused checks

```bash
pnpm test:circuit-bench
cargo check -p e3-zk-benchmarks
```

The tests cover selection, ABI projection, nullable outcomes, artifact identity, and
external-command failures. They do not claim to verify mocked cryptographic proofs. The retained
fixture shell utility `sync_bfv_vk_binding_fixture.sh` under `circuits/benchmarks/scripts/` runs
only when explicitly requested.
