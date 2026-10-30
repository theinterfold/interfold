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
pnpm bench:circuits list --mode insecure --preset insecure-lbfv --committee minimum
pnpm bench:circuits list --mode secure --preset secure-16384 --committee small
pnpm bench:circuits replay --input <saved-run-or-summary> --output <new-directory>
pnpm bench:circuits report --input <saved-run> [--output <new-report.md>]
pnpm test:circuit-bench
```

`circuits/benchmarks/config.json` selects the leaf cases and their permitted modes/presets; unknown
or restricted selections fail. `insecure-lbfv` selects protocol param-set 4 while sharing the
degree-128 `insecure` archive. Historical result directories and that config stay under
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

`protocol` runs the existing release-profile `e3-tests` integration scenario with full proof
aggregation. `gas` adds the existing Hardhat verifier replay tool. `run` includes these stages
unless `--leaf-only` or `--witness-only` is set. The driver copies no protocol workflow and
implements no EVM: it sets export paths and concurrency controls, then reads structured JSON
exports. The integration child receives the runner's validated canonical BB path through
`E3_CUSTOM_BB`, never a PATH lookup; run metadata records that path and version.

Install workspace dependencies with `pnpm install --frozen-lockfile`. Select a complete archived
node pair before gas collection. Run benchmarks serially: they change shared Noir selectors.

The active preset and committee must match the request, and the driver verifies the runtime artifact
inventory and checksums. To select an archived pair without compiling:

```bash
pnpm build:circuits --preset insecure --committee minimum --hydrate-bin-only
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

## Focused checks

```bash
pnpm test:circuit-bench
cargo check -p e3-zk-benchmarks
```

The tests cover selection, ABI projection, nullable outcomes, artifact identity, and
external-command failures. They do not claim to verify mocked cryptographic proofs. The retained
fixture shell utility `sync_bfv_vk_binding_fixture.sh` under `circuits/benchmarks/scripts/` runs
only when explicitly requested.
