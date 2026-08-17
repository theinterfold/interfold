# Interfold ZK Circuit Benchmarks

**Generated:** 2026-08-10 08:30:41 UTC

**Git Branch:** `chunk-circuits`  
**Git Commit:** `84c649e242d0179728adfa25743b5e71e20c8ce4`

**Committee Size:** `H=5`, `N=9`, `T=4`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting | Value |
|---------|-------|
| Benchmark mode | `secure` |
| BFV preset (artifacts) | `secure-8192` |
| BFV preset (enum) | `SecureThreshold8192` |
| λ (smudging / error) | 50 |
| Nodes spawned (integration) | 16 |
| Network model | `in_process_bus` |
| Testmode harness | true |
| `proof_aggregation_enabled` | true |
| `BENCHMARK_MULTITHREAD_JOBS` (max concurrent ZK jobs) | 13 |
| Rayon worker threads | 13 |
| CPU cores (host) | 14 |
| `dkg_fold_attestation_verifier` (EIP-712) | `0x7969c5eD335650692Bc04293B07F5BF2e7A673C0` |
| Verbose logging (`run_benchmarks.sh --verbose`) | true |

### Hardware & software (Nargo / Barretenberg host)

| | |
|--|--|
| **CPU** | Apple M4 Pro |
| **CPU cores** | 14 |
| **RAM** | 48.00 GB |
| **OS** | Darwin |
| **Architecture** | arm64 |
| **Nargo** | nargo version = 1.0.0-beta.26 noirc version = 1.0.0-beta.26+40d6574f851d926f93e0c3a271bac3e6e82ac905 (git version hash: 40d6574f851d926f93e0c3a271bac3e6e82ac905, is dirty: false)  |
| **Barretenberg** | 5.1.0  |

---

## Audit status

On-chain verify gas: **complete** (CRISP Π_user + Interfold Π_DKG / Π_dec replay).

---

## Measurement methodology

| Metric kind | Source | Meaning | Do **not** use for |
|-------------|--------|---------|-------------------|
| **wall_clock** | `test_trbfv_actor` phase timers / HLC event span | End-to-end wait in the in-process test harness | Production WAN latency; per-node deployment cost |
| **isolated_nargo** | `benchmark_circuit.sh` per circuit | Single `bb prove` on oracle witness, one circuit at a time | Full protocol pipeline (different witness path) |
| **tracked_job_wall** | `MultithreadReport` per `ComputeRequest` | Wall time of each job on the shared Rayon pool (≤ `BENCHMARK_MULTITHREAD_JOBS` concurrent) | End-to-end time — **sums exceed wall clock** when jobs overlap |

**Harness limits (integration):** all ciphernodes share one process and bus (`network_model: in_process_bus`); sortition registers extra nodes; `testmode_*` enabled; proof aggregation always enabled. Compare runs only with the same `benchmark_mode`, committee, `BENCHMARK_MULTITHREAD_JOBS`, commit, and hardware.

---
## Protocol Summary

### Circuit Benchmarks (isolated Nargo + Barretenberg)

Single-circuit `bb prove` on the benchmark oracle witness (not the integration actor pipeline).

| Circuit | Constraints | Prove (s) | Verify (ms) | Proof (KiB) |
|---------|-------------|-----------|-------------|------------|
| C0 | 287727 | 0.98 | 10.43 | 14.31 |
| C1 | 2226972 | 5.99 | 10.85 | 14.31 |
| C2a chunk (SK) | 274757 | 0.91 | 10.63 | 14.31 |
| C2b chunk (ESM) | 364915 | 1.14 | 10.39 | 14.31 |
| C3a | 3478343 | 8.98 | 10.46 | 14.31 |
| C3b | 3478343 | 8.98 | 10.46 | 14.31 |
| C4a | 2447701 | 6.51 | 11.52 | 14.31 |
| C4b | 2447701 | 6.51 | 11.52 | 14.31 |
| C5 | 1426371 | 4.08 | 10.71 | 14.31 |
| user_data_encryption | 1688639 | 4.72 | 10.94 | 14.31 |
| C6 | 2977228 | 7.88 | 10.68 | 14.31 |
| C7 | 191201 | 0.65 | 10.92 | 14.31 |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
|----------|------------|-------------------|------------|--------------|-----------|
| Π_DKG | 10.44 KiB | 1.22 KiB | 3222303 | 186296 | 3408599 |
| Π_user | 14.31 KiB | 0.12 KiB | 2982226 | 200664 | 3182890 |
| Π_dec | 10.44 KiB | 3.84 KiB | 3761654 | 190424 | 3952078 |

### Role / Phase / Activity

| Role | Phase | Activity | Metric | Duration | Proof size | Bandwidth |
|------|-------|----------|--------|----------|------------|-----------|
| Each ciphernode | P1 | one-time DKG participation (test harness) | wall_clock | 5166.65 s | 114.50 KiB | 117.75 KiB |
| Aggregator | P2 | C5 + Π_DKG fold (aggregator span) | wall_clock | 408.35 s | 10.44 KiB | 11.66 KiB |
| User | P3 | per user input | isolated_nargo | 8.73 s | 14.31 KiB | 14.44 KiB |
| Each ciphernode | P4 | per computation output (C6) | isolated_nargo | 7.88 s | 14.31 KiB | 14.50 KiB |
| Aggregator | P4 | C7 + Π_dec fold (full publish→aggregate) | wall_clock | 293.92 s | 10.44 KiB | 14.28 KiB |
| Aggregator | P4 | C7 + fold only (pending→plaintext span) | wall_clock | 86.29 s | 10.44 KiB | 14.28 KiB |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **41.27 s** — not comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase | Metric | Duration (s) |
|-------|--------|---------------|
| Starting trbfv actor test | `wall_clock` | 0.00 |
| Setup completed | `wall_clock` | 1.98 |
| Committee Setup Completed | `wall_clock` | 16.11 |
| Committee Finalization Complete | `wall_clock` | 0.00 |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 408.35 |
| ThresholdShares -> PublicKeyAggregated | `wall_clock` | 5166.65 |
| E3Request -> PublicKeyAggregated | `wall_clock` | 5167.15 |
| Application CT Gen | `wall_clock` | 0.29 |
| Running FHE Application | `wall_clock` | 0.00 |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall) | `wall_clock` | 86.29 |
| Ciphertext published -> PlaintextAggregated | `wall_clock` | 293.92 |
| Entire Test | `wall_clock` | 5479.46 |

### Multithread job timings (`tracked_job_wall`)

| Name | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| CalculateDecryptionKey | 0.04 | 9 | 0.38 |
| CalculateDecryptionShare | 0.17 | 9 | 1.50 |
| CalculateThresholdDecryption | 0.20 | 1 | 0.20 |
| GenEsiSss | 16.80 | 9 | 151.23 |
| GenPkShareAndSkSss | 0.61 | 9 | 5.52 |
| NodeDkgFold/c2ab_chunk_fold | 25.02 | 9 | 225.15 |
| NodeDkgFold/c3a_fold | 610.82 | 9 | 5497.35 |
| NodeDkgFold/c3ab_fold | 11.11 | 9 | 100.01 |
| NodeDkgFold/c3b_fold | 574.69 | 9 | 5172.17 |
| NodeDkgFold/c4ab_fold | 9.86 | 9 | 88.78 |
| NodeDkgFold/node_fold | 22.55 | 9 | 202.94 |
| ZkDecryptedSharesAggregation | 4.76 | 1 | 4.76 |
| ZkDecryptionAggregation | 81.31 | 1 | 81.31 |
| ZkDkgAggregation | 3.96 | 1 | 3.96 |
| ZkDkgShareDecryption | 56.46 | 18 | 1016.25 |
| ZkNodeDkgFold | 826.47 | 9 | 7438.21 |
| ZkNodesFoldStep | 6.42 | 5 | 32.08 |
| ZkPkAggregation | 37.32 | 1 | 37.32 |
| ZkPkBfv | 6.64 | 9 | 59.77 |
| ZkPkGeneration | 68.69 | 9 | 618.23 |
| ZkShareComputation | 374.56 | 18 | 6742.06 |
| ZkShareComputation/batches | 86.11 | 18 | 1550.07 |
| ZkShareComputation/chunks | 260.81 | 18 | 4694.58 |
| ZkShareComputation/finalize | 26.74 | 18 | 481.23 |
| ZkShareEncryption | 94.55 | 432 | 40843.47 |
| ZkThresholdShareDecryption | 166.01 | 9 | 1494.07 |
| ZkVerifyShareDecryptionProofs | 0.14 | 9 | 1.24 |
| ZkVerifyShareProofs | 0.79 | 11 | 8.67 |

Raw sum of tracked timing rows: **76552.50 s** — includes nested sub-steps and overlapping jobs; it is **not** elapsed time.
Top-level tracked job sum (excluding nested sub-steps): **58540.23 s** — jobs still run in parallel up to `BENCHMARK_MULTITHREAD_JOBS`.
Nested sub-step rows reported separately: **18012.27 s**.

### Operation sub-steps (`tracked_job_wall`)

| Step | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| c2ab_chunk_fold | 25.02 | 9 | 225.15 |
| c3a_fold | 610.82 | 9 | 5497.35 |
| c3ab_fold | 11.11 | 9 | 100.01 |
| c3b_fold | 574.69 | 9 | 5172.17 |
| c4ab_fold | 9.86 | 9 | 88.78 |
| node_fold | 22.55 | 9 | 202.94 |
| batches | 86.11 | 18 | 1550.07 |
| chunks | 260.81 | 18 | 4694.58 |
| finalize | 26.74 | 18 | 481.23 |

### Aggregation jobs (`tracked_job_wall`)

| Operation | Avg (s) | Runs | Total (s) |
|-----------|---------|------|-----------|
| ZkDecryptedSharesAggregation | 4.76 | 1 | 4.76 |
| ZkDecryptionAggregation | 81.31 | 1 | 81.31 |
| ZkDkgAggregation | 3.96 | 1 | 3.96 |
| ZkNodeDkgFold | 826.47 | 9 | 7438.21 |
| ZkPkAggregation | 37.32 | 1 | 37.32 |

Sum of aggregation job tracked time: **7565.55 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact | Proof (bytes) | Public inputs (bytes) |
|----------|---------------|------------------------|
| dkg_aggregator | 10688 | 1248 |
| decryption_aggregator | 10688 | 3936 |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with `crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without re-running the integration test.

| File |
|------|
| `config_default.json` |
| `dkg_esm_share_computation_chunk_default.json` |
| `dkg_pk_default.json` |
| `dkg_share_decryption_default.json` |
| `dkg_share_encryption_default.json` |
| `dkg_sk_share_computation_chunk_default.json` |
| `threshold_decrypted_shares_aggregation_default.json` |
| `threshold_pk_aggregation_default.json` |
| `threshold_pk_generation_default.json` |
| `threshold_share_decryption_default.json` |
| `threshold_user_data_encryption_ct0_default.json` |
| `threshold_user_data_encryption_ct1_default.json` |

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is effectively 0.
