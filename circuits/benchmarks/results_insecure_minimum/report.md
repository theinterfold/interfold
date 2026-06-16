# Interfold ZK Circuit Benchmarks

**Generated:** 2026-06-13 10:29:25 UTC

**Git Branch:** `lock/fhers`  
**Git Commit:** `c2dfd37d36d9e85b45b03db03bc7267964a4a6da`

**Committee Size:** `H=2`, `N=3`, `T=1`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting                                               | Value                                        |
| ----------------------------------------------------- | -------------------------------------------- |
| Benchmark mode                                        | `insecure`                                   |
| BFV preset (artifacts)                                | `insecure-512`                               |
| BFV preset (enum)                                     | `InsecureThreshold512`                       |
| λ (smudging / error)                                  | 2                                            |
| Nodes spawned (builder)                               | 7                                            |
| Network model                                         | `in_process_bus`                             |
| Testmode harness                                      | true                                         |
| `proof_aggregation_enabled`                           | true                                         |
| `BENCHMARK_MULTITHREAD_JOBS` (max concurrent ZK jobs) | 13                                           |
| Rayon worker threads                                  | 13                                           |
| CPU cores (host)                                      | 14                                           |
| `dkg_fold_attestation_verifier` (EIP-712)             | `0x7969c5eD335650692Bc04293B07F5BF2e7A673C0` |
| Verbose logging (`run_benchmarks.sh --verbose`)       | false                                        |

### Hardware & software (Nargo / Barretenberg host)

|                  |                                                                                                                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CPU**          | Apple M4 Pro                                                                                                                                                                       |
| **CPU cores**    | 14                                                                                                                                                                                 |
| **RAM**          | 48.00 GB                                                                                                                                                                           |
| **OS**           | Darwin                                                                                                                                                                             |
| **Architecture** | arm64                                                                                                                                                                              |
| **Nargo**        | nargo version = 1.0.0-beta.16 noirc version = 1.0.0-beta.16+2d46fca7203545cbbfb31a0d0328de6c10a8db95 (git version hash: 2d46fca7203545cbbfb31a0d0328de6c10a8db95, is dirty: false) |
| **Barretenberg** | 3.0.0-nightly.20260102                                                                                                                                                             |

---

## Audit status

On-chain verify gas: **complete** (CRISP Π_user + Interfold Π_DKG / Π_dec replay).

---

## Measurement methodology

| Metric kind          | Source                                           | Meaning                                                                                    | Do **not** use for                                             |
| -------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| **wall_clock**       | `test_trbfv_actor` phase timers / HLC event span | End-to-end wait in the in-process test harness                                             | Production WAN latency; per-node deployment cost               |
| **isolated_nargo**   | `benchmark_circuit.sh` per circuit               | Single `bb prove` on oracle witness, one circuit at a time                                 | Full protocol pipeline (different witness path)                |
| **tracked_job_wall** | `MultithreadReport` per `ComputeRequest`         | Wall time of each job on the shared Rayon pool (≤ `BENCHMARK_MULTITHREAD_JOBS` concurrent) | End-to-end time — **sums exceed wall clock** when jobs overlap |

**Harness limits (integration):** all ciphernodes share one process and bus
(`network_model: in_process_bus`); sortition registers extra nodes; `testmode_*` enabled; proof
aggregation always enabled. Compare runs only with the same `benchmark_mode`, committee,
`BENCHMARK_MULTITHREAD_JOBS`, commit, and hardware.

---

## Protocol Summary

### Circuit Benchmarks (isolated Nargo + Barretenberg)

Single-circuit `bb prove` on the benchmark oracle witness (not the integration actor pipeline).

| Circuit              | Constraints | Prove (s) | Verify (ms) | Proof (KB) |
| -------------------- | ----------- | --------- | ----------- | ---------- |
| C0                   | 6847        | 0.12      | 24.41       | 15.88      |
| C1                   | 53485       | 0.32      | 24.38       | 15.88      |
| C2a                  | 41244       | 0.30      | 24.71       | 15.88      |
| C2b                  | 79591       | 0.47      | 25.55       | 15.88      |
| C3a                  | 120114      | 0.55      | 24.84       | 15.88      |
| C3b                  | 120114      | 0.55      | 24.84       | 15.88      |
| C4a                  | 62750       | 0.32      | 24.77       | 15.88      |
| C4b                  | 62750       | 0.32      | 24.77       | 15.88      |
| C5                   | 21501       | 0.21      | 24.81       | 15.88      |
| user_data_encryption | 53732       | 0.33      | 24.44       | 15.88      |
| C6                   | 86927       | 0.51      | 24.10       | 15.88      |
| C7                   | 90841       | 0.46      | 24.55       | 15.88      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.69 KB   | 0.38 KB           | 3119529    | 175044       | 3294573   |
| Π_user   | 15.88 KB   | 0.12 KB           | 2973001    | 170404       | 3143405   |
| Π_dec    | 10.69 KB   | 3.47 KB           | 3641094    | 187368       | 3828462   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 132.70 s | 127.00 KB  | 128.06 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 120.64 s | 10.69 KB   | 11.06 KB  |
| User            | P3    | per user input                            | isolated_nargo | 0.64 s   | 15.88 KB   | 16.00 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 0.51 s   | 15.88 KB   | 16.00 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 52.00 s  | 10.69 KB   | 14.16 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 48.43 s  | 10.69 KB   | 14.16 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **5.76 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 0.95         |
| Committee Setup Completed                                          | `wall_clock` | 7.02         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 120.64       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 132.70       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 133.20       |
| Application CT Gen                                                 | `wall_clock` | 0.01         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 48.43        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 52.00        |
| Entire Test                                                        | `wall_clock` | 193.18       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.00    | 3    | 0.01      |
| CalculateDecryptionShare      | 0.02    | 3    | 0.06      |
| CalculateThresholdDecryption  | 0.02    | 1    | 0.02      |
| GenEsiSss                     | 0.01    | 3    | 0.02      |
| GenPkShareAndSkSss            | 0.01    | 3    | 0.03      |
| NodeDkgFold/c2ab_fold         | 18.13   | 3    | 54.39     |
| NodeDkgFold/c3a_fold          | 71.19   | 3    | 213.56    |
| NodeDkgFold/c3ab_fold         | 7.88    | 3    | 23.63     |
| NodeDkgFold/c3b_fold          | 70.95   | 3    | 212.86    |
| NodeDkgFold/c4ab_fold         | 7.87    | 3    | 23.62     |
| NodeDkgFold/node_fold         | 18.29   | 3    | 54.86     |
| ZkDecryptedSharesAggregation  | 1.53    | 1    | 1.53      |
| ZkDecryptionAggregation       | 46.89   | 1    | 46.89     |
| ZkDkgAggregation              | 5.35    | 1    | 5.35      |
| ZkDkgShareDecryption          | 1.00    | 6    | 6.01      |
| ZkNodeDkgFold                 | 105.40  | 3    | 316.20    |
| ZkNodesFoldStep               | 5.04    | 2    | 10.08     |
| ZkPkAggregation               | 0.41    | 1    | 0.41      |
| ZkPkBfv                       | 0.22    | 3    | 0.65      |
| ZkPkGeneration                | 2.25    | 3    | 6.74      |
| ZkShareComputation            | 2.37    | 6    | 14.21     |
| ZkShareEncryption             | 4.00    | 24   | 96.07     |
| ZkThresholdShareDecryption    | 3.25    | 3    | 9.74      |
| ZkVerifyShareDecryptionProofs | 0.08    | 3    | 0.25      |
| ZkVerifyShareProofs           | 0.25    | 5    | 1.27      |

Sum of tracked job wall time: **1098.46 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 18.13   | 3    | 54.39     |
| c3a_fold  | 71.19   | 3    | 213.56    |
| c3ab_fold | 7.88    | 3    | 23.63     |
| c3b_fold  | 70.95   | 3    | 212.86    |
| c4ab_fold | 7.87    | 3    | 23.62     |
| node_fold | 18.29   | 3    | 54.86     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 1.53    | 1    | 1.53      |
| ZkDecryptionAggregation      | 46.89   | 1    | 46.89     |
| ZkDkgAggregation             | 5.35    | 1    | 5.35      |
| ZkNodeDkgFold                | 105.40  | 3    | 316.20    |
| ZkPkAggregation              | 0.41    | 1    | 0.41      |

Sum of aggregation job tracked time: **370.38 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10944         | 384                   |
| decryption_aggregator | 10944         | 3552                  |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with
`crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without
re-running the integration test.

| File                                                  |
| ----------------------------------------------------- |
| `dkg_e_sm_share_computation_default.json`             |
| `dkg_pk_default.json`                                 |
| `dkg_share_decryption_default.json`                   |
| `dkg_share_encryption_default.json`                   |
| `dkg_sk_share_computation_default.json`               |
| `threshold_decrypted_shares_aggregation_default.json` |
| `threshold_pk_aggregation_default.json`               |
| `threshold_pk_generation_default.json`                |
| `threshold_share_decryption_default.json`             |
| `threshold_user_data_encryption_ct0_default.json`     |
| `threshold_user_data_encryption_ct1_default.json`     |

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is
  effectively 0.
