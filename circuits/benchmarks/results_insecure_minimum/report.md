# Interfold ZK Circuit Benchmarks

**Generated:** 2026-08-07 16:09:38 UTC

**Git Branch:** `chunk-circuits`  
**Git Commit:** `2858844afa6275d93de4a4cbd0923353d4fce8e5`

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
| Verbose logging (`run_benchmarks.sh --verbose`)       | true                                         |

### Hardware & software (Nargo / Barretenberg host)

|                  |                                                                                                                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CPU**          | Apple M4 Pro                                                                                                                                                                       |
| **CPU cores**    | 14                                                                                                                                                                                 |
| **RAM**          | 48.00 GB                                                                                                                                                                           |
| **OS**           | Darwin                                                                                                                                                                             |
| **Architecture** | arm64                                                                                                                                                                              |
| **Nargo**        | nargo version = 1.0.0-beta.26 noirc version = 1.0.0-beta.26+40d6574f851d926f93e0c3a271bac3e6e82ac905 (git version hash: 40d6574f851d926f93e0c3a271bac3e6e82ac905, is dirty: false) |
| **Barretenberg** | 5.1.0                                                                                                                                                                              |

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
| C0                   | 6810        | 0.12      | 11.28       | 14.31      |
| C1                   | 53679       | 0.30      | 11.53       | 14.31      |
| C2a chunk (SK)       | 41301       | 0.25      | 11.18       | 14.31      |
| C2b chunk (ESM)      | 79575       | 0.38      | 11.60       | 14.31      |
| C3a                  | 120462      | 0.53      | 11.24       | 14.31      |
| C3b                  | 120462      | 0.53      | 11.24       | 14.31      |
| C4a                  | 63482       | 0.32      | 11.44       | 14.31      |
| C4b                  | 63482       | 0.32      | 11.44       | 14.31      |
| C5                   | 21464       | 0.18      | 11.52       | 14.31      |
| user_data_encryption | 53695       | 0.30      | 11.44       | 14.31      |
| C6                   | 86892       | 0.44      | 11.47       | 14.31      |
| C7                   | 89602       | 0.40      | 11.57       | 14.31      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.44 KB   | 0.44 KB           | 3129772    | 174516       | 3304288   |
| Π_user   | 14.31 KB   | 0.12 KB           | 2982274    | 200640       | 3182914   |
| Π_dec    | 10.44 KB   | 3.56 KB           | 3716573    | 187052       | 3903625   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 149.00 s | 114.50 KB  | 115.75 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 121.53 s | 10.44 KB   | 10.88 KB  |
| User            | P3    | per user input                            | isolated_nargo | 0.59 s   | 14.31 KB   | 14.44 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 0.44 s   | 14.31 KB   | 14.50 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 44.99 s  | 10.44 KB   | 14.00 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 41.80 s  | 10.44 KB   | 14.00 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **4.59 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 0.85         |
| Committee Setup Completed                                          | `wall_clock` | 7.03         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 121.53       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 149.00       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 149.51       |
| Application CT Gen                                                 | `wall_clock` | 0.01         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 41.80        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 44.99        |
| Entire Test                                                        | `wall_clock` | 202.39       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.00    | 3    | 0.01      |
| CalculateDecryptionShare      | 0.02    | 3    | 0.07      |
| CalculateThresholdDecryption  | 0.02    | 1    | 0.02      |
| GenEsiSss                     | 0.01    | 3    | 0.02      |
| GenPkShareAndSkSss            | 0.01    | 3    | 0.03      |
| NodeDkgFold/c2ab_chunk_fold   | 19.21   | 3    | 57.63     |
| NodeDkgFold/c3a_fold          | 73.76   | 3    | 221.27    |
| NodeDkgFold/c3ab_fold         | 7.94    | 3    | 23.82     |
| NodeDkgFold/c3b_fold          | 74.19   | 3    | 222.58    |
| NodeDkgFold/c4ab_fold         | 8.05    | 3    | 24.16     |
| NodeDkgFold/node_fold         | 18.83   | 3    | 56.50     |
| ZkDecryptedSharesAggregation  | 1.52    | 1    | 1.52      |
| ZkDecryptionAggregation       | 40.26   | 1    | 40.26     |
| ZkDkgAggregation              | 4.22    | 1    | 4.22      |
| ZkDkgShareDecryption          | 0.81    | 6    | 4.86      |
| ZkNodeDkgFold                 | 109.02  | 3    | 327.07    |
| ZkNodesFoldStep               | 4.65    | 2    | 9.29      |
| ZkPkAggregation               | 0.36    | 1    | 0.36      |
| ZkPkBfv                       | 0.21    | 3    | 0.63      |
| ZkPkGeneration                | 4.40    | 3    | 13.19     |
| ZkShareComputation            | 22.39   | 6    | 134.36    |
| ZkShareComputation/batches    | 12.17   | 6    | 73.03     |
| ZkShareComputation/chunks     | 1.90    | 6    | 11.42     |
| ZkShareComputation/finalize   | 8.29    | 6    | 49.73     |
| ZkShareEncryption             | 3.99    | 24   | 95.65     |
| ZkThresholdShareDecryption    | 2.96    | 3    | 8.87      |
| ZkVerifyShareDecryptionProofs | 0.09    | 3    | 0.28      |
| ZkVerifyShareProofs           | 0.12    | 5    | 0.62      |

Sum of tracked job wall time: **1381.49 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### Operation sub-steps (`tracked_job_wall`)

| Step            | Avg (s) | Runs | Total (s) |
| --------------- | ------- | ---- | --------- |
| c2ab_chunk_fold | 19.21   | 3    | 57.63     |
| c3a_fold        | 73.76   | 3    | 221.27    |
| c3ab_fold       | 7.94    | 3    | 23.82     |
| c3b_fold        | 74.19   | 3    | 222.58    |
| c4ab_fold       | 8.05    | 3    | 24.16     |
| node_fold       | 18.83   | 3    | 56.50     |
| batches         | 12.17   | 6    | 73.03     |
| chunks          | 1.90    | 6    | 11.42     |
| finalize        | 8.29    | 6    | 49.73     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 1.52    | 1    | 1.52      |
| ZkDecryptionAggregation      | 40.26   | 1    | 40.26     |
| ZkDkgAggregation             | 4.22    | 1    | 4.22      |
| ZkNodeDkgFold                | 109.02  | 3    | 327.07    |
| ZkPkAggregation              | 0.36    | 1    | 0.36      |

Sum of aggregation job tracked time: **373.44 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10688         | 448                   |
| decryption_aggregator | 10688         | 3648                  |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with
`crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without
re-running the integration test.

| File                                                  |
| ----------------------------------------------------- |
| `dkg_esm_share_computation_chunk_default.json`        |
| `dkg_pk_default.json`                                 |
| `dkg_share_decryption_default.json`                   |
| `dkg_share_encryption_default.json`                   |
| `dkg_sk_share_computation_chunk_default.json`         |
| `threshold_decrypted_shares_aggregation_default.json` |
| `threshold_pk_aggregation_default.json`               |
| `threshold_pk_generation_default.json`                |
| `threshold_share_decryption_default.json`             |
| `threshold_user_data_encryption_ct0_default.json`     |
| `threshold_user_data_encryption_ct1_default.json`     |

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is
  effectively 0.
