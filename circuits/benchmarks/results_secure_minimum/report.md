# Interfold ZK Circuit Benchmarks

**Generated:** 2026-06-11 11:21:27 UTC

**Git Branch:** `update/committee`  
**Git Commit:** `876ab64e1921c6e109fd9551435afe8f12b8c546`

**Committee Size:** `H=2`, `N=3`, `T=1`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting                                               | Value                                        |
| ----------------------------------------------------- | -------------------------------------------- |
| Benchmark mode                                        | `secure`                                     |
| BFV preset (artifacts)                                | `secure-8192`                                |
| BFV preset (enum)                                     | `SecureThreshold8192`                        |
| λ (smudging / error)                                  | 50                                           |
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
| C0                   | 287764      | 1.44      | 26.23       | 15.88      |
| C1                   | 2223151     | 9.08      | 26.70       | 15.88      |
| C2a                  | 1446348     | 5.16      | 29.68       | 15.88      |
| C2b                  | 2889001     | 9.65      | 26.32       | 15.88      |
| C3a                  | 3475239     | 10.80     | 26.51       | 15.88      |
| C3b                  | 3475239     | 10.80     | 26.51       | 15.88      |
| C4a                  | 1746067     | 5.48      | 25.81       | 15.88      |
| C4b                  | 1746067     | 5.48      | 25.81       | 15.88      |
| C5                   | 754597      | 2.88      | 26.86       | 15.88      |
| user_data_encryption | 1688676     | 5.78      | 25.85       | 15.88      |
| C6                   | 2977263     | 10.26     | 26.40       | 15.88      |
| C7                   | 109424      | 0.50      | 26.41       | 15.88      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.69 KB   | 0.38 KB           | 3119554    | 175080       | 3294634   |
| Π_user   | 15.88 KB   | 0.12 KB           | 2972808    | 193240       | 3166048   |
| Π_dec    | 10.69 KB   | 3.47 KB           | 3640997    | 187272       | 3828269   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 591.11 s | 127.00 KB  | 128.38 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 150.01 s | 10.69 KB   | 11.06 KB  |
| User            | P3    | per user input                            | isolated_nargo | 11.00 s  | 15.88 KB   | 16.00 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 10.26 s  | 15.88 KB   | 16.00 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 145.38 s | 10.69 KB   | 14.16 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 49.25 s  | 10.69 KB   | 14.16 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **19.62 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 1.01         |
| Committee Setup Completed                                          | `wall_clock` | 7.03         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 150.01       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 591.11       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 591.62       |
| Application CT Gen                                                 | `wall_clock` | 0.28         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 49.25        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 145.38       |
| Entire Test                                                        | `wall_clock` | 745.33       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.03    | 3    | 0.10      |
| CalculateDecryptionShare      | 0.16    | 3    | 0.49      |
| CalculateThresholdDecryption  | 0.16    | 1    | 0.16      |
| GenEsiSss                     | 0.09    | 3    | 0.26      |
| GenPkShareAndSkSss            | 0.10    | 3    | 0.30      |
| NodeDkgFold/c2ab_fold         | 15.96   | 3    | 47.88     |
| NodeDkgFold/c3a_fold          | 93.87   | 3    | 281.60    |
| NodeDkgFold/c3ab_fold         | 5.20    | 3    | 15.60     |
| NodeDkgFold/c3b_fold          | 93.12   | 3    | 279.35    |
| NodeDkgFold/c4ab_fold         | 5.40    | 3    | 16.21     |
| NodeDkgFold/node_fold         | 12.26   | 3    | 36.77     |
| ZkDecryptedSharesAggregation  | 2.74    | 1    | 2.74      |
| ZkDecryptionAggregation       | 46.41   | 1    | 46.41     |
| ZkDkgAggregation              | 5.36    | 1    | 5.36      |
| ZkDkgShareDecryption          | 26.99   | 6    | 161.95    |
| ZkNodeDkgFold                 | 131.50  | 3    | 394.49    |
| ZkNodesFoldStep               | 5.03    | 2    | 10.05     |
| ZkPkAggregation               | 14.27   | 1    | 14.27     |
| ZkPkBfv                       | 3.48    | 3    | 10.45     |
| ZkPkGeneration                | 111.12  | 3    | 333.35    |
| ZkShareComputation            | 46.70   | 6    | 280.22    |
| ZkShareEncryption             | 114.19  | 36   | 4110.81   |
| ZkThresholdShareDecryption    | 94.55   | 3    | 283.65    |
| ZkVerifyShareDecryptionProofs | 0.08    | 3    | 0.25      |
| ZkVerifyShareProofs           | 0.68    | 5    | 3.41      |

Sum of tracked job wall time: **6336.15 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 15.96   | 3    | 47.88     |
| c3a_fold  | 93.87   | 3    | 281.60    |
| c3ab_fold | 5.20    | 3    | 15.60     |
| c3b_fold  | 93.12   | 3    | 279.35    |
| c4ab_fold | 5.40    | 3    | 16.21     |
| node_fold | 12.26   | 3    | 36.77     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 2.74    | 1    | 2.74      |
| ZkDecryptionAggregation      | 46.41   | 1    | 46.41     |
| ZkDkgAggregation             | 5.36    | 1    | 5.36      |
| ZkNodeDkgFold                | 131.50  | 3    | 394.49    |
| ZkPkAggregation              | 14.27   | 1    | 14.27     |

Sum of aggregation job tracked time: **463.26 s** (parallel CPU work; not P1/P2 wall clock).

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
| `config_default.json`                                 |
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
