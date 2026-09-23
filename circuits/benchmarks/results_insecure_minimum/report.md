# Interfold ZK Circuit Benchmarks

**Generated:** 2026-09-23 19:22:29 UTC

**Git Branch:** `fix/fhe_new_extended` **Git Commit:** `99fae96fc524a67fb3a86b124873361b10146920`

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
| `BENCHMARK_MULTITHREAD_JOBS` (max concurrent ZK jobs) | 2                                            |
| Rayon worker threads                                  | 12                                           |
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

| Circuit              | Constraints | Prove (s) | Verify (ms) | Proof (KiB) |
| -------------------- | ----------- | --------- | ----------- | ----------- |
| C0                   | 6810        | 0.11      | 12.98       | 14.31       |
| C1                   | 55145       | 0.30      | 12.74       | 14.31       |
| C2a                  | 27813       | 0.19      | 11.63       | 14.31       |
| C2b                  | 81029       | 0.36      | 12.59       | 14.31       |
| C3a                  | 116879      | 0.49      | 13.23       | 14.31       |
| C3b                  | 116879      | 0.49      | 13.23       | 14.31       |
| C4a                  | 62713       | 0.30      | 12.98       | 14.31       |
| C4b                  | 62713       | 0.30      | 12.98       | 14.31       |
| C5                   | 21464       | 0.17      | 12.79       | 14.31       |
| user_data_encryption | 53158       | 0.29      | 13.34       | 14.31       |
| C6                   | 86892       | 0.40      | 13.23       | 14.31       |
| C7                   | 89602       | 0.38      | 13.87       | 14.31       |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.44 KiB  | 0.38 KiB          | 3125145    | 173516       | 3298661   |
| Π_user   | 14.31 KiB  | 0.12 KiB          | 3034178    | 200568       | 3234746   |
| Π_dec    | 10.44 KiB  | 3.56 KiB          | 3716640    | 186920       | 3903560   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth  |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | ---------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 105.22 s | 114.50 KiB | 115.69 KiB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 25.28 s  | 10.44 KiB  | 10.81 KiB  |
| User            | P3    | per user input                            | isolated_nargo | 0.55 s   | 14.31 KiB  | 14.44 KiB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 0.40 s   | 14.31 KiB  | 14.50 KiB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 51.35 s  | 10.44 KiB  | 14.00 KiB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 43.67 s  | 10.44 KiB  | 14.00 KiB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **7.92 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 0.92         |
| Committee Setup Completed                                          | `wall_clock` | 7.10         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 25.28        |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 105.22       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 105.72       |
| Application CT Gen                                                 | `wall_clock` | 0.01         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 43.67        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 51.35        |
| Entire Test                                                        | `wall_clock` | 165.10       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.00    | 3    | 0.01      |
| CalculateDecryptionShare      | 0.02    | 3    | 0.07      |
| CalculateThresholdDecryption  | 0.03    | 1    | 0.03      |
| GenEsiSss                     | 0.01    | 3    | 0.02      |
| GenPkShareAndSkSss            | 0.01    | 3    | 0.03      |
| NodeDkgFold/c2ab_fold         | 9.97    | 3    | 29.90     |
| NodeDkgFold/c3a_fold          | 39.26   | 3    | 117.77    |
| NodeDkgFold/c3ab_fold         | 4.65    | 3    | 13.96     |
| NodeDkgFold/c3b_fold          | 39.48   | 3    | 118.44    |
| NodeDkgFold/c4ab_fold         | 4.83    | 3    | 14.50     |
| NodeDkgFold/node_fold         | 11.89   | 3    | 35.68     |
| ZkDecryptedSharesAggregation  | 1.76    | 1    | 1.76      |
| ZkDecryptionAggregation       | 41.91   | 1    | 41.91     |
| ZkDkgAggregation              | 7.43    | 1    | 7.43      |
| ZkDkgShareDecryption          | 0.51    | 6    | 3.05      |
| ZkNodeDkgFold                 | 60.86   | 3    | 182.59    |
| ZkNodesFoldStep               | 8.67    | 2    | 17.34     |
| ZkPkAggregation               | 0.49    | 1    | 0.49      |
| ZkPkBfv                       | 0.16    | 3    | 0.47      |
| ZkPkGeneration                | 0.46    | 3    | 1.38      |
| ZkShareComputation            | 0.48    | 6    | 2.85      |
| ZkShareEncryption             | 0.75    | 24   | 17.99     |
| ZkThresholdShareDecryption    | 2.49    | 3    | 7.46      |
| ZkVerifyShareDecryptionProofs | 0.06    | 3    | 0.17      |
| ZkVerifyShareProofs           | 0.09    | 5    | 0.43      |

Sum of tracked job wall time: **615.74 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 9.97    | 3    | 29.90     |
| c3a_fold  | 39.26   | 3    | 117.77    |
| c3ab_fold | 4.65    | 3    | 13.96     |
| c3b_fold  | 39.48   | 3    | 118.44    |
| c4ab_fold | 4.83    | 3    | 14.50     |
| node_fold | 11.89   | 3    | 35.68     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 1.76    | 1    | 1.76      |
| ZkDecryptionAggregation      | 41.91   | 1    | 41.91     |
| ZkDkgAggregation             | 7.43    | 1    | 7.43      |
| ZkNodeDkgFold                | 60.86   | 3    | 182.59    |
| ZkPkAggregation              | 0.49    | 1    | 0.49      |

Sum of aggregation job tracked time: **234.18 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10688         | 384                   |
| decryption_aggregator | 10688         | 3648                  |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with
`crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without
re-running the integration test.

| File                                                  |
| ----------------------------------------------------- |
| `dkg_e_sm_share_computation_default.json`             |
| `dkg_esm_share_computation_chunk_default.json`        |
| `dkg_pk_default.json`                                 |
| `dkg_share_decryption_default.json`                   |
| `dkg_share_encryption_default.json`                   |
| `dkg_sk_share_computation_chunk_default.json`         |
| `dkg_sk_share_computation_default.json`               |
| `threshold_decrypted_shares_aggregation_default.json` |
| `threshold_lbfv_pk_aggregation_default.json`          |
| `threshold_lbfv_pk_generation_limb_default.json`      |
| `threshold_pk_aggregation_default.json`               |
| `threshold_pk_generation_default.json`                |
| `threshold_rlk_aggregation_default.json`              |
| `threshold_rlk_generation_limb_default.json`          |
| `threshold_share_decryption_default.json`             |
| `threshold_user_data_encryption_ct0_default.json`     |
| `threshold_user_data_encryption_ct1_default.json`     |

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is
  effectively 0.
