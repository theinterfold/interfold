# Interfold ZK Circuit Benchmarks

**Generated:** 2026-08-05 19:38:58 UTC

**Git Branch:** `nargo22`  
**Git Commit:** `2ae5713c04eecd7392441a0fa2628c0188af3a97`

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

| Circuit              | Constraints | Prove (s) | Verify (ms) | Proof (KiB) |
| -------------------- | ----------- | --------- | ----------- | ----------- |
| C0                   | 6810        | 0.14      | 15.25       | 14.31       |
| C1                   | 53448       | 0.35      | 14.75       | 14.31       |
| C2a                  | 41207       | 0.31      | 15.34       | 14.31       |
| C2b                  | 79554       | 0.46      | 15.17       | 14.31       |
| C3a                  | 120078      | 0.73      | 15.46       | 14.31       |
| C3b                  | 120078      | 0.73      | 15.46       | 14.31       |
| C4a                  | 62713       | 0.41      | 15.86       | 14.31       |
| C4b                  | 62713       | 0.41      | 15.86       | 14.31       |
| C5                   | 21464       | 0.21      | 14.59       | 14.31       |
| user_data_encryption | 53695       | 0.36      | 15.27       | 14.31       |
| C6                   | 86892       | 0.50      | 14.81       | 14.31       |
| C7                   | 89602       | 0.48      | 14.89       | 14.31       |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.44 KiB  | 0.38 KiB          | 3125084    | 173456       | 3298540   |
| Π_user   | 14.31 KiB  | 0.12 KiB          | 2982310    | 200640       | 3182950   |
| Π_dec    | 10.44 KiB  | 3.56 KiB          | 3716480    | 187004       | 3903484   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth  |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | ---------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 206.57 s | 114.50 KiB | 115.56 KiB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 189.94 s | 10.44 KiB  | 10.81 KiB  |
| User            | P3    | per user input                            | isolated_nargo | 0.69 s   | 14.31 KiB  | 14.44 KiB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 0.50 s   | 14.31 KiB  | 14.50 KiB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 58.93 s  | 10.44 KiB  | 14.00 KiB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 54.50 s  | 10.44 KiB  | 14.00 KiB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **5.97 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 0.87         |
| Committee Setup Completed                                          | `wall_clock` | 7.03         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 189.94       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 206.57       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 207.08       |
| Application CT Gen                                                 | `wall_clock` | 0.01         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 54.50        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 58.93        |
| Entire Test                                                        | `wall_clock` | 273.92       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.01    | 3    | 0.02      |
| CalculateDecryptionShare      | 0.03    | 3    | 0.09      |
| CalculateThresholdDecryption  | 0.03    | 1    | 0.03      |
| GenEsiSss                     | 0.01    | 3    | 0.03      |
| GenPkShareAndSkSss            | 0.01    | 3    | 0.04      |
| NodeDkgFold/c2ab_fold         | 31.62   | 3    | 94.87     |
| NodeDkgFold/c3a_fold          | 118.02  | 3    | 354.06    |
| NodeDkgFold/c3ab_fold         | 12.07   | 3    | 36.20     |
| NodeDkgFold/c3b_fold          | 118.28  | 3    | 354.84    |
| NodeDkgFold/c4ab_fold         | 12.19   | 3    | 36.56     |
| NodeDkgFold/node_fold         | 29.71   | 3    | 89.12     |
| ZkDecryptedSharesAggregation  | 1.94    | 1    | 1.94      |
| ZkDecryptionAggregation       | 52.54   | 1    | 52.54     |
| ZkDkgAggregation              | 5.46    | 1    | 5.46      |
| ZkDkgShareDecryption          | 1.18    | 6    | 7.10      |
| ZkNodeDkgFold                 | 172.31  | 3    | 516.94    |
| ZkNodesFoldStep               | 6.13    | 2    | 12.27     |
| ZkPkAggregation               | 0.52    | 1    | 0.52      |
| ZkPkBfv                       | 0.25    | 3    | 0.74      |
| ZkPkGeneration                | 3.11    | 3    | 9.34      |
| ZkShareComputation            | 2.98    | 6    | 17.88     |
| ZkShareEncryption             | 5.73    | 24   | 137.44    |
| ZkThresholdShareDecryption    | 4.14    | 3    | 12.43     |
| ZkVerifyShareDecryptionProofs | 0.07    | 3    | 0.21      |
| ZkVerifyShareProofs           | 0.14    | 5    | 0.70      |

Sum of tracked job wall time: **1741.37 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 31.62   | 3    | 94.87     |
| c3a_fold  | 118.02  | 3    | 354.06    |
| c3ab_fold | 12.07   | 3    | 36.20     |
| c3b_fold  | 118.28  | 3    | 354.84    |
| c4ab_fold | 12.19   | 3    | 36.56     |
| node_fold | 29.71   | 3    | 89.12     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 1.94    | 1    | 1.94      |
| ZkDecryptionAggregation      | 52.54   | 1    | 52.54     |
| ZkDkgAggregation             | 5.46    | 1    | 5.46      |
| ZkNodeDkgFold                | 172.31  | 3    | 516.94    |
| ZkPkAggregation              | 0.52    | 1    | 0.52      |

Sum of aggregation job tracked time: **577.40 s** (parallel CPU work; not P1/P2 wall clock).

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
