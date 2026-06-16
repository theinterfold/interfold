# Interfold ZK Circuit Benchmarks

**Generated:** 2026-06-04 11:57:41 UTC

**Git Branch:** `main`  
**Git Commit:** `334123af5e1f043fd91d5b4928c461bda17951e4`

**Committee Size:** `H=3`, `N=3`, `T=1`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting                                               | Value                                        |
| ----------------------------------------------------- | -------------------------------------------- |
| Benchmark mode                                        | `secure`                                     |
| BFV preset (artifacts)                                | `secure-8192`                                |
| BFV preset (enum)                                     | `SecureThreshold8192`                        |
| λ (smudging / error)                                  | 50                                           |
| Nodes spawned (builder)                               | 20                                           |
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
(`network_model: in_process_bus`); sortition registers extra nodes; `testmode_*` enabled. Compare
runs only with the same `benchmark_mode`, proof-aggregation flag, `BENCHMARK_MULTITHREAD_JOBS`,
commit, and hardware.

---

## Protocol Summary

### Circuit Benchmarks (isolated Nargo + Barretenberg)

Single-circuit `bb prove` on the benchmark oracle witness (not the integration actor pipeline).

| Circuit              | Constraints | Prove (s) | Verify (ms) | Proof (KB) |
| -------------------- | ----------- | --------- | ----------- | ---------- |
| C0                   | 287764      | 1.42      | 27.90       | 15.88      |
| C1                   | 2430707     | 9.34      | 25.96       | 15.88      |
| C2a                  | 1446348     | 5.13      | 24.04       | 15.88      |
| C2b                  | 2889001     | 9.68      | 24.89       | 15.88      |
| C3a                  | 3475239     | 10.75     | 24.47       | 15.88      |
| C3b                  | 3475239     | 10.75     | 24.47       | 15.88      |
| C4a                  | 1961956     | 5.82      | 24.93       | 15.88      |
| C4b                  | 1961956     | 5.82      | 24.93       | 15.88      |
| C5                   | 3719555     | 10.89     | 25.11       | 15.88      |
| user_data_encryption | 1688676     | 5.75      | 25.31       | 15.88      |
| C6                   | 2977263     | 10.22     | 25.89       | 15.88      |
| C7                   | 109424      | 0.51      | 26.84       | 15.88      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.69 KB   | 0.47 KB           | 3125343    | 176196       | 3301539   |
| Π_user   | 15.88 KB   | 0.12 KB           | 2972977    | 193336       | 3166313   |
| Π_dec    | 10.69 KB   | 3.47 KB           | 3640899    | 187176       | 3828075   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 603.10 s | 127.00 KB  | 128.56 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 163.13 s | 10.69 KB   | 11.16 KB  |
| User            | P3    | per user input                            | isolated_nargo | 11.01 s  | 15.88 KB   | 16.00 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 10.22 s  | 15.88 KB   | 16.00 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 176.86 s | 10.69 KB   | 14.16 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 50.75 s  | 10.69 KB   | 14.16 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **44.37 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 2.98         |
| Committee Setup Completed                                          | `wall_clock` | 20.09        |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 163.13       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 603.10       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 603.69       |
| Application CT Gen                                                 | `wall_clock` | 0.30         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 50.75        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 176.86       |
| Entire Test                                                        | `wall_clock` | 803.94       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.06    | 3    | 0.18      |
| CalculateDecryptionShare      | 0.17    | 3    | 0.50      |
| CalculateThresholdDecryption  | 0.24    | 1    | 0.24      |
| GenEsiSss                     | 0.06    | 3    | 0.19      |
| GenPkShareAndSkSss            | 0.11    | 3    | 0.33      |
| NodeDkgFold/c2ab_fold         | 7.29    | 3    | 21.86     |
| NodeDkgFold/c3a_fold          | 59.07   | 3    | 177.22    |
| NodeDkgFold/c3ab_fold         | 7.22    | 3    | 21.66     |
| NodeDkgFold/c3b_fold          | 49.74   | 3    | 149.22    |
| NodeDkgFold/c4ab_fold         | 8.28    | 3    | 24.83     |
| NodeDkgFold/node_fold         | 14.94   | 3    | 44.83     |
| ZkDecryptedSharesAggregation  | 2.79    | 1    | 2.79      |
| ZkDecryptionAggregation       | 47.82   | 1    | 47.82     |
| ZkDkgAggregation              | 19.61   | 1    | 19.61     |
| ZkDkgShareDecryption          | 23.11   | 6    | 138.65    |
| ZkNodeDkgFold                 | 146.54  | 3    | 439.63    |
| ZkPkAggregation               | 24.75   | 1    | 24.75     |
| ZkPkBfv                       | 3.83    | 3    | 11.48     |
| ZkPkGeneration                | 54.05   | 3    | 162.15    |
| ZkShareComputation            | 51.34   | 6    | 308.06    |
| ZkShareEncryption             | 119.19  | 36   | 4290.86   |
| ZkThresholdShareDecryption    | 91.27   | 3    | 273.80    |
| ZkVerifyShareDecryptionProofs | 0.12    | 3    | 0.36      |
| ZkVerifyShareProofs           | 0.32    | 5    | 1.59      |

Sum of tracked job wall time: **6162.60 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 7.29    | 3    | 21.86     |
| c3a_fold  | 59.07   | 3    | 177.22    |
| c3ab_fold | 7.22    | 3    | 21.66     |
| c3b_fold  | 49.74   | 3    | 149.22    |
| c4ab_fold | 8.28    | 3    | 24.83     |
| node_fold | 14.94   | 3    | 44.83     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 2.79    | 1    | 2.79      |
| ZkDecryptionAggregation      | 47.82   | 1    | 47.82     |
| ZkDkgAggregation             | 19.61   | 1    | 19.61     |
| ZkNodeDkgFold                | 146.54  | 3    | 439.63    |
| ZkPkAggregation              | 24.75   | 1    | 24.75     |

Sum of aggregation job tracked time: **534.60 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10944         | 480                   |
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
