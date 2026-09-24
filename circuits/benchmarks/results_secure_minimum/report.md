# Interfold ZK Circuit Benchmarks

**Generated:** 2026-09-23 21:45:38 UTC

**Git Branch:** `fix/fhe_new_extended` **Git Commit:** `e63fc5ed06939be67af5a1a25a79c76acc482ccb`

**Committee Size:** `H=5`, `N=9`, `T=4`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting                                               | Value                                        |
| ----------------------------------------------------- | -------------------------------------------- |
| Benchmark mode                                        | `secure`                                     |
| BFV preset (artifacts)                                | `secure-8192`                                |
| BFV preset (enum)                                     | `SecureThreshold8192`                        |
| λ (smudging / error)                                  | 45                                           |
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
| Secure config        | 17          | 0.04      | 13.31       | 14.31       |
| C0                   | 287727      | 1.05      | 12.74       | 14.31       |
| C1                   | 2223159     | 6.11      | 12.13       | 14.31       |
| C2a                  | 1446311     | 4.05      | 12.31       | 14.31       |
| C2b                  | 2888964     | 7.49      | 12.28       | 14.31       |
| C3a                  | 3512283     | 9.43      | 11.98       | 14.31       |
| C3b                  | 3512283     | 9.43      | 11.98       | 14.31       |
| C4a                  | 1746030     | 4.68      | 12.59       | 14.31       |
| C4b                  | 1746030     | 4.68      | 12.59       | 14.31       |
| C5                   | 754560      | 2.41      | 12.24       | 14.31       |
| user_data_encryption | 3076350     | 9.03      | 25.09       | 28.62       |
| C6                   | 3001812     | 8.26      | 12.50       | 14.31       |
| C7                   | 108461      | 0.43      | 12.72       | 14.31       |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.44 KiB  | 0.38 KiB          | 3125230    | 173600       | 3298830   |
| Π_user   | N/A        | N/A               | 3034226    | N/A          | N/A       |
| Π_dec    | 10.44 KiB  | 3.56 KiB          | 3716652    | 186932       | 3903584   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth  |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | ---------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 496.03 s | 114.50 KiB | 115.88 KiB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 32.56 s  | 10.44 KiB  | 10.81 KiB  |
| User            | P3    | per user input                            | isolated_nargo | 9.03 s   | 28.62 KiB  | 28.84 KiB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 8.26 s   | 14.31 KiB  | 14.50 KiB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 123.13 s | 10.44 KiB  | 14.00 KiB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 44.52 s  | 10.44 KiB  | 14.00 KiB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **13.65 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 0.88         |
| Committee Setup Completed                                          | `wall_clock` | 7.03         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 32.56        |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 496.03       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 496.53       |
| Application CT Gen                                                 | `wall_clock` | 0.20         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 44.52        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 123.13       |
| Entire Test                                                        | `wall_clock` | 627.79       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.03    | 3    | 0.10      |
| CalculateDecryptionShare      | 0.23    | 3    | 0.69      |
| CalculateThresholdDecryption  | 0.21    | 1    | 0.21      |
| GenEsiSss                     | 0.06    | 3    | 0.17      |
| GenPkShareAndSkSss            | 0.08    | 3    | 0.25      |
| NodeDkgFold/c2ab_fold         | 10.26   | 3    | 30.78     |
| NodeDkgFold/c3a_fold          | 56.52   | 3    | 169.56    |
| NodeDkgFold/c3ab_fold         | 5.14    | 3    | 15.43     |
| NodeDkgFold/c3b_fold          | 56.58   | 3    | 169.74    |
| NodeDkgFold/c4ab_fold         | 5.25    | 3    | 15.74     |
| NodeDkgFold/node_fold         | 11.40   | 3    | 34.19     |
| ZkDecryptedSharesAggregation  | 2.97    | 1    | 2.97      |
| ZkDecryptionAggregation       | 41.54   | 1    | 41.54     |
| ZkDkgAggregation              | 7.70    | 1    | 7.70      |
| ZkDkgShareDecryption          | 8.94    | 6    | 53.66     |
| ZkNodeDkgFold                 | 78.63   | 3    | 235.88    |
| ZkNodesFoldStep               | 9.45    | 2    | 18.91     |
| ZkPkAggregation               | 5.95    | 1    | 5.95      |
| ZkPkBfv                       | 1.68    | 3    | 5.04      |
| ZkPkGeneration                | 11.08   | 3    | 33.23     |
| ZkShareComputation            | 9.76    | 6    | 58.58     |
| ZkShareEncryption             | 16.36   | 36   | 588.79    |
| ZkThresholdShareDecryption    | 47.58   | 3    | 142.73    |
| ZkVerifyShareDecryptionProofs | 0.03    | 3    | 0.08      |
| ZkVerifyShareProofs           | 0.12    | 5    | 0.58      |

Sum of tracked job wall time: **1632.51 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 10.26   | 3    | 30.78     |
| c3a_fold  | 56.52   | 3    | 169.56    |
| c3ab_fold | 5.14    | 3    | 15.43     |
| c3b_fold  | 56.58   | 3    | 169.74    |
| c4ab_fold | 5.25    | 3    | 15.74     |
| node_fold | 11.40   | 3    | 34.19     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 2.97    | 1    | 2.97      |
| ZkDecryptionAggregation      | 41.54   | 1    | 41.54     |
| ZkDkgAggregation             | 7.70    | 1    | 7.70      |
| ZkNodeDkgFold                | 78.63   | 3    | 235.88    |
| ZkPkAggregation              | 5.95    | 1    | 5.95      |

Sum of aggregation job tracked time: **294.05 s** (parallel CPU work; not P1/P2 wall clock).

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
| `config_default.json`                                 |
| `dkg_e_sm_share_computation_default.json`             |
| `dkg_esm_share_computation_chunk_default.json`        |
| `dkg_pk_default.json`                                 |
| `dkg_share_decryption_default.json`                   |
| `dkg_share_encryption_default.json`                   |
| `dkg_sk_share_computation_chunk_default.json`         |
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
