# Interfold ZK Circuit Benchmarks

**Generated:** 2026-09-23 16:24:42 UTC

**Git Branch:** `fix/fhe_new_extended` **Git Commit:** `fb5f14198c6ec812b23020079024695043fa6ee5`

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
| Π_DKG    | 10.44 KiB  | 0.38 KiB          | 3125132    | 173504       | 3298636   |
| Π_user   | 14.31 KiB  | 0.12 KiB          | 3034238    | 200568       | 3234806   |
| Π_dec    | 10.44 KiB  | 3.56 KiB          | 3716786    | 187076       | 3903862   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration | Proof size | Bandwidth  |
| --------------- | ----- | ----------------------------------------- | -------------- | -------- | ---------- | ---------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 116.70 s | 114.50 KiB | 115.69 KiB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 29.23 s  | 10.44 KiB  | 10.81 KiB  |
| User            | P3    | per user input                            | isolated_nargo | 0.55 s   | 14.31 KiB  | 14.44 KiB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 0.40 s   | 14.31 KiB  | 14.50 KiB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 55.32 s  | 10.44 KiB  | 14.00 KiB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 47.05 s  | 10.44 KiB  | 14.00 KiB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **8.02 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 0.84         |
| Committee Setup Completed                                          | `wall_clock` | 7.02         |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 29.23        |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 116.70       |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 117.20       |
| Application CT Gen                                                 | `wall_clock` | 0.00         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 47.05        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 55.32        |
| Entire Test                                                        | `wall_clock` | 180.39       |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.00    | 3    | 0.01      |
| CalculateDecryptionShare      | 0.02    | 3    | 0.07      |
| CalculateThresholdDecryption  | 0.06    | 1    | 0.06      |
| GenEsiSss                     | 0.01    | 3    | 0.02      |
| GenPkShareAndSkSss            | 0.01    | 3    | 0.03      |
| NodeDkgFold/c2ab_fold         | 11.59   | 3    | 34.76     |
| NodeDkgFold/c3a_fold          | 43.48   | 3    | 130.45    |
| NodeDkgFold/c3ab_fold         | 5.22    | 3    | 15.65     |
| NodeDkgFold/c3b_fold          | 43.18   | 3    | 129.53    |
| NodeDkgFold/c4ab_fold         | 6.13    | 3    | 18.40     |
| NodeDkgFold/node_fold         | 13.14   | 3    | 39.42     |
| ZkDecryptedSharesAggregation  | 1.96    | 1    | 1.96      |
| ZkDecryptionAggregation       | 45.07   | 1    | 45.07     |
| ZkDkgAggregation              | 7.84    | 1    | 7.84      |
| ZkDkgShareDecryption          | 0.49    | 6    | 2.93      |
| ZkNodeDkgFold                 | 68.00   | 3    | 203.99    |
| ZkNodesFoldStep               | 10.60   | 2    | 21.20     |
| ZkPkAggregation               | 0.18    | 1    | 0.18      |
| ZkPkBfv                       | 0.15    | 3    | 0.45      |
| ZkPkGeneration                | 0.48    | 3    | 1.44      |
| ZkShareComputation            | 0.47    | 6    | 2.85      |
| ZkShareEncryption             | 0.78    | 24   | 18.78     |
| ZkThresholdShareDecryption    | 2.65    | 3    | 7.94      |
| ZkVerifyShareDecryptionProofs | 0.03    | 3    | 0.08      |
| ZkVerifyShareProofs           | 0.11    | 5    | 0.56      |

Sum of tracked job wall time: **683.67 s** — **not** end-to-end latency (jobs run in parallel up to
`BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 11.59   | 3    | 34.76     |
| c3a_fold  | 43.48   | 3    | 130.45    |
| c3ab_fold | 5.22    | 3    | 15.65     |
| c3b_fold  | 43.18   | 3    | 129.53    |
| c4ab_fold | 6.13    | 3    | 18.40     |
| node_fold | 13.14   | 3    | 39.42     |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 1.96    | 1    | 1.96      |
| ZkDecryptionAggregation      | 45.07   | 1    | 45.07     |
| ZkDkgAggregation             | 7.84    | 1    | 7.84      |
| ZkNodeDkgFold                | 68.00   | 3    | 203.99    |
| ZkPkAggregation              | 0.18    | 1    | 0.18      |

Sum of aggregation job tracked time: **259.05 s** (parallel CPU work; not P1/P2 wall clock).

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
