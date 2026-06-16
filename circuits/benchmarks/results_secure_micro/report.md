# Interfold ZK Circuit Benchmarks

**Generated:** 2026-06-13 18:13:56 UTC

**Git Branch:** `lock/fhers`  
**Git Commit:** `c2dfd37d36d9e85b45b03db03bc7267964a4a6da`

**Committee Size:** `H=5`, `N=9`, `T=4`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting                                               | Value                                        |
| ----------------------------------------------------- | -------------------------------------------- |
| Benchmark mode                                        | `secure`                                     |
| BFV preset (artifacts)                                | `secure-8192`                                |
| BFV preset (enum)                                     | `SecureThreshold8192`                        |
| λ (smudging / error)                                  | 50                                           |
| Nodes spawned (builder)                               | 16                                           |
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
(`network_model: in_process_bus`); sortition registers extra nodes; `testmode_*` enabled; proof
aggregation always enabled. Compare runs only with the same `benchmark_mode`, committee,
`BENCHMARK_MULTITHREAD_JOBS`, commit, and hardware.

---

## Protocol Summary

### Circuit Benchmarks (isolated Nargo + Barretenberg)

Single-circuit `bb prove` on the benchmark oracle witness (not the integration actor pipeline).

| Circuit              | Constraints | Prove (s) | Verify (ms) | Proof (KB) |
| -------------------- | ----------- | --------- | ----------- | ---------- |
| C0                   | 287764      | 1.52      | 27.60       | 15.88      |
| C1                   | 2223151     | 8.98      | 25.48       | 15.88      |
| C2a                  | 4283826     | 17.92     | 24.61       | 15.88      |
| C2b                  | 5726479     | 19.99     | 25.41       | 15.88      |
| C3a                  | 3475239     | 10.76     | 25.48       | 15.88      |
| C3b                  | 3475239     | 10.76     | 25.48       | 15.88      |
| C4a                  | 2418310     | 9.17      | 24.96       | 15.88      |
| C4b                  | 2418310     | 9.17      | 24.96       | 15.88      |
| C5                   | 1426408     | 5.27      | 25.33       | 15.88      |
| user_data_encryption | 1688676     | 5.71      | 24.50       | 15.88      |
| C6                   | 2977263     | 10.14     | 25.04       | 15.88      |
| C7                   | 191104      | 0.81      | 25.24       | 15.88      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.69 KB   | 0.66 KB           | 3136910    | 178440       | 3315350   |
| Π_user   | 15.88 KB   | 0.12 KB           | 2972965    | 193180       | 3166145   |
| Π_dec    | 10.69 KB   | 3.75 KB           | 3658366    | 190656       | 3849022   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration  | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | --------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 5251.56 s | 127.00 KB  | 130.06 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 406.98 s  | 10.69 KB   | 11.34 KB  |
| User            | P3    | per user input                            | isolated_nargo | 10.96 s   | 15.88 KB   | 16.00 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 10.14 s   | 15.88 KB   | 16.00 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 334.20 s  | 10.69 KB   | 14.44 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 103.52 s  | 10.69 KB   | 14.44 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **36.62 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 2.39         |
| Committee Setup Completed                                          | `wall_clock` | 16.09        |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 406.98       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 5251.56      |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 5252.07      |
| Application CT Gen                                                 | `wall_clock` | 0.29         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 103.52       |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 334.20       |
| Entire Test                                                        | `wall_clock` | 5605.04      |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.04    | 9    | 0.38      |
| CalculateDecryptionShare      | 0.17    | 9    | 1.53      |
| CalculateThresholdDecryption  | 0.19    | 1    | 0.19      |
| GenEsiSss                     | 0.52    | 9    | 4.66      |
| GenPkShareAndSkSss            | 0.52    | 9    | 4.68      |
| NodeDkgFold/c2ab_fold         | 28.56   | 9    | 257.08    |
| NodeDkgFold/c3a_fold          | 665.75  | 9    | 5991.76   |
| NodeDkgFold/c3ab_fold         | 13.68   | 9    | 123.10    |
| NodeDkgFold/c3b_fold          | 627.04  | 9    | 5643.40   |
| NodeDkgFold/c4ab_fold         | 12.85   | 9    | 115.66    |
| NodeDkgFold/node_fold         | 29.34   | 9    | 264.02    |
| ZkDecryptedSharesAggregation  | 5.93    | 1    | 5.93      |
| ZkDecryptionAggregation       | 97.37   | 1    | 97.37     |
| ZkDkgAggregation              | 5.38    | 1    | 5.38      |
| ZkDkgShareDecryption          | 76.34   | 18   | 1374.12   |
| ZkNodeDkgFold                 | 904.33  | 9    | 8138.93   |
| ZkNodesFoldStep               | 4.39    | 5    | 21.96     |
| ZkPkAggregation               | 31.24   | 1    | 31.24     |
| ZkPkBfv                       | 9.47    | 9    | 85.24     |
| ZkPkGeneration                | 87.11   | 9    | 784.00    |
| ZkShareComputation            | 94.84   | 18   | 1707.15   |
| ZkShareEncryption             | 105.64  | 432  | 45636.03  |
| ZkThresholdShareDecryption    | 187.47  | 9    | 1687.22   |
| ZkVerifyShareDecryptionProofs | 0.58    | 9    | 5.25      |
| ZkVerifyShareProofs           | 2.36    | 11   | 25.99     |

Sum of tracked job wall time: **72012.25 s** — **not** end-to-end latency (jobs run in parallel up
to `BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 28.56   | 9    | 257.08    |
| c3a_fold  | 665.75  | 9    | 5991.76   |
| c3ab_fold | 13.68   | 9    | 123.10    |
| c3b_fold  | 627.04  | 9    | 5643.40   |
| c4ab_fold | 12.85   | 9    | 115.66    |
| node_fold | 29.34   | 9    | 264.02    |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 5.93    | 1    | 5.93      |
| ZkDecryptionAggregation      | 97.37   | 1    | 97.37     |
| ZkDkgAggregation             | 5.38    | 1    | 5.38      |
| ZkNodeDkgFold                | 904.33  | 9    | 8138.93   |
| ZkPkAggregation              | 31.24   | 1    | 31.24     |

Sum of aggregation job tracked time: **8278.85 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10944         | 672                   |
| decryption_aggregator | 10944         | 3840                  |

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
