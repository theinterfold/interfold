# Interfold ZK Circuit Benchmarks

**Generated:** 2026-08-07 19:05:18 UTC

**Git Branch:** `chunk-circuits`  
**Git Commit:** `e2611551c0f851e8df337e1262acef05fbf44053`

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
| C0                   | 287727      | 1.09      | 11.89       | 14.31      |
| C1                   | 2226972     | 6.35      | 11.05       | 14.31      |
| C2a chunk (SK)       | 274757      | 1.00      | 11.27       | 14.31      |
| C2b chunk (ESM)      | 364915      | 1.23      | 11.27       | 14.31      |
| C3a                  | 3478343     | 9.52      | 11.03       | 14.31      |
| C3b                  | 3478343     | 9.52      | 11.03       | 14.31      |
| C4a                  | 2447701     | 6.90      | 10.90       | 14.31      |
| C4b                  | 2447701     | 6.90      | 10.90       | 14.31      |
| C5                   | 1426371     | 4.37      | 10.87       | 14.31      |
| user_data_encryption | 1688639     | 5.01      | 11.14       | 14.31      |
| C6                   | 2977228     | 8.43      | 10.87       | 14.31      |
| C7                   | 191201      | 0.69      | 11.25       | 14.31      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.44 KB   | 0.72 KB           | 3148405    | 178104       | 3326509   |
| Π_user   | 14.31 KB   | 0.12 KB           | 2982202    | 200736       | 3182938   |
| Π_dec    | 10.44 KB   | 3.84 KB           | 3761800    | 190556       | 3952356   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration  | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | --------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 5600.88 s | 114.50 KB  | 117.75 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 421.45 s  | 10.44 KB   | 11.16 KB  |
| User            | P3    | per user input                            | isolated_nargo | 9.25 s    | 14.31 KB   | 14.44 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 8.43 s    | 14.31 KB   | 14.50 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 323.35 s  | 10.44 KB   | 14.28 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 92.01 s   | 10.44 KB   | 14.28 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **46.68 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 1.90         |
| Committee Setup Completed                                          | `wall_clock` | 16.09        |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 421.45       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 5600.88      |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 5601.39      |
| Application CT Gen                                                 | `wall_clock` | 0.29         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 92.01        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 323.35       |
| Entire Test                                                        | `wall_clock` | 5943.03      |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.05    | 9    | 0.45      |
| CalculateDecryptionShare      | 0.17    | 9    | 1.54      |
| CalculateThresholdDecryption  | 0.20    | 1    | 0.20      |
| GenEsiSss                     | 26.14   | 9    | 235.25    |
| GenPkShareAndSkSss            | 0.85    | 9    | 7.67      |
| NodeDkgFold/c2ab_chunk_fold   | 27.32   | 9    | 245.90    |
| NodeDkgFold/c3a_fold          | 669.10  | 9    | 6021.94   |
| NodeDkgFold/c3ab_fold         | 14.24   | 9    | 128.17    |
| NodeDkgFold/c3b_fold          | 630.65  | 9    | 5675.87   |
| NodeDkgFold/c4ab_fold         | 13.14   | 9    | 118.24    |
| NodeDkgFold/node_fold         | 28.51   | 9    | 256.57    |
| ZkDecryptedSharesAggregation  | 5.08    | 1    | 5.08      |
| ZkDecryptionAggregation       | 86.68   | 1    | 86.68     |
| ZkDkgAggregation              | 4.35    | 1    | 4.35      |
| ZkDkgShareDecryption          | 63.42   | 18   | 1141.53   |
| ZkNodeDkgFold                 | 904.27  | 9    | 8138.40   |
| ZkNodesFoldStep               | 3.90    | 5    | 19.49     |
| ZkPkAggregation               | 42.33   | 1    | 42.33     |
| ZkPkBfv                       | 6.99    | 9    | 62.93     |
| ZkPkGeneration                | 75.44   | 9    | 678.93    |
| ZkShareComputation            | 256.58  | 18   | 4618.44   |
| ZkShareComputation/batches    | 129.37  | 18   | 2328.65   |
| ZkShareComputation/chunks     | 91.63   | 18   | 1649.37   |
| ZkShareComputation/finalize   | 34.06   | 18   | 613.05    |
| ZkShareEncryption             | 110.23  | 432  | 47621.30  |
| ZkThresholdShareDecryption    | 188.83  | 9    | 1699.45   |
| ZkVerifyShareDecryptionProofs | 0.25    | 9    | 2.22      |
| ZkVerifyShareProofs           | 0.80    | 11   | 8.79      |

Sum of tracked job wall time: **81412.80 s** — **not** end-to-end latency (jobs run in parallel up
to `BENCHMARK_MULTITHREAD_JOBS`).

### Operation sub-steps (`tracked_job_wall`)

| Step            | Avg (s) | Runs | Total (s) |
| --------------- | ------- | ---- | --------- |
| c2ab_chunk_fold | 27.32   | 9    | 245.90    |
| c3a_fold        | 669.10  | 9    | 6021.94   |
| c3ab_fold       | 14.24   | 9    | 128.17    |
| c3b_fold        | 630.65  | 9    | 5675.87   |
| c4ab_fold       | 13.14   | 9    | 118.24    |
| node_fold       | 28.51   | 9    | 256.57    |
| batches         | 129.37  | 18   | 2328.65   |
| chunks          | 91.63   | 18   | 1649.37   |
| finalize        | 34.06   | 18   | 613.05    |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 5.08    | 1    | 5.08      |
| ZkDecryptionAggregation      | 86.68   | 1    | 86.68     |
| ZkDkgAggregation             | 4.35    | 1    | 4.35      |
| ZkNodeDkgFold                | 904.27  | 9    | 8138.40   |
| ZkPkAggregation              | 42.33   | 1    | 42.33     |

Sum of aggregation job tracked time: **8276.84 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10688         | 736                   |
| decryption_aggregator | 10688         | 3936                  |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with
`crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without
re-running the integration test.

| File                                                  |
| ----------------------------------------------------- |
| `config_default.json`                                 |
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
