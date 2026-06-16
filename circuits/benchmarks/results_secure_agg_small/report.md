# Interfold ZK Circuit Benchmarks

**Generated:** 2026-05-27 18:28:14 UTC

**Git Branch:** `params/dyn-conf`  
**Git Commit:** `de480d631ab48f652be8ca1c8c136a80262c0c19`

**Committee Size:** `H=5`, `N=5`, `T=2`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting                                               | Value                                        |
| ----------------------------------------------------- | -------------------------------------------- |
| Benchmark mode                                        | `secure`                                     |
| BFV preset (artifacts)                                | `secure-8192`                                |
| BFV preset (enum)                                     | `SecureThreshold8192`                        |
| λ (smudging / error)                                  | 60                                           |
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
| C0                   | 287764      | 1.42      | 25.93       | 15.88      |
| C1                   | 2432074     | 9.16      | 25.45       | 15.88      |
| C2a                  | 2424942     | 9.17      | 24.93       | 15.88      |
| C2b                  | 3867595     | 10.90     | 24.73       | 15.88      |
| C3a                  | 3563512     | 10.76     | 25.30       | 15.88      |
| C3b                  | 3563512     | 10.76     | 25.30       | 15.88      |
| C4a                  | 2418310     | 9.14      | 25.53       | 15.88      |
| C4b                  | 2418310     | 9.14      | 25.53       | 15.88      |
| C5                   | 4656265     | 18.41     | 25.33       | 15.88      |
| user_data_encryption | 1678200     | 5.59      | 25.44       | 15.88      |
| C6                   | 3001847     | 10.18     | 25.04       | 15.88      |
| C7                   | 136374      | 0.74      | 24.68       | 15.88      |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
| -------- | ---------- | ----------------- | ---------- | ------------ | --------- |
| Π_DKG    | 10.69 KB   | 0.66 KB           | 3136885    | 178428       | 3315313   |
| Π_user   | 15.88 KB   | 0.12 KB           | 2972977    | 193300       | 3166277   |
| Π_dec    | 10.69 KB   | 3.56 KB           | 3646908    | 188532       | 3835440   |

### Role / Phase / Activity

| Role            | Phase | Activity                                  | Metric         | Duration  | Proof size | Bandwidth |
| --------------- | ----- | ----------------------------------------- | -------------- | --------- | ---------- | --------- |
| Each ciphernode | P1    | one-time DKG participation (test harness) | wall_clock     | 1669.47 s | 127.00 KB  | 129.31 KB |
| Aggregator      | P2    | C5 + Π_DKG fold (aggregator span)         | wall_clock     | 400.03 s  | 10.69 KB   | 11.34 KB  |
| User            | P3    | per user input                            | isolated_nargo | 10.75 s   | 15.88 KB   | 16.00 KB  |
| Each ciphernode | P4    | per computation output (C6)               | isolated_nargo | 10.18 s   | 15.88 KB   | 16.00 KB  |
| Aggregator      | P4    | C7 + Π_dec fold (full publish→aggregate)  | wall_clock     | 205.70 s  | 10.69 KB   | 14.25 KB  |
| Aggregator      | P4    | C7 + fold only (pending→plaintext span)   | wall_clock     | 64.51 s   | 10.69 KB   | 14.25 KB  |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **77.28 s** — not
comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase                                                              | Metric       | Duration (s) |
| ------------------------------------------------------------------ | ------------ | ------------ |
| Starting trbfv actor test                                          | `wall_clock` | 0.00         |
| Setup completed                                                    | `wall_clock` | 2.82         |
| Committee Setup Completed                                          | `wall_clock` | 20.13        |
| Committee Finalization Complete                                    | `wall_clock` | 0.00         |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 400.03       |
| ThresholdShares -> PublicKeyAggregated                             | `wall_clock` | 1669.47      |
| E3Request -> PublicKeyAggregated                                   | `wall_clock` | 1670.00      |
| Application CT Gen                                                 | `wall_clock` | 0.30         |
| Running FHE Application                                            | `wall_clock` | 0.00         |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)   | `wall_clock` | 64.51        |
| Ciphertext published -> PlaintextAggregated                        | `wall_clock` | 205.70       |
| Entire Test                                                        | `wall_clock` | 1898.95      |

### Multithread job timings (`tracked_job_wall`)

| Name                          | Avg (s) | Runs | Total (s) |
| ----------------------------- | ------- | ---- | --------- |
| CalculateDecryptionKey        | 0.06    | 5    | 0.30      |
| CalculateDecryptionShare      | 0.16    | 5    | 0.80      |
| CalculateThresholdDecryption  | 0.23    | 1    | 0.23      |
| GenEsiSss                     | 0.16    | 5    | 0.78      |
| GenPkShareAndSkSss            | 0.31    | 5    | 1.57      |
| NodeDkgFold/c2ab_fold         | 11.85   | 5    | 59.24     |
| NodeDkgFold/c3a_fold          | 169.18  | 5    | 845.92    |
| NodeDkgFold/c3ab_fold         | 12.82   | 5    | 64.09     |
| NodeDkgFold/c3b_fold          | 151.49  | 5    | 757.46    |
| NodeDkgFold/c4ab_fold         | 10.85   | 5    | 54.24     |
| NodeDkgFold/node_fold         | 23.96   | 5    | 119.78    |
| ZkDecryptedSharesAggregation  | 3.33    | 1    | 3.33      |
| ZkDecryptionAggregation       | 60.96   | 1    | 60.96     |
| ZkDkgAggregation              | 28.09   | 1    | 28.09     |
| ZkDkgShareDecryption          | 61.25   | 10   | 612.53    |
| ZkNodeDkgFold                 | 380.15  | 5    | 1900.77   |
| ZkPkAggregation               | 49.19   | 1    | 49.19     |
| ZkPkBfv                       | 5.47    | 5    | 27.33     |
| ZkPkGeneration                | 67.43   | 5    | 337.16    |
| ZkShareComputation            | 50.51   | 10   | 505.06    |
| ZkShareEncryption             | 112.37  | 120  | 13484.59  |
| ZkThresholdShareDecryption    | 133.84  | 5    | 669.21    |
| ZkVerifyShareDecryptionProofs | 0.29    | 5    | 1.45      |
| ZkVerifyShareProofs           | 1.08    | 7    | 7.54      |

Sum of tracked job wall time: **19591.61 s** — **not** end-to-end latency (jobs run in parallel up
to `BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step      | Avg (s) | Runs | Total (s) |
| --------- | ------- | ---- | --------- |
| c2ab_fold | 11.85   | 5    | 59.24     |
| c3a_fold  | 169.18  | 5    | 845.92    |
| c3ab_fold | 12.82   | 5    | 64.09     |
| c3b_fold  | 151.49  | 5    | 757.46    |
| c4ab_fold | 10.85   | 5    | 54.24     |
| node_fold | 23.96   | 5    | 119.78    |

### Aggregation jobs (`tracked_job_wall`)

| Operation                    | Avg (s) | Runs | Total (s) |
| ---------------------------- | ------- | ---- | --------- |
| ZkDecryptedSharesAggregation | 3.33    | 1    | 3.33      |
| ZkDecryptionAggregation      | 60.96   | 1    | 60.96     |
| ZkDkgAggregation             | 28.09   | 1    | 28.09     |
| ZkNodeDkgFold                | 380.15  | 5    | 1900.77   |
| ZkPkAggregation              | 49.19   | 1    | 49.19     |

Sum of aggregation job tracked time: **2042.34 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact              | Proof (bytes) | Public inputs (bytes) |
| --------------------- | ------------- | --------------------- |
| dkg_aggregator        | 10944         | 672                   |
| decryption_aggregator | 10944         | 3648                  |

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
