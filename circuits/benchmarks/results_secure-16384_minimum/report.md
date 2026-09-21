# Interfold ZK Circuit Benchmarks

**Generated:** 2026-09-21 14:46:17 UTC

**Git Branch:** `bench-redrive`<br>
**Git Commit:** `91ffc386b83ae9d130d0d4bcec4983b64d7cb4c1`

**Committee Size:** `H=2`, `N=3`, `T=1`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting | Value |
|---------|-------|
| Benchmark mode | `secure` |
| BFV preset (artifacts) | `secure-16384` |
| BFV preset (enum) | `SecureThreshold16384` |
| λ (smudging / error) | 31 |
| Nodes spawned (builder) | 7 |
| Network model | `in_process_bus` |
| Testmode harness | true |
| `proof_aggregation_enabled` | true |
| `BENCHMARK_MULTITHREAD_JOBS` (max concurrent ZK jobs) | 6 |
| Rayon worker threads | 6 |
| CPU cores (host) | 14 |
| `dkg_fold_attestation_verifier` (EIP-712) | `0x7969c5eD335650692Bc04293B07F5BF2e7A673C0` |
| Verbose logging (`run_benchmarks.sh --verbose`) | true |

### Hardware & software (Nargo / Barretenberg host)

| | |
|--|--|
| **CPU** | Apple M4 Pro |
| **CPU cores** | 14 |
| **RAM** | 48.00 GB |
| **OS** | Darwin |
| **Architecture** | arm64 |
| **Nargo** | nargo version = 1.0.0-beta.26 noirc version = 1.0.0-beta.26+40d6574f851d926f93e0c3a271bac3e6e82ac905 (git version hash: 40d6574f851d926f93e0c3a271bac3e6e82ac905, is dirty: false)  |
| **Barretenberg** | 5.1.0  |

---

## Audit status

On-chain verify gas: **complete** (CRISP Π_user + Interfold Π_DKG / Π_dec replay).

---

## Measurement methodology

| Metric kind | Source | Meaning | Do **not** use for |
|-------------|--------|---------|-------------------|
| **wall_clock** | `test_trbfv_actor` phase timers / HLC event span | End-to-end wait in the in-process test harness | Production WAN latency; per-node deployment cost |
| **isolated_nargo** | `benchmark_circuit.sh` per circuit | Single `bb prove` on oracle witness, one circuit at a time | Full protocol pipeline (different witness path) |
| **tracked_job_wall** | `MultithreadReport` per `ComputeRequest` | Wall time of each job on the shared Rayon pool (≤ `BENCHMARK_MULTITHREAD_JOBS` concurrent) | End-to-end time — **sums exceed wall clock** when jobs overlap |

**Harness limits (integration):** all ciphernodes share one process and bus (`network_model: in_process_bus`); sortition registers extra nodes; `testmode_*` enabled; proof aggregation always enabled. Compare runs only with the same `benchmark_mode`, committee, `BENCHMARK_MULTITHREAD_JOBS`, commit, and hardware.

---
## Protocol Summary

### Circuit Benchmarks (isolated Nargo + Barretenberg)

Single-circuit `bb prove` on the benchmark oracle witness (not the integration actor pipeline).

| Circuit | Constraints | Prove (s) | Verify (ms) | Proof (KiB) |
|---------|-------------|-----------|-------------|------------|
| C0 | 696393 | 2.20 | 12.42 | 14.31 |
| C1 | 9576804 | 25.11 | 12.70 | 14.31 |
| l-BFV PK generation limb | 3484056 | 9.36 | 12.74 | 14.31 |
| l-BFV PK aggregation row | 5703419 | 14.80 | 14.10 | 14.31 |
| RLK generation limb | 9737770 | 25.79 | 13.11 | 14.31 |
| RLK aggregation row | 9833622 | 24.71 | 12.54 | 14.31 |
| C2a | 165715 | 0.63 | 12.92 | 14.31 |
| C2b | 343998 | 1.15 | 11.97 | 14.31 |
| C3a | 7542423 | 20.38 | 13.16 | 14.31 |
| C3b | 7542423 | 20.38 | 13.16 | 14.31 |
| C4a | 6257626 | 15.65 | 12.93 | 14.31 |
| C4b | 6257626 | 15.65 | 12.93 | 14.31 |
| C5 | 2952076 | 8.06 | 12.18 | 14.31 |
| user_data_encryption | 2960279 | 8.16 | 25.24 | 28.62 |
| C6 | 11098729 | 29.96 | 13.88 | 14.31 |
| C7 | 199088 | 0.72 | 13.56 | 14.31 |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
|----------|------------|-------------------|------------|--------------|-----------|
| Π_DKG | 10.81 KiB | 2.00 KiB | 3412476 | 205120 | 3617596 |
| Π_user | 10.44 KiB | 0.28 KiB | 3034262 | 169700 | 3203962 |
| Π_dec | 10.44 KiB | 3.56 KiB | 3716701 | 187004 | 3903705 |

### Role / Phase / Activity

| Role | Phase | Activity | Metric | Duration | Proof size | Bandwidth |
|------|-------|----------|--------|----------|------------|-----------|
| Each ciphernode | P1 | one-time DKG participation (test harness) | wall_clock | 5033.94 s | 114.50 KiB | 116.69 KiB |
| Aggregator | P2 | C5 + Π_DKG fold (aggregator span) | wall_clock | 422.37 s | 10.81 KiB | 12.81 KiB |
| User | P3 | per user input | isolated_nargo | 8.16 s | 10.44 KiB | 10.72 KiB |
| Each ciphernode | P4 | per computation output (C6) | isolated_nargo | 29.96 s | 14.31 KiB | 14.50 KiB |
| Aggregator | P4 | C7 + Π_dec fold (full publish→aggregate) | wall_clock | 382.38 s | 10.44 KiB | 14.00 KiB |
| Aggregator | P4 | C7 + fold only (pending→plaintext span) | wall_clock | 45.37 s | 10.44 KiB | 14.00 KiB |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **42.89 s** — not comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase | Metric | Duration (s) |
|-------|--------|---------------|
| Starting trbfv actor test | `wall_clock` | 0.00 |
| Setup completed | `wall_clock` | 1.00 |
| Committee Setup Completed | `wall_clock` | 7.02 |
| Committee Finalization Complete | `wall_clock` | 0.00 |
| Aggregator P2: PkAggregation pending -> LbfvPublicKeyAggregated (wall) | `wall_clock` | 422.37 |
| ThresholdShares -> LbfvPublicKeyAggregated | `wall_clock` | 5033.94 |
| E3Request -> LbfvPublicKeyAggregated | `wall_clock` | 5034.87 |
| Application CT Gen | `wall_clock` | 0.48 |
| Running FHE Application | `wall_clock` | 0.00 |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall) | `wall_clock` | 45.37 |
| Ciphertext published -> PlaintextAggregated | `wall_clock` | 382.38 |
| Entire Test | `wall_clock` | 5425.74 |

### Multithread job timings (`tracked_job_wall`)

| Name | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| CalculateDecryptionKey | 0.15 | 3 | 0.44 |
| CalculateDecryptionShare | 0.83 | 3 | 2.48 |
| CalculateThresholdDecryption | 0.72 | 1 | 0.72 |
| GenEsiSss | 0.15 | 3 | 0.46 |
| GenLbfvKeyShares | 0.50 | 3 | 1.49 |
| GenPkShareAndSkSss | 0.29 | 3 | 0.87 |
| NodeDkgFold/c2ab_chunk_fold | 13.52 | 3 | 40.55 |
| NodeDkgFold/c3a_fold | 137.81 | 3 | 413.44 |
| NodeDkgFold/c3ab_fold | 6.56 | 3 | 19.67 |
| NodeDkgFold/c3b_fold | 134.33 | 3 | 402.98 |
| NodeDkgFold/c4ab_fold | 5.11 | 3 | 15.34 |
| NodeDkgFold/node_fold | 10.45 | 3 | 31.35 |
| ZkDecryptedSharesAggregation | 5.70 | 1 | 5.70 |
| ZkDecryptionAggregation | 39.67 | 1 | 39.67 |
| ZkDkgAggregationV2 | 6.06 | 1 | 6.06 |
| ZkDkgShareDecryption | 85.52 | 6 | 513.13 |
| ZkLbfvAggregationFold | 18.00 | 5 | 90.00 |
| ZkLbfvGenerationFold | 14.34 | 15 | 215.03 |
| ZkLbfvPkAggregation | 64.78 | 5 | 323.88 |
| ZkLbfvPkGeneration | 352.34 | 15 | 5285.08 |
| ZkNodeDkgFold | 190.97 | 3 | 572.92 |
| ZkNodeDkgFoldV2 | 6.55 | 3 | 19.64 |
| ZkNodesFoldV2Step | 2.55 | 2 | 5.10 |
| ZkPkAggregation | 36.84 | 1 | 36.84 |
| ZkPkBfv | 6.24 | 3 | 18.73 |
| ZkPkGeneration | 205.51 | 3 | 616.53 |
| ZkRlkAggregation | 122.46 | 5 | 612.29 |
| ZkRlkGeneration | 676.40 | 15 | 10146.04 |
| ZkShareComputation | 318.90 | 6 | 1913.41 |
| ZkShareEncryption | 134.95 | 60 | 8097.01 |
| ZkThresholdShareDecryption | 321.42 | 3 | 964.27 |
| ZkVerifyShareDecryptionProofs | 0.03 | 3 | 0.10 |
| ZkVerifyShareProofs | 0.32 | 5 | 1.59 |

Sum of tracked job wall time: **30412.80 s** — **not** end-to-end latency (jobs run in parallel up to `BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| c2ab_chunk_fold | 13.52 | 3 | 40.55 |
| c3a_fold | 137.81 | 3 | 413.44 |
| c3ab_fold | 6.56 | 3 | 19.67 |
| c3b_fold | 134.33 | 3 | 402.98 |
| c4ab_fold | 5.11 | 3 | 15.34 |
| node_fold | 10.45 | 3 | 31.35 |

### Aggregation jobs (`tracked_job_wall`)

| Operation | Avg (s) | Runs | Total (s) |
|-----------|---------|------|-----------|
| ZkDecryptedSharesAggregation | 5.70 | 1 | 5.70 |
| ZkDecryptionAggregation | 39.67 | 1 | 39.67 |
| ZkNodeDkgFold | 190.97 | 3 | 572.92 |
| ZkPkAggregation | 36.84 | 1 | 36.84 |

Sum of aggregation job tracked time: **655.13 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact | Proof (bytes) | Public inputs (bytes) |
|----------|---------------|------------------------|
| dkg_aggregator | 11072 | 2048 |
| decryption_aggregator | 10688 | 3648 |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with `crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without re-running the integration test.

| File |
|------|
| `config_default.json` |
| `dkg_esm_share_computation_chunk_default.json` |
| `dkg_pk_default.json` |
| `dkg_share_decryption_default.json` |
| `dkg_share_encryption_default.json` |
| `dkg_sk_share_computation_chunk_default.json` |
| `threshold_decrypted_shares_aggregation_default.json` |
| `threshold_lbfv_pk_aggregation_default.json` |
| `threshold_lbfv_pk_generation_limb_default.json` |
| `threshold_pk_aggregation_default.json` |
| `threshold_pk_generation_default.json` |
| `threshold_rlk_aggregation_default.json` |
| `threshold_rlk_generation_limb_default.json` |
| `threshold_share_decryption_default.json` |
| `threshold_user_data_encryption_ct0_default.json` |
| `threshold_user_data_encryption_ct1_default.json` |

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is effectively 0.
