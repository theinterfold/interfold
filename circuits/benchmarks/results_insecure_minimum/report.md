# Interfold ZK Circuit Benchmarks

**Generated:** 2026-09-23 08:36:00 UTC

**Git Branch:** `lbfv/wiring`<br>
**Git Commit:** `26dc5cda4cbbd52fa7d48595cc9b916f88c101fb`

**Committee Size:** `H=2`, `N=3`, `T=1`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting | Value |
|---------|-------|
| Benchmark mode | `insecure` |
| BFV preset (artifacts) | `insecure` |
| BFV preset (enum) | `InsecureThreshold512` |
| λ (smudging / error) | 2 |
| Nodes spawned (builder) | 7 |
| Network model | `in_process_bus` |
| Testmode harness | true |
| `proof_aggregation_enabled` | true |
| `BENCHMARK_MULTITHREAD_JOBS` (max concurrent ZK jobs) | 13 |
| Rayon worker threads | 12 |
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
| C0 | 8333 | 0.10 | 11.85 | 14.31 |
| C1 | 44603 | 0.25 | 12.47 | 14.31 |
| l-BFV PK generation limb | 21700 | 0.16 | 13.43 | 14.31 |
| l-BFV PK aggregation row | 27087 | 0.18 | 12.80 | 14.31 |
| RLK generation limb | 52001 | 0.26 | 11.91 | 14.31 |
| RLK aggregation row | 49935 | 0.25 | 11.82 | 14.31 |
| C2a | 27813 | 0.19 | 11.63 | 14.31 |
| C2b | 53022 | 0.28 | 12.18 | 14.31 |
| C3a | 63403 | 0.32 | 12.59 | 14.31 |
| C3b | 63403 | 0.32 | 12.59 | 14.31 |
| C4a | 33515 | 0.20 | 12.02 | 14.31 |
| C4b | 33515 | 0.20 | 12.02 | 14.31 |
| C5 | 17002 | 0.14 | 14.33 | 14.31 |
| user_data_encryption | 2855313 | 7.79 | 24.84 | 28.62 |
| C6 | 66660 | 0.33 | 12.58 | 14.31 |
| C7 | 162376 | 0.57 | 12.83 | 14.31 |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
|----------|------------|-------------------|------------|--------------|-----------|
| Π_DKG | 10.81 KiB | 1.81 KiB | 3399196 | 201976 | 3601172 |
| Π_user | 10.44 KiB | 0.28 KiB | 3034070 | 169508 | 3203578 |
| Π_dec | 10.44 KiB | 3.56 KiB | 3716737 | 187016 | 3903753 |

### Role / Phase / Activity

| Role | Phase | Activity | Metric | Duration | Proof size | Bandwidth |
|------|-------|----------|--------|----------|------------|-----------|
| Each ciphernode | P1 | one-time DKG participation (test harness) | wall_clock | 281.99 s | 114.50 KiB | 116.06 KiB |
| Aggregator | P2 | C5 + Π_DKG fold (aggregator span) | wall_clock | 178.83 s | 10.81 KiB | 12.62 KiB |
| User | P3 | per user input | isolated_nargo | 7.79 s | 10.44 KiB | 10.72 KiB |
| Each ciphernode | P4 | per computation output (C6) | isolated_nargo | 0.33 s | 14.31 KiB | 14.50 KiB |
| Aggregator | P4 | C7 + Π_dec fold (full publish→aggregate) | wall_clock | 42.16 s | 10.44 KiB | 14.00 KiB |
| Aggregator | P4 | C7 + fold only (pending→plaintext span) | wall_clock | 39.93 s | 10.44 KiB | 14.00 KiB |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **6.58 s** — not comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase | Metric | Duration (s) |
|-------|--------|---------------|
| Starting trbfv actor test | `wall_clock` | 0.00 |
| Setup completed | `wall_clock` | 0.90 |
| Committee Setup Completed | `wall_clock` | 7.02 |
| Committee Finalization Complete | `wall_clock` | 0.00 |
| Aggregator P2: PkAggregation pending -> LbfvPublicKeyAggregated (wall) | `wall_clock` | 178.83 |
| ThresholdShares -> LbfvPublicKeyAggregated | `wall_clock` | 281.99 |
| E3Request -> LbfvPublicKeyAggregated | `wall_clock` | 282.49 |
| Application CT Gen | `wall_clock` | 0.03 |
| Running FHE Application | `wall_clock` | 0.00 |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall) | `wall_clock` | 39.93 |
| Ciphertext published -> PlaintextAggregated | `wall_clock` | 42.16 |
| Entire Test | `wall_clock` | 332.60 |

### Multithread job timings (`tracked_job_wall`)

| Name | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| CalculateDecryptionKey | 0.01 | 3 | 0.02 |
| CalculateDecryptionShare | 0.03 | 3 | 0.09 |
| CalculateThresholdDecryption | 0.03 | 1 | 0.03 |
| GenEsiSss | 0.01 | 3 | 0.02 |
| GenLbfvKeyShares | 0.01 | 3 | 0.03 |
| GenPkShareAndSkSss | 0.01 | 3 | 0.03 |
| NodeDkgFold/c2ab_chunk_fold | 18.37 | 3 | 55.12 |
| NodeDkgFold/c3a_fold | 92.21 | 3 | 276.63 |
| NodeDkgFold/c3ab_fold | 7.01 | 3 | 21.02 |
| NodeDkgFold/c3b_fold | 91.68 | 3 | 275.04 |
| NodeDkgFold/c4ab_fold | 6.90 | 3 | 20.69 |
| NodeDkgFold/node_fold | 16.30 | 3 | 48.91 |
| ZkDecryptedSharesAggregation | 2.38 | 1 | 2.38 |
| ZkDecryptionAggregation | 37.55 | 1 | 37.55 |
| ZkDkgAggregationV2 | 5.92 | 1 | 5.92 |
| ZkDkgShareDecryption | 1.10 | 6 | 6.60 |
| ZkLbfvAggregationFold | 13.01 | 3 | 39.02 |
| ZkLbfvGenerationFold | 12.01 | 9 | 108.13 |
| ZkLbfvPkAggregation | 0.96 | 3 | 2.88 |
| ZkLbfvPkGeneration | 48.75 | 9 | 438.73 |
| ZkNodeDkgFold | 122.43 | 3 | 367.28 |
| ZkNodeDkgFoldV2 | 9.67 | 3 | 29.02 |
| ZkNodesFoldV2Step | 2.53 | 2 | 5.06 |
| ZkPkAggregation | 0.66 | 1 | 0.66 |
| ZkPkBfv | 0.19 | 3 | 0.57 |
| ZkPkGeneration | 31.29 | 3 | 93.88 |
| ZkRlkAggregation | 1.21 | 3 | 3.62 |
| ZkRlkGeneration | 51.01 | 9 | 459.10 |
| ZkShareComputation | 31.58 | 6 | 189.49 |
| ZkShareEncryption | 2.41 | 36 | 86.68 |
| ZkThresholdShareDecryption | 2.04 | 3 | 6.11 |
| ZkVerifyShareDecryptionProofs | 0.04 | 3 | 0.13 |
| ZkVerifyShareProofs | 0.23 | 5 | 1.14 |

Sum of tracked job wall time: **2581.56 s** — **not** end-to-end latency (jobs run in parallel up to `BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| c2ab_chunk_fold | 18.37 | 3 | 55.12 |
| c3a_fold | 92.21 | 3 | 276.63 |
| c3ab_fold | 7.01 | 3 | 21.02 |
| c3b_fold | 91.68 | 3 | 275.04 |
| c4ab_fold | 6.90 | 3 | 20.69 |
| node_fold | 16.30 | 3 | 48.91 |

### Aggregation jobs (`tracked_job_wall`)

| Operation | Avg (s) | Runs | Total (s) |
|-----------|---------|------|-----------|
| ZkDecryptedSharesAggregation | 2.38 | 1 | 2.38 |
| ZkDecryptionAggregation | 37.55 | 1 | 37.55 |
| ZkNodeDkgFold | 122.43 | 3 | 367.28 |
| ZkPkAggregation | 0.66 | 1 | 0.66 |

Sum of aggregation job tracked time: **407.86 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact | Proof (bytes) | Public inputs (bytes) |
|----------|---------------|------------------------|
| dkg_aggregator | 11072 | 1856 |
| decryption_aggregator | 10688 | 3648 |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with `crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without re-running the integration test.

| File |
|------|
| `dkg_e_sm_share_computation_default.json` |
| `dkg_esm_share_computation_chunk_default.json` |
| `dkg_pk_default.json` |
| `dkg_share_decryption_default.json` |
| `dkg_share_encryption_default.json` |
| `dkg_sk_share_computation_chunk_default.json` |
| `dkg_sk_share_computation_default.json` |
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
