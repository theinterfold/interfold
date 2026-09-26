# Interfold ZK Circuit Benchmarks

**Generated:** 2026-09-23 12:34:30 UTC

**Git Branch:** `lbfv/wiring`<br>
**Git Commit:** `1b7bb6360ff27ae3a8468cba7f8b0985e7d90c45`

**Committee Size:** `H=2`, `N=3`, `T=1`

## Run configuration

Settings for this benchmark run (integration test + Nargo circuit benches on the same host).

### Integration test (`test_trbfv_actor`)

| Setting | Value |
|---------|-------|
| Benchmark mode | `secure` |
| BFV preset (artifacts) | `secure-8192` |
| BFV preset (enum) | `SecureThreshold8192` |
| λ (smudging / error) | 45 |
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
| C0 | 429773 | 1.40 | 11.46 | 14.31 |
| C1 | 2786787 | 7.29 | 12.60 | 14.31 |
| l-BFV PK generation limb | N/A | N/A | N/A | N/A |
| l-BFV PK aggregation row | N/A | N/A | N/A | N/A |
| RLK generation limb | N/A | N/A | N/A | N/A |
| RLK aggregation row | N/A | N/A | N/A | N/A |
| C2a | 115355 | 0.45 | 11.69 | 14.31 |
| C2b | 216952 | 0.75 | 11.45 | 14.31 |
| C3a | 4220602 | 10.93 | 11.98 | 14.31 |
| C3b | 4220602 | 10.93 | 11.98 | 14.31 |
| C4a | 2065372 | 5.38 | 11.82 | 14.31 |
| C4b | 2065372 | 5.38 | 11.82 | 14.31 |
| C5 | 1067904 | 3.18 | 12.07 | 14.31 |
| user_data_encryption | 2921203 | 7.86 | 24.50 | 28.62 |
| C6 | 3850947 | 10.05 | 12.43 | 14.31 |
| C7 | 163779 | 0.57 | 12.58 | 14.31 |

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
|----------|------------|-------------------|------------|--------------|-----------|
| Π_DKG | 10.44 KiB | 0.94 KiB | 3204168 | 182828 | 3386996 |
| Π_user | 10.44 KiB | 0.28 KiB | 3034202 | 169640 | 3203842 |
| Π_dec | 10.44 KiB | 3.56 KiB | 3716823 | 187100 | 3903923 |

### Role / Phase / Activity

| Role | Phase | Activity | Metric | Duration | Proof size | Bandwidth |
|------|-------|----------|--------|----------|------------|-----------|
| Each ciphernode | P1 | one-time DKG participation (test harness) | wall_clock | 692.85 s | 114.50 KiB | 116.06 KiB |
| Aggregator | P2 | C5 + Π_DKG fold (aggregator span) | wall_clock | 142.32 s | 10.44 KiB | 11.38 KiB |
| User | P3 | per user input | isolated_nargo | 7.86 s | 10.44 KiB | 10.72 KiB |
| Each ciphernode | P4 | per computation output (C6) | isolated_nargo | 10.05 s | 14.31 KiB | 14.50 KiB |
| Aggregator | P4 | C7 + Π_dec fold (full publish→aggregate) | wall_clock | 140.15 s | 10.44 KiB | 14.00 KiB |
| Aggregator | P4 | C7 + fold only (pending→plaintext span) | wall_clock | 41.69 s | 10.44 KiB | 14.00 KiB |

_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **27.20 s** — not comparable to P2 wall_clock row above._

## Integration test (`test_trbfv_actor`)

### End-to-end phase timings (integration test)

| Phase | Metric | Duration (s) |
|-------|--------|---------------|
| Starting trbfv actor test | `wall_clock` | 0.00 |
| Setup completed | `wall_clock` | 0.93 |
| Committee Setup Completed | `wall_clock` | 7.03 |
| Committee Finalization Complete | `wall_clock` | 0.00 |
| Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall) | `wall_clock` | 142.32 |
| ThresholdShares -> PublicKeyAggregated | `wall_clock` | 692.85 |
| E3Request -> PublicKeyAggregated | `wall_clock` | 693.36 |
| Application CT Gen | `wall_clock` | 0.27 |
| Running FHE Application | `wall_clock` | 0.00 |
| Aggregator P4: Aggregation pending -> PlaintextAggregated (wall) | `wall_clock` | 41.69 |
| Ciphertext published -> PlaintextAggregated | `wall_clock` | 140.15 |
| Entire Test | `wall_clock` | 841.74 |

### Multithread job timings (`tracked_job_wall`)

| Name | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| CalculateDecryptionKey | 0.03 | 3 | 0.10 |
| CalculateDecryptionShare | 0.17 | 3 | 0.52 |
| CalculateThresholdDecryption | 0.14 | 1 | 0.14 |
| GenEsiSss | 0.04 | 3 | 0.11 |
| GenPkShareAndSkSss | 0.06 | 3 | 0.19 |
| NodeDkgFold/c2ab_chunk_fold | 19.33 | 3 | 58.00 |
| NodeDkgFold/c3a_fold | 97.15 | 3 | 291.45 |
| NodeDkgFold/c3ab_fold | 7.24 | 3 | 21.71 |
| NodeDkgFold/c3b_fold | 97.46 | 3 | 292.39 |
| NodeDkgFold/c4ab_fold | 7.35 | 3 | 22.05 |
| NodeDkgFold/node_fold | 17.27 | 3 | 51.80 |
| ZkDecryptedSharesAggregation | 2.99 | 1 | 2.99 |
| ZkDecryptionAggregation | 38.69 | 1 | 38.69 |
| ZkDkgAggregation | 4.02 | 1 | 4.02 |
| ZkDkgShareDecryption | 24.76 | 6 | 148.55 |
| ZkNodeDkgFold | 129.32 | 3 | 387.96 |
| ZkNodesFoldStep | 4.36 | 2 | 8.72 |
| ZkPkAggregation | 23.18 | 1 | 23.18 |
| ZkPkBfv | 3.56 | 3 | 10.68 |
| ZkPkGeneration | 158.24 | 3 | 474.71 |
| ZkShareComputation | 254.10 | 6 | 1524.61 |
| ZkShareEncryption | 103.51 | 36 | 3726.37 |
| ZkThresholdShareDecryption | 97.69 | 3 | 293.08 |
| ZkVerifyShareDecryptionProofs | 0.03 | 3 | 0.09 |
| ZkVerifyShareProofs | 0.11 | 5 | 0.55 |

Sum of tracked job wall time: **7382.68 s** — **not** end-to-end latency (jobs run in parallel up to `BENCHMARK_MULTITHREAD_JOBS`).

### NodeDkgFold sub-steps (`tracked_job_wall`, per fold prove)

| Step | Avg (s) | Runs | Total (s) |
|------|---------|------|-----------|
| c2ab_chunk_fold | 19.33 | 3 | 58.00 |
| c3a_fold | 97.15 | 3 | 291.45 |
| c3ab_fold | 7.24 | 3 | 21.71 |
| c3b_fold | 97.46 | 3 | 292.39 |
| c4ab_fold | 7.35 | 3 | 22.05 |
| node_fold | 17.27 | 3 | 51.80 |

### Aggregation jobs (`tracked_job_wall`)

| Operation | Avg (s) | Runs | Total (s) |
|-----------|---------|------|-----------|
| ZkDecryptedSharesAggregation | 2.99 | 1 | 2.99 |
| ZkDecryptionAggregation | 38.69 | 1 | 38.69 |
| ZkDkgAggregation | 4.02 | 1 | 4.02 |
| ZkNodeDkgFold | 129.32 | 3 | 387.96 |
| ZkPkAggregation | 23.18 | 1 | 23.18 |

Sum of aggregation job tracked time: **456.85 s** (parallel CPU work; not P1/P2 wall clock).

### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)

| Artifact | Proof (bytes) | Public inputs (bytes) |
|----------|---------------|------------------------|
| dkg_aggregator | 10688 | 960 |
| decryption_aggregator | 10688 | 3648 |

## Raw circuit benchmark JSON (Nargo)

Source files for the **Circuit Benchmarks** table. Persist this directory with `crisp_verify_gas.json` (and optional `integration_summary.json`) to regenerate the report without re-running the integration test.

| File |
|------|
| `config_default.json` |
| `dkg_e_sm_share_computation_default.json` |
| `dkg_esm_share_computation_chunk_default.json` |
| `dkg_pk_default.json` |
| `dkg_share_decryption_default.json` |
| `dkg_share_encryption_default.json` |
| `dkg_sk_share_computation_chunk_default.json` |
| `dkg_sk_share_computation_default.json` |
| `threshold_decrypted_shares_aggregation_default.json` |
| `threshold_pk_aggregation_default.json` |
| `threshold_pk_generation_default.json` |
| `threshold_share_decryption_default.json` |
| `threshold_user_data_encryption_ct0_default.json` |
| `threshold_user_data_encryption_ct1_default.json` |

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is effectively 0.
