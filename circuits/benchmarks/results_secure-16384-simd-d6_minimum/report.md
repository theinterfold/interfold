# Circuit and protocol benchmarks

## Run configuration

### Saved benchmark settings

| Setting | Saved value |
|---|---|
| arch | aarch64 |
| bb_binary | /Users/ctrlc03/.bb/bb |
| bb_version | 6.0.0 |
| benchmark_mode | secure |
| bfv_preset_subdir | secure-16384-simd-d6 |
| committee | minimum |
| committee_size_h | 2 |
| committee_size_n | 3 |
| committee_threshold_t | 1 |
| git_branch | feat/lbfv-secure-16384-simd-d6 |
| git_commit | dd37e44842ac4e8cf6560758f646bee36b560db3 |
| git_dirty | true |
| logical_cpus | 11 |
| multithread_jobs | 1 |
| os | macos |
| proof_aggregation | false |
| runner_sha256 | 8a6b8235238061f5b3b5a7c8f13803d5212f7cd44367fe668776bc786d0221c2 |
| rust_build_profile | optimized |
| rust_noir_version | 1.0.0-rc.3 |
| schema_version | 2 |
| timestamp | 2026-10-28T15:08:02.508986+00:00 |
| variant | recursive |
| verbose | false |

### Artifact source stamp

| Setting | Saved value |
|---|---|
| builtAt | 2026-10-28T10:55:06.229Z |
| committee | minimum |
| preset | secure-16384-simd-d6 |
| sourceHash | 8fae21ea9e3a8ed4 |

## Measurement methodology

| Metric | Meaning |
|---|---|
| production_input_preparation_wall | Production computation and ABI input conversion; sample/config setup excluded |
| production_abi_input_projection_wall | Per-leg ABI projection after shared UDE preparation |
| production_encryption_and_preparation_wall | One UDE encryption and prepared witness, shared by both legs |
| production_noir_execution_wall | ABI encoding, ACVM execution, and witness serialization in Rust |
| production_bb_adapter_wall | Production BB adapter, including process startup and file I/O |
| external_bb_prove_wall / external_bb_verify_wall | BB process wall time for development circuits without CircuitName |
| isolated_nargo | Historical isolated shell/Nargo measurements, not in-process Rust execution |
| wall_clock | Integration event/phase span in the in-process test harness, not WAN latency |
| tracked_job_wall | Shared Rayon job wall time; overlapping sums are not end-to-end latency |

Sample generation, configuration construction, and artifact loading are outside leaf phase timers. Missing measurements are N/A, not false zero. Legacy zero compilation durations can represent reused artifacts. Compare host, build profile, preset, committee, variant, source and tool identities before comparing runs.

## Leaf phases

| Circuit | Prove metric | Preparation (s) | Compile (s) | Noir/execute (s) | VK generation (s) | Prove (s) | Verify (s) | Status |
|---|---|---:|---:|---:|---:|---:|---:|---|
| config | external_bb_prove_wall | N/A | N/A | N/A | N/A | N/A | N/A | failed |

config: Config reuse has no artifact-specific provenance; compile the selected config case explicitly with --bench-compile (and --bench-vk for proofs): No such file or directory (os error 2)

| dkg/esm_share_computation_chunk | production_bb_adapter_wall | 0.438780 | N/A | 6.822144 | N/A | 33.725189 | 0.169406 | verified |
| dkg/pk | production_bb_adapter_wall | 0.052282 | N/A | 1.372705 | N/A | 7.407967 | 0.106833 | verified |
| dkg/sk_share_computation_chunk | production_bb_adapter_wall | 0.161983 | N/A | 3.629863 | N/A | 22.847808 | 0.114762 | verified |
| threshold/decrypted_shares_aggregation_wide | production_bb_adapter_wall | 0.001301 | N/A | 0.349487 | N/A | 0.696649 | 0.178604 | verified |
| threshold/lbfv_pk_aggregation | production_bb_adapter_wall | 0.330014 | N/A | 7.936198 | N/A | 20.438987 | 0.173655 | verified |
| threshold/lbfv_pk_generation | production_bb_adapter_wall | 1.818097 | N/A | 5.350627 | N/A | 27.454517 | 0.162262 | verified |
| threshold/rlk_aggregation | production_bb_adapter_wall | 0.320925 | N/A | 7.511086 | N/A | 21.556849 | 0.171776 | verified |
| threshold/rlk_generation | production_bb_adapter_wall | 0.616486 | N/A | 11.378977 | N/A | 48.361523 | 0.166987 | verified |
| threshold/share_decryption | production_bb_adapter_wall | 1.382172 | N/A | 11.497932 | N/A | 60.338833 | 0.177327 | verified |

### Canonical pair build (measured once)

| Setting | Saved value |
|---|---|
| metric | canonical_build_command_wall |
| success | N/A |
| time_seconds | N/A |

### Shared preparation (count once)

| Group | Metric | Duration (s) | Success |
|---|---|---:|---|

## Leaf constraints and sizes

| Circuit | Gates | Circuit bytes | Witness bytes | VK bytes | Proof bytes | Public-input bytes | Calldata gas |
|---|---:|---:|---:|---:|---:|---:|---:|
| config | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| dkg/esm_share_computation_chunk | 4927720 | 26522329 | 18452421 | 3680 | 14656 | 832 | 211472 |
| dkg/pk | 991310 | 3909877 | 3635023 | 3680 | 14656 | 32 | 198708 |
| dkg/sk_share_computation_chunk | 3065578 | 17038383 | 9381764 | 3680 | 14656 | 832 | 210992 |
| threshold/decrypted_shares_aggregation_wide | 147764 | 1763055 | 277079 | 3680 | 14656 | 1728 | 206884 |
| threshold/lbfv_pk_aggregation | 3970758 | 16635898 | 17144442 | 3680 | 14656 | 288 | 202060 |
| threshold/lbfv_pk_generation | 4614755 | 21960285 | 21533245 | 3680 | 14656 | 192 | 200944 |
| threshold/rlk_aggregation | 3970668 | 16639355 | 17144581 | 3680 | 14656 | 320 | 201792 |
| threshold/rlk_generation | 9257697 | 46020545 | 53895301 | 3680 | 14656 | 256 | 202064 |
| threshold/share_decryption | 9608886 | 35170624 | 50241077 | 3680 | 14656 | 192 | 200848 |

## On-chain artifacts

| Artifact | Proof bytes | Public-input bytes | Verifier gas | Calldata gas | Total gas |
|---|---:|---:|---:|---:|---:|
| Π_DKG | N/A | N/A | N/A | N/A | N/A |
| Π_user | N/A | N/A | N/A | N/A | N/A |
| Π_dec | N/A | N/A | N/A | N/A | N/A |

Verifier gas: incomplete (3 missing). Calldata-only values do not establish measured verifier gas.

## Role / phase / activity

| Role | Phase | Activity | Metric | Duration (s) | Proof bytes | Proof + public-input bytes |
|---|---|---|---|---:|---:|---:|
| Each ciphernode | P1 | DKG participation in the test harness | wall_clock | N/A | N/A | N/A |
| Aggregator | P2 | C5 and DKG aggregation | wall_clock | N/A | N/A | N/A |
| Aggregator | P4 | Publish ciphertext through plaintext aggregation | wall_clock | N/A | N/A | N/A |
| Aggregator | P4 | C7 and fold after pending aggregation | wall_clock | N/A | N/A | N/A |
| Each ciphernode | P4 | C6 leaf proof, not a deployment estimate | production_bb_adapter_wall | 60.338833 | 14656 | 14848 |

Integration timing: incomplete (no saved summary).

## Artifact provenance

| Circuit | Compiled SHA-256 | VK SHA-256 | Artifact source |
|---|---|---|---|
| config | N/A | N/A | N/A |
| dkg/esm_share_computation_chunk | 46022af6b26aed1b1d30afad76d5634941beb4c071f210f0104cd439994500c3 | 5cf3a7e470b63c0c49fb5eebd7f69c966e49af55e2095efb76da56d9979a19c6 | 8fae21ea9e3a8ed4 |
| dkg/pk | 9895d40dc77c6bc22921f18a4c86b48bf5e995aa3c09205e99e98c453230e22c | 519c8342f66b01c4336ccb27f2e7eeaf06ccc44db1cbb73433f393dc3cb3835b | 8fae21ea9e3a8ed4 |
| dkg/sk_share_computation_chunk | b06db3d6b7cb1c681c1f399c9c7ddefbd7b1d8b579e96dc6e0f8c37696b9dc07 | 4aafa4162a3ec0ba7342b64cbdedfbfe2e136690bb706b0f41c44a25608c5164 | 8fae21ea9e3a8ed4 |
| threshold/decrypted_shares_aggregation_wide | cefe3562a22381493ae038523e09a87b2af4d349d7b4a95a85ac2bd6fd2b24bf | c766900c8c7762215c20c9aefa54b9bbff5437c83f0a5d0ef5db0917bdecb43e | 8fae21ea9e3a8ed4 |
| threshold/lbfv_pk_aggregation | e18aaaab0c4664b46b86efee7ec0f9d882256ead4214fdabaf85d4c493ac7150 | ef8e989f1e06f8a2c141e48161ccfb6bfb8ce2ad0e66d60e229165a6c9159373 | 8fae21ea9e3a8ed4 |
| threshold/lbfv_pk_generation | ef1121d0072fbdc2e4c960b7f1cfe637583818f0c9081bf24d40c638223efca8 | a3f1ced34a2f4bc3e8d08c301c908798f90429b78c5e7364d8b118f693b14cb4 | 8fae21ea9e3a8ed4 |
| threshold/rlk_aggregation | 6cba164b03a13608333dd50ea026eff6a3e14a05214846909cde102eb0e35aea | 8741f0586123ac4d04fcc46f1e5088b591e08bd77864eb6df31e82d946003e1f | 8fae21ea9e3a8ed4 |
| threshold/rlk_generation | c8059324c6a56b8ee48eaf050f8e6df7fe4bf94721049e2b5f14c8b5dd3f2377 | f19d1ce67e10b4e4f03789769b80eeea8e8885ee03c317e7df3a0f5a48bdd92f | 8fae21ea9e3a8ed4 |
| threshold/share_decryption | b65babf87ea03e2fb82b982cf633d25f8cc90ad0830dbd58ecfe7dd79ebc2171 | b1db7d9ccd1454350396b7b4ae50df4ac1df27950721b28e776a8a57fd473ca3 | 8fae21ea9e3a8ed4 |

## Saved raw records

- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/config_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/dkg_esm_share_computation_chunk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/dkg_pk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/dkg_sk_share_computation_chunk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/threshold_decrypted_shares_aggregation_wide_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/threshold_lbfv_pk_aggregation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/threshold_lbfv_pk_generation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/threshold_rlk_aggregation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/threshold_rlk_generation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd-d6/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd-d6_minimum/raw/threshold_share_decryption_default.json`
