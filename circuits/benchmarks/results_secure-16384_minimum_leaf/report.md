# Circuit and protocol benchmarks

## Run configuration

### Saved benchmark settings

| Setting | Saved value |
|---|---|
| arch | aarch64 |
| bb_binary | /Users/ctrlc03/.bb/bb |
| bb_version | 6.0.0 |
| benchmark_mode | secure |
| bfv_preset_subdir | secure-16384 |
| committee | minimum |
| committee_size_h | 2 |
| committee_size_n | 3 |
| committee_threshold_t | 1 |
| git_branch | feat/lbfv-secure-16384-simd |
| git_commit | 4db6f1863b2417be8acc3c1704cdc3763eac3831 |
| git_dirty | true |
| logical_cpus | 11 |
| multithread_jobs | 1 |
| os | macos |
| proof_aggregation | false |
| runner_sha256 | 67c83b41fcd493aa73e3289b5809e177b61977ad5983aa07b5ff5a6a2b2033ea |
| rust_build_profile | optimized |
| rust_noir_version | 1.0.0-rc.3 |
| schema_version | 2 |
| timestamp | 2026-10-26T13:53:35.306722+00:00 |
| variant | recursive |
| verbose | false |

### Artifact source stamp

| Setting | Saved value |
|---|---|
| builtAt | 2026-10-26T13:55:00.000Z |
| committee | minimum |
| preset | secure-16384 |
| sourceHash | e20eeb82ced1a8dc |

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

| dkg/esm_share_computation_chunk | production_bb_adapter_wall | 0.261663 | N/A | 4.042750 | N/A | 12.536095 | 0.173907 | verified |
| dkg/pk | production_bb_adapter_wall | 0.050637 | N/A | 1.092731 | N/A | 3.636056 | 0.173624 | verified |
| dkg/sk_share_computation_chunk | production_bb_adapter_wall | 0.103750 | N/A | 2.091648 | N/A | 7.855814 | 0.169642 | verified |
| threshold/decrypted_shares_aggregation_wide | production_bb_adapter_wall | 0.000878 | N/A | 0.081542 | N/A | 0.319601 | 0.173469 | verified |
| threshold/lbfv_pk_aggregation | production_bb_adapter_wall | 0.195977 | N/A | 4.821130 | N/A | 12.872864 | 0.150403 | verified |
| threshold/lbfv_pk_generation | production_bb_adapter_wall | 1.065386 | N/A | 3.913465 | N/A | 12.501041 | 0.104899 | verified |
| threshold/rlk_aggregation | production_bb_adapter_wall | 0.218247 | N/A | 5.220431 | N/A | 19.441510 | 0.166520 | verified |
| threshold/rlk_generation | production_bb_adapter_wall | 0.428688 | N/A | 7.648141 | N/A | 46.368940 | 0.133482 | verified |
| threshold/share_decryption | production_bb_adapter_wall | 1.154987 | N/A | 7.069623 | N/A | 46.639882 | 0.149432 | verified |

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
| dkg/esm_share_computation_chunk | 3059476 | 16069898 | 11408460 | 3680 | 14656 | 544 | 206816 |
| dkg/pk | 958882 | 3909889 | 3542297 | 3680 | 14656 | 32 | 198804 |
| dkg/sk_share_computation_chunk | 1926746 | 10714619 | 5703118 | 3680 | 14656 | 544 | 206492 |
| threshold/decrypted_shares_aggregation_wide | 39463 | 921148 | 90181 | 3680 | 14656 | 1728 | 206980 |
| threshold/lbfv_pk_aggregation | 2482171 | 10501267 | 10322342 | 3680 | 14656 | 288 | 202084 |
| threshold/lbfv_pk_generation | 2952949 | 14635120 | 13749546 | 3680 | 14656 | 192 | 200728 |
| threshold/rlk_aggregation | 2482090 | 10500967 | 10324002 | 3680 | 14656 | 320 | 201744 |
| threshold/rlk_generation | 5935356 | 30641613 | 34724127 | 3680 | 14656 | 256 | 201884 |
| threshold/share_decryption | 5903144 | 22071805 | 30561795 | 3680 | 14656 | 192 | 200884 |

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
| Each ciphernode | P4 | C6 leaf proof, not a deployment estimate | production_bb_adapter_wall | 46.639882 | 14656 | 14848 |

Integration timing: incomplete (no saved summary).

## Artifact provenance

| Circuit | Compiled SHA-256 | VK SHA-256 | Artifact source |
|---|---|---|---|
| config | N/A | N/A | N/A |
| dkg/esm_share_computation_chunk | d9bfead780263fa7248bf4d74f505473d4889fdecd841e7f65dc552576a08b9c | 0e8c689e6a73bb327f279e372f16791239cf690f0c2a3f6144f4bd332caad788 | e20eeb82ced1a8dc |
| dkg/pk | 6a59b7224fafb743f9a9373ebb7ec8da6babab850bdf6e7707bfa19e0c928d35 | bff350a433ca23f30683b25cea94389c9bb5364e2a205c0f33abe414e35e5485 | e20eeb82ced1a8dc |
| dkg/sk_share_computation_chunk | 2afe8afb7d543e0edd95225bfdbcd854e3ce916eb2a2a46ed9df54e155d2d1d0 | 5a44dd65246e1eb88d0e30e7557c9153784ca0476806f8846e68955b88dee92b | e20eeb82ced1a8dc |
| threshold/decrypted_shares_aggregation_wide | be7c9be14a5652d42289aa468d22883abd1b11a91fc378ef5ed0eca1ace6cdc0 | 3e8405c13e1c9f69d7d1245eca383e751c214989d9747be03f94b53b9a91f79e | e20eeb82ced1a8dc |
| threshold/lbfv_pk_aggregation | 03d38a0d52d7891c4892ef0c8356c83f628fddc491360eabde5f16ac49658b6c | c3e20214db87ff5a2eccf5b90f7b4e441f784f4f63301145b031dba6069d98e1 | e20eeb82ced1a8dc |
| threshold/lbfv_pk_generation | 081b05efe89cce3ae9ad58186c2ea207b9482cf6b0b2e21075f46310f542dcb6 | 621488909bf37eadb8caed9776cc3acbb5c4d6e3f2784fe787c871ffaccf7aec | e20eeb82ced1a8dc |
| threshold/rlk_aggregation | 317b46e38715a9bd3fe774aa810ed8ed2d6932bea67cebf634f13c4e6aa3a2a1 | 7322157300597ba10f47a0c3bb28b090d20f262b9c6463a9445ec42d1ce57969 | e20eeb82ced1a8dc |
| threshold/rlk_generation | f6f0dd87dc126f7e7b8ece5b76df79855d822b41304aeb0b6c6feac0aa8406ca | 96a39a955432b6eb36249404d61c93df975b03e194cb0cb4f50d5c9eb6d76536 | e20eeb82ced1a8dc |
| threshold/share_decryption | fc8cc94be6be89748f4114a2b7eebb333a20c170d3f882a84d2427aaf3a1dc60 | 95c779e960dc3c08e8ea1eb127634a1aef376e71e0fd0be74227857f97188da1 | e20eeb82ced1a8dc |

## Saved raw records

- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/config_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/dkg_esm_share_computation_chunk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/dkg_pk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/dkg_sk_share_computation_chunk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/threshold_decrypted_shares_aggregation_wide_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/threshold_lbfv_pk_aggregation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/threshold_lbfv_pk_generation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/threshold_rlk_aggregation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/threshold_rlk_generation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384_minimum_leaf/raw/threshold_share_decryption_default.json`
