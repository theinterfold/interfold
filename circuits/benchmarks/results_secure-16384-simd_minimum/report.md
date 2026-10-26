# Circuit and protocol benchmarks

## Run configuration

### Saved benchmark settings

| Setting | Saved value |
|---|---|
| arch | aarch64 |
| bb_binary | /Users/ctrlc03/.bb/bb |
| bb_version | 6.0.0 |
| benchmark_mode | secure |
| bfv_preset_subdir | secure-16384-simd |
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
| timestamp | 2026-10-26T13:31:08.107287+00:00 |
| variant | recursive |
| verbose | false |

### Artifact source stamp

| Setting | Saved value |
|---|---|
| builtAt | 2026-10-26T10:34:24.572Z |
| committee | minimum |
| preset | secure-16384-simd |
| sourceHash | 4ae56f725e3aa3bd |

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

| dkg/esm_share_computation_chunk | production_bb_adapter_wall | 0.233243 | N/A | 3.598917 | N/A | 14.041268 | 0.164361 | verified |
| dkg/pk | production_bb_adapter_wall | 0.046510 | N/A | 1.091532 | N/A | 3.896945 | 0.162004 | verified |
| dkg/sk_share_computation_chunk | production_bb_adapter_wall | 0.101093 | N/A | 1.957485 | N/A | 6.747200 | 0.251102 | verified |
| threshold/decrypted_shares_aggregation_wide | production_bb_adapter_wall | 0.001031 | N/A | 0.210890 | N/A | 0.512237 | 0.125182 | verified |
| threshold/lbfv_pk_aggregation | production_bb_adapter_wall | 0.203389 | N/A | 4.713883 | N/A | 9.969343 | 0.159358 | verified |
| threshold/lbfv_pk_generation | production_bb_adapter_wall | 1.233559 | N/A | 3.664757 | N/A | 11.718045 | 0.142757 | verified |
| threshold/rlk_aggregation | production_bb_adapter_wall | 0.197799 | N/A | 4.706686 | N/A | 9.815136 | 0.160352 | verified |
| threshold/rlk_generation | production_bb_adapter_wall | 0.400866 | N/A | 7.284475 | N/A | 26.066687 | 0.176657 | verified |
| threshold/share_decryption | production_bb_adapter_wall | 0.915455 | N/A | 6.817151 | N/A | 25.462313 | 0.160308 | verified |

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
| dkg/esm_share_computation_chunk | 3083973 | 16069927 | 11943565 | 3680 | 14656 | 544 | 206840 |
| dkg/pk | 1135164 | 3991509 | 4002972 | 3680 | 14656 | 32 | 198612 |
| dkg/sk_share_computation_chunk | 1926657 | 10714631 | 5909037 | 3680 | 14656 | 544 | 206384 |
| threshold/decrypted_shares_aggregation_wide | 77759 | 1220287 | 146020 | 3680 | 14656 | 1728 | 206824 |
| threshold/lbfv_pk_aggregation | 2482073 | 10501629 | 10755880 | 3680 | 14656 | 288 | 202072 |
| threshold/lbfv_pk_generation | 2973340 | 14635137 | 14116475 | 3680 | 14656 | 192 | 200896 |
| threshold/rlk_aggregation | 2481992 | 10502399 | 10756300 | 3680 | 14656 | 320 | 201600 |
| threshold/rlk_generation | 5976227 | 30641639 | 35463050 | 3680 | 14656 | 256 | 201764 |
| threshold/share_decryption | 6006784 | 22071933 | 31552021 | 3680 | 14656 | 192 | 200824 |

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
| Each ciphernode | P4 | C6 leaf proof, not a deployment estimate | production_bb_adapter_wall | 25.462313 | 14656 | 14848 |

Integration timing: incomplete (no saved summary).

## Artifact provenance

| Circuit | Compiled SHA-256 | VK SHA-256 | Artifact source |
|---|---|---|---|
| config | N/A | N/A | N/A |
| dkg/esm_share_computation_chunk | 26e968658d69a86fb32f8d1494c1b980edfe34e06ac6bb40d4a4d579d042d0ff | 522b3f0de5a7410edad5e07e5cc74b42098657e82270305755e63b99c6ea3916 | 4ae56f725e3aa3bd |
| dkg/pk | 5302d34972207f9ea17e2bf79f3e39a36c07a803023a5e8903c4d25c221e64ff | 08dbb15696cdeda531ae1b0a71b0c408d186ada456c96e0b5fae97adcc0476f4 | 4ae56f725e3aa3bd |
| dkg/sk_share_computation_chunk | 8bd991dc8cef84f57c87f19360e666872209e2bf928d82b49764fa70854d1bf5 | cb051f4d41771bc3a1417c3de5d104070d7f590c0d99c11cc825364e2f3b1812 | 4ae56f725e3aa3bd |
| threshold/decrypted_shares_aggregation_wide | 721442e7b3ae29f725c9d661d06243c868f7d7eca53180a7ab3c4663fd1f4bd2 | a01b1cf7cdb5d73c8b11c4eec97eff99bee54dc7dfef446b5a107b51716cdeb3 | 4ae56f725e3aa3bd |
| threshold/lbfv_pk_aggregation | 5f170d78ba710dfed6d849ed70c05238e64469e77319bdddea62fe5d4e64b8e9 | 9f3dd084a0524d3a47c4b21f3b77e7b05aa612f3df26a4d528b8ca8f393feb26 | 4ae56f725e3aa3bd |
| threshold/lbfv_pk_generation | dbc2dbae946d8acf5db8ae7c011ab861755652456b0df22975e9a17cafaea13e | f71960db57f415d4130342c73c7d1c1c6ec9b5c4b6e29c92b02f1f4443e895c5 | 4ae56f725e3aa3bd |
| threshold/rlk_aggregation | 21520b222e4031d0cb4cd200d313b6182d5d7f0bc7c0c123dd9d12778392633e | 82a22547438587b67f7c7f233575cd0920d8c2c3e9902bb88ba2dcf75ab07ccd | 4ae56f725e3aa3bd |
| threshold/rlk_generation | eafadbc9c760d9ddf878882457ebd31a9977f0d6fc8432516f97b1d15d88117b | 1166758ad1b424495dfd1cbd7fe60fc8ad23e4df8b8131a6195109082a59a733 | 4ae56f725e3aa3bd |
| threshold/share_decryption | 4292cca02256c8fa4bf8db0e646e8823690dc4adeb5a7105bf6a650aa37b2ae3 | 265315f313afffe8ac1b571cfc3a06abc82e7f124fb99e0014d195e1ae93541b | 4ae56f725e3aa3bd |

## Saved raw records

- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/config_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/dkg_esm_share_computation_chunk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/dkg_pk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/dkg_sk_share_computation_chunk_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/threshold_decrypted_shares_aggregation_wide_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/threshold_lbfv_pk_aggregation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/threshold_lbfv_pk_generation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/threshold_rlk_aggregation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/threshold_rlk_generation_default.json`
- `/Users/ctrlc03/.omp/worktrees/interfold/lbfv-secure-16384-simd/crates/zk/benchmarks/../../../circuits/benchmarks/results_secure-16384-simd_minimum/raw/threshold_share_decryption_default.json`
