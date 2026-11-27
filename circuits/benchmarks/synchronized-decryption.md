# Synchronized decryption qualification — 2026-11-19

One level-zero ciphertext, Minimum `N=3, T=1, H=2`, designated zero-based IDs `[0,2]`. The two
owners use the pinned `fhe.rs` v0.6.0 native shares, directed keys and local noise draws. C7 checks
the same 50 plaintext coefficients as native reconstruction. The final EVM proof verifies both
complete C6 rows and C7. Independent rebuilding verified both public VK pins and the outer proof;
the generated verifier compiled with solc 0.8.28 accepted it and rejected changed plaintext.

| Profile                    | C6 gates (one owner) |  C7 gates | Outer gates | Peak sampled RSS during proof suite |
| -------------------------- | -------------------: | --------: | ----------: | ----------------------------------: |
| `sync-insecure-64/minimum` |               92,038 |    17,265 |   2,242,265 |                            4.51 GiB |
| `sync-secure-8192/minimum` |            8,609,254 | 1,516,802 |   2,242,265 |                           26.68 GiB |

The 45-party parameter search (#2542) raises the secure C6 noise bound to 145 bits. The secure C6 is
then 8,609,260 gates; C7 and the outer circuit are unchanged. The timings in the next paragraph
predate it. The 2026-11-21 requalification on an Apple M5 Ultra peaked at 26.63 GiB.

Apple M4 Pro / 48 GiB, Nargo `1.0.0-rc.3`, bb `6.0.0`, local CRS. In the secure run, C6
`bb prove --write_vk` took **21.06 s / 20.74 s** for the two owners; C7 took **4.23 s**. Outer
witness preparation and EVM proving together took **4.81 s** (insecure: **5.12 s**). A separate
insecure run measured **0.35 / 0.37 s** for C6 and **0.12 s** for C7. These are observations, not
latency guarantees: leaf timings include the VK work of that command but exclude Noir
compilation/solving and the subsequent `bb verify`. The entire secure Rust suite, including
independent negative checks and recompilation, took **792.49 s**. The separate candidate build and
proof check peaked at **26.04 GiB**. The guard sampled the process tree every 0.5 s; neither run hit
its 32 GiB stop threshold. Sampled peaks are not hard memory bounds.

The secure case rejected a changed full-product coefficient, shifted noise above `2B`, and an
altered native share in ACVM. This decryption-only run used native setup openings. At the time, only
the insecure case had signed registry/authority wrapper integration. The two outer VKs coincide
because the Minimum recursive verifier has the same shape; the C6 and C7 VKs differ and must be
pinned independently. See the [versioned manifests](../qualification/README.md) and
[reproduction commands](../../scripts/circuits/README.md#synchronized-decryption-candidates). Secure
Micro/Small [PRF-only measurements](synchronized-prf.md) do not qualify decryption.

## Secure Minimum rerun — 2026-11-25 (#2461)

On an Apple M4 Pro / 48 GiB with the same toolchain, the post-#2542 C6 proofs took **20.64 s / 20.65
s**, C7 **3.94 s**, and outer witness preparation plus EVM proving **4.80 s**. The Rust test took
**688.60 s**; the guarded command including the Cargo build took **725.6 s**, peaking at **25.82
GiB**. The separate candidate build took **211.1 s** and peaked at **25.76 GiB**. These are sampled
process-tree peaks under the same 32 GiB guard.

The rebuilt
[secure manifest at `262600ea7`](https://github.com/theinterfold/interfold/blob/262600ea71665b8b9eb686f7505fdafeebff9389/circuits/qualification/sync-secure-8192/minimum/manifest.json)
matched byte for byte, including the two child VKs, outer VK, gate counts and generated Solidity
checksum. Hardhat accepted the proof in that generated verifier and rejected a changed plaintext
field. Inputs were native synchronized setup openings.

## Signed DKG through mined plaintext — 2026-11-26 (#2549)

The [signed Minimum runner](../../scripts/circuits/README.md#synchronized-decryption-candidates)
measures both synchronized profiles. The [SS benchmark runner](../../crates/zk/benchmarks/README.md)
selects the archived SS pairs with `--mode insecure` or `--mode secure`. For comparisons, keep the
signed rehearsal's debug wall time and full transaction gas separate from the SS runner's release
phase timings and verifier-only gas.

The final runs include cross-request negatives, separate source rebuilds of both proof graphs, and
verification of the signed exports. Figures are wall time / peak sampled process-tree RSS under the
same 32 GiB guard:

| Minimum profile    |      Signed rehearsal | DKG candidate rebuild | Decryption candidate rebuild |
| ------------------ | --------------------: | --------------------: | ---------------------------: |
| `sync-insecure-64` |   204.7 s / 11.22 GiB |     29.3 s / 7.73 GiB |            15.9 s / 3.18 GiB |
| `sync-secure-8192` | 1,961.7 s / 25.29 GiB |     86.2 s / 7.78 GiB |          196.9 s / 25.64 GiB |

In the first signed rehearsal the secure run took **2,006.8 s / 25.89 GiB**, the insecure control
**192.2 s / 11.21 GiB**. In both rehearsals, the secure actors recovered the 368,670-byte public key
from confirmed logs. Owners `[0,2]` decrypted encrypted `19 + 18` and the matching request mined
`37`. The [coexistence record](../qualification/minimum-coexistence.md) gives the final Anvil
receipts (excluding key-chunk transactions), candidate source hashes and substitution results.

## Optimized Minimum comparison — 2026-11-26

Apple M4 Pro, 48 GiB, bb `6.0.0`, Noir `1.0.0-rc.3`. Each row is a single observation using the
[Rust benchmark runner](../../crates/zk/benchmarks/README.md#synchronized-minimum) on the post-#2542
Minimum artifacts listed in the [coexistence record](../qualification/minimum-coexistence.md). Input
preparation excludes native sample construction. Witness includes ACVM solving and serialization;
proving and verification include the BB process and file I/O, with prebuilt VKs. C6/C7 in this table
use `recursive`; outer uses `evm`. All of these proofs verified. The SS actor run below uses its own
protocol variants, including `default` for the C7 consumed by the final verifier.

| Profile          | Operation  |     Gates | Preparation (s) | Witness (s) | Prove (s) | Verify (s) |
| ---------------- | ---------- | --------: | --------------: | ----------: | --------: | ---------: |
| SS insecure      | C6         |    14,956 |          0.0014 |      0.0104 |    0.1111 |     0.1111 |
| SS insecure      | C7         |    12,448 |          0.0004 |      0.0116 |    0.1110 |     0.1067 |
| SyncDec insecure | C6 owner 0 |    92,038 |          0.0009 |      0.0718 |    0.3312 |     0.1113 |
| SyncDec insecure | C6 owner 2 |    92,038 |          0.0014 |      0.0807 |    0.3261 |     0.1019 |
| SyncDec insecure | C7         |    17,265 |          0.0010 |      0.0199 |    0.1121 |     0.1113 |
| SyncDec insecure | Outer      | 2,242,265 |          0.0077 |      0.0045 |    4.4137 |     0.1124 |
| SS secure        | C6         | 2,081,086 |          1.7884 |      1.6972 |    4.4429 |     0.1117 |
| SS secure        | C7         |    14,797 |          0.0004 |      0.0099 |    0.1109 |     0.1112 |
| SyncDec secure   | C6 owner 0 | 8,609,260 |          0.0925 |      9.1921 |   16.4322 |     0.1113 |
| SyncDec secure   | C6 owner 2 | 8,609,260 |          0.0956 |      9.4852 |   16.6591 |     0.1115 |
| SyncDec secure   | C7         | 1,516,802 |          0.1231 |      1.4099 |    3.3038 |     0.1112 |
| SyncDec secure   | Outer      | 2,242,265 |          0.0149 |      0.0034 |    4.5041 |     0.1118 |

The SS two-leaf commands took **2.1 / 10.5 s** and peaked at **0.32 / 4.63 GiB** (insecure /
secure). The SyncDec full decryption graph commands, including both owners, C7, the outer and EVM
replay, took **10.0 / 73.0 s** and peaked at **4.43 / 19.60 GiB**. These memory figures cover
different command scopes. Standalone `SynchronizedDecryptionVerifier.verify` estimates were
**3,567,383 / 3,567,371 gas** with the matching independently pinned children. Neither command clock
starts at a CLI request.

The two secure C6 witness and proving phases together account for **51.77 s (71%)** of the serial
73.0 s graph. Per owner, witness execution averaged **5.5×** the secure SS C6 time and proving
**3.7×**. These timers cover the full C6 statement; they do not isolate the operations proposed in
[#2558](https://github.com/theinterfold/interfold/issues/2558).

The [current PRF](../lib/src/core/synchronized/prf.nr) hashes both ciphertext components and derives
one field per coefficient. Replacing the components with a commitment changes the native transcript;
taking several coefficients from a field also needs a distribution review. PRF evaluation already
absorbs the key as one field. It is the
[directed-key commitment](../lib/src/core/synchronized/commitments.nr) that absorbs 32 byte fields
and DKG transport that packs individual bits. Changing key width or commitment encoding therefore
affects setup as well as C6.

Saved secure proof replay reproduced the verifier estimate without reproving. Substituting the
insecure C6 pin or C7 pin separately reverted with `VkHashMismatch`. The runner also rejected the
other profile's manifest and a modified C6 VK before invoking the verifier.

For the SS actor run (`--multithread-jobs 1`), `ZkDecryptionAggregation` includes the
[C6 Chonk stack, tube and root](../../docs/architecture/proof-statements.md#recursive-trust-and-exported-values)
and final EVM proof. The complete SS command also proves DKG. The job, whole-actor command and
standalone verifier call have different measurement boundaries:

| Minimum  | SS fold + final proof (job) | SS ciphertext → `PlaintextAggregated` | Whole SS command / peak RSS | SS decryption verifier gas | SyncDec decryption verifier gas |
| -------- | --------------------------: | ------------------------------------: | --------------------------: | -------------------------: | ------------------------------: |
| Insecure |                     25.68 s |                               26.48 s |         334.9 s / 16.65 GiB |                  3,441,155 |                       3,567,383 |
| Secure   |                     24.96 s |                               50.94 s |         634.8 s / 19.89 GiB |                  3,441,216 |                       3,567,371 |

The SS ciphertext interval ends at an in-process actor event. Standalone SS DKG verifier estimates
were **3,123,413 / 3,123,340 gas** (insecure / secure). Secure SyncDec used **126,155 more gas
(3.7%)** than SS for the standalone decryption call. Its proof and public inputs were 11,072 and
2,432 bytes, versus 10,688 and 2,048 bytes for SS. Each standalone call uses its real verifier with
public anchors in a fixture registry. Estimates include transaction intrinsic gas; the mined
publication costs are recorded separately below.

The first insecure control overlapped build and test activity: **569.48 s** for the fold and final
proof, **1,104.6 s / 16.59 GiB** for the command, and **3,123,584 / 3,441,265 gas** for the DKG /
decryption verifiers. The table uses the serial repeat with the same archive and one job. The first
secure attempt hit the enclosing command's time limit during DKG and produced no measurement.

### Local `committee:new` → mined plaintext

**SyncDec reached the mined plaintext sooner in both Minimum runs.** Insecure took **80.02 s**
versus **268.31 s** for SS (70.2% less time); secure took **343.66 s** versus **538.16 s** (36.1%
less). Secure SyncDec reached the published key **234.74 s earlier**, but took **23.45 s longer**
from ciphertext to plaintext. These are single observations of the local workloads described below.

All four optimized runs used the same Mac, one fresh Anvil chain each (`31337`, Anvil
`1.3.1-stable`, solc `0.8.28+commit.7893614a`). The regular CLI request passed the three-owner
preflight, paid the fee and froze both verifiers. Each request then survived rotation of the future
decryption default and mined **37** from one ciphertext containing encrypted `19 + 18`.

| Minimum profile                                                        | Submit → published key | Key → ciphertext | Ciphertext → plaintext receipt | **Submit → plaintext receipt** | CLI invocation → receipt | Peak command RSS |
| ---------------------------------------------------------------------- | ---------------------: | ---------------: | -----------------------------: | -----------------------------: | -----------------------: | ---------------: |
| [SS insecure](results_ss_insecure_minimum/request_receipt.json)        |               241.16 s |           0.03 s |                        27.11 s |                   **268.31 s** |                 269.14 s |        16.72 GiB |
| [SyncDec insecure](results_sync_insecure_minimum/request_receipt.json) |                57.12 s |          14.64 s |                         8.26 s |                    **80.02 s** |                  80.75 s |        11.35 GiB |
| [SS secure](results_ss_secure_minimum/request_receipt.json)            |               486.57 s |           0.84 s |                        50.74 s |                   **538.16 s** |                 538.92 s |        19.90 GiB |
| [SyncDec secure](results_sync_secure_minimum/request_receipt.json)     |               251.83 s |          17.64 s |                        74.19 s |                   **343.66 s** |                 344.45 s |        20.71 GiB |

Submission starts at the CLI's `request(...)` call after approval. Published key means the DKG proof
and all key chunks are mined. Both clocks include fixture computation and HTTP ciphertext retrieval;
Anvil advances the ticket and input windows. RSS is the sampled process-tree peak of the whole
command, including local deployment. The serial SS commands took **338.5 / 610.4 s** (insecure /
secure); those totals include startup and post-receipt checks.

- **SS:** Three full nodes used live EVM readers and writers, local libp2p with a bootstrap peer,
  separate persisted stores and one shared proof job. All stayed online. The accepted decryption
  proofs identified slots `[0,1]` in both runs. The benchmark polled the chain every 200 ms for the
  last key chunk and the matching plaintext event, then read their successful receipts.
- **SyncDec:** The signed actor and recovery driver recorded the writer's returned receipts. The
  timed workload includes resuming the key writer, owner `1`'s late setup, aggregator failover and
  reopening the journal. The lowest canonical `T+1` owners of confirmed H remained `[0,2]`. The
  key-to-ciphertext phase includes recovery checks that the all-online SS run does not perform.
  These runs compare observable request latency without isolating the protocols from their drivers.

| Mined transaction gas |   Request | Signed DKG (excludes key chunks) | Ciphertext | Plaintext |
| --------------------- | --------: | -------------------------------: | ---------: | --------: |
| SS insecure           | 2,753,679 |                        3,658,469 |    201,381 | 3,932,252 |
| SyncDec insecure      | 2,744,620 |                        3,926,049 |    201,393 | 4,066,480 |
| SS secure             | 2,753,603 |                        3,658,421 | 14,723,020 | 3,932,396 |
| SyncDec secure        | 2,747,103 |                        3,925,967 | 14,726,860 | 4,066,540 |

The local DA fixture takes the ciphertext bytes in calldata, which matters especially for secure
Minimum. The linked receipts preserve all four transaction hashes, the ciphertext commitment,
request identity and verifier rotation. Matching numeric E3 IDs and addresses across runs reflect
deterministic deployments on separate chains.

The SyncDec receipts above used the original benchmark controller. Current benchmark runs link the
quote check through the lifecycle library, so their transaction gas can differ.

After each SS receipt, replaying the actual verifier subcalls as standalone estimates gave
**3,122,591 / 3,122,531 gas** for DKG and **3,449,925 / 3,450,069 gas** for decryption (insecure /
secure). The SyncDec standalone _decryption graph_ estimates above were **3,567,383 / 3,567,371
gas**. The latter use a fixture registry; neither set of standalone estimates is the gas charged for
a full publication transaction.

**Decision for [#2461](https://github.com/theinterfold/interfold/issues/2461): defer #2558 for the
Minimum release candidate.** Secure Minimum spent **73.3%** of request time getting to the published
key. The entire ciphertext-to-plaintext interval, including both C6 proofs, C7, the outer and
failover, was **21.6%**. C6 is a good target for later work on decryption latency. None of the three
proposed changes was benchmarked, so no end-to-end saving is established. Keep the current
statements, native vectors and pinned candidate keys for Minimum qualification. Evaluate
alternatives against the same phase and request clocks, including DKG if the setup encoding changes.
The
[rollout proposal](../../docs/architecture/upgrades.md#synchronized-minimum-rollout-proposal-v1-pending-review)
tracks the separate review and activation decisions.
