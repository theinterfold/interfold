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
