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
altered native share in ACVM. It verifies decryption from native setup openings, **not** a secure
DKG proof, secure registry publication, production request admission or noise freshness. The
insecure case additionally has the signed registry/authority wrapper integration. The two outer VKs
coincide because the Minimum recursive verifier has the same shape; the C6 and C7 VKs differ and
must be pinned independently. See the [versioned manifests](../qualification/README.md) and
[reproduction commands](../../scripts/circuits/README.md#synchronized-decryption-candidates). Secure
Micro/Small [PRF-only measurements](synchronized-prf.md) do not qualify decryption.
