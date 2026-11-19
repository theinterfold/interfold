# Synchronized PRF sizing — 2026-11-19

Isolated [#2050](https://github.com/theinterfold/interfold/issues/2050) probe, based on `8c2865ace`,
using `fhe.rs` `30cce841`, Nargo `1.0.0-rc.3` and bb `6.0.0`. One owner, three CRT limbs, both
native ciphertext components, two directed evaluations per peer, and the entire expected synthetic
mask as public inputs. The probe includes no DKG openings, C6 relation or recursion. Secure sizes
use the threshold parameters only.

Apple M4 Pro, 48 GiB, one proof at a time, bb's 14 threads, `noir-recursive` (ZK), local CRS. One
observation per size. Proving wall time is `bb prove` with a prepared VK, excluding Nargo,
`bb write_vk` and the subsequent independent `bb verify`. Secure wall times/RSS are sampled at 0.5 s
intervals.
[Reproduction commands](../../crates/zk/samples/README.md#synchronized-prf-conformance-and-sizing).

| Degree / committee | ACIR opcodes |   bb gates |      Proving wall | Peak prover RSS | Independent verification |
| ------------------ | -----------: | ---------: | ----------------: | --------------: | ------------------------ |
| 64 / Minimum       |       12,247 |     48,614 |            0.16 s |         161 MiB | Passed                   |
| 8192 / Minimum     |    1,556,567 |  5,604,438 |           ~11.3 s |        12.1 GiB | Passed                   |
| 8192 / Micro       |    5,292,342 | 17,579,495 |           ~39.1 s |        23.8 GiB | Passed                   |
| 8192 / Small       |   11,518,634 | 37,537,949 | Failed at ~67.8 s |        31.1 GiB | No proof                 |

Micro's native mask matched the Noir witness. Compilation and solving completed in ~236 s (20.3 GiB
sampled peak). The first `bb write_vk` stopped at the 22 GiB guard (22.8 GiB last sampled). With a
**32 GiB sampled RSS guard** and the same compiled bytecode and witness, VK generation completed in
~30.4 s (22.1 GiB peak), proving in ~39.1 s, and a separate `bb verify` accepted the saved proof.

Small (19 members, 10 designated, nine peers per owner) compiled in ~463 s and solved against the
native mask in ~66 s. VK generation completed in ~123 s. With the same 32 GiB guard, `bb prove`
exited with `compute_libra_univariate: round_idx out of range`; the guard did not fire. The measured
circuit exceeds 2^25 rows and needs 26 sumcheck rounds. In bb v6.0.0, the padded Ultra flavor uses a
[fixed 25-round proof size](https://github.com/AztecProtocol/aztec-packages/blob/v6.0.0/barretenberg/cpp/src/barretenberg/constants.hpp#L21)
and the
[ZK prover uses that length for Libra](https://github.com/AztecProtocol/aztec-packages/blob/v6.0.0/barretenberg/cpp/src/barretenberg/ultra_honk/ultra_prover.cpp#L120).
Increasing the RSS guard does not change that limit.

SHA-256 of the decoded `bytecode` blob in the measured Nargo JSON:

- 64 / Minimum: `9ca7e829e3ebe084d91a3f4d5dd1a094aa6cbddfa01d50262c53d303730af351`
- 8192 / Minimum: `050dc754f3b397cbac567aee3b426e5291995f33e821987e137627e3f2ee98ee`
- 8192 / Micro: `ff0b5088c268f90c79b77f58472f289f058a8644fd02cd16e8966d7fae82a2d9`
- 8192 / Small: `ba29f3dac44081f10cb00a39934ead0e9aa79d4f130ad3b9903eaf468ca9cd43`
