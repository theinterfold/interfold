# `e_sm_share_computation` — C2b (share computation)

Correct Threshold Smudging Noise Share Computation (**Circuit 2b**). Verifies the expected secret
commitment, checks secret consistency (`y[i][j][0] == e_sm[j][i]` per modulus), performs range
checks (`y` in `[0, q_j)`), and enforces Reed–Solomon parity using the preset `PARITY_MATRIX`.
Commits computed party shares for downstream aggregation.

|           |                                                                                           |
| --------- | ----------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/dkg/share_computation.nr`](../../../lib/src/core/dkg/share_computation.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                         |
| **Docs**  | [Noir Circuits](../../../../docs/pages/noir-circuits.mdx)                                 |
