# `e_sm_share_computation` — C2b (share computation)

Correct Threshold Smudging Noise Share Computation (**Circuit 2b**), the final circuit of a chunk
chain. It verifies the `e_sm_share_computation_chain` chunk proofs (the last place takes
`e_sm_share_computation_chain_last`), which run the per-coefficient checks: secret consistency
(`y[i][j][0] == e_sm[j][i]` per modulus), range checks (`y` in `[0, q_j)`), and that the shares lie
on a degree-`T` polynomial, with `(T + 1)`-th finite differences over windows of `T + 2` consecutive
values. It verifies the expected secret commitment, links the chunks from fresh commitment sponges,
and returns the party share commitments for downstream aggregation, followed by the hash of the
chunk keys.

|           |                                                                                                                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Core**  | [`lib/src/core/dkg/share_computation_chain.nr`](../../../lib/src/core/dkg/share_computation_chain.nr), [`lib/src/core/dkg/share_computation.nr`](../../../lib/src/core/dkg/share_computation.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                                                                                                                                |
| **Docs**  | [Noir Circuits](../../../../docs/pages/build/noir-circuits.mdx)                                                                                                                                  |
