# `pk` — C0

BFV **individual** public key commitment: binds the ciphernode’s share-encryption key used in C3,
and range-checks every coefficient of `pk0` and `pk1` to its centred window
`[-(q_i - 1)/2, (q_i - 1)/2]`. C3 opens this commitment with checked packing, so the bound transfers
and C3 does not repeat it.

|           |                                                                   |
| --------- | ----------------------------------------------------------------- |
| **Core**  | [`lib/src/core/dkg/pk.nr`](../../../lib/src/core/dkg/pk.nr)       |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index) |
| **Docs**  | [Noir Circuits](../../../../docs/pages/build/noir-circuits.mdx)   |
