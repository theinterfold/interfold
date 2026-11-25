# `share_decryption` — C4a / C4b

Decrypts incoming shares and aggregates them; outputs commitments consumed by **C6** (threshold
decryption). It is the final circuit of a limb chain: it verifies the `share_decryption_limb_0`,
`_1` and `_2` proofs, which run C4's statement for one CRT limb each and carry the aggregate
commitment sponge between them. It links the limbs from a fresh sponge and returns the aggregate
commitment, followed by the hash of the limb keys.

|           |                                                                                                                                                                                              |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/dkg/share_decryption_chain.nr`](../../../lib/src/core/dkg/share_decryption_chain.nr), [`lib/src/core/dkg/share_decryption.nr`](../../../lib/src/core/dkg/share_decryption.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                                                                                                                            |
| **Docs**  | [Noir Circuits](../../../../docs/pages/build/noir-circuits.mdx)                                                                                                                              |
