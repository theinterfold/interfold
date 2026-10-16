# `user_data_encryption` — P3

Proves both legs of a user BFV encryption under the **aggregated** threshold public key in one
circuit. The ct0 leg (`UserDataEncryptionCt0::execute`) bounds `u` to `{-1, 0, 1}` and commits it.
The ct1 leg (`UserDataEncryptionCt1::execute_with_u_commitment`) reads the same `u` witness and
takes that commitment into its transcript. `pk1` is the circuit-constant CRS (`CRP`), so the circuit
can prove only a key on the default-seed CRP. Every committee key is on it. At `secure-8192` the
circuit has 1,891,256 gates and fits one `2^21` proof.

Inputs: `pk0is`, `ct0is`, `ct1is`, `u`, `e0`, `e1`, `k1`, `r`, `r_ct1`. Public outputs:
`(pk_commitment, ct_commitment, k1_commitment)`. The ABI depends on the BFV degree, so build the
circuit for each preset.

|           |                                                                                                                                                                                            |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Legs**  | [`user_data_encryption_ct0.nr`](../../../lib/src/core/threshold/user_data_encryption_ct0.nr), [`user_data_encryption_ct1.nr`](../../../lib/src/core/threshold/user_data_encryption_ct1.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                                                                                                                          |
| **Docs**  | [Noir Circuits](../../../../docs/pages/noir-circuits.mdx)                                                                                                                                  |
