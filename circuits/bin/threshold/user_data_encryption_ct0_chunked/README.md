# `user_data_encryption_ct0_chunked` — P3 (l-BFV, ct0 leg)

Top-level ct0 leg of the l-BFV chunked user-data encryption: verifies the `ct0_eval_chunk_identity`
and `ct0_pk_ct_commit` proofs over one `ct0_chunk_main` leaf and checks the batched reduced
identity. Paired with `user_data_encryption_ct1_chunked`; `user_data_encryption_chunked` verifies
both legs. The trBFV path proves both legs in one circuit, `user_data_encryption`.

|           |                                                                                                                         |
| --------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/threshold/user_data_encryption_chunk.nr`](../../../lib/src/core/threshold/user_data_encryption_chunk.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                                                       |
| **Docs**  | [Noir Circuits](../../../../docs/pages/build/noir-circuits.mdx)                                                         |
