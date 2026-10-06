# `share_decryption` — C6

Threshold decryption share for one ciphertext. The partial share is the Lagrange coefficient times
`c1` times the secret share, plus fresh noise and the PRF mask. `c0` is not in this share. The
Lagrange coefficient comes from the public decryptor set.

|           |                                                                                                     |
| --------- | --------------------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/threshold/share_decryption.nr`](../../../lib/src/core/threshold/share_decryption.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                                   |
| **Docs**  | [Noir Circuits](../../../../docs/pages/noir-circuits.mdx)                                           |
