# `share_decryption` — C6

Threshold **decryption share** for the homomorphic result ciphertext, using aggregated `sk` / `e_sm`
commitments from C4.

|           |                                                                                                     |
| --------- | --------------------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/threshold/share_decryption.nr`](../../../lib/src/core/threshold/share_decryption.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                                   |
| **Docs**  | [Noir Circuits](../../../../docs/pages/build/noir-circuits.mdx)                                     |

The residue checks use the active preset's `Q_BIT` (27 for insecure-64, 60 for secure-8192). Adding
a parameter set, or changing its moduli, means updating that constant. See
[Q_BIT](../../../lib/src/README.md#q_bit).
