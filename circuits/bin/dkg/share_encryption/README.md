# `share_encryption` — C3a

BFV-encrypts each packed Shamir share under the recipient's individual public key. The packed
plaintext is `residue + bit·q`. The circuit checks the residue against the C2 share commitment and
the PRF-key bits against the C2 key commitment.

|           |                                                                                         |
| --------- | --------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/dkg/share_encryption.nr`](../../../lib/src/core/dkg/share_encryption.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                       |
| **Docs**  | [Noir Circuits](../../../../docs/pages/noir-circuits.mdx)                               |
