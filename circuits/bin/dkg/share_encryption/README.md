# `share_encryption` — C3a / C3b

BFV-encrypts each Shamir share under the recipient’s **individual** public key. Same Nargo package
for both variants; witnesses differ (`expected_message_commitment` from C2a vs C2b).

|           |                                                                                         |
| --------- | --------------------------------------------------------------------------------------- |
| **Core**  | [`lib/src/core/dkg/share_encryption.nr`](../../../lib/src/core/dkg/share_encryption.nr) |
| **Index** | [Circuit package index](../../../README.md#circuit-package-index)                       |
| **Docs**  | [Noir Circuits](../../../../docs/pages/noir-circuits.mdx)                               |
