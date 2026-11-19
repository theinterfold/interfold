# Synchronized Minimum decryption candidates

These are versioned **decryption-only** manifests for one ciphertext and two designated parties.
They are not the installable SS archive or deployment configuration. Select the profile by the
request's full `cryptoConfigId`, then `committee`, circuit group/role and verifier target. Both
profiles are disabled. Do not select by degree, basename, or outer VK alone.

| Profile                    | Qualification boundary                                                                                                                                         |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sync-insecure-64/minimum` | Real signed registry publication and contextual Solidity decryption wrapper, in a finalized-committee harness.                                                 |
| `sync-secure-8192/minimum` | Real C6/C7 and recursive EVM proof from native synchronized setup openings; generated Solidity Honk verification. No secure DKG publication or admitted route. |

Use the [candidate builder](../../scripts/circuits/README.md#synchronized-decryption-candidates) to
recreate the artifacts and proof checks. For these manifests, check out
`1ef1f79c5302af256a48925e41b472c6b0e2e17a` before rebuilding. `sourceHash` identifies the builder's
selected inputs, including shared sources; it is neither a Git commit nor a VK pin. The earlier
manifests and timing measurements predate the SS chunk-chain merge (#2500); the original records are
in `38f5b81394c526cca49f3f648f2b1d30b55c22a5`. The complete circuit JSON includes debug information.
Compare the key pins, targets and rendered verifier to identify the cryptographic artifacts across
rebuilds.

Both Minimum profiles use the same outer source. Its `T` and C6 row width come from the generated
degree-64 Minimum configuration: they describe the designated set and public row, not the polynomial
degree. Reuse is valid only while both profiles have that exact public **shape**: two child VK
hashes, then the exact ordered C7 fields. A consumer must compare both pins with independently
selected artifacts and verify the confirmed setup, roster, domain, ciphertext, SK/key-bundle
commitments and plaintext. The outer Honk verifier alone cannot authenticate any of that chain
state. No release counter or deployment changes here. Activation, rollback and fresh-noise/retry
policy require separate review.
