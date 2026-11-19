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
recreate the artifacts and proof checks. The manifests record the exact source snapshot, file
digests and tool versions of the qualified build. The complete circuit JSON includes debug
information. The key pins, targets and rendered verifier identify the cryptographic artifacts; a new
source snapshot is not authority to restamp or replace an older candidate.

Both Minimum profiles have the same public **shape**: two child VK hashes, then the exact ordered C7
fields. A consumer must compare both pins with independently selected artifacts and verify the
confirmed setup, roster, domain, ciphertext, SK/key-bundle commitments and plaintext. The outer Honk
verifier alone cannot authenticate any of that chain state. No release counter or deployment changes
here. Activation, rollback and fresh-noise/retry policy require separate review.
