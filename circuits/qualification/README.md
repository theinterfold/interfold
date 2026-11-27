# Synchronized Minimum proof candidates

The manifests identify the two parts of the same signed request: DKG publication and decryption of
one ciphertext by two designated parties. Select by the request's full `cryptoConfigId`, committee,
circuit group/role and verifier target. Neither profile is admitted; these are not installable SS
archives or deployment configurations.

The [Minimum coexistence rehearsal](minimum-coexistence.md) records the tested SS archives,
post-#2542 synchronized proofs, verifier routing and remaining qualification limits.

In both profiles the local registry accepted a signed DKG publication and the request's decryption
verifier accepted the matching plaintext proof. Supply the DKG wrapper's setup-tree and C5 pins from
its nine-role manifest. The decryption wrapper selects the recorded C6 and C7 pins by configuration
ID. Each manifest records its outer VK and generated Solidity checksum.

Use the [candidate builder](../../scripts/circuits/README.md#synchronized-decryption-candidates) to
recreate the artifacts and proof checks. Each manifest is generated against the source tree that
records it. From a later checkout use
`git log -1 --format=%H -- circuits/qualification/PROFILE/minimum/FILE` (replace `PROFILE` and
`FILE` with the profile and manifest names) to find that revision, including after a squash merge.
`sourceHash` identifies the builder's selected inputs, including shared sources; it is neither a Git
commit nor a VK pin. Full circuit JSON includes debug information. Compare the key pins, targets and
rendered verifier to identify cryptographic artifacts across source revisions.

Both Minimum profiles use the same decryption outer source. Its `T` and C6 row width come from the
generated degree-64 Minimum configuration: they describe the designated set and public row, not the
polynomial degree. Reuse is valid only while both profiles have that exact public **shape**: two
child VK hashes, then the exact ordered C7 fields. A consumer must compare both pins with
independently selected artifacts and verify the confirmed setup, roster, domain, ciphertext,
SK/key-bundle commitments and plaintext. The outer Honk verifier alone cannot authenticate any of
that chain state. No release counter or deployment changes here. Activation, rollback and
fresh-noise/retry policy require separate review.
