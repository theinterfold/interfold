# e3-zk-samples

This unpublished crate supplies cryptographically valid artificial BFV data for tests and
development benchmarks. Its samples are not live application inputs.

Free functions under `dkg` and `threshold` construct keys, ciphertexts, shares, and plaintexts. They
return the production input types from `e3-zk-witness`. Configuration stays in `e3-zk-config`;
witness preparation, encoding, and commitments stay in `e3-zk-witness`.

Constructors reuse supplied parameters or circuit configurations. The share-encryption constructor
needs both threshold sharing parameters and DKG encryption parameters. C7 uses the supplied message
prefix width and verifies that threshold decryption recovers the encrypted sample message.

C6 retains the first `T+1` dealers for recipient zero; its public key includes all `N` dealers. C7
retains all `N` dealer contributions but collects only `T+1` reconstructing recipients. Each sample
call reuses share-management and noise setup. Each dealer receives fresh noise and Shamir
randomness. C2 uses `N` as its ciphertext count. C3 accepts an explicit count; C4/C6/C7 use the
preset's `z`, and C1 uses its configured bound.

Consumers use this package through `[dev-dependencies]`. `pnpm check:invariants` enforces this
boundary, including renamed and target-specific dependencies. No test-support feature exists in
the production libraries.
