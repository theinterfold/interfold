# e3-zk-samples

## Purpose

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

All consumers use this package through `[dev-dependencies]`, with one exception: the unpublished
development benchmark crate `e3-zk-benchmarks` links it as a normal dependency because its
executable itself prepares the samples. `pnpm check:repository` enforces this boundary, including
renamed and target-specific dependencies, and allows that runtime use only for `e3-zk-benchmarks`.
No test-support feature exists in the production libraries.

`pnpm bench:circuits` sends these samples through production preparation, Noir execution, and proof
adapters. `--export-toml` writes debug ABI inputs inside the benchmark run directory. Static
configuration generation belongs to `pnpm build:circuits`.

## Map and use

| Location                                           | Responsibility                                                |
| -------------------------------------------------- | ------------------------------------------------------------- |
| [dkg/](src/dkg), [threshold/](src/threshold)       | Artificial per-circuit inputs using production witness types. |
| [Smudging noise](../../fhe-params/src/smudging.rs) | Shared smudging-noise calculation.                            |
| [lib.rs](src/lib.rs)                               | Sample module exports.                                        |

Add this unpublished crate as a dev-dependency, then call the family's constructor with the same
parameters/configuration that production preparation consumes. Keep generated secrets local.
Benchmarks are the explicit normal-dependency exception; runtime fallbacks must not create samples.

## Tests

Run `cargo test --locked -p e3-zk-samples` for constructor behavior and
`cargo test --locked -p e3-zk-witness` for sample-to-preparation coverage. Use
`pnpm check:repository` for dependency containment. Successful artificial preparation is not a proof
or a release qualification. [AGENTS.md](AGENTS.md) owns editing constraints.
