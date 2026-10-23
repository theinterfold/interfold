# e3-keyshare

## Purpose

Per-E3 DKG and secret-share lifecycle for a ciphernode: collect authenticated dealer material,
produce threshold contributions, assemble this node's decryption key, and later emit proven
decryption shares. Arithmetic runs through [e3-trbfv](../trbfv/README.md) and shared workers; this
capability coordinates protocol state and recovery.

## Map

| Location                                                                                                                                                | Responsibility                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [`ext.rs`](src/ext.rs), [`repo.rs`](src/repo.rs)                                                                                                        | Per-E3 actor construction/hydration and typed storage.                         |
| [`threshold_keyshare/actor.rs`](src/threshold_keyshare/actor.rs), [`handlers.rs`](src/threshold_keyshare/handlers.rs)                                   | Mailbox shell and event dispatch.                                              |
| [`state.rs`](src/threshold_keyshare/state.rs), [`roster.rs`](src/threshold_keyshare/roster.rs), [`validation.rs`](src/threshold_keyshare/validation.rs) | Phase model, mutually ready dealer roster, and authenticated input checks.     |
| [`collection decisions`](src/threshold_keyshare/collect_threshold_shares.rs)                                                                            | Encryption-key, threshold-share, and decryption-key cutoff/expulsion handling. |
| [`effects/`](src/threshold_keyshare/effects)                                                                                                            | Compute/proof requests, roster coordination, delivery, and replay recovery.    |
| [`recovery_state.rs`](src/threshold_keyshare/recovery_state.rs), [`recovery_payloads.rs`](src/threshold_keyshare/recovery_payloads.rs)                  | Durable recovery metadata and separately stored large inputs.                  |

Selection creates this node's per-E3 keyshare actor. It exchanges encryption keys, generates and
checks dealer shares, coordinates an accepted roster, and assembles local decryption material. After
the canonical committee key and ciphertext are available, it produces decryption shares. The same
saved phase/inputs drive restart, with external work dispatched by effects.

## Runtime integration

Register `ext::ThresholdKeyshareExtension::create(...)` on `E3RouterBuilder` with recipient name
`threshold_keyshare`. It creates `ThresholdKeyshare` on `CiphernodeSelected` and hydrates the
corresponding saved actor during restart. It is not one globally shared keyshare actor.

Actors created during replay inherit the context's disabled effects, as hydrated actors do. They
record keys/shares without starting collectors or timers until `EffectsEnabled` rebuilds them.

The constructor takes the bus, local encryption `Cipher`, operator address, per-chain Interfold
addresses, `DkgTimingReader`, signer, and shared `canonical_key::CanonicalPublicKeys`. The timing
reader returns the request's canonical deadline/window; metadata comes from the router context. See
the [production wiring](../ciphernode-builder/src/builder/extensions.rs) for dependencies and
named-recipient registration rather than reproducing a runtime fixture.

The crate exports actor construction parameters, recovery payload/state types, and
`ThresholdKeyshareRepositoryFactory` for specialized harnesses. `EncryptionKeyCollector` is the
dealer-key collection boundary. Canonical-key types are shared from `e3-request`; a local aggregate
intent is not permission to decrypt under an unconfirmed key.

The threshold-share soft checkpoint can advance when every missing dealer lacked a C0 key at
key-collection closure. Verification still needs H−1 external shares, and collection remains open
until completion or the canonical DKG deadline.

Successful randomized contributions are reused after restart. Secret material is wrapped in local
encrypted storage; do not treat the exported state types as safe plaintext diagnostics. Detailed
dimensions, roster transitions, proof batches, and recovery limits are in
[DKG](../../docs/architecture/dkg.md) and
[threshold decryption](../../docs/architecture/threshold-decryption.md).

## Tests

Run `cargo test --locked -p e3-keyshare` after the
[test-helper prerequisites](../test-helpers/README.md). Its test graph includes EVM/prover build
steps. Actor/mock coverage is separate from matching real-proof acceptance.

[`threshold_keyshare/tests.rs`](src/threshold_keyshare/tests.rs) exercises actor histories and
restart/cutoff behavior; [`tests/admission.rs`](src/threshold_keyshare/tests/admission.rs) covers
forged dealer inputs. Collection, roster, state-transition, and payload-digest cases sit beside
their pure modules. For complete DKG/decryption scenarios use [e3-tests](../tests/README.md).
[AGENTS.md](AGENTS.md) carries phase-order and secret-lifecycle editing rules.
