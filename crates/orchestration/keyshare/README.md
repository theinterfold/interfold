# e3-keyshare

## Purpose

Per-E3 DKG and secret-share lifecycle for a ciphernode: collect authenticated dealer material,
produce threshold contributions, assemble this node's decryption key, and later emit proven
decryption shares. Arithmetic runs through [e3-trbfv](../../bfv/threshold/README.md) and shared
workers; this capability coordinates protocol state and recovery.

## Map

| Location                                                                                         | Responsibility                                                                 |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| [`ext.rs`](src/ext.rs), [`repo.rs`](src/repo.rs)                                                 | Per-E3 actor construction/hydration and typed storage.                         |
| [`actor.rs`](src/actor.rs), [`handlers.rs`](src/handlers.rs)                                     | Mailbox shell and event dispatch.                                              |
| [`state.rs`](src/state.rs), [`roster.rs`](src/roster.rs), [`validation.rs`](src/validation.rs)   | Phase model, mutually ready dealer roster, and authenticated input checks.     |
| [`collection decisions`](src/collect_threshold_shares.rs)                                        | Encryption-key, threshold-share, and decryption-key cutoff/expulsion handling. |
| [`effects/`](src/effects)                                                                        | Compute/proof requests, roster coordination, delivery, and replay recovery.    |
| [`recovery_state.rs`](src/recovery_state.rs), [`recovery_payloads.rs`](src/recovery_payloads.rs) | Durable recovery metadata and separately stored large inputs.                  |

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
the [production wiring](../../ciphernode/builder/src/extensions.rs) for dependencies and
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
[DKG](../../../docs/architecture/dkg.md) and
[threshold decryption](../../../docs/architecture/threshold-decryption.md).

## Tests

Run `cargo test --locked -p e3-keyshare` after the
[system prerequisites](../../testing/system/README.md#prerequisites-and-assurance). Its test graph
includes EVM/prover build steps. Actor/mock coverage is separate from matching real-proof
acceptance.

The [`synchronized` child module](src/tests/synchronized.rs) reuses the actor/recovery fixtures in
[`tests.rs`](src/tests.rs). It exercises production generation, encrypted work plans and prover
preparation, while runtime admission stays disabled:

```sh
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 cargo test --locked -p e3-keyshare --lib synchronized
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 E3_CUSTOM_BB=$(which bb) cargo test --locked -p e3-keyshare --lib synchronized_prepared_runtime_requests_prove_with_real_crypto -- --ignored
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 E3_CUSTOM_BB=$(which bb) pnpm rust:test:sync-dkg:recovery
```

The proof commands require pinned nargo/bb and build only the affected leaves in temporary
directories. The second verifies ten real C1/C2/C3/C4 proofs. The recovery command also verifies 30
C0–C4 proofs across three independent keyshare actors/stores, including C4 from disk-restored,
reissued private inputs. It tests orderly stop/flush/cache eviction/reopen, exact saved work and
proof artifacts, non-prefix H `[0,2]`, self/outside-H recipients, and authenticated rejection
followed by valid replacement. Its ordinary variant uses synthetic signed proof statements, not
valid proofs. The provisional rejection fixture is synthetic in both variants; the real-proof
variant proves and verifies the accepted C0–C4 artifacts.

These private fixtures load checkpoints through production repositories/payloads below the disabled
extension-hydration and generation/calculation dispatch guards. They are not full node startup,
durable event-log replay, network delivery, process-crash durability, synchronized
publication/contract acceptance, secure-profile qualification or repeated-decryption assurance.

[`tests.rs`](src/tests.rs) exercises actor histories and restart/cutoff behavior;
[`tests/admission.rs`](src/tests/admission.rs) covers forged dealer inputs. Collection, roster,
state-transition, and payload-digest cases sit beside their pure modules. For complete
DKG/decryption scenarios use [e3-tests](../../testing/system/README.md). [AGENTS.md](AGENTS.md)
carries phase-order and secret-lifecycle editing rules.
