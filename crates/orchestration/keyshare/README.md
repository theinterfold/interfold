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

The disabled `synchronized` capability retains the node collector's locally admitted recipient
result in an exclusive flushed setup intent before producing consent. Native PK shares come from the
authenticated fixed C4 batch and survive retirement of encrypted transport. Consent waits for
current-boot effects and the shared chain-frozen domain. Only H recipients sign. If event admission
refuses consent, retry the signed payload from the flushed intent with its original causation.
Confirmed publication, terminal cleanup and shutdown stop those attempts. SS terminal cleanup does
not access the synchronized setup store. A restored `SynchronizedSetupIntent::confirmed_setup`
rechecks native PK bytes, sealed keys and local anchors against shared confirmed authority,
including outside-H recipients. This is the read-only #2050 boundary; admitted full-node startup
remains unqualified.

A closed setup store stops automatic attempts for the current boot. Outside shutdown, check the
storage service before restarting; closure does not indicate damaged data. An intent that cannot be
decoded or validated is left untouched. Stop the node and preserve the store, aggregate logs, and
matching key configuration. If recovery is needed, use a verified, schema-compatible backup for the
same node with matching logs and key material, or escalate if none exists. Do not delete or patch
the row to resume an active committee: replay cannot recreate secret shares. See
[state recovery and rollback](../../../docs/architecture/upgrades.md#controlled-state-reset-never-directory-deletion).
Retryable storage failures retain the candidate and back off only with current-boot effects, with
one journal error per failure episode.

The threshold-share soft checkpoint can advance when every missing dealer lacked a C0 key at
key-collection closure. Verification still needs H−1 external shares, and collection remains open
until completion or the canonical DKG deadline.

Successful randomized contributions are reused after restart. On the disabled fixed-set route, a
designated keyshare that misses the live opening or restarts before saving its allocation cannot
contribute from replay. Secret material is wrapped in local encrypted storage; do not treat the
exported state types as safe plaintext diagnostics. Detailed dimensions, roster transitions, proof
batches, and recovery limits are in [DKG](../../../docs/architecture/dkg.md) and
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
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 E3_CUSTOM_BB=$(which bb) cargo test --locked -p e3-keyshare --lib synchronized_native_worker_real_c6_and_signed_reuse -- --ignored
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 E3_CUSTOM_BB=$(which bb) pnpm rust:test:sync-dkg:recovery
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 E3_CUSTOM_BB=$(which bb) pnpm rust:test:sync-dkg:qualification
```

The proof commands require pinned nargo/bb and stage explicit variants in temporary directories,
preserving source dependency pins. The C1–C4 command verifies ten real proofs. The C6 worker test
reopens the saved native shares after prover failure, proves both designated contributions and
checks native plaintext reconstruction. Its DKG verdict is a fixture. The recovery command verifies
the DKG proofs: C0–C4 across three independent actors/stores, then dealer/recipient joins, C5 and
publication from their reopened signed artifacts, sealed keys and native PK-share bytes. Only H
reopens setup and consents before registry publication. The outside-H join is dispatched before or
after publication in separate histories; both late results must produce a durable local setup for
the authority rebuilt from the mined journal, with no consent or publication on reopen. The
rehearsal continues with the reopened SKs and a mined ciphertext reference. The production DA
coordinator reads a local HTTP object and delivers the opening to both designated actors. A demoted
collector reopens its journal and plaintext checkpoints, verifies both C6 rows and finishes the same
started batch. It checks the reconstructed plaintext, C7 and final proof through the writer's
request-bound transaction and the inclusive on-chain deadline. It requires Anvil,
`pnpm install --frozen-lockfile`, `pnpm evm:build` and solc 0.8.28 on PATH; generated Honk/Solidity
acceptance and substitution rejection are mandatory, not skipped when unavailable. It tests orderly
stop/flush/cache eviction/reopen, exact saved work, non-prefix H `[0,2]`, self/outside-H recipients
and authenticated replacement. Its ordinary variant and provisional negatives use synthetic signed
statements, not valid proofs.

The qualification command selects all synchronized keyshare cases except the
[opt-in CLI request benchmark](../../zk/benchmarks/README.md#synchronized-minimum). It includes
recovery and a complementary durable-log replay test. That test reopens actual commit logs through
`EventSystem` and production startup sync, preserves aggregate sequence despite decreasing HLC,
filters stale boot controls and records authenticated replacements without effects until this boot's
fresh enable signal. Snapshot persistence assertions follow an acknowledged drain; event-log flush
alone does not drain buffered snapshots.

To select secure Minimum for the signed rehearsal and rebuild both candidate manifests, use the
[guarded `--signed` runner](../../../scripts/circuits/README.md#synchronized-decryption-candidates).
It first needs a signed insecure control export. The request's selected profile follows the sealed
inputs on reopen; the resulting public proofs can be checked without retaining private inputs.

These private fixtures load checkpoints through production repositories/payloads below the disabled
extension-hydration and generation/calculation dispatch guards. Replay supplies empty historical
EVM/network adapters; the DKG proof campaign drives prepared requests explicitly, and the decryption
actors use the bounded worker and the writer effect below admission. Neither fixture establishes
whole-node startup, admitted production publication orchestration, network delivery, process-crash
durability or repeated-decryption assurance. The local registry campaign seeds its finalized
committee/controller lifecycle below disabled admission; it does not test the production
request/sortition path.

[`tests.rs`](src/tests.rs) exercises actor histories and restart/cutoff behavior;
[`tests/admission.rs`](src/tests/admission.rs) covers forged dealer inputs. Collection, roster,
state-transition, and payload-digest cases sit beside their pure modules. For complete
DKG/decryption scenarios use [e3-tests](../../testing/system/README.md). [AGENTS.md](AGENTS.md)
carries phase-order and secret-lifecycle editing rules.
