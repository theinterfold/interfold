# e3-aggregator

## Purpose

Ciphernode capabilities for assembling a committee public key and decrypting the computed ciphertext
from threshold shares. These capabilities retain phase/recovery state; proof workers and EVM writers
perform the expensive computation and on-chain publication.

## Map

| Location                                                | Responsibility                                                            |
| ------------------------------------------------------- | ------------------------------------------------------------------------- |
| [`ext.rs`](src/ext.rs)                                  | Per-request factories and hydration for aggregation recipients and roles. |
| [`committee_finalization/`](src/committee_finalization) | Node-wide finalization requests and their chain/recovery context.         |
| [`public_key_aggregation/`](src/public_key_aggregation) | Public-key phase state, validation, pure transitions, and actor effects.  |
| [`plaintext_aggregation/`](src/plaintext_aggregation)   | C6 share admission, threshold reconstruction, C7 work, and publication.   |
| [`repo.rs`](src/repo.rs)                                | Typed persistence accessors for phase and recovery state.                 |

Each aggregation capability separates actor/handlers from state, transitions, validation, and
effects. Standbys collect inputs alongside the active aggregator. The active phase dispatches
compute/proof work and emits a publication intent; chain readers return the confirmed result.
Recovery restores the phase and inputs before effects resume.

## Runtime integration

Use the extensions in `e3_aggregator::ext` with an `e3_request::E3RouterBuilder`:

- `AggregatorRoleExtension::create(initial_roles)` supplies restored per-E3 aggregator roles.
- `PublicKeyAggregatorExtension::create(bus)` creates or hydrates the `publickey` recipient.
- `ThresholdPlaintextAggregatorExtension::create(...)` creates or hydrates `plaintext`, using the
  bus, sortition actor, proof-aggregation setting, canonical keys, and sequence-history reader.

The [ciphernode wiring](../ciphernode-builder/src/builder/extensions.rs) shows registration through
`with_recipient`, including the FHE dependency. Consumers do not construct the private
public-key/plaintext actor modules directly. `CommitteeFinalizer` is a separate node-wide actor; its
[startup caller](../ciphernode-builder/src/builder/startup.rs) provides recovery storage and
fresh-provider factories for the enabled chains.

Aggregation follows the canonical roster and active/standby roles, not the fastest arriving shares.
Plaintext reconstruction needs T+1 valid roster shares. Local aggregation results are publication
intents; confirmed contract events establish canonical completion.

## Using the capability

For a complete runtime use [CiphernodeBuilder](../ciphernode-builder/README.md). The crate also
exports typed recovery states and repository factory traits for persistence integration. See
[DKG](../../docs/architecture/dkg.md) and
[threshold decryption](../../docs/architecture/threshold-decryption.md) for protocol boundaries.

## Tests

Run `cargo test --locked -p e3-aggregator` from the repository root. Prepare the
[test-helper prerequisites](../test-helpers/README.md) first; the test graph includes chain fixtures
and the prover. Actor tests with mock proofs do not validate recursive proofs.

Public-key [tests](src/public_key_aggregation/tests) cover attestations and failures; plaintext
[tests](src/plaintext_aggregation/tests) cover share admission, thresholds, publication, completion,
and recovery. Neighboring `workflow_tests.rs` files exercise pure phase decisions separately from
actor delivery. Multi-node flows are in [e3-tests](../tests/README.md). See [AGENTS.md](AGENTS.md)
for change-specific rules.
