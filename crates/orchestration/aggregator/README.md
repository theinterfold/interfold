# e3-aggregator

## Purpose

Ciphernode capabilities for assembling a committee public key and decrypting the computed ciphertext
from threshold shares. These capabilities retain phase/recovery state; proof workers and EVM writers
perform the expensive computation and on-chain publication.

## Map

| Location                                                | Responsibility                                                            |
| ------------------------------------------------------- | ------------------------------------------------------------------------- |
| [`ext.rs`](src/ext.rs)                                  | Per-request factories and hydration for aggregation recipients and roles. |
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
- `PublicKeyAggregatorExtension::create(...)` creates or hydrates the `publickey` recipient, using
  the bus, sequence-history reader, shared canonical keys and configured controllers.
- `ThresholdPlaintextAggregatorExtension::create(...)` creates or hydrates `plaintext`, using the
  bus, sortition actor, proof-aggregation setting, canonical keys, and sequence-history reader.

The [ciphernode wiring](../../ciphernode/builder/src/extensions.rs) shows registration through
`with_recipient`, including the FHE dependency. Consumers do not construct the private
public-key/plaintext actor modules directly. Committee formation is owned by
[sortition](../sortition/Readme.md#runtime-integration), not aggregation. Canonical-key inputs come
from the shared `e3_request::canonical_key` authority; local aggregation results do not create a
second authority.

Aggregation follows the canonical roster and active/standby roles, not the fastest arriving shares.
Plaintext reconstruction needs T+1 valid roster shares. Local aggregation results are publication
intents; confirmed contract events establish canonical completion.

The disabled synchronized publication path fixes its batch from the node collector's local recipient
verdict. It binds authenticated C1 inputs to the canonical request and native PK bytes even before
that verdict, independently aggregates the shares, joins selected recipient proofs, and requires
every H recipient's consent over the exact frozen domain and anchors. Standbys retain inputs too;
the node that starts C5 continues after demotion. Exclusive flushed records preserve native inputs,
successful proof bytes and original causation across restart. Worker correlations are boot-local.
Unrelated compute outcomes are ignored. Local generation failures and recipient-proof repairs use a
coalesced, capped-backoff actor retry; malformed parameters do not automatically retry. A standby
cannot start work, but a recorded started owner can finish after demotion. This path emits a local
publication intent; registry writing and activation remain unfinished.

Failed flushes retain validated progress and retry with current-boot effects, including on standbys,
but emit no readiness, compute or publication intent until the flush succeeds. Storage retries
preserve live worker correlations; canonical publication/termination cancels both storage and worker
retries.

Missing C5/wrapper outcomes trigger fresh-correlated redelivery through the compute gate, which owns
running-job deduplication. Known frozen consent domains are checked before slot replacement, also
during replay. Peer SK/bundle anchors remain provisional until the wrapper is verified, so they
cannot erase early consent; output still requires every exact verified anchor.

## Using the capability

For a complete runtime use [CiphernodeBuilder](../../ciphernode/builder/README.md). The crate also
exports typed recovery states and repository factory traits for persistence integration. See
[DKG](../../../docs/architecture/dkg.md) and
[threshold decryption](../../../docs/architecture/threshold-decryption.md) for protocol boundaries.

## Tests

Run `cargo test --locked -p e3-aggregator` from the repository root. Prepare the
[system prerequisites](../../testing/system/README.md#prerequisites-and-assurance) first; the test
graph includes chain fixtures and the prover. Actor tests with mock proofs do not validate recursive
proofs.

Public-key [tests](src/public_key_aggregation/tests) cover attestations, failures, and replay;
plaintext [tests](src/plaintext_aggregation/tests) cover share admission, thresholds, publication,
completion, and recovery. Neighboring `workflow_tests.rs` files exercise pure phase decisions
separately from actor delivery. Multi-node flows are in [e3-tests](../../testing/system/README.md).
See [AGENTS.md](AGENTS.md) for change-specific rules.

The BFV/event setup tuple is private to these aggregation tests. Event-only consumers use
event-system's opt-in fixture rather than constructing unrelated BFV material.
