# Architecture assessment

This assessment records implementation evidence and architectural judgments from the study
discussion. It follows branch `main`, reviewed on 2026-10-06. Its root manifests declare version
`0.18.0`. The branch and manifest version are readable locators, not an immutable pin. The `v0.18.0`
release tag points to a different snapshot. The [component inventory](COMPONENT_INVENTORY.md) turns
these observations into specific study questions.

## 1. The implemented architecture

The most defensible description is:

> Interfold is a distributed cryptographic protocol implemented across several languages. Its
> ciphernode runtime uses actors, events, durable event history, replay, and capability-specific
> state machines.

These patterns describe different dimensions of the system. They coexist rather than compete as one
architecture label.

| Pattern                                                          | Implementation evidence                                                                                                                                                           | What the evidence establishes                                                                                     |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Actor model                                                      | [`lifecycle/actor.rs`](../../crates/request/src/lifecycle/actor.rs), `Actor` and `Handler` implementations.                                                                       | Components receive messages and control access to owned runtime state.                                            |
| Event-driven coordination                                        | [`public_key_aggregation/handlers.rs`](../../crates/aggregator/src/public_key_aggregation/handlers.rs), `Handler<InterfoldEvent>`.                                                | Aggregation reacts to keyshares, verification results, compute responses, membership changes, and failover.       |
| Durable event logging                                            | [`eventstore.rs`](../../crates/events/src/eventstore.rs), `store_event`.                                                                                                          | The store appends and flushes an event before returning it for dispatch. History supports execution and recovery. |
| Snapshot recovery and replay                                     | [`sync/service.rs`](../../crates/sync/src/sync/service.rs), `reconcile_request_router_checkpoint`.                                                                                | Recovery reconstructs routing state from saved checkpoints and event history.                                     |
| Functional core with an imperative shell, in specific components | [`lifecycle/workflow.rs`](../../crates/request/src/lifecycle/workflow.rs), `observe`, and [`lifecycle/actor.rs`](../../crates/request/src/lifecycle/actor.rs), its event handler. | Decision logic calculates lifecycle changes. The actor handles runtime and persistence effects.                   |
| Composition root                                                 | [`ciphernode_builder.rs`](../../crates/ciphernode-builder/src/ciphernode_builder.rs), `build_inner`.                                                                              | One construction point connects storage, recovery, networking, chain access, and protocol actors.                 |
| Ports and adapters, in specific interfaces                       | [`ciphertext_output.rs`](../../crates/compute-provider/src/ciphertext_output.rs), `ComputeProvider`.                                                                              | Computation orchestration can use an interface rather than one proving implementation.                            |

### Where the labels stop

The evidence does not establish clean or hexagonal architecture across the entire implementation.
Those approaches require controlled dependency directions between domain logic and infrastructure.

The [aggregator manifest](../../crates/aggregator/Cargo.toml) directly depends on Actix, concrete
storage, EVM integration, keyshare workflows, and proof infrastructure. Its actor-free
[workflow module](../../crates/aggregator/src/public_key_aggregation/workflow.rs) also imports
functionality from `e3-zk-prover`.

This does not establish a correctness defect. It establishes that module-level separation does not
provide complete crate-level isolation.

Other labels also need care:

- Event logging and replay do not establish a uniform event-sourcing model for all state
  transitions.
- Domain-specific names do not establish complete domain-driven design or explicit bounded contexts.
- Separate executables do not make the Rust crates inside a ciphernode independently deployed
  microservices.

The [target architecture](../../agent/ARCHITECTURE.md) explicitly distinguishes its design
constraints from current implementation. The
[Rust architecture map](../../agent/CRATES_ARCHITECTURE.md) describes current dependencies and
runtime behavior.

## 2. Architectural judgment

**The main runtime choices fit Interfold. The current component boundaries need improvement to
support clear ownership and predictable changes.**

This is an engineering judgment based on the observed responsibilities and dependencies. It is not a
measured comparison of all possible architectures.

### Choices worth retaining

| Choice                               | Why it fits the problem                                                                                                                   |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Actors                               | A node handles chain events, peer messages, timers, and job results concurrently. Actors provide useful state and concurrency boundaries. |
| Deterministic state machines         | Protocol decisions can be explained and tested separately from networking and expensive cryptography.                                     |
| Durable recovery                     | Nodes can restart during key generation or decryption. They need to recover their existing obligations.                                   |
| Separate application computation     | Application execution and committee key management have different inputs, resource needs, and correctness conditions.                     |
| Specialized implementation languages | Rust, Noir, Solidity, and TypeScript serve distinct runtime, proof, settlement, and client responsibilities.                              |

These choices require explicit contracts. Their presence alone does not establish correct ordering,
safe recovery, or compatible proof formats.

### Improvement area: workflow ownership

The `E3LifecycleCoordinator` observes lifecycle events and saves the resulting state. It does not
direct the whole protocol. Aggregation and other subsystems separately react to events and maintain
their own progress.

Understanding the next required action therefore involves several subscribers and their states. Each
local workflow needs an identifiable owner for pending work, completion conditions, failures, and
restart behavior.

This recommendation does not imply one coordinator for the whole node. It calls for an explicit
division of coordination responsibilities.

### Improvement area: shared dependencies

The [events crate](../../crates/events/Cargo.toml) combines event infrastructure with rich protocol
payloads and cryptographic dependencies.

At the source snapshot, manifest inspection found:

- 20 root workspace members directly depend on `e3-events`.
- `e3-aggregator` has 17 direct dependencies on other root workspace members.

These counts use normal dependency sections, including target-specific sections. They exclude
development-only dependencies but include test-support workspace members. They identify broad
dependencies, rather than measure architectural quality.

The study question is whether each consumer needs the complete dependency or a smaller, stable
interface within it.

### Improvement area: recovery contracts

A component's contract includes more than its successful execution. It also includes saved state,
durable progress, repeated actions, restart behavior, and compatibility with older state.

These responsibilities need to remain understandable together. Otherwise, a local change to the
successful path can affect recovery elsewhere.

### What this assessment cannot establish

The architecture alone cannot establish the cause of the team's reported regressions. That requires
examining actual failures, the changes that introduced them, and the checks that missed them.

Past decision rationale and human ownership also require team input. Code evidence establishes what
the implementation does, but rarely establishes why the team selected it.

## 3. Repository organization

Several libraries inside one process are normal. A crate is not required to be a service. The
important question is whether each component has a clear responsibility and controlled dependencies.

### Four different boundaries

| Boundary               | Question it answers                                    |
| ---------------------- | ------------------------------------------------------ |
| Ownership and domain   | Who owns this behavior, its state, and its invariants? |
| Package and build      | What compiles together, and what API does it expose?   |
| Process and deployment | What runs, fails, and scales independently?            |
| Repository and release | What changes, versions, and distributes independently? |

These boundaries do not need to coincide. A cryptographic library can have a dedicated owner, API,
invariant set, and release policy while running inside a ciphernode process.

### Current organization

The repository combines several organizing principles:

- Language and tooling: `crates/`, `packages/`, and `circuits/`.
- Protocol capabilities: `keyshare`, `sortition`, and `slashing`.
- Infrastructure: `data`, `net`, and `evm`.
- Applications: CRISP and the project template.
- Cross-component concerns: artifact generation, deployment, and release tooling.

As a result, ownership of a directory does not necessarily cover a complete capability.

Two concrete examples show the difference between directory boundaries and independent components:

- The [SDK prebuild](../../packages/interfold-sdk/package.json) builds contracts, Rust WASM, and
  circuits.
- [CRISP's Cargo workspace](../../examples/CRISP/Cargo.toml) imports core crates through relative
  source paths.

Separate repositories would retain these dependencies unless their interfaces and artifact
consumption changed too. They would also require coordination between repository versions.

### Recommendation from the discussion

First establish component boundaries and ownership within the existing monorepo. Consider separate
repositories where independent releases, access control, or external consumers justify them.

A component can contain several crates and languages when those implementations jointly fulfill one
responsibility. Each component needs an identifiable owner, supported interface, allowed
dependencies, invariants, verification commands, and compatibility obligations.

This is a recommendation, not a completed decomposition or an agreed repository plan.

## 4. Key distinctions to preserve

- A package boundary does not imply an ownership, process, or compatibility boundary.
- A documented architectural target does not establish current compliance.
- A deterministic workflow module does not automatically isolate its crate from infrastructure.
- Persistence, replay, and idempotency answer different questions.
- Cross-language agreement is part of correctness, not merely build tooling.
- An invariant document is a requirement or review claim, not proof of enforcement.
- Moving code does not remove the assumptions that connect it to other code.

The desired outcome is a system whose responsibilities, decisions, dependencies, and failure
behavior each have an accountable owner.
