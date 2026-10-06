# Architectural component inventory

This inventory lists 25 responsibilities to understand and own. Some mechanisms, such as actors, are
implementation choices. Other responsibilities, such as recovery after a crash, are requirements.

An inventory row is a study unit. It does not imply a new crate, service, or repository. One
capability can require several of these responsibilities.

Implementation references follow branch `main`, reviewed on 2026-10-06. Its root manifests declare
version `0.18.0`. The branch and manifest version are readable locators, not an immutable pin. The
`v0.18.0` release tag points to a different snapshot. Unless stated otherwise, directory names below
refer to `crates/`.

## 1. Protocol state and execution

| #   | Component              | Current role and implementation                                                                                                  | Questions to answer                                                                                                    |
| --- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| 1   | Protocol state machine | Contracts define E3 stages and valid transitions. `request` tracks lifecycle state locally.                                      | Which state is authoritative? What permits each transition? How do local and on-chain states reconcile?                |
| 2   | Workflow coordination  | `request`, `keyshare`, `aggregator`, and `slashing` coordinate different parts of an E3 through events and local state machines. | Who decides the next action? Where is pending work recorded? Who detects that progress has stopped?                    |
| 3   | Actor model            | Actix actors receive messages and control access to runtime state.                                                               | Why is each actor an actor? What state does it exclusively own? Which decisions can run independently of Actix?        |
| 4   | Events and routing     | `events` defines shared messages and event infrastructure. `request` routes work to E3-specific components.                      | Is each message a command, a fact, or a notification? Who produces and consumes it? What happens without a consumer?   |
| 5   | Ordering and delivery  | Sequencing, timestamps, queues, and routing determine when components observe events.                                            | Which ordering guarantees are required? Can messages repeat, arrive late, or disappear? Where are these cases handled? |
| 6   | Timers and deadlines   | Contract deadlines and runtime timers govern timeouts, retries, and aggregator failover.                                         | Which clock is authoritative? Which deadlines survive restart? Does retrying preserve the original deadline?           |

Entry points:
[contract stages](../../packages/interfold-contracts/contracts/interfaces/IInterfold.sol),
[request lifecycle](../../crates/request/src/lifecycle/),
[aggregation handlers](../../crates/aggregator/src/public_key_aggregation/handlers.rs), and
[event infrastructure](../../crates/events/src/).

## 2. State, recovery, and external effects

| #   | Component                        | Current role and implementation                                                                                           | Questions to answer                                                                                                     |
| --- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 7   | Persistent state                 | `data` stores event history, snapshots, checkpoints, and protocol state.                                                  | What must survive a crash? What is authoritative versus derived? Which writes must succeed together?                    |
| 8   | Replay and recovery              | `sync` and `ciphernode-builder` restore snapshots, replay history, and reconcile chain and peer observations.             | What can be reconstructed? What cannot? When is the node ready to perform new work?                                     |
| 9   | External effects and idempotency | Components send transactions, publish network messages, launch jobs, and save results. Recovery can revisit pending work. | What happens after an effect succeeds but before its acknowledgement is saved? How do we recognize completed work?      |
| 10  | Networking                       | `net` manages peer discovery, gossip, documents, and historical exchange.                                                 | What do we trust from a peer? How are messages authenticated and validated? What happens during a partition?            |
| 11  | Blockchain integration           | `evm` reads chain events and submits transactions. `indexer` also supports application-facing chain observations.         | What counts as finalized? How are missed events recovered? How are reverted, pending, or repeated transactions handled? |
| 12  | Resource management              | `multithread`, proof workers, and runtime queues control expensive work and buffering.                                    | What bounds CPU, memory, and queue growth? What happens under overload? How are jobs cancelled or resumed?              |

Entry points: [storage](../../crates/data/src/), [recovery](../../crates/sync/src/sync/),
[node construction](../../crates/ciphernode-builder/src/ciphernode_builder.rs),
[networking](../../crates/net/src/), [EVM integration](../../crates/evm/src/), and
[worker scheduling](../../crates/multithread/src/).

These three concepts need separate answers:

- **Persistence:** What did we save?
- **Replay:** How do we rebuild state?
- **Idempotency:** What can we safely repeat?

A durable event does not, by itself, establish that every external effect executes exactly once.

## 3. Cryptography and application behavior

| #   | Component                         | Current role and implementation                                                                                                | Questions to answer                                                                                                                         |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 13  | Identity and secrets              | Cryptographic utilities, configuration, and startup code manage operator keys, peer identity, signing, and protected material. | Which key authorizes which action? Where does each secret live? How are secrets recovered, rotated, and destroyed?                          |
| 14  | Committee selection               | `sortition` and registry contracts determine eligibility, scores, membership, and party identity.                              | Why these selection rules? What is snapshotted? Which ordering and membership assumptions do later stages require?                          |
| 15  | Distributed keys and decryption   | `keyshare`, `trbfv`, `bfv-client`, and `fhe` implement key generation, share exchange, and threshold decryption.               | What does each participant know? What threshold protects privacy? What happens when members fail or disagree?                               |
| 16  | Proof generation and verification | `zk-prover`, `zk-helpers`, Noir circuits, and Solidity verifiers establish and connect cryptographic claims.                   | What exactly does each proof establish? Which inputs remain unproven? How is each proof bound to this E3, committee, and ciphertext?        |
| 17  | Application computation           | `compute-provider`, `program-server`, `support`, and application programs process ciphertexts and produce compute evidence.    | Who defines the function and input-selection policy? Does the receipt cover the exact published result? What can the coordinator influence? |
| 18  | Data availability                 | `data-availability` and application services publish and retrieve ciphertext bytes through Avail/VectorX.                      | What proves publication? What guarantees later retrieval? What happens when correct bytes are unavailable?                                  |
| 19  | Economics and fault handling      | Contracts and `slashing` implement fees, collateral, accusations, penalties, refunds, and rewards.                             | Who bears each failure? What evidence justifies punishment? Can settlement complete when participants disappear?                            |
| 20  | Client and application interfaces | Rust/TypeScript SDKs, WASM, React integration, and application contracts expose the protocol to users.                         | Which checks belong in clients versus contracts? What must clients verify independently? Which interfaces are stable promises?              |

Entry points: [sortition](../../crates/sortition/), [keyshare workflows](../../crates/keyshare/),
[circuit map](../../circuits/README.md), [prover](../../crates/zk-prover/),
[compute support](../../crates/support/README.md),
[CRISP program](../../examples/CRISP/program/src/lib.rs),
[data availability](../../crates/data-availability/src/lib.rs),
[contracts](../../packages/interfold-contracts/contracts/), and
[TypeScript SDK](../../packages/interfold-sdk/src/index.ts).

The cryptographic questions have different owners:

- Encryption determines how data stays confidential during computation.
- Threshold cryptography determines which cooperation permits decryption.
- Proofs establish specific statements about operations and their inputs.
- Application policy determines which inputs count and which output the application reveals.
- Availability determines whether participants can obtain the required bytes.

None of these responsibilities substitutes for the others.

## 4. Assembly, operation, and change

| #   | Component                            | Current role and implementation                                                                          | Questions to answer                                                                                                               |
| --- | ------------------------------------ | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 21  | Composition and configuration        | `ciphernode-builder`, `entrypoint`, and `config` assemble the runtime and select its behavior.           | Which combinations are valid? Which settings affect protocol compatibility? Who validates configuration before work starts?       |
| 22  | Builds and generated artifacts       | Root scripts connect Rust, Noir, WASM, verification keys, and Solidity verifiers.                        | What is the source of truth? What must be regenerated together? Can we reproduce and identify the exact deployed artifacts?       |
| 23  | Versioning and upgrades              | Release policy, storage schemas, wire formats, and cryptographic configuration govern compatibility.     | Can old and new versions coexist? What requires draining or resynchronization? What does rollback mean for saved state?           |
| 24  | Operations and observability         | CLI, dashboards, logs, deployment packages, and shutdown handling expose and control the running system. | Can an operator explain a stalled E3? What indicates readiness versus process health? What makes shutdown safe?                   |
| 25  | Verification and architectural rules | Tests, invariant documents, CI, and mechanical checks constrain changes.                                 | Which guarantees have executable checks? Which rely on review? What prevents forbidden dependencies or duplicated protocol rules? |

Entry points: [node construction](../../crates/ciphernode-builder/src/ciphernode_builder.rs),
[root commands](../../package.json), [circuit build](../../scripts/build-circuits.ts),
[release compatibility](../../crates/config/protocol-release.toml), [deployment](../../deploy/),
[DAppNode packaging](../../dappnode/), [invariants](../../agent/invariants/00_INDEX.md), and
[CI](../../.github/workflows/ci.yml).

## 5. How to use the inventory

Start with items 1–9. They explain how the node progresses, remembers, fails, and resumes. Then
study the cryptographic and infrastructure responsibilities against that execution model.

For each item, record the answer and its evidence in an [ownership record](OWNERSHIP_RECORD.md).
Separate implemented guarantees, intended guarantees, and unresolved questions. Use the matching
[flow trace](../../agent/flow-trace/00_INDEX.md) to follow interactions across components.

The goal is to explain each component in these terms:

> This responsibility belongs here, for this reason. These assumptions connect it to the rest of the
> system. These checks establish its guarantees.
