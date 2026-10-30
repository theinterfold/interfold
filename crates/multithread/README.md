# e3-multithread

## Purpose

Ciphernode compute dispatch for ZK and threshold-BFV work, using shared admission from
[e3-task-pool](../task-pool/README.md). It keeps expensive jobs off actor mailboxes and coordinates
replay-safe effects; protocol validity remains with the requesting capabilities.

## Map

| Location                               | Responsibility                                                                   |
| -------------------------------------- | -------------------------------------------------------------------------------- |
| [e3-task-pool](../task-pool/README.md) | Semaphore admission, Rayon execution, cancellation groups, and task results.     |
| [`memory.rs`](src/memory.rs)           | CPU/requested-job and host/cgroup-memory capacity calculation.                   |
| [`effect_gate.rs`](src/effect_gate.rs) | Current-boot dispatch gating, duplicate/redrive matching, and retained outcomes. |
| [`multithread.rs`](src/multithread.rs) | Bus-facing ZK/TrBFV dispatch, retries, request teardown, and result publication. |
| [`report.rs`](src/report.rs)           | Timing/capacity report actor and flattened diagnostics.                          |

The dispatcher admits an event through the effect gate, queues its work in the shared pool, executes
off the actor thread, and publishes a correlated result. Effect readiness and request termination
control admission independently of the pool's CPU/memory limits.

## Task pool

`TaskPool::new(threads, max_tasks)` separates worker-thread count from concurrent job capacity. Its
async `spawn(task_name, timed_logs, operation)` waits for admission and returns the operation's
result (or `TaskPoolError`). Timed logs describe elapsed work; they are not hard preemption of
executing Rayon closures.

The pool types are re-exported here for existing callers; `e3-task-pool` owns their implementation.
Prover-specific memory budgets remain in this runtime, not in the generic executor.

The composition root supplies the same pool and node scope to this dispatcher and the prover's C0
verification actor. C0 verification waits asynchronously for admission, keeps serial completion and
barrier ordering, and shares protocol cancellation groups. Pool failures are local infrastructure
outcomes. Cancellation retires pending C0 verification without retry or invalid-peer evidence.

### Ownership boundary

Selected compute-owner dependencies (Cargo manifests contain the full graph):

```text
ciphernode-builder -> multithread, zk/prover, task-pool
multithread        -> task-pool, zk/prover, trbfv
zk/prover          -> task-pool, zk/witness, zk/config, trbfv
task-pool          -> Rayon, Tokio (no protocol dependencies)
```

Circuit-request adaptation and ZK execution belong to
[`zk/prover`](../zk/prover/src/request_execution.rs); deterministic preparation remains in
`zk/witness`. This dispatcher owns admission, replay gates, retry policy, correlation, timing
publication and terminal filtering. Native request execution, RNG access and typed calculation
failures belong to `trbfv`. The dispatcher only wraps native results with their E3/correlation
identity; it contains no circuit or threshold calculation. The memory-only gate is not a
transactional outbox.

The extraction preserves the existing pool-type re-exports and changes no persisted/event/wire
encoding or cryptographic statement. `setup_zk_actors` and `ZkActor::new` now require the shared
pool and node scope, so direct Rust callers must supply them when constructing the runtime. No
protocol/schema or node-generation counter change is proposed for this ownership split.

For production sizing, `ComputeCapacity::detect(requested_jobs, cpu_jobs)` applies CPU and detected
host/cgroup-memory limits. [CiphernodeBuilder](../ciphernode-builder/README.md) exposes
`with_multithread_config` and optional shared task pools/reports. ZK and TrBFV work share admission
instead of each using unrelated pool capacity.

## Event-driven workers

`Multithread::attach` installs threshold-BFV dispatch. `attach_with_zk` additionally supplies the
prover backend, restored lifecycle stages, and canonical keys. Both need the bus, RNG, local cipher,
task pool, and node-specific task scope; see the
[builder caller](../ciphernode-builder/src/builder/extensions.rs) for the complete wiring. These are
node-wide workers, not per-E3 router extensions.

Dispatch correlates jobs with their request/E3 and gates recovery on current-boot effect readiness.
Queued cancellation does not stop an executing closure. Prover process deadlines are separate, and
local resource failure is not proof that a peer supplied invalid crypto. `MultithreadReport` /
`ToReport` expose timing and capacity diagnostics, not proof validity.

See
[effect recovery](../../docs/architecture/persistence-and-replay.md#effect-recovery-and-shutdown)
for admission/retry limits.

## Tests

`cargo test --locked -p e3-multithread` transitively builds the prover; read its
[build prerequisites and side effects](../zk/prover/README.md) first.

Inline suites distinguish deterministic capacity calculations, effect-gate replay/redelivery, and
bus dispatch/retry/teardown. Pool cancellation/panic tests live in `e3-task-pool`. Fake outcomes
test scheduling and correlation, not production prover resource use. [AGENTS.md](AGENTS.md) covers
scheduler changes.
