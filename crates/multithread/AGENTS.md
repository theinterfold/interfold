# e3-multithread

`e3-task-pool` owns resource admission; ComputeEffectGate owns replay-safe worker dispatch, not
protocol validity. Preserve shared capacity for ZK/TrBFV work rather than spawning around its
semaphore.

- Correlate a result with its exact E3/request. Replayed success may satisfy regenerated
  correlations; replayed errors must not suppress recovery. Successful random TrBFV output is
  reused, not regenerated.
- Protocol task cancellation is node-scoped as well as E3-scoped. Accusation re-verification has its
  own group and survives local E3 failure until request teardown.
- Queued cancellation does not preempt executing Rayon work. Keep terminal filtering and the
  prover's process timeout; local resource failures cannot become invalid-peer evidence.
- A missing-outcome redelivery waits until no matching job remains queued/running. Memory-only gate
  buffers are not a transactional outbox or a complete exactly-once guarantee.

[Persistence](../../docs/architecture/persistence-and-replay.md#effect-recovery-and-shutdown) owns
budgets/retries and current limits. Use the [README tests/prerequisites](README.md#tests). Gate and
retry changes need replay/redrive/cancellation histories; fake outcomes do not measure production
prover memory or verify cryptographic correctness.
