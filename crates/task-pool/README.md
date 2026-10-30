# e3-task-pool

Bounded CPU execution over Rayon, with Tokio admission and caller-named cancellation groups. This
crate knows nothing about E3s, event replay, cryptography, actors, or prover memory requirements.

`TaskPool::new(threads, max_tasks)` separates worker count from concurrent admission. Clone the pool
to share its semaphore and worker threads; constructing another pool creates another resource
budget. `spawn` executes ordinary work; `spawn_in_group` also checks cancellation before admission
and before the queued closure starts. `cancel_group` permanently cancels that caller-defined group,
and `wait_for_retry` makes retry waits interruptible. Running closures are not preempted.

The caller owns group identity, retry classification, result correlation, terminal filtering, and
capacity policy. `TaskTimeouts` schedules diagnostic logs, not execution deadlines. Panics return a
structured `TaskPoolError`; actual process deadlines remain with process adapters.

Run `cargo test --locked -p e3-task-pool` for queued cancellation, retry cancellation and panic
coverage. No chain, FHE or prover preparation is required.
