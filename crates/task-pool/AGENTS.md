# e3-task-pool

Keep this executor independent of protocol payloads, actors, cryptography and node configuration.

- Clones share one admission budget. Callers, not this crate, define group namespaces and memory
  policy.
- Cancellation rejects queued and future grouped work, but does not preempt a running native
  closure.
- Preserve panic/channel errors and keep diagnostic timed logs distinct from hard execution
  deadlines.
- Test actual semaphore/Rayon queue behavior, not only a cancellation flag.

Use the focused tests in [README.md](README.md).
