# e3-events

This crate owns event identity and the durable transport pipeline. It also contains rich protocol
payloads with crypto dependencies; do not mistake it for a dependency-free vocabulary layer or add
orchestration merely because many crates already import it.

- Keep logical event identity separate from delivery occurrence/transport. Equal EVM facts from
  distinct logs and equal verdicts from distinct dispatch batches must still reach projections.
- Snapshot pre-fanout admission happens before domain dedup, including replay. Log sync precedes
  dispatch; enqueuing a send is not durable acceptance.
- Route only configured aggregates. An unknown aggregate must signal fatal storage failure without
  dispatch or misrouting, using the same health path as append/flush errors. Dead fire-and-forget
  mailboxes do not automatically acquire that signal.
- Durable payload changes need schema/wire review beyond a Rust compile or updated layout fixture.
  Process readiness/effect/shutdown signals are current-boot control, not replayable instructions.

See [persistence](../../docs/architecture/persistence-and-replay.md) for actual guarantees and gaps.
Use the [README test map/prerequisites](README.md#tests). Failure-signal changes also need
production composition and CLI-exit coverage at their owners. Do not describe all actor panics as
supervised; checking event types alone does not exercise those integrations.
