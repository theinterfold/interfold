# e3-events

This crate owns event identity and the durable transport pipeline. It also contains rich protocol
payloads with crypto dependencies; do not mistake it for a dependency-free vocabulary layer or add
orchestration merely because many crates already import it.

- Keep logical event identity separate from delivery occurrence/transport. Equal EVM facts from
  distinct logs and equal verdicts from distinct dispatch batches must still reach projections.
- Snapshot pre-fanout admission happens before domain dedup, including replay. Log sync precedes
  dispatch; enqueuing a send is not durable acceptance.
- Route only configured aggregates. A panic from an invalid route or a dead fire-and-forget mailbox
  is not automatically a process failure signal. Append/flush errors use the explicit health path.
- Durable payload changes need schema/wire review beyond a Rust compile or updated layout fixture.
  Process readiness/effect/shutdown signals are current-boot control, not replayable instructions.

See [persistence](../../docs/architecture/persistence-and-replay.md) for actual guarantees and gaps.
`cargo test -p e3-events` covers eventstore failure signals and fanout; production signal wiring and
CLI exit are separate owner tests. Do not describe all actor panics as supervised. Crate tests pull
in [test helpers](../test-helpers/AGENTS.md) with chain/prover build prerequisites; checking the
event types alone does not exercise those integrations.
