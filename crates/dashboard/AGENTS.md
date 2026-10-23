# e3-dashboard

Keep the operator dashboard a read-only projection, not an alternate source of protocol decisions.

- The HTTP API deliberately binds to loopback and is unauthenticated; it exposes detailed event and
  operational data. Do not broaden the binding without designing access control.
- Refresh incrementally from each aggregate's sequence cursor. Paging must advance from observed
  sequences, not wall-clock time; a dashboard query must not publish or replay protocol effects.
- Operator RPC status is cached diagnostic data, not canonical eligibility or lifecycle authority.
  Keep timeout/errors visible instead of displaying stale status as current chain truth.
- Operational logs come from the bounded logger collector; durable event history comes from the
  EventStore. Keep their cursor/retention expectations separate, including in the embedded UI.

Use the [README tests/prerequisites](README.md#tests) for projection/update behavior. RPC-facing
changes need explicit adapter coverage rather than assuming projection tests contact a chain.
