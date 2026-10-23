# e3-logger

Keep protocol observation and operational diagnostics passive; the EventStore remains event history.

- Protocol logs summarize structured metadata, not whole cryptographic payloads. Never add secret,
  plaintext, credential, or multi-megabyte Debug dumps to improve observability.
- Redaction is field-name based and cannot sanitize arbitrary message text. Preserve inherited-span
  filtering and the separate OpenTelemetry metadata filter: one layer cannot rewrite a sibling's
  export, and truncation is not secret removal.
- Assign collector sequence numbers under the insertion lock so cursor pagination remains ordered.
  Bounded retention/rotating files are diagnostics, not a replay log or durable delivery guarantee.
- Global collector initialization keeps the first instance, like tracing's subscriber. Use local
  collector instances in focused tests instead of depending on test execution order.

Use the [README tests](README.md#tests); changed paths need redaction/cursor/rotation coverage as
applicable. Logger failure should not acquire protocol authority or reorder events; see
[persistence](../../docs/architecture/persistence-and-replay.md).
