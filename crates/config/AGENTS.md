# e3-config

Keep configuration interpretation and path derivation here; runtime components should consume
resolved configuration instead of inventing their own precedence rules.

- Preserve explicit CLI path → ancestor search → default configuration resolution. Relative key,
  database, log, and program paths have different bases; use `PathsEngine` rather than cwd joins.
- Path changes can select another identity or durable store. Cover project-local and default OS
  layouts, named nodes, absolute overrides, and relative overrides before changing resolution.
- Keep supported program backend validation explicit. Legacy/unknown settings must not silently
  select a different proof backend; development execution requires its explicit configuration.
- Public network/release configuration is admission input, not proof that a chain or peer is
  trusted. Leave runtime chain-ID and compatibility checks at their existing boundaries.

Use the [README tests](README.md#tests). For changes to durable locations or release counters,
consult [upgrades](../../docs/architecture/upgrades.md) and test affected startup callers too.
