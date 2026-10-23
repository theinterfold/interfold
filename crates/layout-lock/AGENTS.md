# e3-layout-lock

This test utility samples serde layouts to make persisted/wire encoding changes visible.

- Keep named and positional digests distinct: names/layout traces reveal structural changes while
  positional samples distinguish actual bytes from cosmetic renames. Neither is a semantic proof.
- Samples must remain deterministic across runs. Length retries and recursion bounds support
  constrained byte types; do not silently skip a root whose deserializer rejects a sample.
- Keep documented blind spots visible: unlisted roots, hand-written framing, opaque encrypted
  payloads, and some equal-width signedness changes are outside this lock's assurance.
- `LAYOUT_LOCK_UPDATE=1` rewrites consumer fixtures. Use it only after reviewing compatibility and
  the required schema/wire version decisions, never as the default response to a failing lock.

Use the [README utility/consumer tests](README.md#tests), then the affected consumer's fixture.
Sampling changes need independent synthetic counterexamples rather than only refreshing runtime
rows. See [upgrades](../../docs/architecture/upgrades.md) before approving changed fixture bytes.
