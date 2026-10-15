# e3-sortition

Keep score/snapshot/admission decisions with the selection workflow; actors own timing and delivery.
Contract selection is authoritative, but runtime party slots normalize the finalized addresses into
ascending order. Submission score rank and on-chain array position are not interchangeable party
IDs.

- Historical eligibility, owners, and ticket price must use the same request-time boundary.
  Ingestion time cannot repair missing chain-time owner/admission history; retain the explicit
  fallback.
- Active-job limits gate this node's voluntary submission, never the canonical ticket range. Persist
  provisional reservation before dispatch and reconcile it on canonical finalization/termination.
- Aggregator deadlines begin at durable phase readiness, not merely a stage event. Preserve absolute
  deadline and phase-local skips on unchanged assignment; roster and PK phases have separate
  budgets.
- Backfill only missing versioned recovery records. Existing ticket intents keep ticket number/rank;
  snapshot-derived roles/selections are injected, not appended as synthetic facts on every boot.

See [selection](../../docs/architecture/committee-selection.md) and
[DKG](../../docs/architecture/dkg.md). Run `cargo test -p e3-sortition`; on-chain score/owner-cap
behavior also needs the contract suite.
