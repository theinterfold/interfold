# e3-request

The router owns admitted E3 contexts and recipient lifecycle, not the cryptographic statements of
those recipients. Canonical key admission is shared here so downstream users do not invent separate
authorities.

- Only chain facts/restored contexts admit an E3. Peer inputs cannot create one, and local result
  production cannot manufacture canonical completion.
- Keep the pre-admission peer hold separate from missing-recipient queues. Preserve identity/order
  when chain admission drains it; its oldest-event eviction and restart loss are explicit limits.
- Preserve checkpoint highest-sequence semantics across aggregates; the live routing path must not
  synchronously read repositories or replace hydrated actors with fresh ones.
- Extensions declare expected recipients. Deliver deferred history before the recipient-creating
  event, accounting each retained recipient copy. Bootstrap expects no protocol recipients.
- Propagate `E3Context::effects_enabled` when constructing actors during replay. Hydration is not
  the only path that must suppress timers and external effects until `EffectsEnabled`.
- Overflow isolates the missing recipient queue; it does not authorize silent whole-node dropping.
  Deferred queues/failure records and slashable-failure teardown grace are not durable today.
- Lifecycle is a projection; it accepts forward progress without regressing terminal state. Retained
  failures may still need accusation work, so local Failed is not proof that teardown is harmless.

[Persistence](../../docs/architecture/persistence-and-replay.md) owns the recovery/overflow limits.
Use the [README test map](README.md#tests). Routing changes need capacity and restart histories as
well as reducer cases; Linux RSS checks exercise another boundary.
