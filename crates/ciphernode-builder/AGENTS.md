# e3-ciphernode-builder

See [README.md](README.md) for profiles, configuration, and handle lifecycle. This is the ciphernode
composition root. Protocol decisions belong to their capability crates; attach them here without
copying their rules. `builder/startup.rs` documents the dependency order of Storage → Restart → Live
→ Protocol; preserve the prerequisites, not just the current line order.

- Keep the full/bootstrap profiles closed: bootstrap has only the Interfold reader and no protocol
  extensions/writers or compute scheduler. Do not expose independent component switches that bypass
  role safety. It still owns router/lifecycle/sortition/DA infrastructure and needs an identity.
- Only `go_live` creates `ProviderCache<WriteEnabled>`; earlier phases remain read-only. Use enabled
  chain wrappers for provider work and retain chain ordering for resolved slashing managers.
- Restore canonical contexts, roles/slots, key authority, and verifier inputs before proof replay.
  Derived participation waits for SyncEffect. Missing/contradictory required state fails startup.
- Full-node startup requires a live SlashingManager for every enabled chain; bootstrap skips that
  resolution. Keep terminal-capacity cleanup tied to the restored lifecycle before historical sync.
- Validate new numeric options in `ensure_startup_options`; keep test-only options under
  `test-helpers` with `_for_testing`. Proof-skip support also requires its dedicated test-only
  feature.
- Do not make `e3-test-helpers` depend on this crate: lower-level tests would pull the complete
  stack and can cycle through event-system. Multi-node composition belongs in `crates/tests`.

[Persistence](../../docs/architecture/persistence-and-replay.md) owns startup and failure-signal
semantics; [slashing](../../docs/architecture/slashing.md) owns chain-specific manager resolution.
Use the [README test commands and prerequisites](README.md#tests). Recovery and profile changes need
the affected multi-node scenarios; in-memory construction alone is not restart coverage.
