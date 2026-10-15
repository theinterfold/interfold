# Working on the blueprint

The blueprint navigates source and owner documentation; it is not a second protocol specification.
[README.md](README.md) covers building, browsing, checking, and PR previews.

- Add a crate's path under `crates/` (for example `zk/cli`) to `LAYERS` in `lib/inventory.mjs`. On
  removal/rename, update that inventory and its `facts/` entries together; contracts and circuits
  have their own inventories in the same file.
- Keep facts to short summaries and navigation/state/output details. Put detailed rules and limits
  in the owning domain document and link it using [the facts schema](facts/SCHEMA.md).
- Edit `curated.mjs`, facts, and evidence sources, not `out/` HTML. Reference tokens must identify
  code, while documentation links identify the explanation; one is not a substitute for the other.
- The build tolerates stale references; the check is strict. Inspect ambiguous `--fix` relocations
  rather than accepting the nearest matching token as semantic evidence. Ref selection must keep
  before/after documentation links on the corresponding diff side.

Run `node --test scripts/blueprint/documentation.test.mjs` for documentation/navigation changes and
`node scripts/blueprint/build.mjs` for rendering changes. Run `node scripts/blueprint/check.mjs` and
report pre-existing drift separately; a successful build does not mean the strict check passed.
