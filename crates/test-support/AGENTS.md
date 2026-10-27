# e3-test-support

Keep this unpublished crate limited to mechanical support with independent test-suite consumers. No
internal-crate dependencies, domain fixtures, application examples, or node composition belong here.
Consumers use dev-dependencies; do not add compatibility re-exports for relocated fixtures.

- Preserve deterministic seed derivation and separate RNG mutexes per simulated node.
- Keep tracing scoped and tool discovery read-only. Discovery or a skip is not proof evidence.
- Event runtime fixtures belong to event-system; BFV ballots have their own small fixture owner;
  complete composition and mock transport belong to e3-tests.

Use the [README tests](README.md#tests) and verify focused consumer graphs, not only workspace
tests.
