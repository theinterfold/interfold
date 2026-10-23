# e3-zk-benchmarks

This unpublished development runner owns benchmark selection, orchestration, records, and reports.
[README.md](README.md) owns commands, measurement rules, and provenance.

- Use samples through the explicit unpublished normal-dependency exception; exercise production
  preparation, Noir execution, and BB adapters rather than copies of their logic.
- Keep phase timing kinds distinct. Missing/failed measurements remain incomplete, never zero or
  success. Do not sum overlapping job time into end-to-end wall time.
- Validate artifact digests, pair, compiler, and proof variant. A config cache needs its own source,
  compiled, and VK provenance; never assign a hydrated hash to a fresh compilation.
- Forward the validated BB path to protocol children.
- Replay saved proofs without reproving; report runs no tools. Preserve historical runs and refuse
  nonempty output directories. Calldata gas cannot substitute for verifier gas.

Run `pnpm test:circuit-bench` and the affected script harness. Real gas/protocol qualification needs
prepared artifacts and explicit proof runs, not mocked command outcomes.
