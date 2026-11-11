# BFV VK binding fixtures

Golden `dkg_aggregator` / `decryption_aggregator` EVM proofs for
`test/BfvVkBindingIntegration.spec.ts` (insecure minimum preset).

## Explicit refresh

An insecure Rust benchmark run can export `integration_summary.json`. Run
`sync_bfv_vk_binding_fixture.sh <summary-path>` explicitly to update this
directory's `folded_artifacts.json`. The benchmark runner does not overwrite
committed fixtures automatically.

`BfvVkBindingIntegration` reads `BFV_VK_BINDING_FOLDED_ARTIFACTS` first, then
the committed fixture. It reads the benchmark summary at
`circuits/benchmarks/results_insecure_minimum/integration_summary.json` only
when the fixture is absent. To verify a fresh benchmark run without changing the
fixture, set `BFV_VK_BINDING_FOLDED_ARTIFACTS` to the `integration_summary.json`
of that run. The sync script below rewrites the fixture.

## Manual override

```bash
./circuits/benchmarks/scripts/sync_bfv_vk_binding_fixture.sh
```

Or set `BFV_VK_BINDING_FOLDED_ARTIFACTS` to a folded-artifacts JSON file (or an
`integration_summary.json` containing `.folded_artifacts`).
