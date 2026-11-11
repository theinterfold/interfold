# BFV VK binding fixtures

Golden `dkg_aggregator` / `decryption_aggregator` EVM proofs for
`test/BfvVkBindingIntegration.spec.ts` (insecure minimum preset).

## Explicit refresh

An insecure Rust benchmark run can export `integration_summary.json`. Run
`sync_bfv_vk_binding_fixture.sh <summary-path>` explicitly to update this
directory's `folded_artifacts.json`. The benchmark runner does not overwrite
committed fixtures automatically.

`BfvVkBindingIntegration` prefers the committed fixture. To verify a fresh
benchmark run without changing it, use the override below; a local summary is
otherwise only a fallback when the fixture is absent.

## Manual override

```bash
./circuits/benchmarks/scripts/sync_bfv_vk_binding_fixture.sh
```

Or set `BFV_VK_BINDING_FOLDED_ARTIFACTS` to a folded-artifacts JSON file (or an
`integration_summary.json` containing `.folded_artifacts`).
