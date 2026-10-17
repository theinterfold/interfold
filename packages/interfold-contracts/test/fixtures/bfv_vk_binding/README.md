# BFV VK binding fixtures

Golden `dkg_aggregator` / `decryption_aggregator` EVM proofs for
`test/BfvVkBindingIntegration.spec.ts` (insecure minimum preset).

## Explicit refresh

An insecure Rust benchmark run can export `integration_summary.json`. Run
`sync_bfv_vk_binding_fixture.sh <summary-path>` explicitly to update this
directory's `folded_artifacts.json`. The benchmark runner does not overwrite
committed fixtures automatically.

`BfvVkBindingIntegration` also reads `integration_summary.json` directly when
present, so local `pnpm evm:test` stays aligned even before you commit the
synced fixture.

## Manual override

```bash
./circuits/benchmarks/scripts/sync_bfv_vk_binding_fixture.sh
```

Or set `BFV_VK_BINDING_FOLDED_ARTIFACTS` to a folded-artifacts JSON file (or an
`integration_summary.json` containing `.folded_artifacts`).
