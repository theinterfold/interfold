# BFV VK binding fixtures

Golden `dkg_aggregator` / `decryption_aggregator` EVM proofs for
`test/BfvVkBindingIntegration.spec.ts` (insecure minimum preset).

## Which artifacts the test reads

`BfvVkBindingIntegration` takes the folded artifacts from the first usable
source:

1. `BFV_VK_BINDING_FOLDED_ARTIFACTS`, when it is set: a folded-artifacts JSON
   file, or a file named `integration_summary.json` whose `.folded_artifacts`
   holds them. The test then reads no other source.
2. `folded_artifacts.json` in this directory.
3. `circuits/benchmarks/results_insecure_minimum/integration_summary.json`.

A source is unusable when its file is absent or when its JSON is missing any of
the `proof_hex` and `public_inputs_hex` strings of the two aggregators. A
committed fixture with the wrong shape therefore falls back to a local benchmark
summary, so a passing run does not show that the committed fixture was checked.
When no source is usable, the folded-proof test is skipped. JSON that does not
parse fails the test file.

## Check a fresh benchmark run

To check an insecure benchmark run without changing the fixture, set
`BFV_VK_BINDING_FOLDED_ARTIFACTS` to that run's `integration_summary.json`.

## Refresh the fixture

The benchmark runner does not overwrite committed fixtures. To replace
`folded_artifacts.json` with the artifacts of a benchmark run, run the sync
script explicitly from the repository root. Without an argument, it reads
`circuits/benchmarks/results_insecure_minimum/integration_summary.json`. It
leaves the fixture unchanged when the summary is missing or has no valid
`.folded_artifacts`.

```bash
# Rewrites folded_artifacts.json in this directory.
./circuits/benchmarks/scripts/sync_bfv_vk_binding_fixture.sh [<summary-path>]
```
