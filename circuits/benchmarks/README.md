# Circuit benchmarks — results and configuration

This directory keeps benchmark data: historical `results_*` directories, the current selection in
`config.json`, saved `runs/`, and `scripts/sync_bfv_vk_binding_fixture.sh`. Historical results are
immutable inputs for report and replay, never output targets.

The runner and measurement guide live in [e3-zk-benchmarks](../../crates/zk/benchmarks/README.md).
Use `pnpm bench:circuits` from the repository root for leaf, protocol, gas, replay, and report
commands. See that guide for artifact provenance, nullable measurements, and output ownership.
