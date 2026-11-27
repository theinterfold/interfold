# Circuit benchmarks — results and configuration

This directory keeps benchmark data: historical `results_*` directories, the current selection in
`config.json`, saved `runs/`, and `scripts/sync_bfv_vk_binding_fixture.sh`. Historical results are
immutable inputs, never output targets. The
[synchronized Minimum comparison](synchronized-decryption.md#optimized-minimum-comparison--2026-11-26)
links the four local SS and SyncDec request receipts. Use `report` for a saved run directory;
verifier `replay` requires a saved proof.

The runner and measurement guide live in [e3-zk-benchmarks](../../crates/zk/benchmarks/README.md).
Use `pnpm bench:circuits` from the repository root for leaf, protocol, gas, request, replay, and
report commands. See that guide for artifact provenance, nullable measurements, and output
ownership.
