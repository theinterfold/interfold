# Circuit benchmarks — results and configuration

This directory keeps benchmark data: the historical `results_*` directories, the current run
selection in `config.json`, saved `runs/`, and the committed-fixture script
`scripts/sync_bfv_vk_binding_fixture.sh`. Historical results are immutable inputs for `report`
and `replay`; they are never benchmark output targets.

The benchmark runner, its commands, and the measurement guide live in the unpublished crate
[`crates/zk/benchmarks`](../../crates/zk/benchmarks). Start there for `pnpm bench:circuits`
usage, metric definitions, artifact provenance, and output semantics.
