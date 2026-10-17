# e3-zk-build

This unpublished development crate owns repository circuit building. Its library executes build,
hash, generated-configuration check, and synchronization operations from a typed `Request`. Its thin
binary supplies the project command entry point, `pnpm build:circuits`.

The implementation calls `e3-zk-config` for static rendering and parity values, and
`e3-zk-witness::compute_vk_hash` for ordered SAFE hashes. It uses the existing Nargo, BB, and verifier
tools; it does not implement a compiler or a prover. It has no sample-support dependency.

The library owns artifact staging, immutable VK-tree anchors, checksums, source identity, and
hydration. `scripts/circuit-build-pairs.json` owns supported build pairs. Release requirements stay
in the separate runtime release matrix. Hydration accepts a different artifact source hash and
records the original hash. Release validation remains source-bound.

The unpublished `e3-zk-benchmarks` crate uses this crate through a normal dependency. Normal dependency
direction stays `build -> witness -> config`; the configuration library does not import build,
witness, samples, or runtime orchestration.

See `scripts/README.md#circuit-builder` for commands and `pnpm test:circuit-build` for focused tests.
