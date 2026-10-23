# e3-zk-build

## Purpose

This unpublished development crate owns repository circuit building. Its library executes build,
hash, generated-configuration check, and synchronization operations from a typed `Request`. Its thin
binary supplies the project command entry point, `pnpm build:circuits`.

The implementation calls `e3-zk-config` for static rendering and parity values, and
`e3-zk-witness::compute_vk_hash` for ordered SAFE hashes. It uses the existing Nargo, BB, and verifier
tools; it does not implement a compiler or a prover. It has no sample-support dependency.

The library owns artifact staging, immutable VK-tree anchors, checksums, source identity, and
hydration. `scripts/circuits/build-pairs.json` owns supported build pairs. Release requirements stay
in the separate runtime release matrix. Hydration accepts a different artifact source hash and
records the original hash. Release validation remains source-bound.

The unpublished `e3-zk-benchmarks` crate uses this crate through a normal dependency. Normal dependency
direction stays `build -> witness -> config`; the configuration library does not import build,
witness, samples, or runtime orchestration.

## Map and execution

| Location | Responsibility |
| -------- | -------------- |
| [lib.rs](src/lib.rs), [main.rs](src/main.rs) | Typed Request, policy admission, operations, and CLI parsing. |
| [configuration.rs](src/configuration.rs) | Shared material, rendering, isolated checks, and configuration synchronization. |
| [identity.rs](src/identity.rs), [toolchain.rs](src/toolchain.rs) | Framed source identities, required inputs, and exact tool pins. |
| [artifacts.rs](src/artifacts.rs), [vk_tree.rs](src/vk_tree.rs) | Discovery, staging, hydration, checksums, and recursive anchors. |
| [templates/](templates) | Stable generated Solidity and committee selectors. |

The CLI parses a Request, admits supported pairs, validates the tools required by that operation,
then renders or executes the selected work. `check` formats an isolated library copy and compares
without swapping live files. `hash` requires every declared source input; a missing relocated file
fails instead of silently reducing provenance.

## Usage and tests

Use `pnpm build:circuits --help` for flags and the
[circuit tooling guide](../../../scripts/circuits/README.md#circuit-builder) for complete commands.
`sync-config` selects deployment preset/committee names and refreshes Solidity constants;
`sync-preset` regenerates preset declarations.

Run `pnpm test:circuit-build`. Native tests cover typed admission, source framing/inputs, generated
bytes, hydration, anchors, checksums, and tool failures. Explicit ignored cases need pinned tools
and compile only temporary circuits. Run `pnpm build:circuits check --committee all` for this
checkout's generated parity/configuration comparison. These are not a full proof matrix.
[AGENTS.md](AGENTS.md) owns artifact and editing hazards.
