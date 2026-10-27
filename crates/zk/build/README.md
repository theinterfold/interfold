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

Artifact labels are `insecure-64`, `insecure`, `insecure-simd`, `secure-8192`, `secure-16384`, `secure-16384-simd`, and `secure-16384-simd-d6`.
`insecure-64` and `secure-8192` serve the trBFV path. The degree-128 `insecure` archive serves the
l-BFV path only. `insecure-64` is the default build preset.
Secure-16384 builds the l-BFV path for minimum, micro, and small committees. Its only legacy tree
anchor is C6; the V2 DKG verifier binds its complete chunk/row VK genealogy separately.
Secure-16384-simd has the degree, committees and V2 layout of secure-16384, plaintext modulus 65537,
and 56-bit moduli. Its C7 is `decrypted_shares_aggregation_wide`, which holds `Q` and `u` as U384
values because `Q` (276 bits) is above the field.
Secure-16384-simd-d6 has the same degree, committees and V2 layout as secure-16384-simd. It has
multiplicative depth 6 and eight 54-bit moduli, so `Q` is about 424 bits. Its C7 is
`decrypted_shares_aggregation_wide`, which holds `Q` and `u` as U512 values because `Q` is above 352 bits.
Insecure-simd has plaintext modulus 257 and builds the l-BFV path for minimum and micro committees.
The small committee exceeds its smudging-noise budget. Its legacy tree anchor is also C6.

The shared build-pair policy also generates the deployment configuration declarations, testnet
routes, and Solidity pair admission. Network admission remains separate: mainnet accepts only
secure-8192. Runtime release requirements live separately in
`crates/zk/prover/supported-configurations.json`; adding a build pair alone does not ship artifacts.

The unpublished `e3-zk-benchmarks` crate uses this crate through a normal dependency. Normal dependency
direction stays `build -> witness -> config`; the configuration library does not import build,
witness, samples, or runtime orchestration.

## Map and execution

| Location | Responsibility |
| -------- | -------------- |
| [lib.rs](src/lib.rs), [main.rs](src/main.rs) | Typed Request, policy admission, operations, and CLI parsing. |
| [configuration.rs](src/configuration.rs) | Shared material, rendering, isolated checks, and configuration synchronization. |
| [lbfv.rs](src/lbfv.rs), [policy.rs](src/policy.rs) | Deterministic CRS/URS, chunk grids, path selection, and required artifact inventories. |
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
`sync-config` writes TS/Solidity constants; `sync-preset` regenerates preset declarations.

Run `pnpm test:circuit-build`. Native tests cover typed admission, source framing/inputs, generated
bytes, hydration, anchors, checksums, and tool failures. Explicit ignored cases need pinned tools
and compile only temporary circuits. Run `pnpm build:circuits check --committee all` for this
checkout's generated parity/configuration comparison. These are not a full proof matrix.
[AGENTS.md](AGENTS.md) owns artifact and editing hazards.
