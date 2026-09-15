# Releasing the CRISP packages

`@crisp-e3/sdk` and `@crisp-e3/contracts` are published as a matched pair on two channels.

| channel    | tag       | preset         | who it is for                      |
| ---------- | --------- | -------------- | ---------------------------------- |
| testing    | `testing` | `insecure` | testnets, demos, local development |
| production | `latest`  | all supported presets | deployed clients and real rounds   |

## Why presets are separate entry points

The SDK inlines the compiled circuit and the contracts package ships the Solidity verifier generated
from that same circuit's verification key. A verifier only accepts proofs from the circuit it was
generated for, so mixing presets across the two packages produces a round that rejects every ballot
— and it fails at on-chain verification, not anywhere a test would catch it.

Each preset is a separate SDK subpath. The production package carries all subpaths so one client
can read the E3's on-chain `paramSet` and load the matching preset. The testing package carries only
the real insecure preset so local and testnet installs stay small. It also ships tiny stubs for the
other exported subpaths, so bundlers can resolve the client import graph without bundling secure
circuits into test builds.

```ts
// on @crisp-e3/sdk@testing
import { loadCircuits } from '@crisp-e3/sdk/insecure' // resolves
import { loadCircuits } from '@crisp-e3/sdk/secure-8192' // resolves, throws if called
import { loadCircuits } from '@crisp-e3/sdk/secure-16384' // resolves, throws if called

// on @crisp-e3/sdk@latest
import { loadCircuits as loadInsecure } from '@crisp-e3/sdk/insecure'
import { loadCircuits as loadSecure } from '@crisp-e3/sdk/secure-8192'
import { loadCircuits as loadSecure16384 } from '@crisp-e3/sdk/secure-16384'
```

This keeps the secure circuits out of testing installs while making the production client flexible
enough for secure mainnet rounds and insecure test deployments.

## Versioning

Testing releases carry a prerelease identifier; production releases do not.

```text
0.18.0-insecure.0   tag: testing    insecure
0.20.0              tag: latest     insecure + secure-8192 + secure-16384
```

The identifier is load-bearing. npm excludes prerelease versions from ordinary ranges, so a consumer
on `^0.18.0` can never drift onto a testing build through an update — reaching it takes an explicit
`@testing` or an exact version.

## The client tracks production

`client/` reads the E3 `paramSet` before proving and loads the matching preset. Because production
SDK releases carry all supported presets, a production publish moves `client/package.json` and
`client/pnpm-lock.yaml` to the published version. A testing publish leaves the client alone.

The pin cannot be a `workspace:` range, because the same `client/package.json` also serves the
standalone Vercel deploy, which installs with `ignore-workspace=true` (see `client/.npmrc`) and
cannot resolve one. So it is an exact version, and that has a consequence worth stating plainly:

**`linkWorkspacePackages: true` links `packages/crisp-sdk` only while its version still satisfies
that exact pin.** Bump the workspace to `0.20.0` while the client pins `0.19.1` and pnpm stops
linking and resolves the client from the registry instead. That is not a cosmetic difference. It
re-resolves the whole client dependency tree (it pulled `zod@4` in place of `zod@3` across `viem`,
`wagmi`, and `connectkit`), and it makes Vite pre-bundle the SDK as an ordinary dependency, which
breaks the worker subpath:

```text
The file does not exist at ".../client/node_modules/.vite/deps/
workers/generateCircuitInputs.worker.js?worker_file&type=module"
→ [generateProof] failed → the e2e vote never reaches the wallet signature
```

This is why a production publish leaves the CRISP workspace packages and the client on the same
exact version. A testing publish restores the versions it touched because the deployable client does
not track the testing channel.

## Procedure

Publish through `scripts/publish.ts`. It selects the preset from the release channel, builds the
packages, publishes in dependency order, and updates the standalone client lockfile after npm serves
the new SDK version.

SDK builds stage their required artifacts under `circuits/dist/<preset>/`, which git does not track.
The build refuses artifacts that are missing or older than the sources, using the content digest
that `stage-preset-artifacts.mjs` records at staging time.

The default SDK build is intentionally the lightweight testing build. It builds and ships only the
real `insecure` bundle, plus resolver stubs for off-channel presets, so pull-request CI does not
compile or bundle the large secure preset. Use the production channel, or
  `pnpm -C examples/CRISP/packages/crisp-sdk build:prod`, when the output must include real
  `insecure`, `secure-8192`, and `secure-16384` bundles.

```sh
# testing — insecure under the `testing` tag, leaves the client alone
pnpm -C examples/CRISP publish:packages --channel testing 0.19.0-insecure.0

# production — all supported presets under the `latest` tag, and moves the client
pnpm -C examples/CRISP publish:packages --channel prod 0.20.0
```

Add `--dry-run` to print the exact steps for a channel without changing anything. The script bumps
all three packages, builds the SDK against the channel's preset set, and publishes in dependency
order (`zk-inputs`, `sdk`, `contracts`). It never tags and never pushes.

What it leaves behind differs by channel. Production commits the bump so the tree and client stay on
the production version. Testing restores the version bump because the deployable client does not
track the testing channel. Either way, a failure restores the tree: a half-bumped workspace is worse
than no bump, because the next `pnpm install` silently detaches the client from it.

Two gates run on the way:

- `check-staged-preset.mjs` (in `build:testing` / `build:prod`) refuses staged artifacts the
  circuits have moved past.
- `check-presets.mjs` (`prepublishOnly` on both packages) refuses to publish a channel whose
  artifacts do not match its preset set — a missing preset, a wanted preset that is only a stub, an
  exports entry pointing at nothing, missing verifiers, or an unexpected real preset bundle.

## Deploying

Generated aggregator verifiers are preset-specific and committee-specific. The protocol deploys one
concrete PK and decryption verifier for each supported pair. A router selects the concrete verifier
from the proof's public-input length and VK hash anchors.

The SDK must also match the round. A `latest` SDK can load either supported preset and should select
from the E3's on-chain `paramSet`. Pair a `testing` SDK only with `insecure` deployments.

For an existing paused mainnet bootstrap deployment, prepare the complete activation batch with:

```sh
pnpm --dir packages/interfold-contracts upgrade:secure-crisp -- --network mainnet
```

The script requires no active E3s or unreleased committees. It upgrades Interfold to the secure
crypto configuration, deploys all three secure verifier routes and both routers, registers the
secure BFV parameters, wires the ciphertext verifier, registers CRISP, and binds CRISP. It writes an
Aragon-wrapped Safe Builder file, raises the required node protocol version, and keeps requests
paused. Publish a new SemVer ciphernode release from the same source before governance executes the
batch. After execution, run `upgrade:secure-crisp:validate`, restart the matching ciphernodes, and
confirm that enough release-ready nodes are online. Generate the checked unpause transaction with:

```sh
pnpm --dir packages/interfold-contracts upgrade:secure-crisp:resume -- \
  --network mainnet --ciphernodes-restarted
```

The resume command reruns the complete activation validation and requires 19 release-ready active
operators before it writes the DAO/Safe transaction. The older CRISP-only governance builder rejects
mainnet because it cannot install the secure protocol configuration.
