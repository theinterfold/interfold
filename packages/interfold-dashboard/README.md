# @interfold/dashboard

Interfold / CRISP public observation dashboard. Two tabs:

- **CRISP** — hero poll card, live 7-stage timeline, expandable history, network pulse footer.
  Observational only (no vote CTA).
- **E3 inspector** — deep technical record of one E3: request, committee, keygen rounds, input
  window, compute, decryption, publication, fees, on-chain event log.

## Run

```bash
pnpm install
pnpm --filter @interfold/dashboard dev
```

Opens at `http://localhost:5173`.

## On-chain backend (Sepolia)

The dashboard reads live data from the Sepolia deployment of Interfold
(`packages/interfold-contracts/deployed_contracts.json`). ABIs come from the canonical typechain
factories in `@interfold/contracts/types` so they cannot drift from the deployed contracts. The
`E3Stage` enum is mirrored locally in `src/lib/chain.ts` (matching `IInterfold.E3Stage`).

- `Interfold` proxy at `0xB47B267876B60a06138Bc9dfCee7aa3E26907CCB` — `E3Requested`,
  `PlaintextOutputPublished`, `RewardsDistributed`, plus `getE3` / `getE3Stage` / `e3Payments` view
  functions.
- `CiphernodeRegistryOwnable` at `0x497Feea9abB72229aab1584c22b5416ff128926B` — `CommitteeRequested`
  (threshold + seed), `CommitteeFinalized` (members), `CommitteePublished` (joint PK).
- `CRISPProgram` at `0xba3B07aBFd0B8cad68aa1E946CC7AF5C1B1c8B5D` — emits `InputPublished` for every
  ballot. (Interfold's own `InputPublished` is declared but never emitted; inputs live on the
  program.) A re-vote reuses its Merkle-leaf `index`, so the true ballot count is the number of
  **distinct** indexes. Inputs are only observable for CRISP; other programs report
  `inputsTracked: false`.

CRISP question text + option labels are off-chain (the program doesn't store them); the mapping
lives in `src/lib/pollMeta.ts`. Unknown E3 ids get a generic "Encrypted poll #N" header with numeric
option labels.

### Configuration

All deployment-specific values are env-overridable (prefix `VITE_`) so the dashboard can point at a
different deployment without code changes. See `.env.example`; unset values fall back to the current
Sepolia deployment defined in `src/lib/chain.ts`:

- `VITE_SEPOLIA_RPC` — RPC endpoint (defaults to a public node; use Alchemy/Infura for production).
- `VITE_INTERFOLD_ADDRESS`, `VITE_CIPHERNODE_REGISTRY_ADDRESS`, `VITE_CRISP_PROGRAM_ADDRESS` —
  contracts.
- `VITE_DEPLOY_BLOCK` — first block to scan from (the Interfold deploy block).

The fetchers chunk `getLogs` calls to 9_500 blocks per request so they work against the stricter
free-tier providers.

### Polling

`useCrispPolls`, `useAllE3s`, and `useE3Details` poll every 15 seconds while mounted. When the
chain-derived stage advances, the CRISP tab's stage + pollState reconcile automatically; manual
overrides via the Tweaks panel still work (they're clobbered on the next poll tick).

## Build

```bash
pnpm --filter @interfold/dashboard build       # vite build → dist/
pnpm --filter @interfold/dashboard typecheck   # tsc --noEmit
pnpm --filter @interfold/dashboard preview     # serve dist/
```

## Deploy (Vercel)

This is a separate Vercel **Project** from the CRISP client, both pointing at the same repo.

1. New Project → import this repo → set **Root Directory** to `packages/interfold-dashboard`.
2. `vercel.json` (committed here) drives the rest:
   - installs the whole pnpm workspace (`cd ../.. && pnpm install`),
   - builds `@interfold/contracts` first (typechain ABIs the dashboard imports), then the dashboard,
   - serves `dist/`.
3. Optionally set `VITE_SEPOLIA_RPC` in the project's Environment Variables.

> No "Ignored Build Step" is configured, so every push to the deployed branch builds. If you want to
> skip builds when the dashboard/contracts are untouched, add a `git diff` against
> `VERCEL_GIT_PREVIOUS_SHA` (not `HEAD^`, which only sees the latest commit and wrongly cancels
> deploys when an unrelated commit is on top).

The dashboard intentionally has **no dependency on `@interfold/sdk`** (which needs a Rust/Noir
toolchain to build) — only `@interfold/contracts`, which is plain `hardhat compile` + `tsc`.
