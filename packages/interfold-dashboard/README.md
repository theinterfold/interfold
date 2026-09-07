# @interfold/dashboard

Interfold / CRISP public observation dashboard. Three tabs:

- **CRISP** — hero poll card, live 7-stage timeline, expandable history, network pulse footer.
  Observational only (no vote CTA).
- **E3 inspector** — deep technical record of one E3: request, committee, keygen rounds, input
  window, compute, decryption, publication, fees, on-chain event log.
- **Run a ciphernode** — interactive operator guide. The only writing page: it connects a wallet and
  walks the on-chain setup (authorize bond owner → bond the ciphernode bond → register → buy
  tickets).

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

Addresses are **not** repeated here — they go stale. The live values are the defaults in
`src/lib/chain.ts` (`CONTRACTS`), each overridable by its `VITE_*` variable. Cross-check them
against `packages/interfold-contracts/deployed_contracts.json` for the target network.

- `Interfold` proxy — `E3Requested`, `PlaintextOutputPublished`, `RewardsDistributed`, plus `getE3`
  / `getE3Stage` / `e3Payments` view functions.
- `CiphernodeRegistryOwnable` — `CommitteeRequested` (threshold + seed), `CommitteeFinalized`
  (members), `CommitteePublished` (joint PK).
- `BondingRegistry` — operator collateral and the write path behind the operator guide (see below).
  Also feeds the network pulse strip: `totalCiphernodeBondLiability` (total bonded) and
  `eligibilityAt` (active operator count), alongside `numCiphernodes` from the ciphernode registry.
- `CRISPProgram` — emits `InputPublished` for every ballot. (Interfold's own `InputPublished` is
  declared but never emitted; inputs live on the program.) A re-vote reuses its Merkle-leaf `index`,
  so the true ballot count is the number of **distinct** indexes. Inputs are only observable for
  CRISP; other programs report `inputsTracked: false`.

### Operator guide (write path)

`src/Operator.tsx` is the only page that sends transactions. It talks to `BondingRegistry` through a
minimal injected-wallet connector (`src/lib/wallet.ts`) — no wagmi/rainbowkit dependency, since the
guide needs one provider, one chain, and five writes.

The operator key and the bond owner are separate addresses. The operator key is the hot key the node
signs with; the bond owner is the wallet that funds and controls the collateral. They may be the
same wallet. The sequence the guide enforces is:

1. `setBondOwner(bondOwner)` — **sent by the operator key**, authorizing a wallet to post collateral
   for it.
2. `approve` ciphernode bond token to the registry, then `bondCiphernodeFor(operator, amount)`.
3. `registerOperatorFor(operator)` — adds the key to the ciphernode registry (requires the bond).
4. `approve` the ticket underlying to the ticket wrapper, then
   `addTicketBalanceFor(operator, cost)`.

Steps 2–4 must come from the bond owner; the page detects the connected wallet and disables actions
it cannot send. Every write is simulated first (`simulateAndWrite`) so the registry's typed reverts
(for example `NotBondOwner`) surface before the wallet prompt.

Only `VITE_BONDING_REGISTRY_ADDRESS` is configured. The ciphernode bond token, ticket wrapper,
ticket underlying, bond size, ticket price, minimum tickets, and exit delay are all read back from
the registry, so the guide follows the deployment instead of a hardcoded token list.

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
- `VITE_BONDING_REGISTRY_ADDRESS` — bonding registry behind the operator guide.
- `VITE_FAUCET_ADDRESS` — testnet faucet. Ignored unless `VITE_NETWORK` selects a test network;
  set it to the zero address to hide the "Get test tokens" action on a testnet too.
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
