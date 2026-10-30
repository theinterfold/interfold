# @interfold/dashboard

Interfold / CRISP public observation dashboard. Three tabs:

- **CRISP** — hero poll card, live 7-stage timeline, expandable history, network pulse footer.
  Observational only (no vote CTA).
- **E3 inspector** — deep technical record of one E3: request, committee, keygen rounds, input
  window, compute, decryption, publication, failure, fees, and on-chain event log.
- **Run a ciphernode** — interactive operator guide. The only writing page: it connects a wallet,
  walks the on-chain setup (authorize bond owner → bond the ciphernode bond → register → buy
  tickets), and claims E3 rewards.

## Run

```bash
pnpm install
pnpm --filter @interfold/dashboard dev
```

Opens at `http://localhost:5173`.

## On-chain backend

The dashboard reads live data from one Interfold deployment: Sepolia or Ethereum mainnet. ABIs come
from the canonical typechain factories in `@interfold/contracts/types` so they cannot drift from the
deployed contracts. The `E3Stage` enum is mirrored locally in `src/lib/chain.ts` (matching
`IInterfold.E3Stage`).

Addresses are **not** repeated here — they go stale. The live values are the network profiles in
`src/lib/networks.ts` (`NETWORKS`), each overridable by its `VITE_<NETWORK>_*` variable. Cross-check
them against `deployments/manifest.json` for the target network.

- `Interfold` proxy — `E3Requested`, `E3Failed`, `PlaintextOutputPublished`, and
  `RewardsDistributed`, plus the `getE3`, `getE3Stage`, `getFailureReason`, `e3Payments`, and
  `pendingReward` view functions. The operator guide sends `claimReward`.
- `CiphernodeRegistryOwnable` — `CommitteeRequested` (threshold + seed), `CommitteeFinalized`
  (members), `CommitteePublished` (joint PK).
- `BondingRegistry` — operator collateral and the write path behind the operator guide (see below).
  Also feeds the network pulse strip: `totalCiphernodeBondLiability` (total bonded) and
  `eligibilityAt` (active operator count), alongside `numCiphernodes` from the ciphernode registry.
- `CRISPProgram` — emits `InputPublished` for every ballot. (Interfold's own `InputPublished` is
  declared but never emitted; inputs live on the program.) A re-vote reuses its Merkle-leaf `index`,
  so the true ballot count is the number of **distinct** indexes. Inputs are only observable for
  CRISP; other programs report `inputsTracked: false`. The CRISP tab lists the E3s of the current
  CRISP program (`CRISP_PROGRAM_ADDRESS`) and of the earlier deployments in the profile's
  `previousCrispPrograms`. The dashboard reads the inputs of each E3 from its own program. It has no
  option labels, so a past poll shows its on-chain outcome (Completed, Failed, Expired), not a
  winner.

### Operator guide (write path)

`src/Operator.tsx` is the only page that sends transactions. It talks to `BondingRegistry` and the
Interfold contract through a minimal injected-wallet connector (`src/lib/wallet.ts`) — no
wagmi/rainbowkit dependency, since the guide needs one provider, one chain, and a few writes.

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

**E3 rewards** (`src/lib/rewards.ts`) leads the page. It shows the total that the operator's
recipient can claim, a **Claim rewards** action, and the history of the E3 committees that selected
the operator. It filters the `RewardRecipientSnapshotted(e3Id, operator, recipient)` events of the
refund manager that `Interfold.e3RefundManager()` returns by the operator topic. That event gives
each seat and the wallet that receives its payments. Each seat gets one claim state:

| State            | Source                                                                                                    |
| ---------------- | --------------------------------------------------------------------------------------------------------- |
| In progress      | `getE3Stage(e3Id)` is neither `Complete` nor `Failed`.                                                    |
| Forfeited        | `rewardStatus(e3Id, operator)` reports an executed expulsion.                                             |
| On hold          | `rewardStatus` reports an open expulsion proposal. The amount is `operatorHeldRewards(e3Id, operator)`.   |
| Needs processing | Failed E3, and `getRefundDistribution(e3Id).calculated` is false. Any wallet sends `processE3Failure`.    |
| Claimable        | Completed E3: `pendingReward(e3Id, recipient)`. Failed E3: a simulated `claimHonestNodeReward`.           |
| Not eligible     | The simulated `claimHonestNodeReward` reverts with `NotHonestNode`.                                       |
| Claimed          | `RewardClaimed` (Interfold) or `RefundClaimed` with claim type `HONEST_NODE` (refund manager) records it. |
| No reward        | None of the above.                                                                                        |

The contract has no view for the compensation of a failed E3, so the read simulates
`claimHonestNodeReward(e3Id, operator)` from the recipient: the result is the amount. **Claim
rewards** sends `claimRewards(e3Ids)` for the completed E3s of the connected recipient, then one
`claimHonestNodeReward` for each failed E3. Each transaction waits for the previous one. E3s that an
earlier refund manager recorded are not listed. The amounts use the `FEE_TOKEN_*` display settings.

Only `VITE_BONDING_REGISTRY_ADDRESS` is configured. The ciphernode bond token, ticket wrapper,
ticket underlying, bond size, ticket price, minimum tickets, and exit delay are all read back from
the registry, so the guide follows the deployment instead of a hardcoded token list.

CRISP question text + option labels are off-chain (the program does not store them). The mapping
lives in `src/lib/pollMeta.ts`. Unknown E3 IDs get a generic header that contains the compact E3 ID.
They use numeric option labels.

### Configuration

Each build contains every network profile in `src/lib/networks.ts`. The page selects one profile
when it loads:

1. `VITE_NETWORK_HOSTS` maps hostnames to networks, as comma-separated `host=network` pairs (for
   example `dashboard.theinterfold.com=mainnet,testnet.example.com=sepolia`). With this map, one
   deployment serves mainnet and testnet on two domains.
2. A hostname that is not in the map (preview URLs, `localhost`) uses `VITE_NETWORK` (`sepolia` or
   `mainnet`).
3. When `VITE_NETWORK` is not set, the page uses `sepolia`.

Each profile value has an optional override, `VITE_<NETWORK>_<SETTING>`. An override changes only
its network, so a mainnet RPC never reaches the testnet domain. See `.env.example` for each name and
default:

- `RPC_URL` — RPC endpoint (defaults to a public node; use Alchemy/Infura for production).
- `INTERFOLD_ADDRESS`, `CIPHERNODE_REGISTRY_ADDRESS`, `CRISP_PROGRAM_ADDRESS` — contracts.
- `BONDING_REGISTRY_ADDRESS` — bonding registry behind the operator guide.
- `FAUCET_ADDRESS` — testnet faucet, used only on a test network. Set it to the zero address to hide
  the "Get test tokens" action on a testnet too.
- `FEE_TOKEN_SYMBOL`, `FEE_TOKEN_DECIMALS` — fee token display.
- `DEPLOY_BLOCK` — first block to scan from (the Interfold deploy block).
- `COMPUTE_WINDOW`, `DECRYPTION_WINDOW` — E3 timeout windows in seconds.

`vite.config.ts` stops the build when an override has no network scope (for example `VITE_RPC_URL`),
or when `VITE_NETWORK` or `VITE_NETWORK_HOSTS` names an unknown network. Without this check, an
unscoped override would have no effect, and the page would use the profile default.

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

The CRISP client lives in the [CRISP repository](https://github.com/theinterfold/CRISP). The
dashboard is a separate Vercel **Project** that points at this repo.

1. New Project → import this repo → set **Root Directory** to `packages/interfold-dashboard`.
2. `vercel.json` (committed here) drives the rest:
   - installs the whole pnpm workspace (`cd ../.. && pnpm install`),
   - builds `@interfold/contracts` first (typechain ABIs the dashboard imports), then the dashboard,
   - serves `dist/`.
3. Set `VITE_NETWORK` in the project's Environment Variables. Optionally set an RPC per network, for
   example `VITE_MAINNET_RPC_URL`.

To serve the testnet dashboard from the same project:

1. In **Settings → Domains**, add the testnet domain to the project. Do not assign it to a Git
   branch, so it serves the production deployment.
2. Set `VITE_NETWORK_HOSTS` for the Production environment, for example
   `dashboard.theinterfold.com=mainnet,testnet.example.com=sepolia`.
3. Optionally set `VITE_SEPOLIA_RPC_URL`.
4. Redeploy. Vite reads the variables at build time.

> No "Ignored Build Step" is configured, so every push to the deployed branch builds. If you want to
> skip builds when the dashboard/contracts are untouched, add a `git diff` against
> `VERCEL_GIT_PREVIOUS_SHA` (not `HEAD^`, which only sees the latest commit and wrongly cancels
> deploys when an unrelated commit is on top).

The dashboard intentionally has **no dependency on `@interfold/sdk`** (which needs a Rust/Noir
toolchain to build) — only `@interfold/contracts`, which is plain `hardhat compile` + `tsc`.
