# CRISP: proof aggregation and on-chain ZK verification

## Configuration (`crisp.dev.env`)

**Source of truth for local dev:** `examples/CRISP/crisp.dev.env` (from `crisp.dev.env.example`).

| Variable                       | Default        | Effect                                                |
| ------------------------------ | -------------- | ----------------------------------------------------- |
| `CRISP_BFV_PRESET`             | `insecure` | BFV preset for circuits and the server `E3_PARAM_SET` |
| `CRISP_SKIP_PROOF_AGGREGATION` | `true`         | Enables the ciphernode-only local-dev/test skip flag  |

`pnpm dev:setup` copies the example if missing and builds recursive circuits only when the skip flag
is `false`. It also writes the matching `E3_PARAM_SET` into `server/.env`: `0` for `insecure`,
`1` for `secure-8192`, and `2` for `secure-16384`. `pnpm dev:up` → `crisp_deploy.sh` deploys real verifiers for full
aggregation and mock verifiers for skipped local-dev runs.

After changing `crisp.dev.env`, re-run `pnpm dev:setup` and a fresh `pnpm dev:up` (wipe
`.interfold/data` when switching modes).

Lower-level switches (kept in sync by the scripts):

| Switch                                  | Where                  | Effect                                  |
| --------------------------------------- | ---------------------- | --------------------------------------- |
| `E3_NODES__CN*__SKIP_PROOF_AGGREGATION` | Ciphernode environment | Skips recursive aggregation workers     |
| `ENABLE_ZK_VERIFICATION`                | Deploy environment     | Selects real vs mock on-chain verifiers |

The contracts always require and verify final proof payloads. Skip mode works only because the local
deployment uses mock verifiers; enabling the skip flag against production verifiers causes
publication to fail.

---

## Mode A — Local dev without proof aggregation (recommended)

Use this for day-to-day CRISP development: faster DKG, no recursive proving, no on-chain BFV
verifier checks.

### Configuration

```bash
# crisp.dev.env
CRISP_BFV_PRESET=insecure
CRISP_SKIP_PROOF_AGGREGATION=true
```

### Steps

```bash
# From examples/CRISP
pnpm dev:setup   # once — skips recursive aggregation circuit build
pnpm dev:up
```

After deploy, ensure `server/.env` and `client/.env` match addresses printed by deploy or
`packages/crisp-contracts/deployed_contracts.json` → `localhost` (see
[Address sync](#address-sync-after-deploy)).

```bash
pnpm cli init
```

### What you should see

- Ciphernodes skip long `NodeDkgFold` / `zk_dkg_aggregation` runs
- `publishCommittee` still verifies a non-empty ciphernode placeholder through the configured mock
  PK and fold-attestation verifiers
- `POST /rounds/current` returns 200 once the indexer has recorded the round

---

## Mode B — Full proof aggregation + on-chain ZK verification

Use this to exercise the production DKG path: recursive folds, fold attestations, DKG aggregator
Honk proof, and `BfvPkVerifier` checks at `publishCommittee`.

### Configuration

```bash
# crisp.dev.env
CRISP_BFV_PRESET=insecure
CRISP_SKIP_PROOF_AGGREGATION=false
```

CRISP `requestE3` reads `E3_PARAM_SET` from `server/.env`. Keep it aligned with `CRISP_BFV_PRESET`:
`0` for `insecure`, `1` for `secure-8192`, and `2` for `secure-16384`.

### Steps

```bash
cd examples/CRISP
# Edit crisp.dev.env (or crisp.dev.env.example → crisp.dev.env) as above
pnpm dev:setup    # builds DKG circuits
rm -rf .interfold/data   # required when switching from Mode A
pnpm dev:up       # deploy with ENABLE_ZK_VERIFICATION=true
pnpm cli init
```

`dev:setup` runs `pnpm build:circuits --preset <CRISP_BFV_PRESET>` before contract compile and
updates `server/.env`. `dev:up` deploys via `crisp_deploy.sh` with `ENABLE_ZK_VERIFICATION=true`.

**Do not** run `pnpm build:circuits` with a different preset after deploy without redeploying — that
causes **`VkHashMismatch()`** at `publishCommittee`.

Expect DKG aggregation to take on the order of **minutes** per committee (fold + aggregator
proving).

### What you should see

- Logs: `loaded dkgFoldAttestationVerifier`, `NodeDkgFold complete`, `zk_dkg_aggregation`, then
  `Publishing PublicKeyAggregated (dkg_evm_proof=present)`
- On-chain: `publishCommittee` succeeds (no `VkHashMismatch`)
- Registry / Interfold transition to key published; CRISP indexer can serve `/rounds/current`

---

## Invalid combinations

| Deploy                                   | Ciphernode skip flag | Result                                                                                       |
| ---------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------- |
| Mock verifiers                           | `false`              | Valid, but unnecessarily performs the expensive recursive workflow.                          |
| Production verifiers                     | `true`               | Final C5/C7 placeholders are rejected; no contract-side bypass exists.                       |
| ZK, circuits recompiled **after** deploy | `false`              | **`VkHashMismatch()`**; redeploy the production verifier wrappers after rebuilding circuits. |

---

## Address sync after deploy

`pnpm dev:up` runs deploy then automatically updates:

- `interfold.config.yaml` (ciphernode contract watches)
- `server/.env` (`INTERFOLD_ADDRESS`, `E3_PROGRAM_ADDRESS`, `CRISP_VOTING_TOKEN`, registry, fee
  token, and mock references)
- `client/.env` (`VITE_CRISP_TOKEN`)

No manual copy from `deployed_contracts.json` is required. Stale addresses only happen if you skip
`dev:up` deploy and reuse an old Anvil state with new `.env` files.

---

## Troubleshooting

### `publishCommittee` reverts — `0x0c260259` (`VkHashMismatch`)

**Cause:** `BfvPkVerifier` immutables (`expectedNodesFoldKeyHash`, `expectedC5KeyHash`) do not match
the VK hashes embedded in the DKG aggregator proof (usually circuits were rebuilt after verifier
deploy).

**Fix:**

1. Set `CRISP_SKIP_PROOF_AGGREGATION=false` in `crisp.dev.env` (and matching `CRISP_BFV_PRESET`)
2. `pnpm dev:setup` then `rm -rf .interfold/data && pnpm dev:up`
3. `pnpm cli init`

### `POST /rounds/current` → 500

Often a **symptom**, not the root cause: the CRISP indexer has no current round until on-chain DKG
progresses (e.g. committee key published). Fix DKG / `publishCommittee` first, then retry. If the
round was never created, run `pnpm cli init` after the server and ciphernodes are healthy.

### `Historical events channel closed before all chains reported`

Expected on localhost if Sepolia (`11155111`) is configured in ciphernode EVM sync but no Sepolia
RPC is running. Harmless for CRISP-on-Anvil.

### After changing mode

1. Fresh deploy (`clean:deployments` + deploy script for chosen mode)
2. Sync `.env` / `interfold.config.yaml`
3. `rm -rf .interfold/data`
4. Restart stack + `pnpm cli init`

---

## Reference: what the scripts do

| Step             | Mode A (`CRISP_SKIP_PROOF_AGGREGATION=true`) | Mode B (`=false`)                             |
| ---------------- | -------------------------------------------- | --------------------------------------------- |
| `pnpm dev:setup` | Skips recursive circuit builds               | `pnpm build:circuits --preset …`              |
| `pnpm dev:up`    | Mock PK/decryption/fold verifiers            | Production verifiers + full recursive proving |

See also: `packages/interfold-contracts/scripts/deployInterfold.ts`,
`packages/interfold-contracts/contracts/verifiers/bfv/BfvPkVerifier.sol`, and
`agent/flow-trace/04_DKG_AND_COMPUTATION.md` for the full DKG publication flow.
