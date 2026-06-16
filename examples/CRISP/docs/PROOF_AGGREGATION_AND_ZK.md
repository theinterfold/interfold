# CRISP: proof aggregation and on-chain ZK verification

## Configuration (`crisp.dev.env`)

**Source of truth for local dev:** `examples/CRISP/crisp.dev.env` (from `crisp.dev.env.example`).

| Variable                          | Default        | Effect                                                |
| --------------------------------- | -------------- | ----------------------------------------------------- |
| `CRISP_BFV_PRESET`                | `insecure-512` | `pnpm build:circuits --preset` when aggregation is on |
| `CRISP_PROOF_AGGREGATION_ENABLED` | `false`        | Drives setup, deploy, and `server/.env`               |

`pnpm dev:setup` copies the example if missing, syncs `E3_PROOF_AGGREGATION_ENABLED` into
`server/.env`, and builds DKG circuits only when aggregation is `true`. `pnpm dev:up` →
`crisp_deploy.sh` sets `ENABLE_ZK_VERIFICATION` from the same file.

After changing `crisp.dev.env`, re-run `pnpm dev:setup` and a fresh `pnpm dev:up` (wipe
`.interfold/data` when switching modes).

Lower-level switches (kept in sync by the scripts):

| Switch                         | Where                                                | Effect                          |
| ------------------------------ | ---------------------------------------------------- | ------------------------------- |
| `E3_PROOF_AGGREGATION_ENABLED` | `server/.env` (managed by setup)                     | Passed to `Interfold.requestE3` |
| `ENABLE_ZK_VERIFICATION`       | Set at deploy from `CRISP_PROOF_AGGREGATION_ENABLED` | Real vs mock BFV verifiers      |

Misalignment causes `publishCommittee` to revert with **`VkHashMismatch()`** (`0x0c260259`).

---

## Mode A — Local dev without proof aggregation (recommended)

Use this for day-to-day CRISP development: faster DKG, no recursive proving, no on-chain BFV
verifier checks.

### Configuration

```bash
# crisp.dev.env
CRISP_BFV_PRESET=insecure-512
CRISP_PROOF_AGGREGATION_ENABLED=false
```

### Steps

```bash
# From examples/CRISP
pnpm dev:setup   # once — skips DKG circuit build, syncs server/.env
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
- `publishCommittee` succeeds without a DKG Honk proof (empty `proof` bytes are allowed when
  aggregation is disabled on the E3)
- `POST /rounds/current` returns 200 once the indexer has recorded the round

---

## Mode B — Full proof aggregation + on-chain ZK verification

Use this to exercise the production DKG path: recursive folds, fold attestations, DKG aggregator
Honk proof, and `BfvPkVerifier` checks at `publishCommittee`.

### Configuration

```bash
# crisp.dev.env
CRISP_BFV_PRESET=insecure-512
CRISP_PROOF_AGGREGATION_ENABLED=true
```

CRISP `requestE3` still uses on-chain `param_set = 0` (`InsecureThreshold512`) unless you change the
server — keep `CRISP_BFV_PRESET=insecure-512` for the default Minimum committee.

### Steps

```bash
cd examples/CRISP
# Edit crisp.dev.env (or crisp.dev.env.example → crisp.dev.env) as above
pnpm dev:setup    # builds DKG circuits + syncs server/.env
rm -rf .interfold/data   # required when switching from Mode A
pnpm dev:up       # deploy with ENABLE_ZK_VERIFICATION=true
pnpm cli init
```

`dev:setup` runs `pnpm build:circuits --preset <CRISP_BFV_PRESET>` before contract compile. `dev:up`
deploys via `crisp_deploy.sh` with `ENABLE_ZK_VERIFICATION=true`.

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

| Deploy                                   | `E3_PROOF_AGGREGATION_ENABLED` | Result                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mock (`ENABLE_ZK_VERIFICATION` unset)    | `true`                         | Ciphernodes generate real aggregation proofs, but `Interfold.pkVerifier` is `MockPkVerifier`. Attestation path may still run if a previous ZK deploy left `DkgFoldAttestationVerifier` on the registry from stale `deployed_contracts.json` on a **fresh** Anvil — always use `clean:deployments` + fresh chain. Prefer wiping `.interfold/data` and setting aggregation `false` for mock deploy. |
| ZK (`ENABLE_ZK_VERIFICATION=true`)       | `false`                        | Valid but skips on-chain DKG proof verification; committee publication uses empty proof bytes.                                                                                                                                                                                                                                                                                                    |
| ZK, circuits recompiled **after** deploy | `true`                         | **`VkHashMismatch()`** at `publishCommittee` — redeploy `BfvPkVerifier` (full ZK deploy) after `pnpm compile:circuits`.                                                                                                                                                                                                                                                                           |

---

## Address sync after deploy

`pnpm dev:up` runs deploy then automatically updates:

- `interfold.config.yaml` (ciphernode contract watches)
- `server/.env` (`INTERFOLD_ADDRESS`, `E3_PROGRAM_ADDRESS`, `CRISP_VOTING_TOKEN`, registry, fee
  token, mock refs, `E3_PROOF_AGGREGATION_ENABLED` from `crisp.dev.env`)
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

1. Set `CRISP_PROOF_AGGREGATION_ENABLED=true` in `crisp.dev.env` (and matching `CRISP_BFV_PRESET`)
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

| Step             | Mode A (`CRISP_PROOF_AGGREGATION_ENABLED=false`)                  | Mode B (`=true`)                                          |
| ---------------- | ----------------------------------------------------------------- | --------------------------------------------------------- |
| `pnpm dev:setup` | Skips `build:circuits`; sets aggregation `false` in `server/.env` | `pnpm build:circuits --preset …`; sets aggregation `true` |
| `pnpm dev:up`    | Mock BFV verifiers                                                | `ENABLE_ZK_VERIFICATION=true` + prints env vars           |

See also: `packages/interfold-contracts/scripts/deployInterfold.ts`,
`packages/interfold-contracts/contracts/verifiers/bfv/BfvPkVerifier.sol`, and
`agent/flow-trace/04_DKG_AND_COMPUTATION.md` for the full DKG publication flow.
