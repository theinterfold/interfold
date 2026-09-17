// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Checks that every published contract address in the repository matches the
 * current deployment.
 *
 * `deployments/manifest.json` is the single source of truth. A separate check,
 * `pnpm --filter @interfold/contracts gen:manifest:check`, keeps that file equal
 * to `deployed_contracts.json`. This check covers the other direction: the docs,
 * the dashboard, the DAppNode package, and the CRISP example all quote the same
 * addresses, and a redeploy that updates the manifest alone leaves them stale.
 *
 * Two rules apply:
 *
 *   1. Coverage. A tracked file that contains a current manifest address must
 *      appear in `FILES` below. This makes the list self-maintaining: a new file
 *      that quotes a live address fails until somebody classifies it.
 *   2. Freshness. Each `consumer` file must contain only current manifest
 *      addresses, or addresses in `ALLOWED`. This catches the address that stays
 *      behind after a redeploy.
 *
 * Run: `pnpm check:addresses`
 */
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST = 'deployments/manifest.json'

const ADDRESS = /0x[a-fA-F0-9]{40}/g

/**
 * How each file relates to the deployment.
 *
 * `source`   The truth, or the file the truth is generated from.
 * `record`   A deployment or transaction record. It states what happened at one
 *            point in time, so a later redeploy must not rewrite it.
 * `consumer` A file that tells an operator, an application, or a running node
 *            which addresses to use now. Only these get the freshness rule.
 */
type Role = 'source' | 'record' | 'consumer'

const FILES: Record<string, Role> = {
  'deployments/manifest.json': 'source',
  'packages/interfold-contracts/deployed_contracts.json': 'source',

  'packages/interfold-contracts/deploy/protocol/mainnet-protocol.config.json': 'record',
  'packages/interfold-contracts/deploy/protocol/mainnet-protocol.deployment.json': 'record',
  'packages/interfold-contracts/deploy/protocol/mainnet-protocol.safe-transactions.json': 'record',
  'packages/interfold-contracts/deploy/protocol/mainnet-protocol.vrf-sortition.upgrade.governance.safe-builder.json': 'record',
  'packages/interfold-contracts/deploy/protocol/mainnet-protocol.vrf-sortition.upgrade.json': 'record',
  'packages/interfold-contracts/deploy/protocol/mainnet-protocol.vrf-sortition.upgrade.safe.json': 'record',
  'examples/CRISP/packages/crisp-contracts/deployed_contracts.json': 'record',
  'dappnode/tests/test-hardening.sh': 'record',

  'docs/pages/ciphernode-operators/index.mdx': 'consumer',
  'docs/pages/ciphernode-operators/running.mdx': 'consumer',
  'docs/pages/tutorials/deploy-to-testnet.mdx': 'consumer',
  'packages/interfold-dashboard/.env.example': 'consumer',
  'packages/interfold-dashboard/src/lib/chain.ts': 'consumer',
  'examples/CRISP/interfold.config.yaml': 'consumer',
  'dappnode/docker-compose.yml': 'consumer',
}

/**
 * Addresses a consumer file can carry that the manifest does not publish. Each
 * entry needs a reason, because an entry without one hides the drift this check
 * exists to find.
 */
const ALLOWED: Record<string, string> = {
  '0x0000000000000000000000000000000000000000': 'zero address',

  // Third-party tokens. Interfold does not deploy them, so no deployment record
  // can carry them.
  '0xa3931d71877c0e7a3148cb7eb4463524fec27fbd': 'sUSDS, mainnet ticket collateral',

  // An E3 program belongs to its application, not to the protocol. See the
  // comment on `CONTRACT_KEYS` in packages/interfold-contracts/scripts/genManifest.ts.
  '0x8654f380760c46857188097fa0ad0bf995603124': 'CRISPProgram, sepolia',

  // TODO: record these in deployed_contracts.json so the manifest can publish
  // them. Until then no check can tell a correct value here from a stale one.
  '0xe172e9b6cfbeeb5593bdce3f077356fdb33af904': 'InterfoldToken (FOLD), mainnet — no top-level deployment record',
  '0xb568e5ad762f7a75f1ec65a985ec4038f6409297': 'DeployableMockCiphertextVerifier, mainnet — no deployment record',

  // Deterministic Anvil accounts used by the local CRISP stack.
  '0x70997970c51812dc3a010c7d01b50e0d17dc79c8': 'Anvil account 1',
  '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc': 'Anvil account 2',
  '0x90f79bf6eb2c4f870365e785982e1f101e93b906': 'Anvil account 3',
  '0x15d34aaf54267db7d7c367839aaf71a00a2c6a65': 'Anvil account 4',
  '0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc': 'Anvil account 5',
  '0x9a676e781a523b5d0c0e43731313a708cb607508': 'Anvil account 7',
  '0x8198f5d8f8cffe8f9c413d98a0a55aeb8ab9fbb7': 'local devnet deployment',
  '0xa513e6e4b8f2a923d98304ec87f64353c4d5c853': 'local devnet deployment',
  '0xc3e53f4d16ae77db1c982e75a937b9f60fe63690': 'local devnet deployment',
  '0xdc64a140aa3e981100a9beca4e685f962f0cf6c9': 'local devnet deployment',
  '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512': 'local devnet deployment',
}

/**
 * The names a consumer file uses for a manifest entry, mapped to the manifest
 * name. A file states the contract next to the address, so the address alone is
 * not enough: a table whose rows drift apart, or a config key that gets the
 * wrong value, holds only current addresses and still misleads an operator.
 *
 * A label that is absent here is not checked. Add one when a file starts to
 * name a contract in a new way.
 */
const LABELS: Record<string, string> = {
  // interfold.config.yaml keys, and the docs blocks that mirror them.
  interfold: 'interfold',
  ciphernode_registry: 'ciphernode_registry',
  bonding_registry: 'bonding_registry',
  slashing_manager: 'slashing_manager',
  fee_token: 'fee_token',
  faucet: 'faucet',

  // DAppNode and tutorial environment variables.
  INTERFOLD_CONTRACT: 'interfold',
  CIPHERNODE_REGISTRY_CONTRACT: 'ciphernode_registry',
  BONDING_REGISTRY_CONTRACT: 'bonding_registry',
  SLASHING_MANAGER_CONTRACT: 'slashing_manager',
  FEE_TOKEN_CONTRACT: 'fee_token',
  INTERFOLD_ADDRESS: 'interfold',
  CIPHERNODE_REGISTRY_ADDRESS: 'ciphernode_registry',
  FEE_TOKEN_ADDRESS: 'fee_token',

  // Dashboard network profiles.
  ciphernodeRegistry: 'ciphernode_registry',
  bondingRegistry: 'bonding_registry',

  // Operator docs tables. The check drops a parenthetical before it looks the
  // name up, so "InterfoldToken (FOLD)" arrives here as "InterfoldToken".
  Interfold: 'interfold',
  CiphernodeRegistry: 'ciphernode_registry',
  BondingRegistry: 'bonding_registry',
  SlashingManager: 'slashing_manager',
  MockUSDC: 'fee_token',
  USDS: 'fee_token',
  Faucet: 'faucet',
  InterfoldToken: 'InterfoldToken',
  InterfoldTicketToken: 'InterfoldTicketToken',
  E3RefundManager: 'E3RefundManager',
  MockE3Program: 'MockE3Program',
  MockComputeProvider: 'MockComputeProvider',
  MockDecryptionVerifier: 'MockDecryptionVerifier',
  MockCiphertextVerifier: 'MockCiphertextVerifier',
  MockPkVerifier: 'MockPkVerifier',
}

/** Files this check never reads, whatever they contain. */
const SKIP = [
  /(^|\/)node_modules\//,
  /(^|\/)artifacts\//,
  /(^|\/)cache\//,
  /\.(lock|png|jpe?g|gif|svg|gz|zip|wasm|bin)$/,
  /^pnpm-lock\.yaml$/,
  /^Cargo\.lock$/,
]

type Published = { address: string; where: string; network: string; name: string; deployBlock?: number }

/**
 * Every manifest entry, grouped by address.
 *
 * One address can hold more than one entry. A deterministic deployment puts the
 * same address on two networks, and one network can publish an address under
 * both `contracts` and `reference`. Keying by address alone would keep whichever
 * entry the loop reached last, and the name and deploy block checks would then
 * measure a consumer against another network.
 */
const readManifest = (): Map<string, Published[]> => {
  const raw = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, MANIFEST), 'utf8')) as {
    networks: Record<string, Record<string, Record<string, { address?: string; deploy_block?: number }> | unknown>>
  }

  const published = new Map<string, Published[]>()
  for (const [network, body] of Object.entries(raw.networks ?? {})) {
    for (const section of ['contracts', 'reference']) {
      const entries = (body as Record<string, unknown>)[section]
      if (!entries || typeof entries !== 'object') continue
      for (const [name, entry] of Object.entries(entries as Record<string, { address?: string; deploy_block?: number }>)) {
        if (!entry?.address) continue
        const key = entry.address.toLowerCase()
        const found = published.get(key) ?? []
        found.push({
          address: entry.address,
          where: `${network}.${section}.${name}`,
          network,
          name,
          deployBlock: entry.deploy_block,
        })
        published.set(key, found)
      }
    }
  }

  if (published.size === 0) {
    throw new Error(`${MANIFEST} publishes no addresses. Run \`pnpm gen:manifest\`.`)
  }
  return published
}

const trackedFiles = (): string[] =>
  execFileSync('git', ['ls-files'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    .split('\n')
    .filter((file) => file && !SKIP.some((pattern) => pattern.test(file)))

const addressesIn = (file: string): string[] => {
  const full = path.join(REPO_ROOT, file)
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) return []
  const text = fs.readFileSync(full, 'utf8')
  return [...new Set(text.match(ADDRESS) ?? [])]
}

/** One address in a consumer file, with the name and deploy block beside it. */
type Binding = { line: number; label: string; address: string; block?: number }

const TABLE_ROW = /^\|\s*([^|]+?)\s*\|\s*`?(0x[0-9a-fA-F]{40})`?\s*\|\s*(\d+)?/
const KEYED_ADDRESS = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*['"]?(0x[0-9a-fA-F]{40})/
const PARENT_KEY = /^\s*([a-z_]+):\s*$/
const DEPLOY_BLOCK = /^\s*deploy_block:\s*'?(\d+)/

/**
 * Reads every address in a consumer file together with the name beside it.
 *
 * Three shapes cover the files in `FILES`: a markdown table row, a `KEY: 0x...`
 * or `KEY=0x...` pair, and the nested YAML block where `address:` sits under the
 * contract key. The nested block reports `address` as its own key, so the parent
 * key is read from the lines above.
 */
const bindingsIn = (file: string): Binding[] => {
  const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf8').split('\n')
  const bindings: Binding[] = []

  lines.forEach((line, index) => {
    const row = TABLE_ROW.exec(line)
    if (row) {
      // "InterfoldToken (FOLD)" names the same entry as "InterfoldToken".
      const label = row[1]
        .replace(/`/g, '')
        .replace(/\s*\(.*\)\s*$/, '')
        .trim()
      bindings.push({ line: index + 1, label, address: row[2], block: row[3] ? Number(row[3]) : undefined })
      return
    }

    const keyed = KEYED_ADDRESS.exec(line)
    if (!keyed) return

    let label = keyed[1]
    if (label === 'address') {
      for (let above = index - 1; above >= 0 && above > index - 4; above -= 1) {
        const parent = PARENT_KEY.exec(lines[above])
        if (parent) {
          label = parent[1]
          break
        }
      }
    }

    let block: number | undefined
    for (let below = index + 1; below < lines.length && below < index + 3; below += 1) {
      const found = DEPLOY_BLOCK.exec(lines[below])
      if (found) {
        block = Number(found[1])
        break
      }
    }

    bindings.push({ line: index + 1, label, address: keyed[2], block })
  })

  return bindings
}

const main = (): void => {
  const published = readManifest()
  const problems: string[] = []

  // Rule 1: a file that quotes a live address must be classified.
  for (const file of trackedFiles()) {
    if (FILES[file]) continue
    const live = addressesIn(file).filter((a) => published.has(a.toLowerCase()))
    if (live.length === 0) continue
    problems.push(
      `${file}: contains published address ${live[0]} but is not listed in scripts/check-addresses.ts.\n` +
        `  Add it to FILES as "consumer" if it must stay current, or as "record" if it states history.`,
    )
  }

  // Rule 2: a consumer file may quote only current or allowed addresses.
  for (const [file, role] of Object.entries(FILES)) {
    if (role !== 'consumer') continue
    if (!fs.existsSync(path.join(REPO_ROOT, file))) {
      problems.push(`${file}: listed in scripts/check-addresses.ts but not found.`)
      continue
    }
    for (const address of addressesIn(file)) {
      const key = address.toLowerCase()
      if (published.has(key) || ALLOWED[key]) continue
      problems.push(
        `${file}: ${address} is not in ${MANIFEST} and is not allowed.\n` +
          `  A redeploy probably left it behind. Replace it with the current address, or add it to\n` +
          `  ALLOWED in scripts/check-addresses.ts with the reason it cannot come from the manifest.`,
      )
    }

    // Rules 3 and 4: the name and the deploy block beside an address must agree
    // with the manifest. Rule 2 only proves the address is still in the set.
    //
    // An address can hold several entries, so a binding passes when one entry
    // accounts for it. The name narrows the entries first, which keeps the
    // deploy block tied to the contract the line actually names.
    for (const binding of bindingsIn(file)) {
      const entries = published.get(binding.address.toLowerCase())
      if (!entries) continue

      const expected = LABELS[binding.label]
      let candidates = entries
      if (expected) {
        candidates = entries.filter((entry) => entry.name === expected)
        if (candidates.length === 0) {
          problems.push(
            `${file}:${binding.line}: this line calls ${binding.address} "${binding.label}", but the manifest publishes it as ` +
              `${entries.map((entry) => entry.where).join(', ')}.`,
          )
          continue
        }
      }

      if (binding.block === undefined) continue

      const known = candidates.filter((entry) => entry.deployBlock !== undefined)
      if (known.length === 0) continue
      if (known.some((entry) => entry.deployBlock === binding.block)) continue

      problems.push(
        `${file}:${binding.line}: ${binding.address} shows deploy block ${binding.block}, but ` +
          `${known.map((entry) => `${entry.where} was deployed at ${entry.deployBlock}`).join(', ')}.`,
      )
    }
  }

  // Keep the allowlist honest: an entry that no consumer uses is dead weight.
  const used = new Set(
    Object.entries(FILES)
      .filter(([, role]) => role === 'consumer')
      .flatMap(([file]) => addressesIn(file).map((a) => a.toLowerCase())),
  )
  for (const address of Object.keys(ALLOWED)) {
    if (!used.has(address)) {
      problems.push(`${address} is allowed in scripts/check-addresses.ts but no consumer file uses it. Remove it.`)
    }
  }

  if (problems.length > 0) {
    console.error('Contract addresses are inconsistent:\n')
    for (const problem of problems) console.error(`- ${problem}\n`)
    process.exit(1)
  }

  const consumers = Object.values(FILES).filter((role) => role === 'consumer').length
  console.log(`Contract addresses are consistent: ${published.size} published, ${consumers} consumer files checked.`)
}

main()
