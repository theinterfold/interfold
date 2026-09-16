// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { readDeploymentArgs } from '@interfold/contracts/scripts'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

/** examples/CRISP */
const CRISP_ROOT = path.join(__dirname, '..', '..', '..')

function ensureEnvFile(envPath: string, examplePath: string): void {
  if (!fs.existsSync(envPath)) {
    if (!fs.existsSync(examplePath)) {
      throw new Error(`Missing ${examplePath}; cannot create ${envPath}`)
    }
    fs.copyFileSync(examplePath, envPath)
  }
}

/** Set or append KEY=value lines; preserves comments and unrelated keys. */
function applyEnvUpdates(envPath: string, updates: Record<string, string>): void {
  let content = fs.readFileSync(envPath, 'utf8')
  for (const [key, value] of Object.entries(updates)) {
    const pattern = new RegExp(`^${key}=.*$`, 'm')
    const line = `${key}=${value}`
    if (pattern.test(content)) {
      content = content.replace(pattern, line)
    } else {
      if (!content.endsWith('\n')) {
        content += '\n'
      }
      content += `${line}\n`
    }
  }
  fs.writeFileSync(envPath, content)
}

function deploymentAddress(contractName: string, chain: string): string | undefined {
  return readDeploymentArgs(contractName, chain)?.address
}

/**
 * The block a contract was deployed at, or `undefined` when the deployment does not record one.
 *
 * `blockNumber` is `number | null`, and a `null` written by an older deploy means the same as an
 * absent one. Collapsing the two here is what keeps `String(null)` from reaching the client as the
 * literal `null` — a value that looks configured and fails later, inside `BigInt`.
 */
function deploymentBlock(contractName: string, chain: string): number | undefined {
  return readDeploymentArgs(contractName, chain)?.blockNumber ?? undefined
}

/** Writes localhost deployment addresses into server/.env and client/.env. */
export function syncCrispEnvFromDeployments(chain: string): void {
  const interfoldAddress = deploymentAddress('Interfold', chain)
  const feeTokenAddress = deploymentAddress('MockUSDC', chain)
  const programAddress = deploymentAddress('CRISPProgram', chain)
  const registryAddress = deploymentAddress('CiphernodeRegistryOwnable', chain)
  const votingTokenAddress = deploymentAddress('MockVotingToken', chain)
  const programDeployBlock = deploymentBlock('CRISPProgram', chain)

  const missing: string[] = []
  if (!interfoldAddress) missing.push('Interfold')
  if (!feeTokenAddress) missing.push('MockUSDC')
  if (!programAddress) missing.push('CRISPProgram')
  if (!registryAddress) missing.push('CiphernodeRegistryOwnable')
  if (!votingTokenAddress) missing.push('MockVotingToken')

  if (missing.length > 0) {
    throw new Error(`Cannot sync CRISP .env files: missing deployments for ${missing.join(', ')} on chain "${chain}"`)
  }

  // Refused, not skipped. The client scans `CRISPProgram`'s logs from this block, and every way of
  // leaving it out is wrong in a way nothing reports: omitting the key keeps a new client file on
  // the template's `0` — a genesis scan, which hosted providers reject outright — and keeps an
  // existing file on whatever it held before, starting the scan silently in the wrong place.
  if (programDeployBlock === undefined) {
    throw new Error(`Cannot sync CRISP .env files: the "${chain}" deployment record has no block number for CRISPProgram`)
  }

  const serverEnv = path.join(CRISP_ROOT, 'server', '.env')
  const clientEnv = path.join(CRISP_ROOT, 'client', '.env')

  ensureEnvFile(serverEnv, path.join(CRISP_ROOT, 'server', '.env.example'))
  ensureEnvFile(clientEnv, path.join(CRISP_ROOT, 'client', '.env.example'))

  const serverUpdates: Record<string, string> = {
    INTERFOLD_ADDRESS: interfoldAddress!,
    FEE_TOKEN_ADDRESS: feeTokenAddress!,
    E3_PROGRAM_ADDRESS: programAddress!,
    CIPHERNODE_REGISTRY_ADDRESS: registryAddress!,
    CRISP_VOTING_TOKEN: votingTokenAddress!,
  }

  const mockMappings: Array<[string, string]> = [
    ['MOCK_COMPUTE_PROVIDER_ADDRESS', 'MockComputeProvider'],
    ['MOCK_DECRYPTION_VERIFIER_ADDRESS', 'MockDecryptionVerifier'],
    ['MOCK_PK_VERIFIER_ADDRESS', 'MockPkVerifier'],
    ['MOCK_E3_PROGRAM_ADDRESS', 'MockE3Program'],
  ]
  for (const [envKey, contractName] of mockMappings) {
    const addr = deploymentAddress(contractName, chain)
    if (addr) {
      serverUpdates[envKey] = addr
    }
  }

  applyEnvUpdates(serverEnv, serverUpdates)
  // The client scans `CRISPProgram`'s logs to resolve a slot head, and that scan cannot start at
  // genesis: hosted providers refuse a range that wide, and nothing in a round's public state is a
  // block height. The deployment record knows the block, so it is written here for every deployment
  // rather than left for an operator to fill in.
  applyEnvUpdates(clientEnv, {
    VITE_CRISP_TOKEN: votingTokenAddress!,
    VITE_CRISP_PROGRAM_DEPLOY_BLOCK: String(programDeployBlock),
  })

  console.log(`Synced deployment addresses → ${path.relative(CRISP_ROOT, serverEnv)}`)
  console.log(`Synced VITE_CRISP_TOKEN → ${path.relative(CRISP_ROOT, clientEnv)}`)
  console.log(`Synced VITE_CRISP_PROGRAM_DEPLOY_BLOCK=${programDeployBlock} → ${path.relative(CRISP_ROOT, clientEnv)}`)
}
