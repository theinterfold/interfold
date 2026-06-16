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

function parseSimpleEnvFile(filePath: string): Record<string, string> {
  if (!fs.existsSync(filePath)) {
    return {}
  }
  const out: Record<string, string> = {}
  for (const line of fs.readFileSync(filePath, 'utf8').split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) {
      continue
    }
    const eq = trimmed.indexOf('=')
    if (eq === -1) {
      continue
    }
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim()
  }
  return out
}

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
 * Writes localhost deployment addresses into server/.env and client/.env, and
 * syncs E3_PROOF_AGGREGATION_ENABLED from crisp.dev.env.
 */
export function syncCrispEnvFromDeployments(chain: string): void {
  const interfoldAddress = deploymentAddress('Interfold', chain)
  const feeTokenAddress = deploymentAddress('MockUSDC', chain)
  const programAddress = deploymentAddress('CRISPProgram', chain)
  const registryAddress = deploymentAddress('CiphernodeRegistryOwnable', chain)
  const votingTokenAddress = deploymentAddress('MockVotingToken', chain)

  const missing: string[] = []
  if (!interfoldAddress) missing.push('Interfold')
  if (!feeTokenAddress) missing.push('MockUSDC')
  if (!programAddress) missing.push('CRISPProgram')
  if (!registryAddress) missing.push('CiphernodeRegistryOwnable')
  if (!votingTokenAddress) missing.push('MockVotingToken')

  if (missing.length > 0) {
    throw new Error(`Cannot sync CRISP .env files: missing deployments for ${missing.join(', ')} on chain "${chain}"`)
  }

  const crispDev = parseSimpleEnvFile(path.join(CRISP_ROOT, 'crisp.dev.env'))
  const proofAggregation =
    crispDev.CRISP_PROOF_AGGREGATION_ENABLED ??
    parseSimpleEnvFile(path.join(CRISP_ROOT, 'crisp.dev.env.example')).CRISP_PROOF_AGGREGATION_ENABLED ??
    'false'

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
    E3_PROOF_AGGREGATION_ENABLED: proofAggregation,
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
  applyEnvUpdates(clientEnv, {
    VITE_CRISP_TOKEN: votingTokenAddress!,
  })

  console.log(`Synced deployment addresses → ${path.relative(CRISP_ROOT, serverEnv)}`)
  console.log(`Synced VITE_CRISP_TOKEN → ${path.relative(CRISP_ROOT, clientEnv)}`)
  console.log(`  E3_PROOF_AGGREGATION_ENABLED=${proofAggregation} (from crisp.dev.env)`)
}
