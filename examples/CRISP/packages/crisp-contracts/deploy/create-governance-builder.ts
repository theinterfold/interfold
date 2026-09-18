// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { ethers } from 'ethers'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import hre from 'hardhat'

type DeploymentRecord = {
  address?: string
}

type Deployments = Record<string, Record<string, DeploymentRecord>>

type ProtocolConfig = {
  name: string
  chainId: number
  protocolOwner: string
  governance?: {
    adminPlugin: string
    proposerSafe: string
    proposalMetadata?: string
  }
}

type ProtocolDeployment = {
  name: string
  chainId: number
  interfold: string
}

type SafeTransaction = {
  to: string
  value: string
  data: string
  operation: number
  contractMethod: null
  contractInputsValues: null
}

const scriptDir = dirname(fileURLToPath(import.meta.url))
const crispContractsDir = resolve(scriptDir, '..')
const repoRoot = resolve(crispContractsDir, '../../../..')
const protocolDir = resolve(repoRoot, 'packages/interfold-contracts/deploy/protocol')

function envPath(name: string, fallback: string): string {
  const value = process.env[name]
  return value ? resolve(process.cwd(), value) : fallback
}

const crispDeploymentsPath = envPath('CRISP_DEPLOYMENTS_PATH', resolve(crispContractsDir, 'deployed_contracts.json'))
const protocolConfigPath = envPath('PROTOCOL_CONFIG_PATH', resolve(protocolDir, 'mainnet-protocol.config.json'))
const protocolDeploymentPath = envPath('PROTOCOL_DEPLOYMENT_PATH', resolve(protocolDir, 'mainnet-protocol.deployment.json'))
const outputDir = envPath('CRISP_GOVERNANCE_OUTPUT_DIR', scriptDir)

const interfoldInterface = new ethers.Interface([
  'function setCiphertextVerifier(bytes32 encryptionSchemeId,address ciphertextVerifier)',
  'function registerE3Program(address e3Program)',
])
const crispInterface = new ethers.Interface(['function bindInterfold(address interfold)'])
const aragonAdminPluginInterface = new ethers.Interface([
  'function executeProposal(bytes metadata,tuple(address to,uint256 value,bytes data)[] actions,uint256 allowFailureMap)',
])

function readJson<T>(path: string): T {
  if (!existsSync(path)) throw new Error(`Missing ${path}`)
  return JSON.parse(readFileSync(path, 'utf8')) as T
}

function requireAddress(value: string | undefined, label: string): string {
  if (!value) throw new Error(`${label} is missing`)
  return ethers.getAddress(value)
}

function safeTx(to: string, data: string): SafeTransaction {
  return {
    to: ethers.getAddress(to),
    value: '0',
    data,
    operation: 0,
    contractMethod: null,
    contractInputsValues: null,
  }
}

async function main() {
  const chain = hre.globalOptions.network ?? 'localhost'

  const protocolConfig = readJson<ProtocolConfig>(protocolConfigPath)
  const protocolDeployment = readJson<ProtocolDeployment>(protocolDeploymentPath)
  if (!protocolConfig.name.startsWith(`${chain}-`)) {
    throw new Error(`Network mismatch: run with --network ${protocolConfig.name.replace(/-protocol$/, '')}, not --network ${chain}`)
  }
  const chainId = protocolConfig.chainId

  if (chainId === 1) {
    throw new Error(
      'This partial builder cannot activate CRISP on mainnet. Run pnpm --dir packages/interfold-contracts upgrade:secure-crisp so the same DAO batch installs the secure BFV implementation and all verifier routes.',
    )
  }

  const crispDeployments = readJson<Deployments>(crispDeploymentsPath)
  const chainDeployments = crispDeployments[chain]
  if (!chainDeployments) {
    throw new Error(`No CRISP deployments found for ${chain}`)
  }

  if (protocolDeployment.chainId !== chainId) {
    throw new Error(`Chain mismatch: config=${protocolConfig.chainId}, deployment=${protocolDeployment.chainId}`)
  }
  if (!protocolConfig.governance) {
    throw new Error('Protocol config has no Aragon governance route')
  }

  const interfold = requireAddress(protocolDeployment.interfold, 'Interfold')
  const crispProgram = requireAddress(chainDeployments.CRISPProgram?.address, 'CRISPProgram')
  const ciphertextVerifier = requireAddress(chainDeployments.OpenVmBfvCiphertextVerifier?.address, 'OpenVmBfvCiphertextVerifier')
  const adminPlugin = requireAddress(protocolConfig.governance.adminPlugin, 'Aragon Admin plugin')
  const proposerSafe = requireAddress(protocolConfig.governance.proposerSafe, 'Governance proposer Safe')
  const encryptionSchemeId = ethers.keccak256(ethers.toUtf8Bytes('fhe.rs:BFV'))

  const actions = [
    safeTx(interfold, interfoldInterface.encodeFunctionData('setCiphertextVerifier', [encryptionSchemeId, ciphertextVerifier])),
    safeTx(interfold, interfoldInterface.encodeFunctionData('registerE3Program', [crispProgram])),
    safeTx(crispProgram, crispInterface.encodeFunctionData('bindInterfold', [interfold])),
  ]

  const metadata = protocolConfig.governance.proposalMetadata ?? '0x'
  const wrapper = safeTx(
    adminPlugin,
    aragonAdminPluginInterface.encodeFunctionData('executeProposal', [
      metadata,
      actions.map((tx) => ({ to: tx.to, value: BigInt(tx.value), data: tx.data })),
      0n,
    ]),
  )

  mkdirSync(outputDir, { recursive: true })

  const rawActionsPath = resolve(outputDir, `${chain}-crisp.governance.safe-transactions.json`)
  const safeBuilderPath = resolve(outputDir, `${chain}-crisp.governance.safe-builder.json`)

  writeFileSync(
    rawActionsPath,
    JSON.stringify(
      {
        version: '1.0',
        chainId: chainId.toString(),
        createdAt: Date.now(),
        meta: {
          name: `${chain}-crisp protocol wiring`,
          description: 'Set the CRISP ciphertext verifier, register CRISP, and bind it to Interfold.',
          executor: protocolConfig.protocolOwner,
        },
        transactions: actions,
      },
      null,
      2,
    ),
  )

  writeFileSync(
    safeBuilderPath,
    JSON.stringify(
      {
        version: '1.0',
        chainId: chainId.toString(),
        createdAt: Date.now(),
        meta: {
          name: `${chain}-crisp Aragon Admin proposal`,
          description: 'Execute the CRISP protocol wiring actions through the Aragon Admin plugin.',
          txBuilderVersion: '1.18.0',
          createdFromSafeAddress: proposerSafe,
        },
        transactions: [wrapper],
      },
      null,
      2,
    ),
  )

  console.log(`CRISP governance builder written
  chain:                  ${chain}
  Interfold:              ${interfold}
  CRISPProgram:           ${crispProgram}
  OpenVM BFV verifier:      ${ciphertextVerifier}
  encryptionSchemeId:     ${encryptionSchemeId}
  raw DAO actions:        ${rawActionsPath}
  Safe Builder wrapper:   ${safeBuilderPath}`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
