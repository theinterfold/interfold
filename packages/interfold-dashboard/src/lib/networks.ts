// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Network profiles and the environment variables that select and override them.
// Sepolia addresses sourced from deployments/manifest.json (networks.sepolia) and
// packages/interfold-contracts/deployed_contracts.json, mainnet addresses from
// deployments/manifest.json (networks.mainnet).
//
// This module imports no contract bindings, so vite.config.ts can use it to
// reject a bad build environment before the build starts.

import type { Chain } from 'viem'
import { mainnet, sepolia } from 'viem/chains'

// Per-network deployment profile. Every value in it can be overridden for one
// network with `VITE_<NETWORK>_<SETTING>`, so the dashboard can point at a custom
// deployment without code changes.
export type NetworkProfile = {
  chain: Chain
  // Human-readable name used in UI copy ("Reading from Sepolia…").
  name: string
  rpc: string
  explorer: string
  interfold: string
  ciphernodeRegistry: string
  crispProgram: string
  // Earlier CRISP program deployments. Their E3s still show as CRISP polls. No variable overrides
  // this list.
  previousCrispPrograms: readonly string[]
  bondingRegistry: string
  // Empty string = no faucet on this network (hides the operator-guide card).
  faucet: string
  deployBlock: string
  // Fee token metadata for formatting escrowed fees/rewards. Hardcoded per
  // deployment (like the addresses) rather than read on-chain at runtime.
  feeSymbol: string
  feeDecimals: number
  // E3 timeout windows (seconds), from the deployment's getTimeoutConfig().
  computeWindow: string
  decryptionWindow: string
}

export type NetworkKey = 'sepolia' | 'mainnet'

export const NETWORKS: Record<NetworkKey, NetworkProfile> = {
  sepolia: {
    chain: sepolia,
    name: 'Sepolia',
    rpc: 'https://ethereum-sepolia.publicnode.com',
    explorer: 'https://sepolia.etherscan.io',
    interfold: '0xBD5B6D1aDA9e0eB248B678469C9Cd6a63507E42b',
    ciphernodeRegistry: '0xb1E8640CF8D0A927290E3d9E1b01c4899B5225Ef',
    crispProgram: '0xA9894A39061EC33f8550a2B63A66Be59fb9fa443',
    previousCrispPrograms: [],
    bondingRegistry: '0x8687bC7C8f055b41aD2C2447c04aCBD76C1075b2',
    // Test Faucet. It sends 1000 FOLD and 1000 MockUSDC.
    faucet: '0x1B4340A65BB669267BF5DE37385B139987C3F09c',
    // Deploy block of the Interfold and the CiphernodeRegistry (11873232), the earliest of those two
    // and the CRISPProgram (11873424). A later value silently drops early registry events.
    deployBlock: '11873232',
    // MockUSDC (0xE2e534F7…555B), the fee token and ticket collateral. Anyone can mint it.
    feeSymbol: 'USDC',
    feeDecimals: 6,
    computeWindow: '604800',
    decryptionWindow: '21600',
  },
  mainnet: {
    chain: mainnet,
    name: 'Ethereum mainnet',
    rpc: 'https://ethereum-rpc.publicnode.com',
    explorer: 'https://etherscan.io',
    interfold: '0x28cF63B459e6218C69EA97ea7D90541cf648c715',
    ciphernodeRegistry: '0xC927A5B2d8F68697bC28C0670df05178c93df2d7',
    crispProgram: '0x1EA4dBdec0F2F1E9235915847fc59EF4045EEe28',
    // The first mainnet CRISP program. It ran E3-0 to E3-2.
    previousCrispPrograms: ['0x53FCdb21E73A461CfE6c64B19855204384B91BA3'],
    bondingRegistry: '0x0ec90465095C21830BEcED07e032809A2Bd2915F',
    // No faucet on mainnet.
    faucet: '',
    // All mainnet contracts were deployed in the same block.
    deployBlock: '25786403',
    // USDS (0xdC035D45…384F) on the mainnet deployment.
    feeSymbol: 'USDS',
    feeDecimals: 18,
    computeWindow: '604800',
    decryptionWindow: '21600',
  },
}

// Profile values that `VITE_<NETWORK>_<SETTING>` can override.
const SETTINGS = [
  'RPC_URL',
  'INTERFOLD_ADDRESS',
  'CIPHERNODE_REGISTRY_ADDRESS',
  'CRISP_PROGRAM_ADDRESS',
  'BONDING_REGISTRY_ADDRESS',
  'FAUCET_ADDRESS',
  'FEE_TOKEN_SYMBOL',
  'FEE_TOKEN_DECIMALS',
  'DEPLOY_BLOCK',
  'COMPUTE_WINDOW',
  'DECRYPTION_WINDOW',
] as const

export type Setting = (typeof SETTINGS)[number]

export type Env = Record<string, string | undefined>

const NETWORK_KEYS = Object.keys(NETWORKS) as NetworkKey[]

const toNetworkKey = (value: string, variable: string): NetworkKey => {
  const key = value.trim().toLowerCase()
  const match = NETWORK_KEYS.find((k) => k === key)
  if (!match) {
    throw new Error(`Unknown network "${value}" in ${variable}. Expected one of: ${NETWORK_KEYS.join(', ')}`)
  }
  return match
}

// The variable that overrides one profile value of one network, for example
// VITE_SEPOLIA_RPC_URL. Scoping by network lets one build serve several networks
// without one network's override leaking into another.
export const overrideKey = (network: NetworkKey, setting: Setting): string => `VITE_${network.toUpperCase()}_${setting}`

// VITE_NETWORK_HOSTS maps hostnames to networks as comma-separated host=network
// pairs, for example "testnet.example.com=sepolia".
export function parseNetworkHosts(value: string | undefined): Map<string, NetworkKey> {
  const hosts = new Map<string, NetworkKey>()
  for (const entry of (value ?? '').split(',')) {
    if (entry.trim() === '') continue
    const parts = entry.split('=')
    if (parts.length !== 2 || parts[0].trim() === '') {
      throw new Error(`Invalid VITE_NETWORK_HOSTS entry "${entry.trim()}". Expected host=network.`)
    }
    hosts.set(parts[0].trim().toLowerCase(), toNetworkKey(parts[1], 'VITE_NETWORK_HOSTS'))
  }
  return hosts
}

// The network for the page's hostname from VITE_NETWORK_HOSTS. Any other host
// (preview deployments, localhost) gets VITE_NETWORK, and sepolia when that is unset.
export function selectNetwork(env: Env, hostname: string | undefined): NetworkKey {
  const byHost = hostname === undefined ? undefined : parseNetworkHosts(env.VITE_NETWORK_HOSTS).get(hostname.toLowerCase())
  if (byHost) return byHost
  const configured = env.VITE_NETWORK?.trim()
  return configured ? toNetworkKey(configured, 'VITE_NETWORK') : 'sepolia'
}

// Overrides set without a network scope, for example VITE_RPC_URL. The dashboard
// reads only scoped names, so an unscoped one would leave the profile default in
// place without an error. Other VITE_* names (Vercel adds VITE_VERCEL_*) are not
// the dashboard's to check.
export function unscopedOverrideKeys(env: Env): string[] {
  return SETTINGS.map((setting) => `VITE_${setting}`).filter((key) => key in env)
}
