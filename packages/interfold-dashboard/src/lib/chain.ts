// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Sepolia public client + contract addresses.
// Addresses sourced from packages/interfold-contracts/deployed_contracts.json
// and examples/CRISP/packages/crisp-contracts/deployed_contracts.json.
//
// ABIs are imported from the canonical typechain factories in
// @interfold/contracts so they cannot drift from the deployed contracts.

import { createPublicClient, http, type Address } from 'viem'
import { sepolia } from 'viem/chains'
import { CiphernodeRegistryOwnable__factory, Interfold__factory } from '@interfold/contracts/types'

// E3 lifecycle stages — mirrors the Solidity `IInterfold.E3Stage` enum exactly.
// Defined locally (rather than imported from @interfold/sdk) so the dashboard
// has no dependency on the SDK's Rust/Noir build chain when deploying.
export enum E3Stage {
  None = 0,
  Requested = 1,
  CommitteeFinalized = 2,
  KeyPublished = 3,
  CiphertextReady = 4,
  Complete = 5,
  Failed = 6,
}

// All deployment-specific values are env-overridable (see .env.example) so the
// dashboard can point at a different deployment without code changes. Defaults
// are the current Sepolia deployment from deployed_contracts.json.
const env = ((import.meta as any).env ?? {}) as Record<string, string | undefined>
const envStr = (key: string, fallback: string): string => {
  const v = env[key]
  return v && v.trim() !== '' ? v.trim() : fallback
}

const RPC_URL = envStr('VITE_SEPOLIA_RPC', 'https://ethereum-sepolia.publicnode.com')

export const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(RPC_URL, { batch: true }),
})

export const CONTRACTS = {
  Interfold: envStr('VITE_INTERFOLD_ADDRESS', '0x670eFE043d1D340148037b4b76c4F9dfED294309') as Address,
  CiphernodeRegistry: envStr('VITE_CIPHERNODE_REGISTRY_ADDRESS', '0x4D707127F72a216EA116AF0B4262dD7382F84259') as Address,
  CRISPProgram: envStr('VITE_CRISP_PROGRAM_ADDRESS', '0xbCc418F4dd1266Cc6070b1e2AC728ef56De946e7') as Address,
}

// First block to scan from — lower bound for getLogs (the Interfold deploy block).
export const DEPLOY_BLOCK = BigInt(envStr('VITE_DEPLOY_BLOCK', '10939869'))

// E3 timeout windows (seconds), matching the deployment's timeoutConfig. Used to
// decide whether an E3 is still genuinely active vs. expired without completing.
export const TIMEOUTS = {
  computeWindow: Number(envStr('VITE_COMPUTE_WINDOW', '86400')),
  decryptionWindow: Number(envStr('VITE_DECRYPTION_WINDOW', '3600')),
}

export const interfoldAbi = Interfold__factory.abi
export const ciphernodeRegistryAbi = CiphernodeRegistryOwnable__factory.abi
