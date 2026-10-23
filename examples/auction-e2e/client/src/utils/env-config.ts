// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export const INTERFOLD_ADDRESS = import.meta.env.VITE_INTERFOLD_ADDRESS
export const E3_PROGRAM_ADDRESS = import.meta.env.VITE_E3_PROGRAM_ADDRESS
export const REGISTRY_ADDRESS = import.meta.env.VITE_REGISTRY_ADDRESS
export const FEE_TOKEN_ADDRESS = import.meta.env.VITE_FEE_TOKEN_ADDRESS
/** `interfold print-env --vite` names the WebSocket endpoint; the app only needs HTTP and converts it. */
export const RPC_URL: string = import.meta.env.VITE_RPC_URL || 'http://127.0.0.1:8545'
export const CHAIN_ID: string | undefined = import.meta.env.VITE_CHAIN_ID || undefined
export const WALLETCONNECT_PROJECT_ID: string = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || ''
/** Test deployments only: lets a user mint themselves the fee token (the token must expose a public `mint`). */
export const ENABLE_TEST_TOKEN_MINT_FLAG = import.meta.env.VITE_ENABLE_TEST_TOKEN_MINT === 'true'
/** A faucet that hands out the fee token (`Faucet.faucet()`); takes the place of minting when set. */
export const FAUCET_ADDRESS: string | undefined = import.meta.env.VITE_FAUCET_ADDRESS || undefined
/** The coordination server: relayed bids are posted to `<SERVER_URL>/relay`. */
export const SERVER_URL: string = (import.meta.env.VITE_SERVER_URL || 'http://127.0.0.1:8080').replace(/\/+$/, '')
/** The `MerkleAllowlistGate` of this deployment. Without it the create form offers no allowlist. */
export const ALLOWLIST_GATE_ADDRESS: `0x${string}` | undefined = import.meta.env.VITE_ALLOWLIST_GATE_ADDRESS || undefined

const parseBigInt = (name: string, value: string | undefined, fallback: bigint, min = 0n): bigint => {
  if (!value) return fallback
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a non-negative integer, got "${value}"`)
  const parsed = BigInt(value)
  if (parsed < min) throw new Error(`${name} must be at least ${min}, got "${value}"`)
  return parsed
}

/** The block the program's contracts were deployed in: every event scan starts here. */
export const DEPLOY_BLOCK = parseBigInt('VITE_DEPLOY_BLOCK', import.meta.env.VITE_DEPLOY_BLOCK, 0n)
/** Blocks per `eth_getLogs` request; public RPCs cap the range. */
export const LOG_CHUNK_SIZE = parseBigInt('VITE_LOG_CHUNK_SIZE', import.meta.env.VITE_LOG_CHUNK_SIZE, 50_000n, 1n)

const requiredEnvVars = {
  VITE_INTERFOLD_ADDRESS: INTERFOLD_ADDRESS,
  VITE_E3_PROGRAM_ADDRESS: E3_PROGRAM_ADDRESS,
  VITE_REGISTRY_ADDRESS: REGISTRY_ADDRESS,
  VITE_FEE_TOKEN_ADDRESS: FEE_TOKEN_ADDRESS,
}

export const MISSING_ENV_VARS = Object.entries(requiredEnvVars)
  .filter(([, value]) => !value)
  .map(([key]) => key)

/** Validated contract addresses. Only call once `MISSING_ENV_VARS` is empty (the app gates on it). */
export function getContractAddresses() {
  if (MISSING_ENV_VARS.length > 0) {
    throw new Error(`Missing required environment variables: ${MISSING_ENV_VARS.join(', ')}`)
  }
  return {
    interfold: INTERFOLD_ADDRESS as `0x${string}`,
    ciphernodeRegistry: REGISTRY_ADDRESS as `0x${string}`,
    e3Program: E3_PROGRAM_ADDRESS as `0x${string}`,
    feeToken: FEE_TOKEN_ADDRESS as `0x${string}`,
  }
}
