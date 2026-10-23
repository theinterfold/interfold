// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { isAddress, type Address, type Chain, type Hex } from 'viem'
import { hardhat, sepolia } from 'viem/chains'

const CHAINS: Record<number, Chain> = {
  [hardhat.id]: hardhat,
  [sepolia.id]: sepolia,
}

/** Anvil account 9, `0xa0Ee7A142d267C1f36714E4a8F75612F20a79720`. Ciphernodes use accounts 1-5, bidders 6-8, the operator account 0. */
const LOCAL_RELAYER_KEY: Hex = '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6'

export type DataAvailabilityConfig =
  | { mode: 'mock_http' }
  | {
      mode: 'avail'
      rpcUrl: string
      appId: number
      /** Secret URI of the funded Avail account. Never log it. */
      seed: string
      bridgeApiUrl: string
      /** The `auction-da` binary that publishes to Avail and fetches VectorX proofs. */
      helperBinary: string
      proofPollIntervalMs: number
    }

export interface ServerConfig {
  rpcUrl: string
  /** Optional WebSocket endpoint for the live event listener. */
  wsRpcUrl?: string
  /** Never log it. */
  privateKey: Hex
  /**
   * Pays the gas of `POST /relay`. Never log it. `undefined` turns the endpoint off. The local chain
   * defaults to Anvil account 9, which no bidder and no ciphernode uses.
   */
  relayerPrivateKey?: Hex
  chain: Chain
  interfold: Address
  registry: Address
  feeToken: Address
  program: Address
  port: number
  programRunnerUrl: string
  /** The public base URL of this server. The runner calls back at `<callbackUrl>/callback/<e3Id>/<token>`. */
  callbackUrl: string
  /** First block that can hold an event of the auction program. */
  deployBlock: bigint
  /** Largest block range of one `eth_getLogs` request. */
  logChunkSize: bigint
  /** Where the server keeps published objects and Avail publication records. */
  dataDirectory: string
  dataAvailability: DataAvailabilityConfig
}

type Env = Record<string, string | undefined>

function required(env: Env, name: string): string {
  const value = env[name]?.trim()
  if (!value) throw new Error(`Missing required env var: ${name}`)
  return value
}

function url(name: string, value: string, protocols: readonly string[]): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`${name} must be a URL`)
  }
  if (!protocols.includes(parsed.protocol)) {
    throw new Error(`${name} must use ${protocols.map((protocol) => protocol.replace(':', '')).join(' or ')}`)
  }
  return value
}

function address(env: Env, name: string): Address {
  const value = required(env, name)
  if (!isAddress(value, { strict: false })) throw new Error(`${name} must be an address`)
  return value
}

function integer(name: string, value: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be an integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name} must be between ${min} and ${max}`)
  return parsed
}

function optionalInteger(env: Env, name: string, fallback: number, min: number, max?: number): number {
  const value = env[name]?.trim()
  return value ? integer(name, value, min, max) : fallback
}

/**
 * Read and validate the server configuration. The defaults suit the local anvil flow; a public chain
 * needs `DEPLOY_BLOCK` so the event scans do not start at block 0.
 */
export function loadConfig(env: Env = process.env): ServerConfig {
  const chainId = integer('CHAIN_ID', required(env, 'CHAIN_ID'), 1)
  const chain = CHAINS[chainId]
  if (!chain) throw new Error(`CHAIN_ID ${chainId} is not supported; use ${Object.keys(CHAINS).join(' or ')}`)

  const privateKey = required(env, 'PRIVATE_KEY')
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new Error('PRIVATE_KEY must be a 32-byte hex value with a 0x prefix')

  const relayerKey = env.RELAYER_PRIVATE_KEY?.trim() || (chainId === hardhat.id ? LOCAL_RELAYER_KEY : undefined)
  if (relayerKey && !/^0x[0-9a-fA-F]{64}$/.test(relayerKey))
    throw new Error('RELAYER_PRIVATE_KEY must be a 32-byte hex value with a 0x prefix')

  const wsRpcUrl = env.WS_RPC_URL?.trim()
  const deployBlockText = env.DEPLOY_BLOCK?.trim()
  if (!deployBlockText && chainId !== hardhat.id) {
    throw new Error(`DEPLOY_BLOCK is required on chain ${chainId}: it is the block of the AuctionProgram deployment`)
  }

  const mode = env.DATA_AVAILABILITY_MODE?.trim() || 'mock_http'
  let dataAvailability: DataAvailabilityConfig
  if (mode === 'mock_http') {
    dataAvailability = { mode }
  } else if (mode === 'avail') {
    dataAvailability = {
      mode,
      rpcUrl: url('AVAIL_RPC_URL', required(env, 'AVAIL_RPC_URL'), ['http:', 'https:']),
      appId: integer('AVAIL_APP_ID', required(env, 'AVAIL_APP_ID'), 0, 0xffff_ffff),
      seed: required(env, 'AVAIL_SEED'),
      bridgeApiUrl: url('AVAIL_BRIDGE_API_URL', required(env, 'AVAIL_BRIDGE_API_URL'), ['http:', 'https:']),
      helperBinary: env.AUCTION_DA_BIN?.trim() || 'auction-da',
      proofPollIntervalMs: optionalInteger(env, 'AVAIL_PROOF_POLL_INTERVAL_SECONDS', 60, 1) * 1000,
    }
  } else {
    throw new Error(`DATA_AVAILABILITY_MODE must be 'mock_http' or 'avail', not '${mode}'`)
  }

  return {
    rpcUrl: url('RPC_URL', required(env, 'RPC_URL'), ['http:', 'https:']),
    wsRpcUrl: wsRpcUrl ? url('WS_RPC_URL', wsRpcUrl, ['ws:', 'wss:']) : undefined,
    privateKey: privateKey as Hex,
    relayerPrivateKey: relayerKey as Hex | undefined,
    chain,
    interfold: address(env, 'INTERFOLD_ADDRESS'),
    registry: address(env, 'REGISTRY_ADDRESS'),
    feeToken: address(env, 'FEE_TOKEN_ADDRESS'),
    program: address(env, 'E3_PROGRAM_ADDRESS'),
    port: optionalInteger(env, 'PORT', 8080, 1, 65535),
    programRunnerUrl: url('PROGRAM_RUNNER_URL', env.PROGRAM_RUNNER_URL?.trim() || 'http://127.0.0.1:13151', ['http:', 'https:']).replace(
      /\/+$/,
      '',
    ),
    callbackUrl: url('CALLBACK_URL', env.CALLBACK_URL?.trim() || 'http://127.0.0.1:8080', ['http:', 'https:']).replace(/\/+$/, ''),
    deployBlock: BigInt(deployBlockText ? integer('DEPLOY_BLOCK', deployBlockText, 0) : 0),
    logChunkSize: BigInt(optionalInteger(env, 'LOG_CHUNK_SIZE', 10_000, 1)),
    dataDirectory: env.DATA_DIRECTORY?.trim() || '.interfold/data-availability',
    dataAvailability,
  }
}
