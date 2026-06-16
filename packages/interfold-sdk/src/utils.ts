// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Address, type Hash, type Log, PublicClient, encodeAbiParameters } from 'viem'
import type { BfvParams } from './types'

export class SDKError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
  ) {
    super(message)
    this.name = 'SDKError'
  }
}

export function isValidAddress(address: string): address is Address {
  return /^0x[a-fA-F0-9]{40}$/.test(address)
}

export function isValidHash(hash: string): hash is Hash {
  return /^0x[a-fA-F0-9]{64}$/.test(hash)
}

export function formatEventName(contractName: string, eventName: string): string {
  return `${contractName}.${eventName}`
}

export function parseEventData<T>(log: Log): T {
  return log.data as unknown as T
}

/**
 * Sleep for a specified number of milliseconds
 */
export const sleep = (ms: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export function formatBigInt(value: bigint): string {
  return value.toString()
}

export function parseBigInt(value: string): bigint {
  return BigInt(value)
}

export function generateEventId(log: Log): string {
  return `${log.blockHash}-${log.logIndex}`
}

/**
 * Get the current timestamp in seconds
 * from onchain
 * @param publicClient - The public client to use
 */
export async function getCurrentTimestamp(publicClient: PublicClient): Promise<bigint> {
  const block = await publicClient.getBlock()
  return block.timestamp
}

// Compute provider parameters structure
export interface ComputeProviderParams {
  name: string
  parallel: boolean
  batch_size: number
}

// Default compute provider configuration
export const DEFAULT_COMPUTE_PROVIDER_PARAMS: ComputeProviderParams = {
  name: 'risc0',
  parallel: false,
  batch_size: 2,
}

// Default E3 configuration (`committeeSize` is `IInterfold.CommitteeSize`, not circuit N_PARTIES).
export const DEFAULT_E3_CONFIG = {
  committeeSize: 0, // CommitteeSize.Minimum
  duration: 1800, // 30 minutes in seconds
  payment_amount: '0', // 0 ETH in wei
} as const

/**
 * Encode BFV parameters for the smart contract
 * BFV (Brakerski-Fan-Vercauteren) is a type of fully homomorphic encryption
 */
export function encodeBfvParams(params: BfvParams): `0x${string}` {
  const { degree, plaintextModulus, moduli, error1Variance } = params

  if (error1Variance === undefined) {
    throw new SDKError(
      'error1Variance is required in ProtocolParams. All BFV parameter sets must specify error1_variance.',
      'MISSING_ERROR1_VARIANCE',
    )
  }

  return encodeAbiParameters(
    [
      {
        name: 'bfvParams',
        type: 'tuple',
        components: [
          { name: 'degree', type: 'uint256' },
          { name: 'plaintext_modulus', type: 'uint256' },
          { name: 'moduli', type: 'uint256[]' },
          { name: 'error1_variance', type: 'string' },
        ],
      },
    ],
    [
      {
        degree: BigInt(degree),
        plaintext_modulus: BigInt(plaintextModulus),
        moduli: [...moduli],
        error1_variance: error1Variance,
      },
    ],
  )
}

/**
 * Encode compute provider parameters for the smart contract'
 * If mock is true, the compute provider parameters will return 32 bytes of 0x00
 */
export function encodeComputeProviderParams(params: ComputeProviderParams, mock: boolean = false): `0x${string}` {
  if (mock) {
    return `0x${'00'.repeat(32)}` as `0x${string}`
  }

  const jsonString = JSON.stringify(params)
  const encoder = new TextEncoder()
  const bytes = encoder.encode(jsonString)

  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`
}

/**
 * Encode custom parameters for the smart contract.
 */
export function encodeCustomParams(params: Record<string, unknown>): `0x${string}` {
  const jsonString = JSON.stringify(params)
  const encoder = new TextEncoder()
  const bytes = encoder.encode(jsonString)

  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`
}

// inputWindow[0] is always larger than now and dkg deadline
export const inputWindowStartBuffer = 15n

/**
 * Calculate start window for E3 request
 * @dev This function can be used for testing purposes, or for E3s which need to start as soon as possible.
 * @param publicClient - The public client to use
 * @param duration - The duration of the input window in seconds
 * @param startBuffer - Buffer in seconds added to current timestamp for input window start
 */
export async function calculateInputWindow(
  publicClient: PublicClient,
  duration: number = DEFAULT_E3_CONFIG.duration,
  startBuffer: bigint = inputWindowStartBuffer,
): Promise<[bigint, bigint]> {
  const now = await getCurrentTimestamp(publicClient)
  return [BigInt(now) + startBuffer, BigInt(now) + startBuffer + BigInt(duration)]
}

/**
 * Decode plaintextOutput bytes to get the actual result number
 */
export function decodePlaintextOutput(plaintextOutput: string): number | null {
  try {
    // Remove '0x' prefix if present
    const hex = plaintextOutput.startsWith('0x') ? plaintextOutput.slice(2) : plaintextOutput

    // Convert hex to bytes
    const bytes = new Uint8Array(hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [])

    if (bytes.length < 8) {
      console.warn('Plaintext output too short for u64 decoding')
      return null
    }

    // Decode first u64 (8 bytes) as little-endian
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const result = view.getBigUint64(0, true) // true for little-endian

    return Number(result)
  } catch (error) {
    console.error('Failed to decode plaintext output:', error)
    return null
  }
}

// Helper function to convert proof bytes to field elements
export function proofToFields(proof: Uint8Array): string[] {
  const fields: string[] = []
  for (let i = 0; i < proof.length; i += 32) {
    const chunk = proof.slice(i, i + 32)
    fields.push('0x' + Buffer.from(chunk).toString('hex'))
  }
  return fields
}
