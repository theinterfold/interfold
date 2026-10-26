// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { type Address, type Hash, type Log, PublicClient, encodeAbiParameters } from 'viem'
import initializeWasm from '@interfold/wasm/init'
import { simd_decode, simd_recover_sparse } from '@interfold/wasm'
import type { ThresholdBfvParamsPresetName } from './crypto/types'
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
  name: 'openvm',
  parallel: false,
  batch_size: 2,
}

// Default E3 configuration (`committeeSize` is `IInterfold.CommitteeSize`, not circuit N_PARTIES).
export const DEFAULT_E3_CONFIG = {
  committeeSize: 0, // CommitteeSize.Minimum
  duration: 1800, // 30 minutes in seconds
  payment_amount: '0', // 0 ETH in wei
} as const

export function cryptoConfigIdForParamSet(paramSet: number): Hash {
  if (paramSet === 0) {
    return '0x92c8b373eb72cc3600a5a818cf8599db16e618ee3ece2dadd14f8608c1a43ac9'
  }
  if (paramSet === 4) {
    return '0x968e91054be28b2b577ac278284e03274ed46bd5c5064e573290312a2323d495'
  }
  if (paramSet === 2) {
    return '0xa174862efd4487031d423ca96516807775ade0191c714e513aab93d0cc289baa'
  }
  if (paramSet === 3) {
    return '0x9b9181e0304e51388d6edd6eb4d5ae9a8593cbdbf28838734d829d09d0701d86'
  }
  if (paramSet === 5) {
    return '0x843cc091bc39d046eded5e9f0aed8250848b46f7e36623433d31a1f5d7ef5e35'
  }
  if (paramSet === 6) {
    return '0xd053da3859a277a18b1d0bce3f59f7afb5dda18833e3e0fc32c204d066d4e65e'
  }
  throw new SDKError(`Unsupported BFV parameter set: ${paramSet}`, 'UNSUPPORTED_CRYPTO_CONFIG')
}

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

/**
 * Decode a plaintextOutput into the coefficients of the decrypted plaintext.
 *
 * The output is little-endian u64 chunks, one per coefficient, in the poly basis. The coefficient
 * count is the output cap of the preset, so a SIMD plaintext of degree N is N chunks.
 * @throws SDKError if the hex is malformed or its length is not a multiple of 8 bytes
 */
export function decodePlaintextCoefficients(plaintextOutput: string): bigint[] {
  const hex = plaintextOutput.startsWith('0x') ? plaintextOutput.slice(2) : plaintextOutput
  if (hex.length % 16 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new SDKError('Plaintext output must be whole little-endian u64 chunks of hex', 'INVALID_PLAINTEXT_OUTPUT')
  }

  const coefficients: bigint[] = []
  for (let offset = 0; offset < hex.length; offset += 16) {
    // Little-endian: the last byte of the chunk is the most significant.
    const bytes = hex.slice(offset, offset + 16).match(/../g) as string[]
    coefficients.push(BigInt(`0x${bytes.reverse().join('')}`))
  }
  return coefficients
}

/**
 * Decode a plaintextOutput into the SIMD slot values of the decrypted plaintext.
 *
 * The coefficients are mapped to slots by fhe.rs (via wasm), so the slot order is the one
 * `encryptVector(..., { encoding: 'simd' })` packs.
 * @param plaintextOutput - The published plaintext output, as hex
 * @param presetName - A preset whose plaintext modulus is prime and 1 mod 2N, e.g. `INSECURE_THRESHOLD_SIMD`
 */
export async function decodePlaintextSlots(plaintextOutput: string, presetName: ThresholdBfvParamsPresetName): Promise<bigint[]> {
  const coefficients = decodePlaintextCoefficients(plaintextOutput)
  await initializeWasm()
  return Array.from(simd_decode(BigUint64Array.from(coefficients), presetName))
}

/**
 * Recover the SIMD slot values at known positions from a published window of coefficients.
 *
 * A SIMD plaintext with few non-zero slots is dense in the poly basis. A preset that publishes only
 * a prefix of the polynomial (`SECURE_THRESHOLD_16384_SIMD` publishes 50 of 16384 coefficients)
 * therefore gives a window, not the whole plaintext. The window fixes the slots when every non-zero
 * slot is in `support` and `support` is no longer than the window. With spare coefficients, a
 * non-zero slot outside `support` makes the call fail.
 * @param plaintextOutput - The published plaintext output, as hex
 * @param presetName - A SIMD preset, e.g. `SECURE_THRESHOLD_16384_SIMD`
 * @param support - The slot positions that can be non-zero, without repeats
 * @returns The slot values at `support`, in the order of `support`
 */
export async function decodePlaintextSparseSlots(
  plaintextOutput: string,
  presetName: ThresholdBfvParamsPresetName,
  support: number[],
): Promise<bigint[]> {
  const coefficients = decodePlaintextCoefficients(plaintextOutput)
  await initializeWasm()
  return Array.from(simd_recover_sparse(BigUint64Array.from(coefficients), presetName, Uint32Array.from(support)))
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
