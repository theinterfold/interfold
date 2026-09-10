// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { poseidon2 } from 'poseidon-lite'
import { LeanIMT } from '@zk-kit/lean-imt'
import type { MerkleProof } from './types'
import { MAX_MSG_NON_ZERO_COEFFS, MERKLE_TREE_MAX_DEPTH, SIGNATURE_MESSAGE_HASH } from './constants'
import { publicKeyToAddress } from 'viem/utils'
import { hexToBytes, recoverPublicKey } from 'viem'

/**
 * Hash a leaf node for the Merkle tree
 * @param address The voter's address
 * @param balance The voter's balance
 * @returns The hashed leaf as a bigint
 */
export const hashLeaf = (address: string, balance: bigint): bigint => {
  return poseidon2([address.toLowerCase(), balance])
}

/**
 * Generate a new LeanIMT with the leaves provided
 * @param leaves The leaves of the Merkle tree
 * @returns the generated Merkle tree
 */
export const generateMerkleTree = (leaves: bigint[]): LeanIMT => {
  return new LeanIMT((a, b) => poseidon2([a, b]), leaves)
}

/** Parse a Merkle leaf returned by the CRISP server or supplied as an integer. */
const parseMerkleLeaf = (leaf: bigint | string): bigint => {
  if (typeof leaf === 'bigint' || leaf.startsWith('0x')) return BigInt(leaf)

  // The server's persisted tree format is a fixed-width, unprefixed hexadecimal string.
  // Keep accepting decimal strings for callers that used the older SDK input shape.
  return /^[0-9a-fA-F]{64}$/.test(leaf) ? BigInt(`0x${leaf}`) : BigInt(leaf)
}

/**
 * Generate a Merkle proof for a given address to prove inclusion in the voters' list
 * @param balance The voter's balance
 * @param address The voter's address
 * @param leaves The leaves of the Merkle tree
 */
export const generateMerkleProof = (balance: bigint, address: string, leaves: bigint[] | string[]): MerkleProof => {
  const leaf = hashLeaf(address.toLowerCase(), balance)
  const parsedLeaves = leaves.map(parseMerkleLeaf)

  const index = parsedLeaves.findIndex((candidate) => candidate === leaf)

  if (index === -1) {
    throw new Error('Leaf not found in the tree')
  }

  const tree = generateMerkleTree(parsedLeaves)

  const proof = tree.generateProof(index)

  // Pad siblings with zeros
  const paddedSiblings = [...proof.siblings, ...Array(MERKLE_TREE_MAX_DEPTH - proof.siblings.length).fill(0n)]
  // Pad indices with zeros
  const indices = proof.siblings.map((_, i) => Number((BigInt(proof.index) >> BigInt(i)) & 1n))
  const paddedIndices = [...indices, ...Array(MERKLE_TREE_MAX_DEPTH - indices.length).fill(0)]

  return {
    leaf,
    index,
    proof: {
      ...proof,
      siblings: paddedSiblings,
    },
    // Original length before padding
    length: proof.siblings.length,
    indices: paddedIndices,
  }
}

/**
 * Convert a number to its binary representation
 * @param number The number to convert to binary
 * @returns The binary representation of the number as a string
 */
export const toBinary = (number: number): string => {
  if (number < 0) {
    throw new Error('Value cannot be negative')
  }

  return number.toString(2)
}

/**
 * Given a signature, extract the signature components for the Noir signature verification circuit.
 * @param signature The signature to extract the components from.
 * @returns The extracted signature components.
 */
export const extractSignatureComponents = async (
  signature: `0x${string}`,
  messageHash: `0x${string}` = SIGNATURE_MESSAGE_HASH,
): Promise<{
  messageHash: Uint8Array
  publicKeyX: Uint8Array
  publicKeyY: Uint8Array
  signature: Uint8Array
}> => {
  const publicKey = await recoverPublicKey({ hash: messageHash, signature })
  const publicKeyBytes = hexToBytes(publicKey)
  const publicKeyX = publicKeyBytes.slice(1, 33)
  const publicKeyY = publicKeyBytes.slice(33, 65)

  // Extract r and s from signature (remove v)
  const sigBytes = hexToBytes(signature)
  const r = sigBytes.slice(0, 32) // First 32 bytes
  const s = sigBytes.slice(32, 64) // Next 32 bytes

  const signatureBytes = new Uint8Array(64)
  signatureBytes.set(r, 0)
  signatureBytes.set(s, 32)

  return {
    messageHash: hexToBytes(messageHash),
    publicKeyX: publicKeyX,
    publicKeyY: publicKeyY,
    signature: signatureBytes,
  }
}

export const getAddressFromSignature = async (signature: `0x${string}`, messageHash?: `0x${string}`): Promise<string> => {
  const publicKey = await recoverPublicKey({ hash: messageHash || SIGNATURE_MESSAGE_HASH, signature })

  return publicKeyToAddress(publicKey)
}

/**
 * Get the maximum vote value for a given number of choices.
 * @param numChoices Number of choices.
 * @returns Maximum value per choice.
 */
export const getMaxVoteValue = (numChoices: number): number => {
  const segmentSize = Math.floor(MAX_MSG_NON_ZERO_COEFFS / numChoices)
  return 2 ** segmentSize - 1
}

/**
 * Get a zero vote with the given number of choices.
 * @param numChoices Number of choices.
 * @returns A zero vote with the given number of choices.
 */
export const getZeroVote = (numChoices: number): number[] => {
  return Array(numChoices).fill(0)
}

/**
 * Decode bytes to a bigint array (little-endian, 8 bytes per value).
 *
 * @remarks
 * Returns `bigint` rather than `number`: a coefficient of an aggregated plaintext
 * is a sum over all ballots and can exceed `Number.MAX_SAFE_INTEGER`.
 *
 * @param data The bytes to decode (must be multiple of 8).
 * @returns Array of coefficients.
 */
export const decodeBytesToBigInts = (data: Uint8Array): bigint[] => {
  if (data.length % 8 !== 0) {
    throw new Error('Data length must be multiple of 8')
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const arrayLength = data.length / 8
  const result: bigint[] = []

  for (let i = 0; i < arrayLength; i++) {
    result.push(view.getBigUint64(i * 8, true)) // true = little-endian
  }

  return result
}

export const bigInt64ArrayToNumberArray = (bigInt64Array: BigInt64Array): number[] => {
  return Array.from(bigInt64Array).map(Number)
}

export const numberArrayToBigInt64Array = (numberArray: number[]): BigInt64Array => {
  return BigInt64Array.from(numberArray.map(BigInt))
}

// Helper function to convert proof bytes to field elements
export const proofToFields = (proof: Uint8Array): string[] => {
  const fields: string[] = []
  for (let i = 0; i < proof.length; i += 32) {
    const chunk = proof.slice(i, i + 32)
    fields.push('0x' + Buffer.from(chunk).toString('hex'))
  }
  return fields
}

/**
 * Scale down the raw balance to 1 decimal precision
 * @param balance - The raw balance (with all tokens decimals)
 * @param decimals - The decimals of the token
 * @returns The balance as a .1 precision scaled value
 */
export const getScaledBalance = (balance: bigint, decimals: bigint): bigint => {
  const precision = decimals > 1n ? decimals - 1n : 0n

  return balance / 10n ** precision
}
