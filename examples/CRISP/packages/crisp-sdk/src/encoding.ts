// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Vote encoding and BFV encryption for the CRISP voting protocol.
 *
 * A ballot stores one integer per option: coefficient `o` of the message polynomial is the
 * weight on option `o`, and every other coefficient up to the BFV degree is zero. BFV adds
 * ballots coefficient by coefficient, so the decrypted tally holds one total per option in the
 * same positions. Supports encoding, encryption, decryption, and tally decoding.
 */

import { ZKInputsGenerator } from '@crisp-e3/zk-inputs'
import { registeredPreset, type CircuitPreset } from './circuits'
import { numberArrayToBigInt64Array, decodeBytesToBigInts } from './utils'
import { MAX_MSG_NON_ZERO_COEFFS, MAX_VOTE_OPTIONS } from './constants'
import { hexToBytes } from 'viem'
import type { Hex } from 'viem'
import type { TallyResult, Vote } from './types'

let _zkInputsGenerator: InstanceType<typeof ZKInputsGenerator> | null = null
let _zkInputsGeneratorPreset: CircuitPreset | 'default' | null = null
let _zkInputsGeneratorPresetOverride: CircuitPreset | null = null

/** Set or clear the BFV preset override for contexts that do not share the registered bundle. */
export const setZkInputsGeneratorPreset = (preset: CircuitPreset | null): void => {
  if (_zkInputsGeneratorPresetOverride !== preset) {
    _zkInputsGenerator = null
    _zkInputsGeneratorPreset = null
    _zkInputsGeneratorPresetOverride = preset
  }
}

/**
 * Returns the singleton ZK inputs generator instance for the registered BFV preset.
 */
export const getZkInputsGenerator = () => {
  const preset = _zkInputsGeneratorPresetOverride ?? registeredPreset()
  const targetPreset = preset ?? 'default'

  if (!_zkInputsGenerator || _zkInputsGeneratorPreset !== targetPreset) {
    _zkInputsGenerator = preset ? ZKInputsGenerator.fromPreset(preset) : ZKInputsGenerator.withDefaults()
    _zkInputsGeneratorPreset = targetPreset
  }

  return _zkInputsGenerator
}

/**
 * Returns the BFV plaintext modulus `t` of the active preset. A choice weight, and every option
 * total of a round, must stay below it.
 */
export const getPlaintextModulus = (): bigint => BigInt(getZkInputsGenerator().getBFVParams().plaintextModulus)

/**
 * Checks every choice weight against the plaintext modulus `t`. A weight at or above `t` wraps
 * around in the plaintext ring and no longer adds as an integer.
 *
 * @param vote - Weight per option
 * @param plaintextModulus - The plaintext modulus `t` of the active preset
 * @throws If a weight is not a non-negative safe integer below `t`
 */
export const checkVoteWeights = (vote: Vote, plaintextModulus: bigint): void => {
  vote.forEach((value, choiceIdx) => {
    if (!Number.isSafeInteger(value) || value < 0 || BigInt(value) >= plaintextModulus) {
      throw new Error(`Vote value for choice ${choiceIdx} must be a non-negative integer below the plaintext modulus (${plaintextModulus})`)
    }
  })
}

/**
 * Encodes vote choices into a polynomial coefficient array for BFV encryption.
 * Coefficient `o` is the weight on option `o`; every other coefficient, up to the BFV degree, is zero.
 *
 * Decoded by `decodeTally`, and by the other tally decoders that share this layout:
 * `CRISPProgram.decodeTally` (Solidity) and `crisp_utils::decode_tally` (Rust).
 *
 * @param vote - Weight per option, for example [10, 0] for 2 options. Each weight is a non-negative
 *        safe integer below the BFV plaintext modulus.
 * @returns The coefficients, `degree` entries long
 * @throws If vote has fewer than 2 or more than MAX_VOTE_OPTIONS choices, any weight is not a
 *         non-negative safe integer below the plaintext modulus, or the BFV degree is too small
 */
export const encodeVote = (vote: Vote): number[] => {
  const numChoices = vote.length

  if (numChoices < 2) {
    throw new Error('Vote must have at least two choices')
  }

  // The Noir circuit asserts num_options <= MAX_OPTIONS, so a vote beyond this can never
  // produce a valid proof. Reject it here rather than encoding an unprovable vote.
  if (numChoices > MAX_VOTE_OPTIONS) {
    throw new Error(`Number of choices (${numChoices}) exceeds MAX_VOTE_OPTIONS (${MAX_VOTE_OPTIONS})`)
  }

  const { degree, plaintextModulus } = getZkInputsGenerator().getBFVParams() as { degree: number; plaintextModulus: bigint }
  if (degree < MAX_MSG_NON_ZERO_COEFFS) {
    throw new Error(`BFV degree (${degree}) must be at least MAX_MSG_NON_ZERO_COEFFS (${MAX_MSG_NON_ZERO_COEFFS})`)
  }

  checkVoteWeights(vote, plaintextModulus)

  const voteArray: number[] = new Array(degree).fill(0)
  for (let choiceIdx = 0; choiceIdx < numChoices; choiceIdx += 1) {
    voteArray[choiceIdx] = vote[choiceIdx]
  }

  return voteArray
}

/**
 * Encrypts an encoded vote using BFV homomorphic encryption.
 *
 * @param vote - Vote choices to encrypt
 * @param publicKey - BFV public key
 * @returns Encrypted ciphertext
 */
export const encryptVote = (vote: Vote, publicKey: Uint8Array): Uint8Array => {
  const encodedVote = encodeVote(vote)

  return getZkInputsGenerator().encryptVote(publicKey, numberArrayToBigInt64Array(encodedVote))
}

/**
 * Decodes raw tally bytes (or coefficients) into a total per choice.
 * Expects the layout `encodeVote` produces: coefficient `o` holds the total weight on option `o`.
 *
 * Same layout as `CRISPProgram.decodeTally` (Solidity) and `crisp_utils::decode_tally` (Rust).
 * Only the first MAX_MSG_NON_ZERO_COEFFS coefficients are published as the tally; the first
 * `numChoices` of them are the totals and the rest are ignored.
 *
 * @param tallyBytes - Hex string, or the polynomial coefficients from tally/decryption
 * @param numChoices - Number of vote options: an integer from 2 to MAX_VOTE_OPTIONS
 * @returns One total per choice, as bigint because each coefficient is a uint64 word
 * @throws If numChoices is outside 2..MAX_VOTE_OPTIONS or not an integer, or there are fewer
 *         coefficients than MAX_MSG_NON_ZERO_COEFFS
 */
export const decodeTally = (tallyBytes: string | number[] | bigint[], numChoices: number): TallyResult => {
  // `CRISPProgram.validate` rejects a round outside 2..MAX_VOTE_OPTIONS, and `encodeVote` refuses
  // to encode fewer than two choices, so no tally in that range can exist. `Number.isInteger` also
  // screens out NaN, Infinity, and fractions: a fractional count would slice a fractional number of
  // coefficients, and NaN passes both bound checks to return an empty tally.
  if (!Number.isInteger(numChoices) || numChoices < 2) {
    throw new Error(`Number of choices (${numChoices}) must be an integer of at least 2`)
  }

  // Rounds cannot exceed MAX_VOTE_OPTIONS (the circuit's MAX_OPTIONS), so a larger count
  // is a caller error rather than a tally to decode.
  if (numChoices > MAX_VOTE_OPTIONS) {
    throw new Error(`Number of choices (${numChoices}) exceeds MAX_VOTE_OPTIONS (${MAX_VOTE_OPTIONS})`)
  }

  let coefficients: bigint[]
  if (typeof tallyBytes === 'string') {
    const hexString = tallyBytes.startsWith('0x') ? tallyBytes : `0x${tallyBytes}`
    coefficients = decodeBytesToBigInts(hexToBytes(hexString as Hex))
  } else {
    coefficients = (tallyBytes as Array<number | bigint>).map(BigInt)
  }

  if (coefficients.length < MAX_MSG_NON_ZERO_COEFFS) {
    throw new Error(`decoded coefficient count (${coefficients.length}) is less than MAX_MSG_NON_ZERO_COEFFS (${MAX_MSG_NON_ZERO_COEFFS})`)
  }

  return coefficients.slice(0, numChoices)
}

/**
 * Decrypts a BFV-encrypted vote and decodes it to vote values.
 *
 * @param ciphertext - Encrypted vote
 * @param secretKey - BFV secret key
 * @param numChoices - Number of vote options
 * @returns One total per choice
 */
export const decryptVote = (ciphertext: Uint8Array, secretKey: Uint8Array, numChoices: number): TallyResult => {
  const decryptedVote = getZkInputsGenerator().decryptVote(secretKey, ciphertext)

  return decodeTally(
    Array.from(decryptedVote, (value) => BigInt(value)),
    numChoices,
  )
}

/**
 * Generates a BFV keypair for vote encryption and decryption.
 *
 * @returns Object with secretKey and publicKey as Uint8Arrays
 */
export const generateBFVKeys = (): { secretKey: Uint8Array; publicKey: Uint8Array } => {
  return getZkInputsGenerator().generateKeys()
}
