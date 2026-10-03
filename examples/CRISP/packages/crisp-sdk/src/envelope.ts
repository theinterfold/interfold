// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { bytesToHex, decodeAbiParameters, encodeAbiParameters, parseAbiParameters, numberToHex, getAddress, keccak256 } from 'viem/utils'
import type { Hex } from 'viem'
import type { InputIdentity, ProofData } from './types'

/**
 * The input envelope that `CRISPProgram` decodes: proof, slot address, ciphertext commitment,
 * ciphertext hash, parent index plus one, and ciphertext. The encoder and the decoder share this
 * list, so the two cannot disagree on the field order.
 */
const INPUT_ENVELOPE = parseAbiParameters('bytes, address, bytes32, bytes32, uint40, bytes')

/**
 * Encode the proof data into a format that can be used by the CRISP program in Solidity
 * to validate the proof.
 * @param proof The proof data.
 * @returns The encoded proof data as a hex string.
 */
export const encodeSolidityProof = ({ publicInputs, proof, encryptedVote, parentIndexPlusOne }: ProofData): Hex => {
  // Indices follow the fold circuit public inputs:
  //   0 prev_ct_commitment, 1 digest_hi, 2 digest_lo, 3 slot_address,
  //   4 merkle_root | voting_power, 5 is_first_vote, 6 num_options,
  //   7 final_ct_commitment, 8 committee public key
  const slotAddress = getAddress(numberToHex(BigInt(publicInputs[3]), { size: 20 }))
  const encryptedVoteCommitment = publicInputs[7] as `0x${string}`
  const encryptedVoteBytes = bytesToHex(encryptedVote)
  const encryptedVoteHash = keccak256(encryptedVoteBytes)

  // The last field contains the ciphertext only while the availability service stages the job.
  // The service removes it from the proof-commitment transaction, publishes it to Avail, and
  // later supplies the VectorX proof to `finalizeInput`.
  return encodeAbiParameters(INPUT_ENVELOPE, [
    bytesToHex(proof),
    slotAddress,
    encryptedVoteCommitment,
    encryptedVoteHash,
    parentIndexPlusOne,
    encryptedVoteBytes,
  ])
}

/**
 * Read the identity of an input from the envelope that {@link encodeSolidityProof} produces.
 *
 * The CRISP server matches an entry of the round's input tree by these four values, so a client
 * that keeps them can ask later whether the Secure Process selected its input.
 * @param encodedProof The envelope sent to `voting/broadcast`.
 * @returns The slot, ciphertext commitment, ciphertext hash, and parent index plus one.
 */
export const decodeInputIdentity = (encodedProof: Hex): InputIdentity => {
  const [, slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne] = decodeAbiParameters(INPUT_ENVELOPE, encodedProof)
  return { slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne }
}
