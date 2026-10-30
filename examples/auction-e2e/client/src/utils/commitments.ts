// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { bytesToHex, hexToBytes, type Hex } from 'viem'
import { computeCiphertextCommitment } from '@interfold/sdk'
import { PRESET } from '@interfold/auction-core'

/**
 * The `opens` function of `selectBids` and `checkMasks` for these ciphertexts: it hashes each one
 * again, as the program does, and compares the result with the published commitment. Bytes that are
 * no ciphertext open nothing.
 */
export async function opensCommitment(ciphertexts: readonly Hex[]): Promise<(ciphertext: Hex, commitment: Hex) => boolean> {
  const recomputed = new Map<Hex, string>()
  await Promise.all(
    [...new Set(ciphertexts)].map(async (ciphertext) => {
      try {
        recomputed.set(ciphertext, bytesToHex(await computeCiphertextCommitment(hexToBytes(ciphertext), PRESET)))
      } catch {
        // Bytes that are no ciphertext open no commitment: the ciphertext is left out of the map.
      }
    }),
  )
  return (ciphertext, commitment) => recomputed.get(ciphertext) === commitment.toLowerCase()
}
