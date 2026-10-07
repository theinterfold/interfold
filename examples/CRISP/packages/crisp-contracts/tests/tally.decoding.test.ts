// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Cross-layer tally decoding tests.
 *
 * A round produces `plaintextOutput` as the full decrypted BFV polynomial: one
 * little-endian uint64 per coefficient, `degree` coefficients long (Rust
 * `encode_vec_u64_to_bytes` in `crates/bfv-client`). Three decoders read that
 * blob — the SDK (`decodeTally`), the CRISP server (`crisp_utils::decode_tally`)
 * and the contract (`CRISPProgram.decodeTally`). These tests build the blob with
 * the real SDK encoder and assert all readers agree.
 */

import { encodeVote, decodeTally, MAX_MSG_NON_ZERO_COEFFS, MAX_VOTE_OPTIONS } from '@crisp-e3/sdk'
import { expect } from 'chai'
import { deployCRISPProgram, deployMockInterfold } from './utils'
import type { CRISPProgram, MockInterfold } from '../types'

/**
 * Pack polynomial coefficients exactly as the ciphernodes publish them:
 * 8 little-endian bytes per coefficient.
 */
const packCoefficients = (coefficients: number[]): string => {
  const buffer = new Uint8Array(coefficients.length * 8)
  const view = new DataView(buffer.buffer)

  coefficients.forEach((coefficient, i) => view.setBigUint64(i * 8, BigInt(coefficient), true))

  return `0x${Buffer.from(buffer).toString('hex')}`
}

/**
 * Coefficient-wise sum of encoded ballots. BFV addition is coefficient-wise, so
 * this is the plaintext the committee decrypts after aggregating a round.
 */
const aggregateBallots = (ballots: number[][]): number[] =>
  ballots.reduce((acc, ballot) => acc.map((coefficient, i) => coefficient + ballot[i]))

describe('Tally decoding (SDK vs CRISPProgram)', function () {
  this.timeout(120000)

  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram

  before(async function () {
    mockInterfold = await deployMockInterfold()
    crispProgram = await deployCRISPProgram({ mockInterfold })
  })

  /** Publish a plaintext output for a fresh E3 and read back the on-chain tally. */
  const decodeOnChain = async (coefficients: number[], numOptions: number): Promise<bigint[]> => {
    const e3Id = await mockInterfold.nextE3Id()

    await mockInterfold.requestWithOptions(await crispProgram.getAddress(), numOptions)
    await mockInterfold.setPlaintextOutput(packCoefficients(coefficients))

    return crispProgram.decodeTally(e3Id)
  }

  describe('encoder layout', function () {
    it('should place the payload in the first MAX_MSG_NON_ZERO_COEFFS coefficients and pad the rest', function () {
      const coefficients = encodeVote([12345, 6789])

      // The encoder emits the full polynomial, not just the message region.
      expect(coefficients.length).to.be.greaterThan(MAX_MSG_NON_ZERO_COEFFS)
      expect(coefficients.slice(MAX_MSG_NON_ZERO_COEFFS).every((c) => c === 0)).to.equal(true)
    })
  })

  describe('contract agreement', function () {
    it('should decode a single encoded ballot the same way the SDK does', async function () {
      const vote = [10000000, 30000000]
      const coefficients = encodeVote(vote)

      const onChain = await decodeOnChain(coefficients, 2)
      const offChain = decodeTally(packCoefficients(coefficients), 2)

      expect(offChain).to.deep.equal(vote.map(BigInt))
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })

    it('should decode an aggregated round the same way the SDK does', async function () {
      const ballots = [
        [100, 0],
        [0, 250],
        [0, 250],
        [75, 0],
      ]
      const coefficients = aggregateBallots(ballots.map((ballot) => encodeVote(ballot)))

      const onChain = await decodeOnChain(coefficients, 2)
      const offChain = decodeTally(packCoefficients(coefficients), 2)

      expect(offChain).to.deep.equal([175n, 500n])
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })

    it('should decode a three-option round the same way the SDK does', async function () {
      const coefficients = aggregateBallots(
        [
          [3, 0, 0],
          [0, 4, 0],
          [0, 0, 5],
        ].map((ballot) => encodeVote(ballot)),
      )

      const onChain = await decodeOnChain(coefficients, 3)
      const offChain = decodeTally(packCoefficients(coefficients), 3)

      expect(offChain).to.deep.equal([3n, 4n, 5n])
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })
  })

  describe('option count bounds', function () {
    // The Noir circuit asserts num_options <= MAX_OPTIONS (10). A round above that could
    // never accept a ballot, so the contract rejects it at the SDK's MAX_VOTE_OPTIONS.
    // crisp-sdk tests/vote.test.ts covers the SDK's rejection at the same bound.
    it('should reject a round with more options than the circuit allows', async function () {
      await expect(mockInterfold.requestWithOptions(await crispProgram.getAddress(), MAX_VOTE_OPTIONS + 1)).to.be.revertedWithCustomError(
        crispProgram,
        'InvalidNumOptions',
      )
    })

    it('should accept a round at exactly MAX_VOTE_OPTIONS options', async function () {
      const e3Id = await mockInterfold.nextE3Id()

      await mockInterfold.requestWithOptions(await crispProgram.getAddress(), MAX_VOTE_OPTIONS)

      const [, , numOptions] = await crispProgram.getRoundData(e3Id)
      expect(numOptions).to.equal(BigInt(MAX_VOTE_OPTIONS))
    })
  })
})
