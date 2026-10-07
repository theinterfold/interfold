// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Cross-layer tally decoding tests. A round's `plaintextOutput` is the decrypted polynomial, one
 * little-endian uint64 per coefficient, with the total of option `o` at coefficient `o`. These
 * tests build it with the SDK encoder and assert the SDK decoder and `CRISPProgram.decodeTally`
 * agree.
 */

import { encodeVote, decodeTally, MAX_MSG_NON_ZERO_COEFFS, MAX_VOTE_OPTIONS } from '@crisp-e3/sdk'
import { expect } from 'chai'
import { deployCRISPProgram, deployMockInterfold } from './utils'
import type { CRISPProgram, MockInterfold } from '../types'

/**
 * Pack polynomial coefficients exactly as the ciphernodes publish them:
 * 8 little-endian bytes per coefficient.
 */
const packCoefficients = (coefficients: (number | bigint)[]): string => {
  const buffer = new Uint8Array(coefficients.length * 8)
  const view = new DataView(buffer.buffer)

  coefficients.forEach((coefficient, i) => view.setBigUint64(i * 8, BigInt(coefficient), true))

  return `0x${Buffer.from(buffer).toString('hex')}`
}

/**
 * Encode each ballot and sum the encodings coefficient by coefficient. BFV addition is
 * coefficient-wise, so this is the plaintext the committee decrypts after aggregating a round.
 */
const aggregateBallots = (ballots: number[][]): number[] =>
  ballots.map((ballot) => encodeVote(ballot)).reduce((acc, ballot) => acc.map((coefficient, i) => coefficient + ballot[i]))

describe('Tally decoding (SDK vs CRISPProgram)', function () {
  this.timeout(120000)

  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram

  before(async function () {
    mockInterfold = await deployMockInterfold()
    crispProgram = await deployCRISPProgram({ mockInterfold })
  })

  /** Publish a plaintext output for a fresh E3 and read back the on-chain tally. */
  const decodeOnChain = async (output: string, numOptions: number): Promise<bigint[]> => {
    const e3Id = await mockInterfold.nextE3Id()

    await mockInterfold.requestWithOptions(await crispProgram.getAddress(), numOptions)
    await mockInterfold.setPlaintextOutput(output)

    return crispProgram.decodeTally(e3Id)
  }

  /** Assert that the SDK and the contract both decode `coefficients` to `expected`. */
  const expectDecoded = async (coefficients: (number | bigint)[], numOptions: number, expected: bigint[]) => {
    const output = packCoefficients(coefficients)

    expect(decodeTally(output, numOptions)).to.deep.equal(expected)
    expect(Array.from(await decodeOnChain(output, numOptions))).to.deep.equal(expected)
  }

  describe('contract agreement', function () {
    it('should decode an aggregated round the same way the SDK does', async function () {
      // Ballots on different options, with distinct option totals.
      const ballots = [
        [1, 0],
        [0, 2],
        [0, 3],
        [3, 0],
      ]

      await expectDecoded(aggregateBallots(ballots), 2, [4n, 5n])
    })

    it('should sum a three-option round whose ballots spread weight over several options', async function () {
      const ballots = [
        [2, 3, 4],
        [1, 1, 1],
        [0, 0, 0],
      ]

      await expectDecoded(aggregateBallots(ballots), 3, [3n, 4n, 5n])
    })

    it('should read all 8 bytes of the first numOptions coefficients and nothing after them', async function () {
      const max = 2n ** 64n - 1n
      const coefficients: (number | bigint)[] = encodeVote([4, 0])
      coefficients[1] = max
      coefficients[2] = 99

      await expectDecoded(coefficients, 2, [4n, max])
    })
  })

  describe('payload length', function () {
    // One uint64 per coefficient, with the payload in the first MAX_MSG_NON_ZERO_COEFFS
    // coefficients, so a shorter output or a partial coefficient is not a tally.
    it('should reject a plaintext output shorter than the payload or not whole coefficients', async function () {
      const payload = packCoefficients(new Array(MAX_MSG_NON_ZERO_COEFFS).fill(0))

      for (const output of [payload.slice(0, -16), `${payload}00`]) {
        expect(() => decodeTally(output, 2)).to.throw()
        await expect(decodeOnChain(output, 2)).to.be.revertedWithCustomError(crispProgram, 'InvalidTallyLength')
      }
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
