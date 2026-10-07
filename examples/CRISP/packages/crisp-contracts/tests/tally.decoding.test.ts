// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Cross-layer tally decoding tests.
 *
 * A ballot stores one integer per option: coefficient `o` of the message polynomial is the weight
 * on option `o`. BFV adds ballots coefficient by coefficient, so a round produces `plaintextOutput`
 * as the full decrypted polynomial with the total of option `o` at coefficient `o`: one
 * little-endian uint64 per coefficient, `degree` coefficients long (Rust `encode_vec_u64_to_bytes`
 * in `crates/bfv-client`). Three decoders read that blob: the SDK (`decodeTally`), the CRISP server
 * (`crisp_utils::decode_tally`) and the contract (`CRISPProgram.decodeTally`), which the interfold
 * dashboard calls. These tests build the blob with the real SDK encoder and assert the SDK and the
 * contract agree.
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
  /// The plaintext modulus of the parameters the program under test validates against.
  let t: bigint

  before(async function () {
    mockInterfold = await deployMockInterfold()
    crispProgram = await deployCRISPProgram({ mockInterfold })
    t = await mockInterfold.plaintextModulus()
  })

  /** Publish a plaintext output for a fresh E3 and read back the on-chain tally. */
  const decodeOnChain = async (coefficients: number[], numOptions: number): Promise<bigint[]> => {
    const e3Id = await mockInterfold.nextE3Id()

    await mockInterfold.requestWithOptions(await crispProgram.getAddress(), numOptions)
    await mockInterfold.setPlaintextOutput(packCoefficients(coefficients))

    return crispProgram.decodeTally(e3Id)
  }

  describe('encoder layout', function () {
    it('should place the weight of option o at coefficient o and zero everything else', function () {
      const coefficients = encodeVote([5, 0, 7])

      expect(coefficients.slice(0, 3)).to.deep.equal([5, 0, 7])
      // The encoder emits the full polynomial, not just the message region.
      expect(coefficients.length).to.be.greaterThan(MAX_MSG_NON_ZERO_COEFFS)
      expect(coefficients.slice(3).every((c) => c === 0)).to.equal(true)
    })
  })

  describe('contract agreement', function () {
    it('should decode a single encoded ballot the same way the SDK does', async function () {
      const vote = [Number(t / 4n), Number(t / 2n)]
      const coefficients = encodeVote(vote)

      const onChain = await decodeOnChain(coefficients, 2)
      const offChain = decodeTally(packCoefficients(coefficients), 2)

      expect(offChain).to.deep.equal(vote.map(BigInt))
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })

    it('should decode an aggregated round the same way the SDK does', async function () {
      // Ballots on different options, with every option total below `t`.
      const unit = Number(t / 10n)
      const ballots = [
        [unit, 0],
        [0, 2 * unit],
        [0, 2 * unit],
        [3 * unit, 0],
      ]
      const coefficients = aggregateBallots(ballots.map((ballot) => encodeVote(ballot)))

      const onChain = await decodeOnChain(coefficients, 2)
      const offChain = decodeTally(packCoefficients(coefficients), 2)

      expect(offChain).to.deep.equal([BigInt(4 * unit), BigInt(4 * unit)])
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })

    it('should sum a three-option round whose ballots spread weight over several options', async function () {
      const coefficients = aggregateBallots(
        [
          [2, 3, 4],
          [1, 1, 1],
          [0, 0, 0],
        ].map((ballot) => encodeVote(ballot)),
      )

      const onChain = await decodeOnChain(coefficients, 3)
      const offChain = decodeTally(packCoefficients(coefficients), 3)

      expect(offChain).to.deep.equal([3n, 4n, 5n])
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })

    // `validate` keeps every option total below `t`, so `t - 1` is the largest total a round can
    // hold, and the one a decoder is most likely to get wrong.
    it('should decode a total of t - 1 exactly', async function () {
      const first = Number(t / 2n)
      const second = Number(t) - 1 - first
      const coefficients = aggregateBallots([encodeVote([first, 0]), encodeVote([second, 0])])

      const onChain = await decodeOnChain(coefficients, 2)
      const offChain = decodeTally(packCoefficients(coefficients), 2)

      expect(offChain).to.deep.equal([t - 1n, 0n])
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })

    it('should read only the first numOptions coefficients', async function () {
      const coefficients = encodeVote([4, 6])
      coefficients[2] = 99

      const onChain = await decodeOnChain(coefficients, 2)
      const offChain = decodeTally(packCoefficients(coefficients), 2)

      expect(offChain).to.deep.equal([4n, 6n])
      expect(Array.from(onChain)).to.deep.equal(offChain)
    })
  })

  describe('payload length', function () {
    // The payload lives in the first MAX_MSG_NON_ZERO_COEFFS coefficients, so a shorter output is
    // not a tally.
    it('should reject a plaintext output shorter than the payload in both decoders', async function () {
      const tooShort = new Array(MAX_MSG_NON_ZERO_COEFFS - 1).fill(0)
      const e3Id = await mockInterfold.nextE3Id()

      await mockInterfold.requestWithOptions(await crispProgram.getAddress(), 2)
      await mockInterfold.setPlaintextOutput(packCoefficients(tooShort))

      await expect(crispProgram.decodeTally(e3Id)).to.be.revertedWithCustomError(crispProgram, 'InvalidTallyLength')
      expect(() => decodeTally(packCoefficients(tooShort), 2)).to.throw()
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
