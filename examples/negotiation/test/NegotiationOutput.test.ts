// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import hre from 'hardhat'
import type { Hex } from 'viem'
import type { OutputHarness } from '../types/contracts/mocks'
import { OutputHarness__factory } from '../types/factories/contracts/mocks'
import { N, T, coefficientsToPlaintext, coefficientsToSlots, rng } from './helpers'

async function deployHarness(): Promise<OutputHarness> {
  const { ethers } = await hre.network.connect()
  const deployed = await ethers.deployContract('OutputHarness')
  return OutputHarness__factory.connect(await deployed.getAddress(), ethers.provider)
}

/** `sum_{g < 8} slots[g * 16 + i] mod 257`, for the 16 levels. */
function sumsOfSlots(slots: readonly number[]): number[] {
  return Array.from({ length: 16 }, (_, i) => {
    let sum = 0
    for (let g = 0; g < 8; g++) sum += slots[g * 16 + i]
    return sum % T
  })
}

describe('NegotiationOutput', () => {
  it('has the weight table of the slot points: the sums are exact for every unit polynomial', async () => {
    const harness = await deployHarness()
    // The sums are linear in the coefficients, so the 128 unit polynomials fix the whole table.
    for (let k = 0; k < N; k++) {
      const coefficients = new Array<number>(N).fill(0)
      coefficients[k] = 1
      const plaintext = coefficientsToPlaintext(coefficients) as Hex
      const expected = sumsOfSlots(coefficientsToSlots(coefficients))
      expect((await harness.levelSums(plaintext)).map(Number), `x^${k}`).to.deep.equal(expected)
    }
  })

  it('gives the same sums as the 128 slots of SlotCodec for random plaintexts', async () => {
    const harness = await deployHarness()
    const random = rng(42)
    for (let n = 0; n < 8; n++) {
      const coefficients = Array.from({ length: N }, random)
      const plaintext = coefficientsToPlaintext(coefficients) as Hex
      const sums = (await harness.levelSums(plaintext)).map(Number)
      expect(sums).to.deep.equal(sumsOfSlots(coefficientsToSlots(coefficients)))
      expect(sums).to.deep.equal((await harness.referenceSums(plaintext)).map(Number))
    }
  })

  it('handles the largest coefficients without overflow', async () => {
    const harness = await deployHarness()
    const coefficients = new Array<number>(N).fill(T - 1)
    const plaintext = coefficientsToPlaintext(coefficients) as Hex
    expect((await harness.levelSums(plaintext)).map(Number)).to.deep.equal(sumsOfSlots(coefficientsToSlots(coefficients)))
  })

  it('decodes the zero plaintext as no match', async () => {
    const harness = await deployHarness()
    const result = await harness.decode(coefficientsToPlaintext(new Array<number>(N).fill(0)) as Hex, 16)
    expect([result.matched, result.step]).to.deep.equal([false, 0n])
  })

  it('reports the gas of the sums', async () => {
    const harness = await deployHarness()
    const plaintext = coefficientsToPlaintext(Array.from({ length: N }, rng(1))) as Hex
    const gas = await harness.levelSums.estimateGas(plaintext)
    console.log(`      gas levelSums (view, with the call data): ${gas}`)
    expect(gas).to.be.lessThan(400_000n)
  })
})
