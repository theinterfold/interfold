// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { decodeAbiParameters, hashTypedData, parseAbiParameters, recoverTypedDataAddress, stringToHex, zeroAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { describe, expect, it } from 'vitest'
import {
  assertBid,
  bidInputsHash,
  bidSlots,
  bidTypedData,
  CONFIG_DOMAIN,
  COPIES,
  DEGREE,
  decodeRound,
  encodeBidInput,
  encodeClaimData,
  encodeSaleParams,
  evenPrices,
  GATE_BASE,
  GATE_COPIES,
  LEVELS,
  laneFactors,
  linearPrices,
  MAX_BIDDERS,
  MAX_LOTS,
  maskSlots,
  Outcome,
  outputSlotsFor,
  priceListError,
  priceSlot,
  readPriceList,
  type RoundParams,
  roundConfigInput,
  usesComplementSide,
  VERSION_BASE,
  zeroSetSize,
} from './layout'

const ROUND: RoundParams = { levels: 16, reserveStep: 3, lots: 2, minLots: 1 }

/** The versions of `n` counted bidders in the first `n` slots. */
function versionsOf(n: number): number[] {
  return Array.from({ length: MAX_BIDDERS }, (_, i) => (i < n ? 1 + (i % 3) : 0))
}

describe('layout constants', () => {
  it('fits the lanes, the gate and the versions in the ring', () => {
    expect(GATE_BASE).toBe(96)
    expect(GATE_BASE + GATE_COPIES).toBeLessThanOrEqual(VERSION_BASE)
    expect(VERSION_BASE).toBe(115)
    expect(VERSION_BASE + MAX_BIDDERS).toBe(DEGREE)
    expect(MAX_LOTS).toBe(12)
  })
})

describe('bid slots', () => {
  it('has six thermometers, the gate bits and the version in the bidder slot', () => {
    const slots = bidSlots(5, 3, 2, 2)
    expect(slots).toHaveLength(DEGREE)
    for (let g = 0; g < COPIES; g++) for (let l = 0; l < LEVELS; l++) expect(slots[priceSlot(g, l)]).toBe(l <= 5 ? 1n : 0n)
    for (let k = 0; k < GATE_COPIES; k++) expect(slots[GATE_BASE + k]).toBe(1n)
    expect(slots[VERSION_BASE + 2]).toBe(2n)
    expect([...slots].filter((slot) => slot !== 0n)).toHaveLength(COPIES * 6 + GATE_COPIES + 1)
  })

  it('sets the gate bits only for a bid at or above the reserve step', () => {
    for (let k = 0; k < GATE_COPIES; k++) expect(bidSlots(2, 3, 0, 1)[GATE_BASE + k]).toBe(0n)
    for (let k = 0; k < GATE_COPIES; k++) expect(bidSlots(3, 3, 0, 1)[GATE_BASE + k]).toBe(1n)
  })

  it('covers the extreme bids and the last bidder', () => {
    expect([...bidSlots(0, 0, 1, 1)].filter((slot) => slot !== 0n)).toHaveLength(COPIES + GATE_COPIES + 1)
    const last = bidSlots(LEVELS - 1, 0, MAX_BIDDERS - 1, 3)
    expect(last[DEGREE - 1]).toBe(3n)
  })

  it('rejects a bid, an index or a version out of range', () => {
    expect(() => bidSlots(16, 0, 0, 1)).toThrow()
    expect(() => bidSlots(-1, 0, 0, 1)).toThrow()
    expect(() => bidSlots(0, 0, MAX_BIDDERS, 1)).toThrow()
    expect(() => bidSlots(0, 0, 0, 0)).toThrow()
    expect(() => bidSlots(0, 0, 0, 4)).toThrow()
    expect(() => assertBid(1.5)).toThrow()
  })

  it('draws a mask of 128 values below t', () => {
    const mask = maskSlots()
    expect(mask).toHaveLength(DEGREE)
    expect([...mask].every((slot) => slot < 257n)).toBe(true)
    expect(new Set([...mask]).size).toBeGreaterThan(30)
  })
})

describe('configuration', () => {
  it('is the domain and the four parameters', () => {
    expect(roundConfigInput(ROUND)).toBe(
      `${stringToHex(CONFIG_DOMAIN)}${[16, 3, 2, 1].map((b) => b.toString(16).padStart(2, '0')).join('')}`,
    )
  })

  it('rejects invalid parameters', () => {
    expect(() => roundConfigInput({ ...ROUND, levels: 1 })).toThrow()
    expect(() => roundConfigInput({ ...ROUND, levels: 17 })).toThrow()
    expect(() => roundConfigInput({ ...ROUND, reserveStep: 16 })).toThrow()
    expect(() => roundConfigInput({ ...ROUND, lots: 0 })).toThrow()
    expect(() => roundConfigInput({ ...ROUND, lots: 13 })).toThrow()
    expect(() => roundConfigInput({ ...ROUND, minLots: 3 })).toThrow()
    expect(() => roundConfigInput({ ...ROUND, minLots: 0 })).toThrow()
  })
})

describe('lane polynomial', () => {
  it('takes the side with fewer zeros, and the direct side on a tie', () => {
    expect(usesComplementSide(3, 13)).toBe(false)
    expect(usesComplementSide(10, 13)).toBe(true)
    expect(usesComplementSide(5, 3)).toBe(true)
    expect(usesComplementSide(3, 5)).toBe(false)
    expect(zeroSetSize(10, 13, true)).toBe(4)
    expect(zeroSetSize(5, 3, true)).toBe(0)
  })

  it('has at most 7 factors for any round of 13 bidders or fewer, which is depth 3', () => {
    let worst = 0
    for (let n = 1; n <= MAX_BIDDERS; n++) {
      for (let lots = 1; lots <= MAX_LOTS; lots++) {
        for (let minLots = 1; minLots <= lots; minLots++) worst = Math.max(worst, laneFactors({ lots, minLots }, n))
      }
    }
    expect(worst).toBe(7)
  })
})

describe('output decoder', () => {
  it('reads every outcome that outputSlotsFor writes', () => {
    for (let n = 1; n <= MAX_BIDDERS; n++) {
      for (const lots of [1, 2, 5, 7, 12]) {
        for (const minLots of [1, Math.ceil(lots / 2), lots]) {
          const params: RoundParams = { levels: 16, reserveStep: 2, lots, minLots }
          const versions = versionsOf(n)
          expect(decodeRound(outputSlotsFor(params, versions, Outcome.NotMet), params)).toMatchObject({
            counted: n,
            outcome: Outcome.NotMet,
            step: null,
          })
          expect(decodeRound(outputSlotsFor(params, versions, Outcome.Undersubscribed), params)).toMatchObject({
            outcome: Outcome.Undersubscribed,
            step: 2,
          })
          for (const step of [2, 9, 15]) {
            const output = decodeRound(outputSlotsFor(params, versions, Outcome.SoldOut, step), params)
            expect(output, `n ${n}, K ${lots}, m ${minLots}, step ${step}`).toMatchObject({ outcome: Outcome.SoldOut, step })
            expect(output.versions).toEqual(versions)
          }
        }
      }
    }
  })

  it('reads a lane as zero only when all its copies are zero', () => {
    const versions = versionsOf(2)
    const params: RoundParams = { levels: 8, reserveStep: 2, lots: 2, minLots: 1 }
    // Two bidders and 2 lots: the complement side. Undersubscribed: no price lane is zero.
    const slots = outputSlotsFor(params, versions, Outcome.Undersubscribed)
    expect(decodeRound(slots, params).outcome).toBe(Outcome.Undersubscribed)
    // One zero copy of a lane does not make a zero lane.
    slots[priceSlot(0, 4)] = 0n
    expect(decodeRound(slots, params).outcome).toBe(Outcome.Undersubscribed)
    for (let g = 0; g < COPIES; g++) slots[priceSlot(g, 2)] = 0n
    // Now the lane of step 2 is zero (the test holds), the gate holds: sold out at step 2.
    expect(decodeRound(slots, params)).toMatchObject({ outcome: Outcome.SoldOut, step: 2 })
  })

  it('aborts on an output that breaks a rule', () => {
    const versions = versionsOf(2)
    const params: RoundParams = { levels: 8, reserveStep: 2, lots: 2, minLots: 1 }
    const good = outputSlotsFor(params, versions, Outcome.SoldOut, 4)
    const aborted = (edit: (slots: bigint[]) => void, bidCounts?: number[]) => {
      const slots = [...good]
      edit(slots)
      return decodeRound(slots, params, bidCounts).outcome === Outcome.Aborted
    }
    expect(aborted(() => {})).toBe(false)
    expect(aborted((s) => (s[priceSlot(0, 1)] = 1n))).toBe(true) // below the reserve step
    expect(aborted((s) => (s[priceSlot(0, 8)] = 1n))).toBe(true) // from `levels`
    expect(aborted((s) => (s[GATE_BASE + GATE_COPIES] = 1n))).toBe(true) // an unused slot
    expect(aborted((s) => (s[VERSION_BASE] = 4n))).toBe(true) // a version above 3
    expect(aborted((s) => s.fill(0n, VERSION_BASE))).toBe(true) // no bidder counted
    // The test rises: it holds at step 6 but not at step 5.
    expect(
      aborted((s) => {
        for (let g = 0; g < COPIES; g++) {
          s[priceSlot(g, 5)] = 7n
          s[priceSlot(g, 6)] = 0n
        }
      }),
    ).toBe(true)
    // The test holds at the reserve step but the gate does not (the gate is direct: zero means it fails).
    expect(aborted((s) => s.fill(0n, GATE_BASE, GATE_BASE + GATE_COPIES))).toBe(true)
    // A counted version above the bids of the bidder.
    expect(aborted(() => {}, [1, 2])).toBe(false)
    expect(aborted(() => {}, [0, 2])).toBe(true)
  })
})

describe('prices', () => {
  it('accepts a strictly increasing list', () => {
    expect(priceListError(evenPrices(1n, 1n, 16))).toBeNull()
    expect(priceListError(linearPrices(1_000_000n, 2_500_000n, 16))).toBeNull()
  })

  it('rejects an invalid list', () => {
    expect(priceListError([1n])).not.toBeNull()
    expect(priceListError(Array.from({ length: 17 }, (_, i) => BigInt(i + 1)))).not.toBeNull()
    expect(priceListError([2n, 2n])).not.toBeNull()
    expect(priceListError([3n, 2n])).not.toBeNull()
    expect(priceListError([0n, 1n])).not.toBeNull()
    expect(priceListError(linearPrices(1n, 3n, 8))).not.toBeNull()
  })

  it('goes from the floor to the cap', () => {
    expect(linearPrices(100n, 400n, 4)).toEqual([100n, 200n, 300n, 400n])
  })

  it('reads the first `levels` prices of the padded list', () => {
    const padded = [...evenPrices(1n, 1n, 4), ...new Array<bigint>(12).fill(0n)]
    expect(readPriceList(4, padded)).toEqual([1n, 2n, 3n, 4n])
    expect(() => readPriceList(1, padded)).toThrow()
  })
})

describe('encoders', () => {
  const saleToken = '0x5FbDB2315678afecb367f032d93F642f64180aa3'
  const paymentToken = '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'

  it('encodes the sale parameters', () => {
    const prices = evenPrices(10n, 5n, 4)
    const data = encodeSaleParams({ prices, saleToken, lot: 100n, lots: 3, reserveStep: 1, minLots: 2, paymentToken, title: 'A round' })
    const [levels, padded, token, lot, lots, reserveStep, minLots, payment, title, gate, gateConfig] = decodeAbiParameters(
      parseAbiParameters('uint8, uint256[16], address, uint256, uint8, uint8, uint8, address, string, address, bytes'),
      data,
    )
    expect(levels).toBe(4)
    expect(padded.slice(0, 4)).toEqual(prices)
    expect(padded.slice(4).every((price) => price === 0n)).toBe(true)
    expect([token, lot, lots, reserveStep, minLots, payment, title]).toEqual([saleToken, 100n, 3, 1, 2, paymentToken, 'A round'])
    expect(gate).toBe(zeroAddress)
    expect(gateConfig).toBe('0x')
  })

  it('rejects an invalid round', () => {
    const base = { prices: [1n, 2n], saleToken, lot: 1n, lots: 1, reserveStep: 0, minLots: 1, paymentToken, title: '' }
    expect(() => encodeSaleParams({ ...base, prices: [2n, 1n] })).toThrow()
    expect(() => encodeSaleParams({ ...base, lot: 0n })).toThrow()
    expect(() => encodeSaleParams({ ...base, lots: 13 })).toThrow()
    expect(() => encodeSaleParams({ ...base, minLots: 2 })).toThrow()
    expect(() => encodeSaleParams({ ...base, reserveStep: 2 })).toThrow()
  })

  it('encodes the bid input and the claim data', () => {
    const bidder = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
    const data = encodeBidInput({
      bidder,
      ciphertexts: ['0x1234', '0x5678'],
      ctCommitments: [`0x${'11'.repeat(32)}`, `0x${'33'.repeat(32)}`],
      bidCommitment: `0x${'22'.repeat(32)}`,
      proof: '0xabcd',
      gateProof: '0x',
      signature: '0x',
    })
    const decoded = decodeAbiParameters(parseAbiParameters('address, bytes[], bytes32[], bytes32, bytes, bytes, bytes'), data)
    expect(decoded[0]).toBe(bidder)
    expect(decoded[1]).toEqual(['0x1234', '0x5678'])
    expect(decoded[2]).toEqual([`0x${'11'.repeat(32)}`, `0x${'33'.repeat(32)}`])
    expect(decoded[3]).toBe(`0x${'22'.repeat(32)}`)
    expect(decodeAbiParameters(parseAbiParameters('uint8, bytes'), encodeClaimData(2, '0xbeef'))).toEqual([2, '0xbeef'])
  })

  it('signs a bid that recovers to the bidder', async () => {
    const account = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
    const program = '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9'
    const inputsHash = bidInputsHash([`0x${'11'.repeat(32)}`, `0x${'33'.repeat(32)}`], `0x${'22'.repeat(32)}`, ['0x1234', '0x5678'])
    const typed = bidTypedData(31337, program, 7n, account.address, 2, inputsHash)
    const signature = await account.signTypedData(typed)
    expect(await recoverTypedDataAddress({ ...typed, signature })).toBe(account.address)
    expect(hashTypedData(typed)).toMatch(/^0x[0-9a-f]{64}$/)
    expect(typed.domain.name).toBe('PrivateRoundProgram')
  })
})
