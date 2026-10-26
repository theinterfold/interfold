// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import hre from 'hardhat'
import type { RoundHarness } from '../types/contracts/mocks'
import { RoundHarness__factory } from '../types/factories/contracts/mocks'
import {
  COPIES,
  GATE_BASE,
  LEVELS,
  Outcome,
  VERSION_BASE,
  decodeRound,
  outputSlotsFor,
  usesComplementSide,
  type RoundParams,
} from '../sdk/src/layout'
import {
  type ClaimClass,
  type RoundSale,
  allocationOf,
  claimClass,
  clearing,
  compareBid,
  cost,
  escrowOf,
  marginalAllocation,
  marginalRank,
} from '../sdk/src/clearing'
import { N, coefficientsToPlaintext, coefficientsToSlots, plaintextOf, rng, slotsToCoefficients } from './helpers'

const here = path.dirname(fileURLToPath(import.meta.url))
const CLEARING_VECTORS = path.join(here, '../sdk/test-vectors/clearing.json')
const SLOT_VECTORS = path.join(here, '../sdk/test-vectors/slots.json')
const LAYOUT_VECTORS = path.join(here, '../sdk/test-vectors/layout.json')

const CLASS_NUMBER: Record<ClaimClass, number> = { refund: 0, full: 1, marginal: 2 }
const U18 = 10n ** 18n

async function deployHarness(): Promise<RoundHarness> {
  const { ethers } = await hre.network.connect()
  const [owner] = await ethers.getSigners()
  const output = await ethers.deployContract('RoundOutput')
  const factory = await ethers.getContractFactory(
    RoundHarness__factory.abi,
    RoundHarness__factory.linkBytecode({ 'project/contracts/libraries/RoundOutput.sol:RoundOutput': await output.getAddress() }),
    owner,
  )
  return RoundHarness__factory.connect(await (await factory.deploy()).getAddress(), owner) as unknown as RoundHarness
}

const pad16 = (values: readonly bigint[]) => [...values, ...Array.from({ length: LEVELS - values.length }, () => 0n)]

interface DecodedOutput {
  outcome: number
  step: number
  counted: number
  versions: number[]
}

/** The Solidity decode of the output slots, with `bidCounts[i]` bids for the bidder `i`. */
async function solidityDecode(
  harness: RoundHarness,
  slots: readonly (number | bigint)[],
  params: RoundParams,
  bidCounts: number[],
): Promise<DecodedOutput> {
  await (await harness.setBidders(bidCounts)).wait()
  const [outcome, step, counted, packed] = await harness.decode(
    plaintextOf(slots),
    params.levels,
    params.reserveStep,
    params.lots,
    params.minLots,
  )
  return {
    outcome: Number(outcome),
    step: Number(step),
    counted: Number(counted),
    versions: Array.from({ length: 13 }, (_, i) => Number((packed >> BigInt(2 * i)) & 3n)),
  }
}

/** What the SDK reference says about the same slots, in the Solidity shape. */
function referenceDecode(slots: readonly bigint[], params: RoundParams, bidCounts: number[]): DecodedOutput {
  const out = decodeRound(slots, params, bidCounts)
  return { outcome: out.outcome, step: out.step ?? 0, counted: out.counted, versions: out.versions }
}

describe('Round settlement arithmetic', () => {
  /** Hand-picked and random rounds with every outcome. */
  function cases(): { name: string; sale: RoundSale; outcome: Outcome; step: number | null }[] {
    const base = { prices: [1_000_000n, 2_000_000n, 3_000_000n, 4_000_000n], lot: 10n * U18, saleDecimals: 18 }
    const list: { name: string; sale: RoundSale; outcome: Outcome; step: number | null }[] = [
      { name: 'not met', sale: { ...base, lots: 3, reserveStep: 1, minLots: 2 }, outcome: Outcome.NotMet, step: null },
      { name: 'aborted', sale: { ...base, lots: 3, reserveStep: 0, minLots: 1 }, outcome: Outcome.Aborted, step: null },
      {
        name: 'undersubscribed, reserve 0',
        sale: { ...base, lots: 3, reserveStep: 0, minLots: 1 },
        outcome: Outcome.Undersubscribed,
        step: 0,
      },
      {
        name: 'undersubscribed, reserve 2',
        sale: { ...base, lots: 4, reserveStep: 2, minLots: 2 },
        outcome: Outcome.Undersubscribed,
        step: 2,
      },
      { name: 'sold out at the reserve', sale: { ...base, lots: 3, reserveStep: 0, minLots: 1 }, outcome: Outcome.SoldOut, step: 0 },
      { name: 'sold out at the top step', sale: { ...base, lots: 2, reserveStep: 1, minLots: 1 }, outcome: Outcome.SoldOut, step: 3 },
      { name: 'sold out, 12 lots', sale: { ...base, lots: 12, reserveStep: 0, minLots: 12 }, outcome: Outcome.SoldOut, step: 2 },
      {
        name: 'six decimals and an odd lot',
        sale: { prices: [1_000_003n, 1_999_999n, 7_654_321n], lot: 333_333n, lots: 5, reserveStep: 0, minLots: 2, saleDecimals: 6 },
        outcome: Outcome.SoldOut,
        step: 1,
      },
      {
        name: 'largest amounts',
        sale: { prices: [1n, 2n ** 112n], lot: 2n ** 112n / 12n, lots: 12, reserveStep: 0, minLots: 1, saleDecimals: 0 },
        outcome: Outcome.SoldOut,
        step: 1,
      },
    ]
    for (let seed = 1; seed <= 24; seed++) {
      const random = rng(seed * 7919)
      const levels = random.int(2, LEVELS)
      const prices = Array.from({ length: levels }, (_, l) => BigInt(1_000 + l * random.int(1, 400_000) + l))
      for (let l = 1; l < levels; l++) if (prices[l] <= prices[l - 1]) prices[l] = prices[l - 1] + 1n
      const lots = random.int(1, 12)
      const reserveStep = random.int(0, levels - 1)
      const outcome = [Outcome.NotMet, Outcome.Undersubscribed, Outcome.SoldOut, Outcome.Aborted][random.int(0, 3)]
      const step =
        outcome === Outcome.SoldOut ? random.int(reserveStep, levels - 1) : outcome === Outcome.Undersubscribed ? reserveStep : null
      list.push({
        name: `random ${seed}`,
        sale: {
          prices,
          lot: BigInt(random.int(1, 1_000_000)) * 10n ** BigInt(random.int(0, 18)),
          lots,
          reserveStep,
          minLots: random.int(1, lots),
          saleDecimals: random.int(0, 18),
        },
        outcome,
        step,
      })
    }
    return list
  }

  it('matches the SDK reference and the shared vectors (UPDATE_VECTORS=1 rewrites sdk/test-vectors/clearing.json)', async () => {
    const harness = await deployHarness()
    const built = []
    for (const { name, sale, outcome, step } of cases()) {
      const levels = sale.prices.length
      const unit = 10n ** BigInt(sale.saleDecimals)
      const result = clearing(sale, { counted: 0, versions: [], outcome, step, reason: null })
      const escrow = escrowOf(sale)
      await (await harness.setPrices(pad16(sale.prices))).wait()

      // The price and the claim step.
      expect(await harness.pStar(outcome, step ?? 0, sale.reserveStep), name).to.equal(result.pStar)
      const [needed, k] = await harness.claimStep(outcome, step ?? 0, sale.reserveStep)
      expect(needed, name).to.equal(result.k !== null)
      expect(Number(k), name).to.equal(result.k ?? 0)

      // The class and the amounts of every bid step.
      const claims = []
      const bids = result.k === null ? [null] : Array.from({ length: levels }, (_, b) => b)
      for (const b of bids) {
        const cmp = b === null || result.k === null ? null : compareBid(b, result.k)
        const cls = claimClass(result, cmp)
        expect(Number(await harness.classOf(outcome, sale.reserveStep, true, cmp ?? 0)), `${name} class b=${b}`).to.equal(CLASS_NUMBER[cls])
        expect(Number(await harness.classOf(outcome, sale.reserveStep, false, cmp ?? 0)), `${name} not counted b=${b}`).to.equal(0)
        if (cls === 'marginal') continue
        const want = allocationOf(sale, result, cls)
        const tokens = cls === 'full' ? sale.lot : 0n
        const paid = await harness.cost(tokens, result.pStar, unit)
        expect([tokens, paid, escrow - paid], `${name} b=${b}`).to.deep.equal([want.tokens, want.paid, want.refund])
        claims.push({ b, cmp, class: cls, tokens: String(want.tokens), paid: String(want.paid), refund: String(want.refund) })
      }

      // The tokens of a bidder at the clearing step, for some counts of lots claimed by the bidders
      // above (phase 1) and some ranks among the registered bidders (phase 2).
      const marginal = []
      if (outcome === Outcome.SoldOut) {
        for (const aboveClaimed of [...new Set([0, 1, sale.lots - 1])].filter((a) => a < sale.lots)) {
          const remaining = sale.lots - aboveClaimed
          for (const rank of [...new Set([0, 1, remaining - 1, remaining, remaining + 1, 12])].filter((r) => r >= 0 && r <= 12)) {
            const want = marginalAllocation(sale, result, aboveClaimed, rank)
            const filled = await harness.marginalFilled(sale.lots, aboveClaimed, rank)
            const tokens = filled ? sale.lot : 0n
            const paid = await harness.cost(tokens, result.pStar, unit)
            expect([tokens, paid, escrow - paid], `${name} ${aboveClaimed}/${rank}`).to.deep.equal([want.tokens, want.paid, want.refund])
            expect(paid <= escrow, `${name} nobody pays more than the escrow`).to.equal(true)
            marginal.push({
              aboveClaimed,
              rank,
              tokens: String(want.tokens),
              paid: String(want.paid),
              refund: String(want.refund),
            })
          }
        }
      }
      built.push({
        name,
        levels,
        prices: sale.prices.map(String),
        lot: String(sale.lot),
        lots: sale.lots,
        reserveStep: sale.reserveStep,
        minLots: sale.minLots,
        saleDecimals: sale.saleDecimals,
        outcome,
        step,
        expect: {
          escrow: String(escrow),
          pStar: String(result.pStar),
          k: result.k,
          lotCost: String(result.lotCost),
          claims,
          marginal,
        },
      })
    }
    const text = `${JSON.stringify(built, null, 2)}\n`
    if (process.env.UPDATE_VECTORS === '1' || !existsSync(CLEARING_VECTORS)) writeFileSync(CLEARING_VECTORS, text)
    expect(JSON.parse(readFileSync(CLEARING_VECTORS, 'utf8'))).to.deep.equal(JSON.parse(text))
  })

  it('rounds the cost up, and never charges more than the escrow for a lot', async () => {
    const harness = await deployHarness()
    expect(await harness.cost(0n, 5n, 10n)).to.equal(0n)
    expect(await harness.cost(1n, 1n, 10n)).to.equal(1n)
    expect(await harness.cost(10n, 1n, 10n)).to.equal(1n)
    expect(await harness.cost(11n, 1n, 10n)).to.equal(2n)
    const random = rng(99)
    for (let i = 0; i < 40; i++) {
      const decimals = random.int(0, 30)
      const unit = 10n ** BigInt(decimals)
      const tokens = BigInt(random.int(1, 2 ** 30)) * 10n ** BigInt(random.int(0, 20))
      const price = BigInt(random.int(1, 2 ** 30)) * 10n ** BigInt(random.int(0, 12))
      expect(await harness.cost(tokens, price, unit)).to.equal(cost(tokens, price, decimals))
    }
  })

  it('fills the marginal bidders by index, one whole lot each', async () => {
    const harness = await deployHarness()
    for (let lots = 1; lots <= 12; lots++) {
      for (let above = 0; above < lots; above++) {
        for (let rank = 0; rank <= 13; rank++) {
          const filled = await harness.marginalFilled(lots, above, rank)
          expect(filled, `lots=${lots} above=${above} rank=${rank}`).to.equal(rank < lots - above)
          // The SDK reference agrees.
          const sale = { prices: [1n, 2n], lot: 5n, lots, reserveStep: 0, minLots: 1, saleDecimals: 0 }
          const result = clearing(sale, { counted: 0, versions: [], outcome: Outcome.SoldOut, step: 1, reason: null })
          expect(marginalAllocation(sale, result, above, rank).tokens > 0n).to.equal(filled)
        }
      }
    }
  })

  it('ranks a bidder by the registered bidders with a lower index', async () => {
    const harness = await deployHarness()
    const random = rng(5)
    expect(await harness.marginalRank(0, 7)).to.equal(0n)
    expect(await harness.marginalRank(0b1111111111111, 12)).to.equal(12n)
    expect(await harness.marginalRank(0b1111111111111, 0)).to.equal(0n)
    for (let i = 0; i < 60; i++) {
      const mask = random.int(0, 2 ** 13 - 1)
      const index = random.int(0, 12)
      const registered = Array.from({ length: 13 }, (_, bit) => bit).filter((bit) => (mask >> bit) & 1)
      expect(Number(await harness.marginalRank(mask, index)), `mask=${mask} index=${index}`).to.equal(marginalRank(registered, index))
    }
  })
})

describe('Output decoder (RoundOutput)', () => {
  const PARAMS: RoundParams = { levels: 6, reserveStep: 1, lots: 3, minLots: 2 }
  const FULL = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]
  const VERSIONS = [1, 2, 1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0]

  async function expectSame(harness: RoundHarness, name: string, slots: bigint[], params = PARAMS, bidCounts = FULL) {
    const solidity = await solidityDecode(harness, slots, params, bidCounts)
    expect(solidity, name).to.deep.equal(referenceDecode(slots, params, bidCounts))
    return solidity
  }

  it('decodes every honest outcome like the SDK', async () => {
    const harness = await deployHarness()
    for (const n of [1, 2, 3, 4, 5, 8, 13]) {
      const versions = Array.from({ length: 13 }, (_, i) => (i < n ? 1 + (i % 3) : 0))
      for (const params of [
        PARAMS,
        { levels: 2, reserveStep: 0, lots: 1, minLots: 1 },
        { levels: 16, reserveStep: 15, lots: 12, minLots: 12 },
        { levels: 16, reserveStep: 0, lots: 12, minLots: 1 },
        { levels: 8, reserveStep: 3, lots: 4, minLots: 4 },
      ]) {
        const name = `n=${n} ${JSON.stringify(params)}`
        const notMet = await expectSame(harness, `not met ${name}`, outputSlotsFor(params, versions, Outcome.NotMet), params)
        expect(notMet.outcome).to.equal(Outcome.NotMet)
        const under = await expectSame(
          harness,
          `undersubscribed ${name}`,
          outputSlotsFor(params, versions, Outcome.Undersubscribed),
          params,
        )
        expect([under.outcome, under.step]).to.deep.equal([Outcome.Undersubscribed, params.reserveStep])
        for (let step = params.reserveStep; step < params.levels; step += Math.max(1, Math.floor(params.levels / 4))) {
          const sold = await expectSame(
            harness,
            `sold out ${name} at ${step}`,
            outputSlotsFor(params, versions, Outcome.SoldOut, step),
            params,
          )
          expect([sold.outcome, sold.step, sold.counted]).to.deep.equal([Outcome.SoldOut, step, n])
          expect(sold.versions).to.deep.equal(versions)
        }
      }
    }
  })

  it('uses the polarity of the lane test that the number of counted bidders gives', async () => {
    const harness = await deployHarness()
    for (let theta = 1; theta <= 12; theta++) {
      for (let n = 1; n <= 13; n++) {
        expect(await harness.usesComplementSide(theta, n), `theta=${theta} n=${n}`).to.equal(usesComplementSide(theta, n))
      }
    }
  })

  describe('every invalid output is ABORTED and does not revert', () => {
    const honest = () => outputSlotsFor(PARAMS, VERSIONS, Outcome.SoldOut, 3)

    it('accepts the honest output', async () => {
      const harness = await deployHarness()
      const out = await expectSame(harness, 'honest', honest())
      expect([out.outcome, out.step, out.counted]).to.deep.equal([Outcome.SoldOut, 3, 5])
    })

    const aborted: [string, (slots: bigint[]) => void, number[]?][] = [
      ['no bidder is counted', (s) => s.fill(0n, VERSION_BASE, 128)],
      ['a counted version above 3', (s) => (s[VERSION_BASE + 5] = 4n)],
      ['a counted version of 256', (s) => (s[VERSION_BASE + 12] = 256n)],
      ['a counted version above the bids of the bidder', (s) => (s[VERSION_BASE + 2] = 3n), [3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]],
      ['a counted version of a bidder that did not deposit', (s) => (s[VERSION_BASE + 8] = 1n), [3, 3, 3, 3, 3, 3, 3, 3]],
      ['a counted version of a depositor that did not bid', (s) => (s[VERSION_BASE + 6] = 1n), [3, 3, 3, 3, 3, 3, 0, 3]],
      ['a price slot below the reserve step', (s) => (s[2 * LEVELS + 0] = 7n)],
      ['the last copy of a price slot below the reserve step', (s) => (s[(COPIES - 1) * LEVELS + 0] = 1n)],
      ['a price slot from `levels`', (s) => (s[3 * LEVELS + PARAMS.levels] = 5n)],
      ['the last price slot of a copy', (s) => (s[LEVELS - 1] = 5n)],
      ['an unused slot', (s) => (s[GATE_BASE + COPIES] = 1n)],
      ['the last unused slot', (s) => (s[VERSION_BASE - 1] = 200n)],
      ['the first unused slot after the gate lane', (s) => (s[102] = 256n)],
    ]
    for (const [name, mutate, bidCounts] of aborted) {
      it(`aborts: ${name}`, async () => {
        const harness = await deployHarness()
        const slots = honest()
        mutate(slots)
        const out = await expectSame(harness, name, slots, PARAMS, bidCounts ?? FULL)
        expect(out.outcome).to.equal(Outcome.Aborted)
      })
    }

    it('aborts when the demand test rises with the step', async () => {
      const harness = await deployHarness()
      // Sold out at step 2 says [c_l >= lots] holds at 1 and 2 and fails from 3. Make step 4 hold again.
      const slots = outputSlotsFor(PARAMS, VERSIONS, Outcome.SoldOut, 2)
      const sample = outputSlotsFor(PARAMS, VERSIONS, Outcome.SoldOut, 4)
      for (let g = 0; g < COPIES; g++) slots[g * LEVELS + 4] = sample[g * LEVELS + 4]
      const out = await expectSame(harness, 'rising', slots)
      expect(out.outcome).to.equal(Outcome.Aborted)
      // The same with every step from 3 on holding is a plain sell-out at the last step.
      const flat = outputSlotsFor(PARAMS, VERSIONS, Outcome.SoldOut, 5)
      expect((await expectSame(harness, 'flat', flat)).step).to.equal(5)
    })

    it('aborts when the round sells out at the reserve but the gate fails', async () => {
      const harness = await deployHarness()
      const slots = outputSlotsFor(PARAMS, VERSIONS, Outcome.SoldOut, 2)
      const notMet = outputSlotsFor(PARAMS, VERSIONS, Outcome.NotMet)
      for (let k = 0; k < COPIES; k++) slots[GATE_BASE + k] = notMet[GATE_BASE + k]
      expect((await expectSame(harness, 'sold out, no gate', slots)).outcome).to.equal(Outcome.Aborted)
      // The gate holds without a sell-out: undersubscribed, not an abort.
      expect((await expectSame(harness, 'gate only', outputSlotsFor(PARAMS, VERSIONS, Outcome.Undersubscribed))).outcome).to.equal(
        Outcome.Undersubscribed,
      )
    })

    it('reads a lane as nonzero when a single copy is nonzero', async () => {
      const harness = await deployHarness()
      for (const outcome of [Outcome.NotMet, Outcome.Undersubscribed, Outcome.SoldOut] as const) {
        for (let copy = 0; copy < COPIES; copy++) {
          const slots = outputSlotsFor(PARAMS, VERSIONS, outcome, 3)
          // Flip the state of one copy of the gate lane and one copy of the price lane at the step 3.
          slots[GATE_BASE + copy] = slots[GATE_BASE + copy] === 0n ? 9n : 0n
          slots[copy * LEVELS + 3] = slots[copy * LEVELS + 3] === 0n ? 9n : 0n
          await expectSame(harness, `${Outcome[outcome]} copy ${copy}`, slots)
        }
      }
    })

    it('aborts, and does not revert, on a plaintext of the wrong length or with a coefficient of 257', async () => {
      const harness = await deployHarness()
      await (await harness.setBidders(FULL)).wait()
      const decode = (plaintext: string) => harness.decode(plaintext, PARAMS.levels, PARAMS.reserveStep, PARAMS.lots, PARAMS.minLots)
      for (const plaintext of ['0x', '0x1234', `${plaintextOf(honest())}00`, plaintextOf(honest()).slice(0, -2)]) {
        const [outcome, , counted] = await decode(plaintext)
        expect([Number(outcome), Number(counted)], plaintext.slice(0, 12)).to.deep.equal([Outcome.Aborted, 0])
      }
      const coefficients = slotsToCoefficients(honest())
      coefficients[17] = 257
      expect(Number((await decode(coefficientsToPlaintext(coefficients)))[0])).to.equal(Outcome.Aborted)
      // A high byte in a coefficient above the first two.
      const bytes = plaintextOf(honest())
      const bad = `${bytes.slice(0, 2 + 16 * 9 + 4)}01${bytes.slice(2 + 16 * 9 + 6)}`
      expect(Number((await decode(bad))[0])).to.equal(Outcome.Aborted)
    })
  })

  it('agrees with the SDK on 300 random outputs, honest and corrupted', async () => {
    const harness = await deployHarness()
    const random = rng(2024)
    let aborted = 0
    for (let iteration = 0; iteration < 300; iteration++) {
      const levels = random.int(2, LEVELS)
      const lots = random.int(1, 12)
      const params: RoundParams = { levels, reserveStep: random.int(0, levels - 1), lots, minLots: random.int(1, lots) }
      const n = random.int(1, 13)
      const versions = Array.from({ length: 13 }, (_, i) => (i < n ? random.int(1, 3) : 0))
      const outcome = [Outcome.NotMet, Outcome.Undersubscribed, Outcome.SoldOut][random.int(0, 2)] as
        | Outcome.NotMet
        | Outcome.Undersubscribed
        | Outcome.SoldOut
      const step = outcome === Outcome.SoldOut ? random.int(params.reserveStep, levels - 1) : undefined
      const slots = outputSlotsFor(params, versions, outcome, step, () => BigInt(random.int(1, 256)))
      // Corrupt a few slots in half of the cases: a random slot gets a random value, or is zeroed.
      if (iteration % 2 === 1) {
        for (let flips = random.int(1, 3); flips > 0; flips--) {
          const slot = random.int(0, 127)
          slots[slot] = random.int(0, 3) === 0 ? 0n : BigInt(random.int(0, 256))
        }
      }
      const bidCounts = Array.from({ length: random.int(n, 13) }, (_, i) => Math.max(versions[i] ?? 1, random.int(1, 3)))
      const out = await expectSame(harness, `random ${iteration}`, slots, params, bidCounts)
      if (out.outcome === Outcome.Aborted) aborted++
    }
    // The corruption does abort, and the honest outputs do not.
    expect(aborted).to.be.greaterThan(30)
    expect(aborted).to.be.lessThan(200)
  })

  it('decodes the outputs of the fhe program (sdk/test-vectors/layout.json)', async () => {
    const harness = await deployHarness()
    const { cases: vectors } = JSON.parse(readFileSync(LAYOUT_VECTORS, 'utf8')) as {
      cases: {
        levels: number
        reserveStep: number
        lots: number
        minLots: number
        slots: number[]
        outcome: keyof typeof Outcome
        step: number | null
        counted: number
        versions: number[]
      }[]
    }
    expect(vectors.length).to.be.greaterThan(50)
    const seen = new Set<string>()
    for (const [index, vector] of vectors.entries()) {
      const params: RoundParams = { levels: vector.levels, reserveStep: vector.reserveStep, lots: vector.lots, minLots: vector.minLots }
      const out = await solidityDecode(harness, vector.slots, params, FULL)
      const name = `vector ${index} (${vector.outcome})`
      expect(out.outcome, name).to.equal(Outcome[vector.outcome])
      expect(out.step, name).to.equal(vector.step ?? 0)
      expect(out.counted, name).to.equal(vector.counted)
      expect(out.versions, name).to.deep.equal(vector.versions)
      seen.add(vector.outcome)
    }
    expect([...seen].sort()).to.deep.equal(['Aborted', 'NotMet', 'SoldOut', 'Undersubscribed'])
  })
})

describe('Slot decoder (SlotCodec)', () => {
  it('decodes the vectors of the fhe.rs decoder (sdk/test-vectors/slots.json)', async () => {
    const harness = await deployHarness()
    const vectors = JSON.parse(readFileSync(SLOT_VECTORS, 'utf8')) as {
      cases: { name: string; plaintext: `0x${string}`; slots: number[] }[]
    }
    expect(vectors.cases.length).to.be.greaterThan(8)
    for (const vector of vectors.cases) {
      const slots = (await harness.slots(vector.plaintext, N)).map(Number)
      expect(slots, vector.name).to.deep.equal(vector.slots)
      // The TypeScript codec agrees, in both directions.
      const coefficients = Array.from({ length: N }, (_, k) => {
        const chunk = vector.plaintext.slice(2 + 16 * k, 2 + 16 * (k + 1))
        return Number.parseInt(chunk.slice(0, 2), 16) + 256 * Number.parseInt(chunk.slice(2, 4), 16)
      })
      expect(coefficientsToSlots(coefficients), vector.name).to.deep.equal(vector.slots)
      expect(slotsToCoefficients(vector.slots), vector.name).to.deep.equal(coefficients)
      expect(coefficientsToPlaintext(coefficients), vector.name).to.equal(vector.plaintext)
    }
  })

  it('rejects a plaintext of the wrong length or with a coefficient of 257 or more', async () => {
    const harness = await deployHarness()
    await expect(harness.slots('0x00', 1)).to.be.revertedWithCustomError(harness, 'InvalidPlaintextLength')
    const coefficients = new Array<number>(N).fill(0)
    coefficients[3] = 257
    await expect(harness.slots(coefficientsToPlaintext(coefficients), 1)).to.be.revertedWithCustomError(harness, 'CoefficientOutOfRange')
    // A coefficient with a high byte set.
    const bytes = coefficientsToPlaintext(new Array<number>(N).fill(0))
    const bad = `${bytes.slice(0, 2 + 16 * 5 + 4)}01${bytes.slice(2 + 16 * 5 + 6)}` as `0x${string}`
    await expect(harness.slots(bad, 1)).to.be.revertedWithCustomError(harness, 'CoefficientOutOfRange')
  })
})
