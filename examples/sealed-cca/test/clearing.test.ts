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
import { ClearingHarness__factory } from '../types/factories/contracts/mocks'
import {
  type ClearingInput,
  KIND_CAPPED,
  KIND_UNCAPPED,
  KIND_UNDERSUBSCRIBED,
  LEVELS,
  N,
  coefficientsToPlaintext,
  coefficientsToSlots,
  compare,
  demandCurve,
  referenceClear,
  referenceOutcome,
  rng,
  slotsToCoefficients,
} from './helpers'

const here = path.dirname(fileURLToPath(import.meta.url))
const VECTORS = path.join(here, '../sdk/test-vectors/clearing.json')
const SLOT_VECTORS = path.join(here, '../sdk/test-vectors/slots.json')

async function deployHarness() {
  const { ethers } = await hre.network.connect()
  const [owner] = await ethers.getSigners()
  const library = await ethers.deployContract('SaleClearing')
  const factory = await ethers.getContractFactory(
    ClearingHarness__factory.abi,
    ClearingHarness__factory.linkBytecode({ 'project/contracts/libraries/SaleClearing.sol:SaleClearing': await library.getAddress() }),
    owner,
  )
  return ClearingHarness__factory.connect(await (await factory.deploy()).getAddress(), owner)
}

const pad = (values: bigint[]) => [...values, ...Array.from({ length: LEVELS - values.length }, () => 0n)]

/** Run the Solidity clearing and the claim outcome of every bid step. */
async function solidityClear(harness: Awaited<ReturnType<typeof deployHarness>>, input: ClearingInput) {
  const levels = input.prices.length
  const result = await harness.clear(pad(input.prices), levels, pad(input.c.slice(0, levels)), input.supply, input.escrow, input.unit)
  const plain = {
    kind: result.kind,
    step: result.step,
    pStar: result.pStar,
    fullTokens: result.fullTokens,
    marginalTokens: result.marginalTokens,
    sold: result.sold,
  }
  const outcomes = []
  for (let b = 0; b < levels; b++) {
    const cmp = compare(b, Number(result.step))
    const [tokens, paid, refund] = await harness.outcome(plain, cmp, input.escrow, input.unit)
    outcomes.push({ b, cmp, tokens, paid, refund })
  }
  return {
    result: {
      kind: Number(result.kind),
      step: Number(result.step),
      pStar: result.pStar,
      fullTokens: result.fullTokens,
      marginalTokens: result.marginalTokens,
      sold: result.sold,
    },
    outcomes,
  }
}

const U18 = 10n ** 18n

/** A hand-picked sale: the prices are 1.00 to 4.00 USDC per token in steps of 1.00, 100 tokens, 50 USDC escrow. */
const BASE = {
  prices: [1_000_000n, 2_000_000n, 3_000_000n, 4_000_000n],
  supply: 100n * U18,
  escrow: 50_000_000n,
  unit: U18,
}

const curveOf = (steps: number[], levels: number) => demandCurve(steps).map(BigInt).slice(0, levels)

describe('Clearing', () => {
  describe('cases of the README', () => {
    it('is undersubscribed: everybody is filled at the lowest price', async () => {
      const harness = await deployHarness()
      // One bidder buys 50 tokens at 1.00; the supply is 100.
      const { result, outcomes } = await solidityClear(harness, { ...BASE, c: curveOf([1], 4) })
      expect(result).to.deep.equal({
        kind: KIND_UNDERSUBSCRIBED,
        step: 0,
        pStar: 1_000_000n,
        fullTokens: 50n * U18,
        marginalTokens: 0n,
        sold: 50n * U18,
      })
      expect(outcomes[1]).to.include({ tokens: 50n * U18, paid: 50_000_000n, refund: 0n })
    })

    it('is capped at the lowest step: bidders at step 0 share the supply', async () => {
      const harness = await deployHarness()
      // 4 bidders all at step 0 demand 200 tokens at 1.00 for a supply of 100: each gets 25.
      const { result, outcomes } = await solidityClear(harness, { ...BASE, c: curveOf([0, 0, 0, 0], 4) })
      expect(result).to.deep.equal({
        kind: KIND_CAPPED,
        step: 0,
        pStar: 1_000_000n,
        fullTokens: 50n * U18,
        marginalTokens: 25n * U18,
        sold: 100n * U18,
      })
      // The marginal bidder pays 25 USDC and gets 25 back.
      expect(outcomes[0]).to.include({ cmp: 1, tokens: 25n * U18, paid: 25_000_000n, refund: 25_000_000n })
    })

    it('is capped in the middle: higher bidders are full, the ones at the step share the rest', async () => {
      const harness = await deployHarness()
      // One bidder at step 3, five at step 2, one at step 1 and one at step 0: at p_2 = 3.00 a full fill is 16.66.. tokens.
      const input = { ...BASE, c: curveOf([3, 2, 2, 2, 2, 2, 1, 0], 4) }
      const { result, outcomes } = await solidityClear(harness, input)
      expect(result.kind).to.equal(KIND_CAPPED)
      expect(result.step).to.equal(2)
      expect(result.pStar).to.equal(3_000_000n)
      expect(result.fullTokens).to.equal((50_000_000n * U18) / 3_000_000n)
      expect(outcomes[3].tokens).to.equal(result.fullTokens)
      expect(outcomes[1].tokens).to.equal(0n)
      expect(outcomes[1].refund).to.equal(50_000_000n)
      expect(result).to.deep.equal(referenceClear(input))
    })

    it('is uncapped: the price falls between two steps and the supply is sold, up to the rounding dust', async () => {
      const harness = await deployHarness()
      // 3 bidders with b >= 1 escrow 50 USDC each for 80 tokens: 150 / 80 = 1.875 USDC per token, between 1.00 and 2.00.
      const input: ClearingInput = { ...BASE, supply: 80n * U18, c: [3n, 3n, 0n, 0n] }
      const { result, outcomes } = await solidityClear(harness, input)
      expect(result).to.deep.equal({
        kind: KIND_UNCAPPED,
        step: 1,
        pStar: 1_875_000n,
        fullTokens: (50_000_000n * U18) / 1_875_000n,
        marginalTokens: 0n,
        sold: 3n * ((50_000_000n * U18) / 1_875_000n),
      })
      // The sale sells all but the rounding dust: 2 base units.
      expect(80n * U18 - result.sold).to.equal(2n)
      expect(outcomes[1]).to.include({ cmp: 1, paid: 50_000_000n, refund: 0n })
      expect(outcomes[0]).to.include({ cmp: 0, tokens: 0n, paid: 0n, refund: 50_000_000n })
    })

    it('rounds the uncapped price up, so that the sale never sells more than the supply', async () => {
      const harness = await deployHarness()
      // 3 bidders with b >= 1 escrow 50 USDC each for 90 tokens: 150 / 90 = 1.666666.. USDC per token.
      const input: ClearingInput = { ...BASE, supply: 90n * U18, c: [3n, 3n, 0n, 0n] }
      const { result } = await solidityClear(harness, input)
      expect(result.kind).to.equal(KIND_UNCAPPED)
      expect(result.step).to.equal(1)
      expect(result.pStar).to.equal(1_666_667n)
      expect(result.sold <= 90n * U18).to.equal(true)
      expect(result).to.deep.equal(referenceClear(input))
    })

    it('caps a marginal fill at a full fill', async () => {
      const harness = await deployHarness()
      // 6 bidders above step 1 get 1 token each (a full fill is 5 / 3). One bidder at step 1 would get the
      // remainder 10 - 6 = 4, which is more than a full fill: the fill is capped at 1 token.
      const input: ClearingInput = { prices: [1n, 3n, 9n], c: [7n, 7n, 6n], supply: 10n, escrow: 5n, unit: 1n }
      const { result } = await solidityClear(harness, input)
      expect(result).to.deep.equal({ kind: KIND_CAPPED, step: 1, pStar: 3n, fullTokens: 1n, marginalTokens: 1n, sold: 7n })
      expect(result).to.deep.equal(referenceClear(input))
    })

    it('clears a sale with nobody counted', async () => {
      const harness = await deployHarness()
      const { result } = await solidityClear(harness, { ...BASE, c: [0n, 0n, 0n, 0n] })
      expect(result).to.deep.equal({
        kind: KIND_UNDERSUBSCRIBED,
        step: 0,
        pStar: 1_000_000n,
        fullTokens: 50n * U18,
        marginalTokens: 0n,
        sold: 0n,
      })
    })

    it('clears the highest step when it is capped', async () => {
      const harness = await deployHarness()
      // 5 bidders at the top step 3 demand 5 * 12.5 = 62.5 at p_3 = 4.00, below the supply 100: not capped there.
      // 9 bidders demand 112.5 >= 100: capped at the top, the 9 share the supply.
      const input = { ...BASE, c: curveOf(Array(9).fill(3), 4) }
      const { result } = await solidityClear(harness, input)
      expect(result.kind).to.equal(KIND_CAPPED)
      expect(result.step).to.equal(3)
      expect(result).to.deep.equal(referenceClear(input))
    })
  })

  describe('property tests', () => {
    // A random sale and a random set of bidders, from a seed.
    function randomSale(seed: number) {
      const random = rng(seed)
      const levels = random.int(2, LEVELS)
      const unit = 10n ** BigInt(random.int(0, 18))
      const prices: bigint[] = []
      let price = BigInt(random.int(1, 50))
      for (let l = 0; l < levels; l++) {
        prices.push(price)
        price += BigInt(random.int(1, 40))
      }
      const escrow = BigInt(random.int(1, 1000)) * BigInt(random.int(1, 1000))
      const bidders = random.int(0, 112)
      const steps = Array.from({ length: bidders }, () => random.int(0, levels - 1))
      // A supply from far below to far above the demand: a ratio of the largest possible demand.
      const maxTokens = (escrow * unit) / prices[0] + 1n
      const supply = BigInt(Math.max(1, Math.floor(random.next() * 1.5 * bidders))) * (maxTokens / 4n + 1n) + BigInt(random.int(0, 1000))
      return { input: { prices, c: curveOf(steps, levels), supply, escrow, unit } satisfies ClearingInput, steps }
    }

    it('matches the TypeScript reference and keeps the properties, for 300 random sales', async () => {
      const harness = await deployHarness()
      for (let seed = 1; seed <= 300; seed++) {
        const { input, steps } = randomSale(seed)
        const { result, outcomes } = await solidityClear(harness, input)
        const label = `seed ${seed}`
        expect(result, label).to.deep.equal(referenceClear(input))

        // Total sold never exceeds the supply, and equals the sum of what the bidders get.
        expect(result.sold <= input.supply, `${label}: sold <= supply`).to.equal(true)
        let total = 0n
        let proceeds = 0n
        const byStep = new Map<number, { tokens: bigint; paid: bigint }>()
        for (const b of steps) {
          const outcome = outcomes[b]
          total += outcome.tokens
          proceeds += outcome.paid
          byStep.set(b, { tokens: outcome.tokens, paid: outcome.paid })
        }
        expect(total, `${label}: sold is the sum of the fills`).to.equal(result.sold)
        for (const outcome of outcomes) {
          // Nobody pays more than the escrow, and the refund is the rest.
          expect(outcome.paid <= input.escrow, `${label}: paid <= escrow`).to.equal(true)
          expect(outcome.paid + outcome.refund, label).to.equal(input.escrow)
          // Nobody pays more per token than their own maximum price: the uniform price is at most p_b for a winner.
          if (outcome.tokens > 0n) {
            expect(
              result.pStar <= input.prices[outcome.b] || (result.kind === KIND_UNCAPPED && outcome.b >= result.step),
              `${label}: price below the maximum`,
            ).to.equal(true)
            expect(outcome.paid * input.unit <= outcome.tokens * result.pStar + input.unit - 1n, `${label}: one uniform price`).to.equal(
              true,
            )
            // The payment is the price of the tokens, rounded up once.
            expect(outcome.paid, `${label}: paid is the rounded-up cost`).to.equal(
              (outcome.tokens * result.pStar + input.unit - 1n) / input.unit,
            )
          } else {
            expect(outcome.paid, `${label}: no tokens, no payment`).to.equal(0n)
          }
        }
        // A higher bid never gets a worse outcome: tokens do not decrease with the step.
        for (let b = 1; b < outcomes.length; b++) {
          expect(outcomes[b].tokens >= outcomes[b - 1].tokens, `${label}: monotone in the step`).to.equal(true)
        }
        // Bidders below the clearing price get nothing.
        if (result.kind !== KIND_UNDERSUBSCRIBED) {
          for (const outcome of outcomes) {
            if (outcome.b < result.step) expect(outcome.tokens, `${label}: below the step`).to.equal(0n)
          }
        }
        expect(proceeds <= BigInt(steps.length) * input.escrow, `${label}: the proceeds are at most the escrows`).to.equal(true)
        // Uniform price: the capped price is a grid price, the undersubscribed price is the lowest.
        if (result.kind === KIND_CAPPED) expect(result.pStar).to.equal(input.prices[result.step])
        if (result.kind === KIND_UNDERSUBSCRIBED) expect(result.pStar).to.equal(input.prices[0])
        if (result.kind === KIND_UNCAPPED) {
          expect(
            result.pStar > input.prices[result.step - 1] && result.pStar <= input.prices[result.step],
            `${label}: uncapped price in the interval`,
          ).to.equal(true)
        }
      }
    })

    it('never gives a bidder a worse outcome when only their own bid rises', async () => {
      const harness = await deployHarness()
      for (let seed = 1000; seed < 1060; seed++) {
        const { input, steps } = randomSale(seed)
        if (steps.length === 0) continue
        const levels = input.prices.length
        const victim = rng(seed).int(0, steps.length - 1)
        let previous: { tokens: bigint; paid: bigint } | undefined
        for (let b = steps[victim]; b < levels; b++) {
          const raised = [...steps]
          raised[victim] = b
          const raisedInput = { ...input, c: curveOf(raised, levels) }
          const { outcomes } = await solidityClear(harness, raisedInput)
          // The bidder who raises is filled at least as much, and the net cost per token does not rise above the maximum.
          if (previous) expect(outcomes[b].tokens >= previous.tokens, `seed ${seed}: raising to ${b}`).to.equal(true)
          previous = outcomes[b]
        }
      }
    })

    it('reverts when the amounts overflow the arithmetic', async () => {
      const { ethers } = await hre.network.connect()
      const harness = await deployHarness()
      // The program limits amounts to 2^112; far above it the product overflows and the call reverts.
      await expect(harness.clear(pad([1n, 2n]), 2, pad([112n, 112n]), 1n, 2n ** 250n, 10n ** 18n)).to.be.revert(ethers)
    })
  })

  describe('shared test vectors', () => {
    const cases = () => {
      const list: { name: string; input: ClearingInput; decimals: number }[] = []
      const add = (name: string, input: ClearingInput, decimals: number) => list.push({ name, input, decimals })
      add('undersubscribed', { ...BASE, c: curveOf([1], 4) }, 18)
      add('nobody counted', { ...BASE, c: curveOf([], 4) }, 18)
      add('capped at the lowest step', { ...BASE, c: curveOf([0, 0, 0, 0], 4) }, 18)
      add('capped in the middle', { ...BASE, c: curveOf([3, 2, 2, 2, 2, 2, 1, 0], 4) }, 18)
      add('capped at the top step', { ...BASE, c: curveOf(Array(9).fill(3), 4) }, 18)
      add('uncapped, exact price', { ...BASE, supply: 80n * U18, c: [3n, 3n, 0n, 0n] }, 18)
      add('uncapped, price rounded up', { ...BASE, supply: 90n * U18, c: [3n, 3n, 0n, 0n] }, 18)
      add('marginal fill capped at a full fill', { prices: [1n, 3n, 9n], c: [7n, 7n, 6n], supply: 10n, escrow: 5n, unit: 1n }, 0)
      add(
        'two steps, six decimals',
        { prices: [500_000n, 1_500_000n], c: [5n, 2n], supply: 40_000_000n, escrow: 10_000_000n, unit: 10n ** 6n },
        6,
      )
      add(
        'sixteen steps',
        {
          prices: Array.from({ length: 16 }, (_, l) => 1_000_000n + BigInt(l) * 250_000n),
          c: curveOf([15, 12, 12, 9, 9, 9, 5, 5, 3, 0, 0, 7, 8, 14, 2], 16),
          supply: 1_000n * U18,
          escrow: 400_000_000n,
          unit: U18,
        },
        18,
      )
      for (let seed = 1; seed <= 12; seed++) {
        const { input } = (() => {
          const random = rng(seed * 7919)
          const levels = random.int(2, LEVELS)
          const prices = Array.from({ length: levels }, (_, l) => BigInt(1_000_000 + l * random.int(100_000, 400_000)))
          const steps = Array.from({ length: random.int(1, 40) }, () => random.int(0, levels - 1))
          const escrow = BigInt(random.int(1, 500)) * 1_000_000n
          const supply = BigInt(random.int(1, 600)) * U18
          return { input: { prices, c: curveOf(steps, levels), supply, escrow, unit: U18 } }
        })()
        add(`random ${seed}`, input, 18)
      }
      return list
    }

    it('matches sdk/test-vectors/clearing.json (UPDATE_VECTORS=1 rewrites it)', async () => {
      const harness = await deployHarness()
      const built = []
      for (const { name, input, decimals } of cases()) {
        const { result, outcomes } = await solidityClear(harness, input)
        expect(result).to.deep.equal(referenceClear(input), name)
        const levels = input.prices.length
        built.push({
          name,
          levels,
          prices: input.prices.map(String),
          supply: String(input.supply),
          escrow: String(input.escrow),
          saleDecimals: decimals,
          // `counts[l]` is the number of bidders with `b >= l`; 16 entries, 0 from `levels`.
          counts: pad(input.c.slice(0, levels)).map(String),
          expect: {
            kind: result.kind,
            step: result.step,
            k: result.step,
            pStar: String(result.pStar),
            fullTokens: String(result.fullTokens),
            marginalTokens: String(result.marginalTokens),
            sold: String(result.sold),
            outcomes: outcomes.map((outcome) => ({
              b: outcome.b,
              cmp: outcome.cmp,
              tokens: String(outcome.tokens),
              paid: String(outcome.paid),
              refund: String(outcome.refund),
            })),
          },
        })
        expect(input.unit, name).to.equal(10n ** BigInt(decimals))
        expect(referenceOutcome(result, 0, input.escrow, input.unit).tokens, name).to.equal(outcomes[0].tokens)
      }
      // An array of cases. The README of the example describes the fields.
      const text = `${JSON.stringify(built, null, 2)}\n`
      if (process.env.UPDATE_VECTORS === '1' || !existsSync(VECTORS)) writeFileSync(VECTORS, text)
      expect(JSON.parse(readFileSync(VECTORS, 'utf8'))).to.deep.equal(JSON.parse(text))
    })
  })

  describe('slot decoder', () => {
    it('decodes the vectors of the fhe.rs decoder', async () => {
      const harness = await deployHarness()
      const vectors = JSON.parse(readFileSync(SLOT_VECTORS, 'utf8')) as {
        cases: { name: string; plaintext: `0x${string}`; slots: number[] }[]
      }
      expect(vectors.cases.length).to.be.greaterThan(5)
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
})
