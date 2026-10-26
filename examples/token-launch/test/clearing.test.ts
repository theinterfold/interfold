// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { HardhatEthers } from '@nomicfoundation/hardhat-ethers/types'
import hre from 'hardhat'
import { type Hex, toHex } from 'viem'
import { deployProgramLibraries } from '../deploy/libraries'
import { lcg, randomSale } from '../sdk/test-vectors/random-sales'
import { KIND_CAPPED, KIND_UNCAPPED, KIND_UNDERSUBSCRIBED, claimAmounts } from '../sdk/src/clearing'
import { coefficientsToPlaintext, coefficientsToSlots, slotsToCoefficients } from '../sdk/src/layout'
import { type Grid, coarseProbeMask, saleUnitOf, searchRound1, searchRound2 } from '../sdk/src/probes'
import { demandSums, revealed, simulateSale } from '../sdk/src/simulate'
import { ClearingHarness__factory } from '../types/factories/contracts/mocks'
import { outputPlaintext } from './fixture'

const here = path.dirname(fileURLToPath(import.meta.url))
const VECTORS = path.join(here, '../sdk/test-vectors/clearing.json')
const SLOT_VECTORS = path.join(here, '../sdk/test-vectors/slots.json')
const CLAIM_SPECS = [0, 1, 2]
  .flatMap((cmp) => (cmp === 0 ? [{ cmp, budgetUnits: 0 }] : [1, 37, 100].map((budgetUnits) => ({ cmp, budgetUnits }))))
  .map((spec) => ({ ...spec, escrowUnits: 100 }))

async function deployHarness(ethers: HardhatEthers) {
  const [owner] = await ethers.getSigners()
  const poseidon = await ethers.deployContract('PoseidonT3')
  const links = await deployProgramLibraries(ethers, await poseidon.getAddress())
  const factory = await ethers.getContractFactory(
    ClearingHarness__factory.abi,
    ClearingHarness__factory.linkBytecode({
      'project/contracts/libraries/SaleClearing.sol:SaleClearing': links['project/contracts/libraries/SaleClearing.sol:SaleClearing'],
      'project/contracts/libraries/SaleOutput.sol:SaleOutput': links['project/contracts/libraries/SaleOutput.sol:SaleOutput'],
      'project/contracts/libraries/ProbeSearch.sol:ProbeSearch': links['project/contracts/libraries/ProbeSearch.sol:ProbeSearch'],
      'project/contracts/libraries/ProofInputs.sol:ProofInputs': links['project/contracts/libraries/ProofInputs.sol:ProofInputs'],
    }),
    owner,
  )
  return ClearingHarness__factory.connect(await (await factory.deploy()).getAddress(), owner)
}

type Harness = Awaited<ReturnType<typeof deployHarness>>

const gridArg = (grid: Grid) => ({
  prices: Array.from({ length: 16 }, (_, l) => grid.prices[l] ?? 0n),
  levels: grid.prices.length,
  supply: grid.supply,
  budgetUnit: grid.budgetUnit,
  saleUnit: saleUnitOf(grid),
})
const str = (values: readonly bigint[]) => values.map(String)

/** What the Solidity libraries compute for the sums of two rounds. */
async function solidityRun(harness: Harness, grid: Grid, sums1: bigint[], sums2For: (mask2: number) => bigint[]) {
  const g = gridArg(grid)
  const r1 = await harness.round1(g, sums1)
  const round1 = { valid: r1.valid, lo: Number(r1.lo), hi: Number(r1.hi), probeMask2: Number(r1.mask2) }
  if (!round1.valid) return { round1, round2: null, clearing: null }
  const sums2 = sums2For(round1.probeMask2)
  const r2 = await harness.round2(g, sums1, sums2, round1.lo, round1.probeMask2)
  const round2 = { valid: r2.valid, lstar: Number(r2.lstar), sums: r2.merged.map((sum) => sum) }
  if (!round2.valid) return { round1, round2, clearing: null }
  const c = await harness.clear(g, round2.lstar, round2.sums)
  return { round1, round2, clearing: { kind: Number(c.kind), step: Number(c.step), pStar: c.pStar, sold: c.sold, remaining: c.remaining } }
}

describe('Probe search and clearing', () => {
  let harness: Harness
  let ethers: HardhatEthers
  before(async () => {
    ;({ ethers } = await hre.network.connect())
    harness = await deployHarness(ethers)
  })

  it('computes the coarse probes like the SDK', async () => {
    for (let levels = 8; levels <= 16; levels++) expect(Number(await harness.coarseProbeMask(levels))).to.equal(coarseProbeMask(levels))
  })

  it('agrees with the SDK mirror on 300 random sales, and keeps the clearing properties', async function () {
    this.timeout(600_000)
    const seen = { [KIND_UNDERSUBSCRIBED]: 0, [KIND_CAPPED]: 0, [KIND_UNCAPPED]: 0 }
    for (let seed = 1; seed <= 300; seed++) {
      const { grid, bids } = randomSale(lcg(seed * 7919))
      const full = demandSums(bids)
      const mask1 = coarseProbeMask(grid.prices.length)
      const run = await solidityRun(harness, grid, revealed(full, mask1), (mask2) => revealed(full, mask2))
      const mirror = simulateSale(grid, bids)
      expect(run.round1, `seed ${seed}`).to.deep.equal(mirror.round1)
      expect(run.round2?.valid, `seed ${seed}`).to.equal(true)
      expect(run.round2?.lstar, `seed ${seed}`).to.equal(mirror.round2?.lstar)
      expect(run.round2?.sums.map(String), `seed ${seed}`).to.deep.equal(str(mirror.round2!.sums))
      expect(run.clearing, `seed ${seed}`).to.deep.equal(mirror.clearing)
      const clearing = run.clearing!
      seen[clearing.kind as 0 | 1 | 2]++

      // Properties of the outcome.
      expect(clearing.sold <= grid.supply, `seed ${seed}: sold <= supply`).to.equal(true)
      const tokens = mirror.outcomes.reduce((sum, outcome) => sum + outcome.tokens, 0n)
      expect(tokens <= clearing.sold, `seed ${seed}: the bids get at most what was sold`).to.equal(true)
      const u = saleUnitOf(grid)
      mirror.outcomes.forEach((outcome, index) => {
        const escrow = BigInt(bids[index].escrow) * grid.budgetUnit
        expect(outcome.paid + outcome.refund, `seed ${seed} bid ${index}`).to.equal(escrow)
        expect(outcome.paid <= BigInt(bids[index].budget) * grid.budgetUnit, `seed ${seed} bid ${index}: pays at most its budget`).to.equal(
          true,
        )
        // A bid never pays more than the uniform price for its tokens (rounded up).
        expect(outcome.paid, `seed ${seed} bid ${index}`).to.equal((outcome.tokens * clearing.pStar + u - 1n) / u)
      })
      if (clearing.kind === KIND_CAPPED) {
        expect(clearing.sold, `seed ${seed}`).to.equal(grid.supply)
        expect(clearing.remaining <= grid.supply, `seed ${seed}`).to.equal(true)
      }
      // The Solidity payout of a claim equals the SDK's.
      for (const spec of CLAIM_SPECS.filter((_, i) => i % 3 === seed % 3)) {
        const [t, p, r] = await harness.outcome(clearing, spec.cmp, spec.budgetUnits, spec.escrowUnits, grid.budgetUnit, u)
        const mirrorAmounts = claimAmounts(grid, clearing, spec as { cmp: 0 | 1 | 2; budgetUnits: number; escrowUnits: number })
        expect([t, p, r], `seed ${seed} ${JSON.stringify(spec)}`).to.deep.equal([
          mirrorAmounts.tokens,
          mirrorAmounts.paid,
          mirrorAmounts.refund,
        ])
      }
    }
    expect(seen[KIND_UNDERSUBSCRIBED]).to.be.greaterThan(5)
    expect(seen[KIND_CAPPED]).to.be.greaterThan(20)
    expect(seen[KIND_UNCAPPED]).to.be.greaterThan(20)
  })

  it('refuses sums that are not a demand curve, like the mirror', async () => {
    const grid: Grid = { prices: Array.from({ length: 16 }, (_, l) => BigInt(l + 1) * 1000n), supply: 10n, budgetUnit: 1n, saleDecimals: 0 }
    const sums = (entries: Record<number, number>) => Array.from({ length: 16 }, (_, l) => BigInt(entries[l] ?? 0))
    const g = gridArg(grid)
    for (const bad of [sums({ 4: 10, 8: 11, 12: 0 }), sums({ 4: 10, 8: 5, 12: 6 })]) {
      expect((await harness.round1(g, bad)).valid).to.equal(false)
      expect(searchRound1(grid, bad).valid).to.equal(false)
    }
    const sums1 = sums({ 4: 80_000, 8: 50_000, 12: 100 })
    const r1 = await harness.round1(g, sums1)
    for (const bad of [sums({ 5: 80_001 }), sums({ 5: 70_000, 6: 60_000, 7: 60_001 }), sums({ 5: 70_000, 6: 60_000, 7: 49_999 })]) {
      const solidity = await harness.round2(g, sums1, bad, r1.lo, r1.mask2)
      expect(solidity.valid).to.equal(false)
      expect(searchRound2(grid, sums1, bad, Number(r1.lo), Number(r1.mask2)).valid).to.equal(false)
    }
  })

  it('refuses a clearing without the levels it needs', async () => {
    const grid: Grid = { prices: [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n], supply: 1n, budgetUnit: 1n, saleDecimals: 0 }
    await expect(harness.clear(gridArg(grid), 2, Array(16).fill(0n))).to.be.revert(ethers)
  })

  it('reads the output: sums at the masked levels, the counted set, and rejects what cannot be real', async () => {
    const bids = [
      { step: 5, budget: 1234, index: 0 },
      { step: 2, budget: 77, index: 3 },
      { step: 7, budget: 4095, index: 9 },
    ]
    const mask = 0b10100100
    const plaintext = outputPlaintext(bids, mask)
    const out = await harness.decodeOutput(plaintext, mask, 10)
    expect(out.valid).to.equal(true)
    expect(out.counted).to.equal((1n << 0n) | (1n << 3n) | (1n << 9n))
    const full = demandSums(bids.map((bid) => ({ ...bid, escrow: 4095 })))
    expect(out.sums.map(String)).to.deep.equal(str(revealed(full, mask)))
    // A flag at or above the bid count, and a cell above 3 per bid.
    expect((await harness.decodeOutput(plaintext, mask, 9)).valid).to.equal(false)
    expect((await harness.decodeOutput(plaintext, mask, 85)).valid).to.equal(true)
    expect((await harness.decodeOutput(outputPlaintext([{ step: 5, budget: 3, index: 0 }], mask), mask, 0)).valid).to.equal(false)
    const huge = outputPlaintext(
      Array.from({ length: 5 }, (_, index) => ({ step: 7, budget: 4095, index })),
      mask,
    )
    expect((await harness.decodeOutput(huge, mask, 4)).valid).to.equal(false)
  })

  describe('vectors', () => {
    it('writes the vectors of the SDK mirror from the Solidity libraries', async function () {
      this.timeout(600_000)
      const built: object[] = []
      for (let seed = 1; seed <= 60; seed++) {
        const { grid, bids } = randomSale(lcg(seed * 104729))
        const full = demandSums(bids)
        const sums1 = revealed(full, coarseProbeMask(grid.prices.length))
        let sums2: bigint[] = Array(16).fill(0n)
        const run = await solidityRun(harness, grid, sums1, (mask2) => (sums2 = revealed(full, mask2)))
        const u = saleUnitOf(grid)
        const claims = run.clearing
          ? await Promise.all(
              CLAIM_SPECS.map(async (spec) => {
                const [tokens, paid, refund] = await harness.outcome(
                  run.clearing!,
                  spec.cmp,
                  spec.budgetUnits,
                  spec.escrowUnits,
                  grid.budgetUnit,
                  u,
                )
                return { ...spec, tokens: String(tokens), paid: String(paid), refund: String(refund) }
              }),
            )
          : []
        built.push({
          name: `random-${seed}`,
          input: {
            prices: str(grid.prices),
            supply: String(grid.supply),
            budgetUnit: String(grid.budgetUnit),
            saleDecimals: grid.saleDecimals,
            sums1: str(sums1),
            sums2: str(sums2),
          },
          expected: {
            round1: run.round1,
            round2: run.round2 && { valid: run.round2.valid, lstar: run.round2.lstar, sums: str(run.round2.sums) },
            clearing: run.clearing && {
              ...run.clearing,
              pStar: String(run.clearing.pStar),
              sold: String(run.clearing.sold),
              remaining: String(run.clearing.remaining),
            },
            claims,
          },
        })
      }
      // The invalid cases: round 1 is not a demand curve.
      const prices = Array.from({ length: 16 }, (_, l) => String(BigInt(l + 1) * 1000n))
      const bad = Array.from({ length: 16 }, (_, l) => String({ 4: 10, 8: 11 }[l] ?? 0))
      const g = gridArg({ prices: prices.map(BigInt), supply: 10n, budgetUnit: 1n, saleDecimals: 0 })
      const invalid = await harness.round1(g, bad.map(BigInt))
      built.push({
        name: 'invalid-round-1',
        input: { prices, supply: '10', budgetUnit: '1', saleDecimals: 0, sums1: bad, sums2: Array(16).fill('0') },
        expected: { round1: { valid: invalid.valid, lo: 0, hi: 0, probeMask2: 0 }, round2: null, clearing: null, claims: [] },
      })
      const file = {
        description:
          'Probe search, clearing and claim payouts, from the Solidity libraries (test/clearing.test.ts; UPDATE_VECTORS=1 rewrites this file). `sums1` and `sums2` are the revealed sums of the two rounds (0 at levels that were not revealed). `claims` give the immediate payout of a claim with the comparison `cmp`; a capped claim with cmp 1 pays nothing there (it registers and is filled by `marginalFills`).',
        cases: built,
      }
      const text = `${JSON.stringify(file, null, 2)}\n`
      if (process.env.UPDATE_VECTORS === '1' || !existsSync(VECTORS)) writeFileSync(VECTORS, text)
      expect(JSON.parse(readFileSync(VECTORS, 'utf8'))).to.deep.equal(JSON.parse(text))
    })
  })

  describe('slot decoder', () => {
    it('decodes the vectors of the fhe.rs decoder', async () => {
      const vectors = JSON.parse(readFileSync(SLOT_VECTORS, 'utf8')) as { cases: { name: string; plaintext: Hex; slots: number[] }[] }
      expect(vectors.cases.length).to.be.greaterThan(5)
      for (const vector of vectors.cases) {
        const slots = (await harness.slots(vector.plaintext, 128)).map(Number)
        expect(slots, vector.name).to.deep.equal(vector.slots)
        const coefficients = slotsToCoefficients(vector.slots)
        expect(coefficientsToSlots(coefficients), vector.name).to.deep.equal(vector.slots)
        expect(coefficientsToPlaintext(coefficients), vector.name).to.equal(vector.plaintext)
      }
    })

    it('rejects a plaintext of the wrong length or with a coefficient of 257 or more', async () => {
      await expect(harness.slots('0x00', 1)).to.be.revertedWithCustomError(harness, 'InvalidPlaintextLength')
      const coefficients = new Array<number>(128).fill(0)
      coefficients[3] = 257
      await expect(harness.slots(coefficientsToPlaintext(coefficients), 1)).to.be.revertedWithCustomError(harness, 'CoefficientOutOfRange')
      const bytes = coefficientsToPlaintext(new Array<number>(128).fill(0))
      const bad = `${bytes.slice(0, 2 + 16 * 5 + 4)}01${bytes.slice(2 + 16 * 5 + 6)}` as Hex
      await expect(harness.slots(bad, 1)).to.be.revertedWithCustomError(harness, 'CoefficientOutOfRange')
      expect(toHex(0)).to.equal('0x0')
    })
  })
})
