// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import type { Hex } from 'viem'
import { Outcome, encodeClaimData, outputSlotsFor, type RoundParams } from '../sdk/src/layout'
import { type Allocation, allocationOf, claimClass, clearing, compareBid, escrowOf, marginalRank, supplyOf } from '../sdk/src/clearing'
import {
  ESCROW,
  LOT,
  LOTS,
  PRICES,
  type Fixture,
  type PlayOptions,
  type Played,
  claimData,
  deployFixture,
  mineAt,
  playRound,
} from './fixture'
import { rng } from './helpers'

type Role = 'above' | 'marginal' | 'other'

interface Plan {
  /** The outcome the contract must reach, when it differs from the honest outcome of the bids. */
  outcome?: Outcome
  step?: number | null
  /** Bidders that skip a step: they do not claim (above), do not register (marginal) or never claim (other). */
  skip?: Partial<Record<Role, number[]>>
  /** The order in which the marginal bidders register. The default is the reverse bidder order. */
  registerOrder?: number[]
  /** The creator takes the supply of a round that sold nothing before the sweep. */
  withdrawSupply?: boolean
}

const ZERO: Allocation = { tokens: 0n, paid: 0n, refund: 0n }

describe('Clear and claim', () => {
  let fixture: Fixture
  let nextRound = 100n

  before(async () => {
    fixture = await deployFixture()
  })

  const play = (steps: (number | null)[], options: PlayOptions = {}) => playRound(fixture, steps, { ...options, e3Id: nextRound++ })

  const balancesOf = async (holder: { address: string }) => ({
    sale: await fixture.saleToken.balanceOf(holder.address),
    usdc: await fixture.usdc.balanceOf(holder.address),
  })

  /** The next block gets this timestamp. */
  const setNext = (at: bigint) => fixture.ethers.provider.send('evm_setNextBlockTimestamp', [Number(at)])

  /** The clearing of a played round, in the SDK shape. */
  const resultOf = (played: Played, plan: Plan = {}) =>
    clearing(played.sale, {
      counted: 0,
      versions: [],
      outcome: plan.outcome ?? played.outcome,
      step: plan.step === undefined ? played.step : plan.step,
      reason: null,
    })

  /** The role of each bidder: above the clearing step, at it, or neither. Only a sold-out round has roles. */
  function rolesOf(played: Played, plan: Plan = {}): Role[] {
    const result = resultOf(played, plan)
    return played.steps.map((step, i) => {
      if (result.outcome !== Outcome.SoldOut || step === null || played.counted[i] === 0) return 'other'
      return step > (result.step as number) ? 'above' : step === result.step ? 'marginal' : 'other'
    })
  }

  /**
   * Plays the whole settlement of a round the way the contract specifies it, checks every payment
   * against the SDK reference and the conservation of the tokens, and returns what each bidder got.
   */
  async function settle(played: Played, plan: Plan = {}): Promise<Allocation[]> {
    const { program, relayer, creator, actors } = fixture
    const { e3Id, sale, steps, counted } = played
    const result = resultOf(played, plan)
    const soldOut = result.outcome === Outcome.SoldOut
    const roles = rolesOf(played, plan)
    const escrow = escrowOf(sale)
    const n = steps.length
    const bidders = Array.from({ length: n }, (_, i) => i)
    const skipped = (role: Role, i: number) => roles[i] === role && (plan.skip?.[role] ?? []).includes(i)
    const before = await Promise.all(bidders.map((i) => balancesOf(actors[i])))
    const creatorBefore = await balancesOf(creator)

    await program.connect(relayer).clear(e3Id)
    const view = await program.clearing(e3Id)
    expect([Number(view.outcome), Number(view.step), view.pStar, Number(view.counted)]).to.deep.equal([
      result.outcome,
      result.step ?? 0,
      result.pStar,
      counted.filter((c) => c > 0).length,
    ])
    for (const i of bidders) {
      const [needed, k] = await program.claimRequirement(e3Id, actors[i].address)
      expect([needed, Number(k)], `claim requirement of bidder ${i}`).to.deep.equal(
        counted[i] > 0 && result.k !== null ? [true, result.k] : [false, 0],
      )
    }

    const claim = async (i: number) => program.connect(relayer).claim(e3Id, actors[i].address, await claimData(fixture, played, i))
    // Phase 1 (or any time, when the round is not sold out): the claims that do not wait for phase 2.
    const done = new Set<number>()
    for (const i of bidders) {
      if ((!soldOut || roles[i] === 'above') && !skipped(roles[i], i)) {
        await claim(i)
        done.add(i)
      }
    }
    const aboveClaimed = bidders.filter((i) => soldOut && roles[i] === 'above' && done.has(i)).length
    expect(Number((await program.clearing(e3Id)).aboveClaimed)).to.equal(aboveClaimed)

    // Phase 2: the marginal bidders register, in any order. After it, the settlement and the refunds.
    const registered: number[] = []
    if (soldOut) {
      await mineAt(fixture, view.phase1End + 1n)
      const order = plan.registerOrder ?? bidders.filter((i) => roles[i] === 'marginal').reverse()
      for (const i of order.filter((j) => roles[j] === 'marginal' && !skipped('marginal', j))) {
        await claim(i)
        registered.push(i)
      }
      expect(Number((await program.clearing(e3Id)).marginalRegistered)).to.equal(registered.length)
      await mineAt(fixture, view.phase2End + 1n)
      for (const i of [...registered].sort((a, b) => a - b)) {
        await program.connect(relayer).settleMarginal(e3Id, actors[i].address)
        done.add(i)
      }
      for (const i of bidders) {
        if (!done.has(i) && !skipped('other', i)) {
          await claim(i)
          done.add(i)
        }
      }
    }

    // What each bidder got, against the SDK reference.
    const got: Allocation[] = []
    for (const i of bidders) {
      let expected = ZERO
      if (done.has(i)) {
        const cmp = counted[i] > 0 && steps[i] !== null && result.k !== null ? compareBid(steps[i] as number, result.k) : null
        const cls = counted[i] > 0 ? claimClass(result, cmp) : 'refund'
        // A bidder that skipped its step gets the escrow back after the phase: a forfeit.
        const forfeit = (cls === 'full' && soldOut && skipped('above', i)) || (cls === 'marginal' && !registered.includes(i))
        expected = allocationOf(sale, result, forfeit ? 'refund' : cls, { aboveClaimed, rank: marginalRank(registered, i) })
      }
      const after = await balancesOf(actors[i])
      expect({ tokens: after.sale - before[i].sale, usdc: after.usdc - before[i].usdc }, `bidder ${i} (${roles[i]})`).to.deep.equal({
        tokens: expected.tokens,
        usdc: expected.refund,
      })
      expect(await program.claimed(e3Id, actors[i].address), `bidder ${i} claimed`).to.equal(done.has(i))
      if (expected.tokens > 0n) expect(expected.paid, 'the same price for every lot').to.equal(result.lotCost)
      got.push(expected)
    }
    const sold = got.reduce((sum, a) => sum + a.tokens, 0n)
    const paid = got.reduce((sum, a) => sum + a.paid, 0n)
    expect(sold <= supplyOf(sale), 'never sells more than the supply').to.equal(true)
    expect(sold % sale.lot, 'only whole lots').to.equal(0n)

    // The creator takes the payments, then the rest after the claim window.
    if (paid > 0n) {
      await expect(program.connect(creator).withdrawProceeds(e3Id))
        .to.emit(program, 'ProceedsWithdrawn')
        .withArgs(e3Id, creator.address, paid)
    } else {
      await expect(program.connect(creator).withdrawProceeds(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
    }
    const supplyTaken = Boolean(plan.withdrawSupply) && (result.outcome === Outcome.NotMet || result.outcome === Outcome.Aborted)
    if (supplyTaken) await program.connect(creator).withdrawSupply(e3Id)
    const unclaimedEscrows = BigInt(n - done.size) * escrow
    await mineAt(fixture, view.claimDeadline + 1n)
    await expect(program.connect(creator).sweep(e3Id))
      .to.emit(program, 'Swept')
      .withArgs(e3Id, creator.address, supplyTaken ? 0n : supplyOf(sale) - sold, unclaimedEscrows)
    expect(await program.swept(e3Id)).to.equal(true)

    // Conservation: the escrows and the supply are all accounted for.
    const creatorAfter = await balancesOf(creator)
    const refunds = got.reduce((sum, a) => sum + a.refund, 0n)
    expect(refunds + paid + unclaimedEscrows, 'payment tokens').to.equal(BigInt(n) * escrow)
    expect(creatorAfter.usdc - creatorBefore.usdc, 'creator payment tokens').to.equal(paid + unclaimedEscrows)
    expect(creatorAfter.sale - creatorBefore.sale, 'creator sale tokens').to.equal(supplyOf(sale) - sold)
    return got
  }

  describe('clear', () => {
    it('clears a round once, for anyone, and publishes the windows', async () => {
      const { program, relayer } = fixture
      const played = await play([3, 2, 2, 1])
      const { e3Id } = played
      expect((await program.clearing(e3Id)).cleared).to.equal(false)
      const tx = await program.connect(relayer).clear(e3Id)
      const block = BigInt((await fixture.ethers.provider.getBlock(tx.blockNumber as number))!.timestamp)
      const [phase1End, phase2End, claimDeadline] = [block + 2n * 86_400n, block + 4n * 86_400n, block + 30n * 86_400n]
      await expect(tx).to.emit(program, 'SaleCleared').withArgs(e3Id, Outcome.SoldOut, 2, PRICES[2], 4)
      await expect(tx).to.emit(program, 'ClaimWindowOpened').withArgs(e3Id, phase1End, phase2End, claimDeadline)
      const view = await program.clearing(e3Id)
      expect([view.cleared, view.phase1End, view.phase2End, view.claimDeadline, view.aboveClaimed, view.marginalRegistered]).to.deep.equal([
        true,
        phase1End,
        phase2End,
        claimDeadline,
        0n,
        0n,
      ])
      // A second call changes nothing and emits nothing.
      await expect(program.clear(e3Id)).not.to.emit(program, 'SaleCleared')
      expect((await program.clearing(e3Id)).phase1End).to.equal(phase1End)
    })

    it('reverts while the output is not published, and for a round that does not exist', async () => {
      const { program } = fixture
      const played = await play([3, 2], { noOutput: true })
      await expect(program.clear(played.e3Id)).to.be.revertedWithCustomError(program, 'OutputNotPublished')
      await expect(program.clear(999_999n)).to.be.revertedWithCustomError(program, 'E3DoesNotExist')
    })

    it('clears an output that breaks a rule of the output as ABORTED and does not revert', async () => {
      const { program } = fixture
      const params: RoundParams = { levels: 4, reserveStep: 0, lots: LOTS, minLots: 1 }
      const slots = outputSlotsFor(params, [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], Outcome.SoldOut, 2)
      slots[110] = 3n // an unused slot
      const played = await play([3, 2, 2, 1], { slots })
      await expect(program.clear(played.e3Id)).to.emit(program, 'SaleCleared').withArgs(played.e3Id, Outcome.Aborted, 0, 0, 4)
    })

    it('clears an output of the wrong length as ABORTED', async () => {
      const { program, interfold } = fixture
      const played = await play([3, 2], { noOutput: true })
      await (await interfold.setPlaintext(played.e3Id, '0x1234')).wait()
      await expect(program.clear(played.e3Id)).to.emit(program, 'SaleCleared').withArgs(played.e3Id, Outcome.Aborted, 0, 0, 0)
    })

    it('is called by the first claim', async () => {
      const { program, relayer } = fixture
      const played = await play([1, 0], { reserveStep: 0 })
      // Undersubscribed at reserve 0: no proof, and a claim clears the round.
      await expect(program.connect(relayer).claim(played.e3Id, fixture.actors[0].address, '0x'))
        .to.emit(program, 'SaleCleared')
        .withArgs(played.e3Id, Outcome.Undersubscribed, 0, PRICES[0], 2)
    })
  })

  describe('a sold-out round', () => {
    it('gives the lots left to the marginal bidders by index, whatever the order of their registrations', async () => {
      // Lots 3: above is the bidder 0, the marginal bidders are 1, 2 and 3, and R = 2.
      const orders = [
        [1, 2, 3],
        [3, 2, 1],
        [2, 3, 1],
      ]
      for (const registerOrder of orders) {
        const played = await play([3, 2, 2, 2, 1])
        const got = await settle(played, { registerOrder })
        expect(
          got.map((a) => a.tokens),
          registerOrder.join(),
        ).to.deep.equal([LOT, LOT, LOT, 0n, 0n])
        expect(got.map((a) => a.paid)).to.deep.equal([30n, 30n, 30n, 0n, 0n].map((x) => x * 1_000_000n))
        expect(got[3].refund, 'the third marginal bidder gets the whole escrow').to.equal(ESCROW)
      }
    })

    it('pays a whole lot or nothing, never a part', async () => {
      const played = await play([2, 2, 2, 2, 2, 1])
      const got = await settle(played)
      for (const a of got) expect(a.tokens === 0n || a.tokens === LOT).to.equal(true)
      expect(got.filter((a) => a.tokens === LOT)).to.have.length(LOTS)
      expect(got.slice(0, 3).map((a) => a.tokens)).to.deep.equal([LOT, LOT, LOT])
    })

    it('gives the lot of an above bidder that did not claim to the marginal bidders', async () => {
      // Above: 0 and 1. R = 1 when both claim, 2 when the bidder 0 forfeits.
      const claimedBoth = await settle(await play([3, 3, 2, 2, 2, 1]))
      expect(claimedBoth.map((a) => a.tokens)).to.deep.equal([LOT, LOT, LOT, 0n, 0n, 0n])
      const forfeited = await settle(await play([3, 3, 2, 2, 2, 1]), { skip: { above: [0] } })
      expect(forfeited.map((a) => a.tokens)).to.deep.equal([0n, LOT, LOT, LOT, 0n, 0n])
      expect(forfeited[0].refund).to.equal(ESCROW)
    })

    it('lets the next marginal bidder in when one does not register', async () => {
      const got = await settle(await play([3, 2, 2, 2, 1]), { skip: { marginal: [1] } })
      expect(got.map((a) => a.tokens)).to.deep.equal([LOT, 0n, LOT, LOT, 0n])
    })

    it('sells to one marginal bidder when all the bidders are at the clearing step and one lot is for sale', async () => {
      const options = { lots: 1, minLots: 1 }
      const all = await settle(await play([2, 2, 2], options))
      expect(all.map((a) => a.tokens)).to.deep.equal([LOT, 0n, 0n])
      const second = await settle(await play([2, 2, 2], options), { skip: { marginal: [0] } })
      expect(second.map((a) => a.tokens)).to.deep.equal([0n, LOT, 0n])
      // Nobody registers: nothing sells, and the creator gets the lot back with the sweep.
      const none = await settle(await play([2, 2], options), { skip: { marginal: [0, 1] } })
      expect(none.map((a) => a.tokens)).to.deep.equal([0n, 0n])
    })

    it('counts a bidder that is not counted as nothing', async () => {
      // The bidder 3 bid, but its counted version is 0: it is not part of the output.
      const played = await play([3, 3, 3, 3], { counted: [1, 1, 1, 0] })
      const got = await settle(played)
      expect(got.map((a) => a.tokens)).to.deep.equal([LOT, LOT, LOT, 0n])
      expect(got[3].refund).to.equal(ESCROW)
    })

    it('pays the counted version of a bidder that updated its bid', async () => {
      // The bidder 0 bid three times and the committee counted the second bid.
      const played = await play([3, 2, 1], { counted: [2, 1, 1], bidsOf: [3, 1, 1], lots: 2, minLots: 1 })
      const got = await settle(played)
      expect(got.map((a) => a.tokens)).to.deep.equal([LOT, LOT, 0n])
    })

    it('clears at the top step with the reserve there', async () => {
      const got = await settle(await play([3, 3, 3, 0], { reserveStep: 3, minLots: 2, lots: 2 }))
      // Lots 2: above none, three marginal bidders at the step 3, R = 2.
      expect(got.map((a) => a.tokens)).to.deep.equal([LOT, LOT, 0n, 0n])
      expect(got[0].paid).to.equal(40_000_000n)
    })
  })

  describe('an undersubscribed round', () => {
    it('gives every counted bidder a lot at the reserve price without a proof, when the reserve is the first step', async () => {
      const { program, actors } = fixture
      const played = await play([1, 0], { counted: [1, 1] })
      await program.clear(played.e3Id)
      expect(await program.claimRequirement(played.e3Id, actors[0].address)).to.deep.equal([false, 0n])
      const got = await settle(played)
      expect(got.map((a) => a.tokens)).to.deep.equal([LOT, LOT])
      expect(got.map((a) => a.paid)).to.deep.equal([10_000_000n, 10_000_000n])
    })

    it('needs a proof at the step before the reserve, and pays the bidders at or above the reserve', async () => {
      const { program, actors } = fixture
      const played = await play([3, 2, 1, 0], { reserveStep: 2, minLots: 1 })
      await program.clear(played.e3Id)
      expect(played.outcome).to.equal(Outcome.Undersubscribed)
      expect(await program.claimRequirement(played.e3Id, actors[0].address)).to.deep.equal([true, 1n])
      const got = await settle(played)
      expect(got.map((a) => a.tokens)).to.deep.equal([LOT, LOT, 0n, 0n])
      expect(got[0].paid).to.equal(30_000_000n)
    })

    it('does not register anybody and has no phases', async () => {
      const { program } = fixture
      const played = await play([3, 2], { reserveStep: 1, minLots: 1 })
      await settle(played)
      const view = await program.clearing(played.e3Id)
      expect([view.aboveClaimed, view.marginalRegistered]).to.deep.equal([0n, 0n])
    })
  })

  describe('a round that sells nothing', () => {
    it('gives every bidder the escrow back when the reserve is not met, and the supply back to the creator', async () => {
      const played = await play([3, 3], { minLots: 3 })
      expect(played.outcome).to.equal(Outcome.NotMet)
      const got = await settle(played, { withdrawSupply: true })
      expect(got.map((a) => a.refund)).to.deep.equal([ESCROW, ESCROW])
    })

    it('gives every bidder the escrow back when the output is aborted', async () => {
      const params: RoundParams = { levels: 4, reserveStep: 0, lots: LOTS, minLots: 1 }
      const slots = outputSlotsFor(params, [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], Outcome.SoldOut, 1)
      slots[115 + 5] = 1n // the bidder 5 is not a bidder of the round
      const played = await play([3, 1, 1], { slots })
      const got = await settle(played, { outcome: Outcome.Aborted, step: null, withdrawSupply: true })
      expect(got.map((a) => a.refund)).to.deep.equal([ESCROW, ESCROW, ESCROW])
    })

    it('refunds depositors when nobody bid: the output has no counted bidder and is aborted', async () => {
      const { program, actors, relayer } = fixture
      const played = await play([null, null], { minLots: 1 })
      await expect(program.connect(relayer).claim(played.e3Id, actors[0].address, '0x'))
        .to.emit(program, 'Claimed')
        .withArgs(played.e3Id, actors[0].address, 0, 0, ESCROW)
      expect((await program.clearing(played.e3Id)).outcome).to.equal(Outcome.Aborted)
    })
  })

  describe('claim', () => {
    it('reverts on a second claim, for an address that did not deposit, and for a round that does not exist', async () => {
      const { program, relayer, actors } = fixture
      const played = await play([3, 2, 2, 2])
      await program.clear(played.e3Id)
      const { e3Id } = played
      const data = await claimData(fixture, played, 0)
      await program.connect(relayer).claim(e3Id, actors[0].address, data)
      await expect(program.connect(relayer).claim(e3Id, actors[0].address, data))
        .to.be.revertedWithCustomError(program, 'AlreadyClaimed')
        .withArgs(actors[0].address)
      await expect(program.claim(e3Id, actors[10].address, '0x'))
        .to.be.revertedWithCustomError(program, 'NotDeposited')
        .withArgs(actors[10].address)
      await expect(program.claim(e3Id + 1000n, actors[0].address, '0x')).to.be.revertedWithCustomError(program, 'E3DoesNotExist')
    })

    it('reverts with a proof that the verifier rejects, and with a comparison above 2', async () => {
      const { program, relayer, actors } = fixture
      const played = await play([3, 2, 2])
      const { e3Id } = played
      const encoded = (cmp: number, proof: Hex) => encodeClaimData(cmp as 0 | 1 | 2, proof)
      await expect(program.connect(relayer).claim(e3Id, actors[0].address, encoded(2, '0x02'))).to.be.revertedWithCustomError(
        fixture.claimVerifier,
        'ProofRejected',
      )
      await expect(program.connect(relayer).claim(e3Id, actors[0].address, encoded(3, '0x01')))
        .to.be.revertedWithCustomError(program, 'InvalidComparison')
        .withArgs(3)
      await expect(program.connect(relayer).claim(e3Id, actors[0].address, '0x')).to.be.revert(fixture.ethers)
    })

    it('sends the funds to the bidder, whoever calls', async () => {
      const { program, relayer, actors, saleToken } = fixture
      const played = await play([3, 2, 2, 2])
      await program.clear(played.e3Id)
      const before = await saleToken.balanceOf(actors[0].address)
      const relayerBefore = await saleToken.balanceOf(relayer.address)
      await program.connect(relayer).claim(played.e3Id, actors[0].address, await claimData(fixture, played, 0))
      expect(await saleToken.balanceOf(actors[0].address)).to.equal(before + LOT)
      expect(await saleToken.balanceOf(relayer.address)).to.equal(relayerBefore)
    })

    it('emits the payment of a full claim', async () => {
      const { program, relayer, actors } = fixture
      const played = await play([3, 2, 2, 2])
      await program.clear(played.e3Id)
      await expect(program.connect(relayer).claim(played.e3Id, actors[0].address, await claimData(fixture, played, 0)))
        .to.emit(program, 'Claimed')
        .withArgs(played.e3Id, actors[0].address, LOT, 30_000_000n, ESCROW - 30_000_000n)
    })
  })

  describe('the phases of a sold-out round', () => {
    it('has a first phase for the bidders above, a second one for the marginal bidders, and then the settlement', async () => {
      const { program, relayer, actors, creator } = fixture
      // Lots 3. Above: 0 and 1. Marginal: 2, 3 and 4. Below: 5. The bidder 1 forfeits, so R = 2.
      const played = await play([3, 3, 2, 2, 2, 1])
      const { e3Id } = played
      await program.clear(e3Id)
      const w = await program.clearing(e3Id)
      const claim = async (i: number) => program.connect(relayer).claim(e3Id, actors[i].address, await claimData(fixture, played, i))

      // Phase 1: a marginal bidder cannot register yet. The last second still belongs to phase 1.
      await setNext(w.phase1End)
      await expect(claim(2)).to.be.revertedWithCustomError(program, 'MarginalPhaseNotOpen').withArgs(w.phase1End)
      await setNext(w.phase1End)
      await expect(claim(0))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, actors[0].address, LOT, 30_000_000n, ESCROW - 30_000_000n)
      // After phase 1, an above bidder gets the escrow back and its lot goes to the marginal bidders.
      await setNext(w.phase1End + 1n)
      await expect(claim(1)).to.emit(program, 'Claimed').withArgs(e3Id, actors[1].address, 0, 0, ESCROW)
      // Phase 2: the registration.
      await setNext(w.phase1End + 2n)
      await expect(claim(3)).to.emit(program, 'MarginalRegistered').withArgs(e3Id, actors[3].address)
      await expect(claim(3)).to.be.revertedWithCustomError(program, 'AlreadyRegistered').withArgs(actors[3].address)
      expect(await program.marginalMask(e3Id)).to.equal(0b1000)
      // The settlement waits for the end of phase 2. The last second still belongs to phase 2.
      await setNext(w.phase2End)
      await expect(program.settleMarginal(e3Id, actors[3].address))
        .to.be.revertedWithCustomError(program, 'SettlementNotOpen')
        .withArgs(w.phase2End)
      await setNext(w.phase2End)
      await expect(claim(2)).to.emit(program, 'MarginalRegistered').withArgs(e3Id, actors[2].address)
      expect(await program.marginalMask(e3Id)).to.equal(0b1100)
      // A marginal bidder that did not register gets the escrow back from the first second after phase 2.
      await setNext(w.phase2End + 1n)
      await expect(claim(4)).to.emit(program, 'Claimed').withArgs(e3Id, actors[4].address, 0, 0, ESCROW)
      await expect(program.settleMarginal(e3Id, actors[5].address))
        .to.be.revertedWithCustomError(program, 'NotRegistered')
        .withArgs(actors[5].address)
      // The bidder 2 has the lowest index of the two registered bidders: it gets a lot.
      await expect(program.settleMarginal(e3Id, actors[2].address))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, actors[2].address, LOT, 30_000_000n, ESCROW - 30_000_000n)
      // The last second of the claim window is still open.
      await expect(program.connect(creator).sweep(e3Id)).to.be.revertedWithCustomError(program, 'ClaimWindowOpen').withArgs(w.claimDeadline)
      await setNext(w.claimDeadline)
      await expect(program.settleMarginal(e3Id, actors[3].address))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, actors[3].address, LOT, 30_000_000n, ESCROW - 30_000_000n)
      await setNext(w.claimDeadline + 1n)
      await expect(claim(5)).to.be.revertedWithCustomError(program, 'ClaimWindowClosed').withArgs(w.claimDeadline)
      await expect(program.settleMarginal(e3Id, actors[3].address)).to.be.revertedWithCustomError(program, 'AlreadyClaimed')
      // The sweep: 3 lots were sold, the bidder 5 never claimed: its escrow and the payments go to the creator.
      await expect(program.connect(creator).sweep(e3Id))
        .to.emit(program, 'Swept')
        .withArgs(e3Id, creator.address, 0, ESCROW + 3n * 30_000_000n)
    })

    it('reverts a settlement before the clearing and for a bidder that did not register', async () => {
      const { program, actors } = fixture
      const played = await play([3, 2, 2])
      await expect(program.settleMarginal(played.e3Id, actors[1].address)).to.be.revertedWithCustomError(program, 'NotCleared')
      await program.clear(played.e3Id)
      await expect(program.settleMarginal(played.e3Id, actors[15].address)).to.be.revertedWithCustomError(program, 'NotRegistered')
    })

    it('previews the claim with the timing of the phases and the registrations so far', async () => {
      const { program, relayer, actors } = fixture
      const played = await play([3, 2, 2, 2, 1])
      const { e3Id } = played
      await program.clear(e3Id)
      const w = await program.clearing(e3Id)
      const preview = async (i: number, cmp: number) => {
        const [cls, tokens, paid, refund] = await program.previewClaim(e3Id, actors[i].address, cmp)
        return [Number(cls), tokens, paid, refund]
      }
      const refund = [0, 0n, 0n, ESCROW]
      const full = [1, LOT, 30_000_000n, ESCROW - 30_000_000n]
      // Phase 1: above bidders get the lot, the marginal bidders are provisional (nobody registered: all would fill).
      expect(await preview(0, 2)).to.deep.equal(full)
      expect(await preview(1, 1)).to.deep.equal([2, LOT, 30_000_000n, ESCROW - 30_000_000n])
      expect(await preview(4, 0)).to.deep.equal(refund)
      await mineAt(fixture, w.phase1End + 1n)
      expect(await preview(0, 2), 'an above bidder after phase 1').to.deep.equal(refund)
      // Register 1 and 2. The bidder 0 did not claim, so R = 3 and the bidder 3 would still get a lot.
      for (const i of [1, 2]) {
        await program.connect(relayer).claim(e3Id, actors[i].address, await claimData(fixture, played, i))
      }
      expect((await program.clearing(e3Id)).marginalRegistered).to.equal(2n)
      expect(await preview(1, 1)).to.deep.equal([2, LOT, 30_000_000n, ESCROW - 30_000_000n])
      // R = 3 (the bidder 0 forfeits), so the third marginal bidder would still fill.
      expect((await preview(3, 1))[1]).to.equal(LOT)
      await mineAt(fixture, w.phase2End + 1n)
      expect(await preview(3, 1), 'a marginal bidder that did not register').to.deep.equal(refund)
      expect((await preview(1, 1))[0], 'a registered bidder after phase 2').to.equal(2)
      await expect(program.previewClaim(e3Id, actors[1].address, 3)).to.be.revertedWithCustomError(program, 'InvalidComparison')
      await expect(program.previewClaim(e3Id, actors[14].address, 0)).to.be.revertedWithCustomError(program, 'NotDeposited')
    })

    it('ranks an unregistered marginal bidder behind the registered ones with a lower index', async () => {
      const { program, relayer, actors } = fixture
      // Lots 3, above: 0. Marginal: 1, 2, 3. R = 2 once the bidder 0 claimed.
      const played = await play([3, 2, 2, 2, 1])
      const { e3Id } = played
      await program.clear(e3Id)
      const w = await program.clearing(e3Id)
      await program.connect(relayer).claim(e3Id, actors[0].address, await claimData(fixture, played, 0))
      await mineAt(fixture, w.phase1End + 1n)
      for (const i of [2, 1]) await program.connect(relayer).claim(e3Id, actors[i].address, await claimData(fixture, played, i))
      // R = 2, and 1 and 2 are registered below the index 3: the bidder 3 would get nothing.
      const [cls, tokens, paid, refund] = await program.previewClaim(e3Id, actors[3].address, 1)
      expect([Number(cls), tokens, paid, refund]).to.deep.equal([2, 0n, 0n, ESCROW])
      expect(await program.marginalMask(e3Id)).to.equal(0b110)
    })
  })

  describe('the creator', () => {
    it('takes the payments of the claims so far, and nothing twice', async () => {
      const { program, relayer, actors, creator, usdc } = fixture
      const played = await play([3, 2, 2, 2])
      await program.clear(played.e3Id)
      const { e3Id } = played
      await expect(program.connect(creator).withdrawProceeds(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      await program.connect(relayer).claim(e3Id, actors[0].address, await claimData(fixture, played, 0))
      await expect(program.connect(actors[0]).withdrawProceeds(e3Id))
        .to.be.revertedWithCustomError(program, 'NotCreator')
        .withArgs(actors[0].address)
      const before = await usdc.balanceOf(creator.address)
      await expect(program.connect(creator).withdrawProceeds(e3Id))
        .to.emit(program, 'ProceedsWithdrawn')
        .withArgs(e3Id, creator.address, 30_000_000n)
      expect((await usdc.balanceOf(creator.address)) - before).to.equal(30_000_000n)
      await expect(program.connect(creator).withdrawProceeds(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      // The sweep gives the creator the rest, but not the payment that it took: 2 lots and 3 escrows.
      await mineAt(fixture, (await program.clearing(e3Id)).claimDeadline + 1n)
      await expect(program.connect(creator).sweep(e3Id))
        .to.emit(program, 'Swept')
        .withArgs(e3Id, creator.address, 2n * LOT, 3n * ESCROW)
      await expect(program.connect(creator).sweep(e3Id)).to.be.revertedWithCustomError(program, 'AlreadySwept')
    })

    it('takes the supply back only when nothing sells, and only once', async () => {
      const { program, creator, actors, saleToken } = fixture
      const sold = await play([3, 3, 3])
      await expect(program.connect(creator).withdrawSupply(sold.e3Id))
        .to.be.revertedWithCustomError(program, 'SupplyNotWithdrawable')
        .withArgs(Outcome.SoldOut)
      const under = await play([1], { reserveStep: 0 })
      await expect(program.connect(creator).withdrawSupply(under.e3Id))
        .to.be.revertedWithCustomError(program, 'SupplyNotWithdrawable')
        .withArgs(Outcome.Undersubscribed)

      const notMet = await play([3], { minLots: 2 })
      await expect(program.connect(actors[0]).withdrawSupply(notMet.e3Id)).to.be.revertedWithCustomError(program, 'NotCreator')
      const before = await saleToken.balanceOf(creator.address)
      // `withdrawSupply` clears the round when nobody did.
      await expect(program.connect(creator).withdrawSupply(notMet.e3Id))
        .to.emit(program, 'SupplyWithdrawn')
        .withArgs(notMet.e3Id, creator.address, LOT * BigInt(LOTS))
      expect((await saleToken.balanceOf(creator.address)) - before).to.equal(LOT * BigInt(LOTS))
      expect(await program.supplyReturned(notMet.e3Id)).to.equal(true)
      await expect(program.connect(creator).withdrawSupply(notMet.e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      // The sweep does not send the supply a second time.
      await program.clear(notMet.e3Id)
      await mineAt(fixture, (await program.clearing(notMet.e3Id)).claimDeadline + 1n)
      await expect(program.connect(creator).sweep(notMet.e3Id)).to.emit(program, 'Swept').withArgs(notMet.e3Id, creator.address, 0, ESCROW)
    })

    it('sweeps only after the output, and only after the claim window', async () => {
      const { program, creator } = fixture
      const played = await play([3, 3, 3])
      await expect(program.connect(creator).sweep(played.e3Id)).to.be.revertedWithCustomError(program, 'NotCleared')
      await program.clear(played.e3Id)
      const { claimDeadline } = await program.clearing(played.e3Id)
      await setNext(claimDeadline)
      await expect(program.connect(creator).sweep(played.e3Id))
        .to.be.revertedWithCustomError(program, 'ClaimWindowOpen')
        .withArgs(claimDeadline)
      await setNext(claimDeadline + 1n)
      await expect(program.connect(creator).sweep(played.e3Id))
        .to.emit(program, 'Swept')
        .withArgs(played.e3Id, creator.address, LOT * 3n, 3n * ESCROW)
    })
  })

  describe('two rounds at once', () => {
    it('keeps the money of each round apart', async () => {
      const { program, saleToken, usdc, programAddress } = fixture
      const baseline = { sale: await saleToken.balanceOf(programAddress), usdc: await usdc.balanceOf(programAddress) }
      const first = await play([3, 2, 2, 2, 1])
      const second = await play([2, 2], { lots: 1, minLots: 1 })
      const third = await play([3], { minLots: 2 })
      expect((await saleToken.balanceOf(programAddress)) - baseline.sale).to.equal(LOT * 3n + LOT + LOT * 3n)
      // The rounds settle in the opposite order.
      await settle(third, { withdrawSupply: true })
      await settle(second)
      await settle(first)
      expect(await saleToken.balanceOf(programAddress)).to.equal(baseline.sale)
      expect(await usdc.balanceOf(programAddress)).to.equal(baseline.usdc)
      expect((await program.clearing(first.e3Id)).step).to.equal(2)
    })
  })

  describe('random rounds against the SDK reference', () => {
    it('settles 40 random rounds with the invariants of the round', async () => {
      const random = rng(31415)
      for (let round = 0; round < 40; round++) {
        const n = random.int(1, 8)
        const lots = random.int(1, 4)
        const reserveStep = random.int(0, 2)
        const options: PlayOptions = { lots, minLots: random.int(1, lots), reserveStep }
        const steps = Array.from({ length: n }, () => (random.int(0, 9) === 0 ? null : random.int(0, 3)))
        const bidsOf = steps.map((step) => (step === null ? 0 : random.int(1, 3)))
        const counted = bidsOf.map((bids) => random.int(0, bids))
        const played = await play(steps, { ...options, bidsOf, counted })
        const roles = rolesOf(played)
        const pick = (role: Role) => roles.flatMap((r, i) => (r === role && random.int(0, 3) === 0 ? [i] : []))
        const skip = { above: pick('above'), marginal: pick('marginal'), other: pick('other') }
        const registerOrder = Array.from({ length: n }, (_, i) => i).sort(() => random.int(0, 2) - 1)
        // With no counted bidder the output is not a valid output of the program: the round aborts.
        const empty = counted.every((c) => c === 0) ? { outcome: Outcome.Aborted, step: null } : {}
        const got = await settle(played, { skip, registerOrder, ...empty })
        const sold = got.filter((a) => a.tokens > 0n).length
        expect(sold, `round ${round}: ${JSON.stringify({ steps, counted, options })}`).to.be.at.most(lots)
      }
    })
  })

  describe('gas', () => {
    it('clears the largest round: 13 bidders with 3 bids each and 16 steps', async function () {
      this.timeout(0)
      const { program, relayer } = fixture
      const prices = Array.from({ length: 16 }, (_, l) => BigInt(1_000_000 + l * 100_000))
      const steps = [15, 15, 14, 14, 13, 12, 12, 11, 10, 9, 8, 7, 6]
      const played = await play(steps, {
        prices,
        lots: 12,
        minLots: 1,
        reserveStep: 0,
        bidsOf: steps.map(() => 3),
        counted: steps.map((_, i) => 1 + (i % 3)),
      })
      const tx = await program.connect(relayer).clear(played.e3Id)
      const gas = (await tx.wait())!.gasUsed
      console.log(`      clear() of 13 bidders, 39 bids, 16 steps, sold out: ${gas} gas`)
      expect(gas < 5_000_000n, 'clear fits a block with room to spare').to.equal(true)
      expect((await program.clearing(played.e3Id)).outcome).to.equal(played.outcome)
    })
  })
})
