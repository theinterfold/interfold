// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { type Hex, encodeAbiParameters, parseAbiParameters, toHex } from 'viem'
import { type ClaimAmounts, marginalFills } from '../sdk/src/clearing'
import { coefficientsToPlaintext, slotsToCoefficients } from '../sdk/src/layout'
import { ClaimTree } from '../sdk/src/merkle'
import { searchRound1 } from '../sdk/src/probes'
import { encodeBidInput, encodeClaimData, encodeLinkParams } from '../sdk/src/sale'
import { simulateSale } from '../sdk/src/simulate'
import {
  type BidSpec,
  type Fixture,
  FAR,
  KEY1,
  KEY2,
  KIND_CAPPED,
  KIND_UNCAPPED,
  KIND_UNDERSUBSCRIBED,
  USDC,
  VK_ANCHOR,
  type TestSale,
  bidData,
  claim,
  claimData,
  clearSale,
  closeInputs,
  createSale,
  decryptRound1,
  decryptRound2,
  deployFixture,
  nextWord,
  placeBid,
  placeBids,
  publishProbes,
  readClearing,
  type RawSale,
  rawSaleRequest,
  saleRequest,
} from './fixture'

const PHASE = { None: 0, Bidding: 1, Round1: 2, Probing: 3, Round2: 4, Clearable: 5, Cleared: 6, Aborted: 7, Failed: 8 } as const
const ABORT = { None: 0, NoRoundTwo: 1, InvalidRound1Output: 2, InvalidRound2Output: 3, CountedSetMismatch: 4 } as const
const DAY = 24 * 3600

/** Capped at step 5 (6 USDC): the step-7 bid buys 50 tokens of 100; 4 bids of 100 USDC share the other half. */
const CAPPED: BidSpec[] = [{ step: 7, budget: 400 }, ...Array.from({ length: 4 }, () => ({ step: 5, budget: 100 }))]
/** Uncapped: 150 USDC of demand clear at 1.50 USDC per token. */
const UNCAPPED: BidSpec[] = [
  { step: 3, budget: 50 },
  { step: 3, budget: 50 },
  { step: 3, budget: 50 },
]
/** Thin: 30 USDC of demand at the floor price, so 70 tokens stay unsold. */
const THIN: BidSpec[] = Array.from({ length: 3 }, () => ({ step: 3, budget: 10 }))
/** Undersubscribed: 10 USDC of demand at the floor price of 1 USDC. */
const UNDERSUBSCRIBED: BidSpec[] = [{ step: 4, budget: 10 }]

const balance = async (token: Fixture['usdc'] | Fixture['saleToken'], holder: string) => token.balanceOf(holder)

/** A plaintext with chosen slot values (slot index to value), as a decryption could produce for a bad output. */
function rawPlaintext(slots: Record<number, number>): Hex {
  const values = new Array<number>(128).fill(0)
  for (const [slot, value] of Object.entries(slots)) values[Number(slot)] = value
  return coefficientsToPlaintext(slotsToCoefficients(values))
}

async function saleWith(f: Fixture, specs: BidSpec[]): Promise<TestSale> {
  const sale = await createSale(f)
  await placeBids(f, sale, specs)
  return sale
}

describe('TokenLaunchProgram', () => {
  let f: Fixture
  beforeEach(async () => {
    f = await deployFixture()
  })

  describe('requests', () => {
    it('creates a sale: stores it, pulls the supply, and starts the input trees', async () => {
      const sale = await createSale(f)
      const info = await f.program.getSale(sale.saleId)
      expect(info.creator).to.equal(f.creator.address)
      expect(info.levels).to.equal(8)
      expect(info.supply).to.equal(sale.grid.supply)
      expect(info.budgetUnit).to.equal(USDC)
      expect(info.saleUnit).to.equal(10n ** 18n)
      expect(info.title).to.equal('Demo sale')
      expect(await f.program.salePrices(sale.saleId)).to.deep.equal([...sale.grid.prices, ...Array(8).fill(0n)])
      expect(await f.program.saleTiers(sale.saleId)).to.deep.equal([10n, 100n, 1000n, 0n])
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(sale.grid.supply)
      expect(await f.program.roundTwo(sale.saleId)).to.equal(sale.round2Id)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Bidding)
      expect(await f.program.phase(sale.round2Id)).to.equal(PHASE.None)
      // Input 0 of each tree is the configuration.
      expect((await f.program.inputs(sale.saleId)).numberOfLeaves).to.equal(1n)
      expect((await f.program.inputs(sale.round2Id)).numberOfLeaves).to.equal(1n)
    })

    it('emits SaleCreated and RoundTwoLinked', async () => {
      const saleId = 9n
      await f.saleToken.mint(f.creator.address, 100n * 10n ** 18n)
      await f.saleToken.approve(f.programAddress, 100n * 10n ** 18n)
      await f.interfold.setE3(saleId, FAR, KEY1, f.creator.address)
      await f.interfold.setE3(saleId + 1n, FAR, KEY2, f.creator.address)
      const params = await saleRequest(f)
      await expect(f.interfold.request(saleId, f.programAddress, params)).to.emit(f.program, 'SaleCreated')
      await expect(f.interfold.request(saleId + 1n, f.programAddress, encodeLinkParams(saleId)))
        .to.emit(f.program, 'RoundTwoLinked')
        .withArgs(saleId, saleId + 1n)
    })

    it('refuses what a sale cannot be', async () => {
      let next = 20n
      const refuse = async (body: Partial<RawSale>, error: string) => {
        const saleId = next++
        await f.interfold.setE3(saleId, FAR, KEY1, f.creator.address)
        await f.saleToken.mint(f.creator.address, 100n * 10n ** 18n)
        await f.saleToken.approve(f.programAddress, 100n * 10n ** 18n)
        await expect(f.interfold.request(saleId, f.programAddress, await rawSaleRequest(f, body)), error).to.be.revertedWithCustomError(
          f.errors,
          error,
        )
      }
      const prices = (count: number, step = 1n) => [
        ...Array.from({ length: count }, (_, l) => BigInt(l + 1) * step),
        ...Array(16 - count).fill(0n),
      ]
      await refuse({ levels: 7, prices: prices(7) }, 'InvalidLevels')
      await refuse({ levels: 17 }, 'InvalidLevels')
      await refuse({ prices: [0n, ...prices(8).slice(1)] }, 'InvalidPrices')
      await refuse({ prices: [1n, 2n, 2n, 4n, 5n, 6n, 7n, 8n, ...Array(8).fill(0n)] }, 'InvalidPrices')
      await refuse({ prices: prices(9) }, 'InvalidPrices')
      await refuse({ supply: 0n }, 'InvalidAmount')
      await refuse({ budgetUnit: 0n }, 'InvalidAmount')
      await refuse({ supply: 2n ** 112n + 1n }, 'InvalidAmount')
      await refuse({ tiers: [100, 10, 0, 0] }, 'InvalidTiers')
      await refuse({ tiers: [10, 10, 0, 0] }, 'InvalidTiers')
      await refuse({ tiers: [4096, 0, 0, 0] }, 'InvalidTiers')
      await refuse({ tiers: [10, 0, 20, 0] }, 'InvalidTiers')
      await refuse({ tiers: [0, 0, 0, 0] }, 'InvalidTiers')
      await refuse({ title: '' }, 'InvalidTitle')
      await refuse({ title: 'x'.repeat(81) }, 'InvalidTitle')
      await refuse({ saleToken: f.actors[0].address as Hex }, 'InvalidToken')
      await refuse({ paymentToken: f.actors[0].address as Hex }, 'InvalidToken')
      await refuse({ paymentToken: (await f.saleToken.getAddress()) as Hex }, 'InvalidToken')
    })

    it('refuses callers, replays, roles, and a sale without approval', async () => {
      await f.interfold.setE3(5n, FAR, KEY1, f.creator.address)
      const params = await saleRequest(f)
      await expect(f.program.connect(f.actors[0]).validate(5n, 0n, '0x', '0x', params)).to.be.revertedWithCustomError(
        f.errors,
        'CallerNotAuthorized',
      )
      await expect(
        f.interfold.request(5n, f.programAddress, encodeAbiParameters(parseAbiParameters('uint8, bytes'), [3, '0x'])),
      ).to.be.revertedWithCustomError(f.errors, 'InvalidRole')
      // No sale-token approval: the supply cannot be pulled.
      await expect(f.interfold.request(5n, f.programAddress, params)).to.be.revert(f.ethers)
      await f.saleToken.mint(f.creator.address, 100n * 10n ** 18n)
      await f.saleToken.approve(f.programAddress, 100n * 10n ** 18n)
      await f.interfold.request(5n, f.programAddress, params)
      await expect(f.interfold.request(5n, f.programAddress, params)).to.be.revertedWithCustomError(f.errors, 'E3AlreadyInitialized')
    })

    it('links a round 2 only for a sale, once, with the same requester, window and committee', async () => {
      const sale = await createSale(f, { noRoundTwo: true })
      const link = encodeLinkParams(sale.saleId)
      await f.interfold.setE3(sale.round2Id, FAR, KEY2, f.actors[0].address)
      await expect(f.interfold.request(sale.round2Id, f.programAddress, link)).to.be.revertedWithCustomError(f.errors, 'RoundTwoMismatch')
      await f.interfold.setE3(sale.round2Id, FAR + 1n, KEY2, f.creator.address)
      await expect(f.interfold.request(sale.round2Id, f.programAddress, link)).to.be.revertedWithCustomError(f.errors, 'RoundTwoMismatch')
      await f.interfold.setE3(sale.round2Id, FAR, KEY2, f.creator.address)
      await f.interfold.setCommitteeSize(sale.round2Id, 1)
      await expect(f.interfold.request(sale.round2Id, f.programAddress, link)).to.be.revertedWithCustomError(f.errors, 'RoundTwoMismatch')
      await f.interfold.setCommitteeSize(sale.round2Id, 0)
      await expect(f.interfold.request(sale.round2Id, f.programAddress, encodeLinkParams(999n))).to.be.revertedWithCustomError(
        f.errors,
        'InvalidRoundTwo',
      )
      await f.interfold.request(sale.round2Id, f.programAddress, link)
      await f.interfold.setE3(sale.round2Id + 1n, FAR, KEY2, f.creator.address)
      await expect(f.interfold.request(sale.round2Id + 1n, f.programAddress, link)).to.be.revertedWithCustomError(
        f.errors,
        'RoundTwoAlreadyLinked',
      )
    })
  })

  describe('bids', () => {
    it('stores a relayed bid with a permit and escrows the tier', async () => {
      const sale = await createSale(f)
      const { bid } = await placeBid(f, sale, { step: 4, budget: 40 })
      expect(bid.tier).to.equal(1)
      expect(await f.program.bidCount(sale.saleId)).to.equal(1n)
      expect(await f.program.bidderAt(sale.saleId, 0)).to.equal(bid.bidder)
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(100n * USDC)
      expect(await f.usdc.balanceOf(bid.bidder)).to.equal(0n)
      expect((await f.program.inputs(sale.saleId)).numberOfLeaves).to.equal(2n)
      expect((await f.program.inputs(sale.round2Id)).numberOfLeaves).to.equal(2n)
      const info = await f.program.bidInfo(sale.saleId, 0)
      expect(info[0]).to.equal(bid.bidder)
      expect(info[1]).to.equal(1n)
      expect(info[2]).to.equal(bid.bidCommitment)
    })

    it('stores a direct bid, with no signature and an approval', async () => {
      const sale = await createSale(f)
      const { bid } = await placeBid(f, sale, { step: 1, budget: 5, direct: f.actors[0] })
      expect(bid.bidder).to.equal(f.actors[0].address)
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(10n * USDC)
    })

    it('passes the 11 public inputs of the pair proof, in order', async () => {
      const sale = await createSale(f)
      const bidder = f.ethers.Wallet.createRandom()
      await f.usdc.mint(bidder.address, 100n * USDC)
      const input = await bidData(f, sale, bidder, 1, true)
      const word = (value: bigint | number | string) => toHex(BigInt(value), { size: 32 })
      const expected = [
        input.ctCommitment1,
        input.ctCommitment2,
        input.bidCommitment,
        word(bidder.address),
        word(sale.saleId),
        word(8),
        word(0),
        word(100),
        KEY1,
        KEY2,
        VK_ANCHOR,
      ]
      await f.bidVerifier.expect(expected)
      await f.program.publishInput(sale.saleId, encodeBidInput(input))
      // Another index fails the same pin.
      const second = f.ethers.Wallet.createRandom()
      await f.usdc.mint(second.address, 100n * USDC)
      await expect(
        f.program.publishInput(sale.saleId, encodeBidInput(await bidData(f, sale, second, 1, true))),
      ).to.be.revertedWithCustomError(f.bidVerifier, 'PublicInputsMismatch')
    })

    it('keeps the claim tree root equal to the SDK tree of the commitments', async () => {
      const sale = await createSale(f)
      const tree = new ClaimTree()
      expect(await f.program.claimRoot(sale.saleId)).to.equal(tree.root)
      for (let i = 0; i < 9; i++) {
        const { bid } = await placeBid(f, sale, { step: i % 8, budget: 5 })
        tree.insert(BigInt(bid.bidCommitment))
        expect(await f.program.claimRoot(sale.saleId), `after bid ${i}`).to.equal(tree.root)
      }
    })

    it('refuses wrong rounds, windows, keys and ids', async () => {
      const sale = await createSale(f)
      const bidder = f.ethers.Wallet.createRandom()
      await f.usdc.mint(bidder.address, 100n * USDC)
      const data = encodeBidInput(await bidData(f, sale, bidder, 1, true))
      await expect(f.program.publishInput(sale.round2Id, data)).to.be.revertedWithCustomError(f.errors, 'NotASale')
      await expect(f.program.publishInput(1234n, data)).to.be.revertedWithCustomError(f.errors, 'NotASale')
      await f.interfold.setCommitteePublicKey(sale.round2Id, `0x${'00'.repeat(32)}`)
      await expect(f.program.publishInput(sale.saleId, data)).to.be.revertedWithCustomError(f.errors, 'KeyNotPublished')
      await f.interfold.setCommitteePublicKey(sale.round2Id, KEY2)
      await f.program.publishInput(sale.saleId, data)
      await closeInputs(f, sale)
      const late = f.ethers.Wallet.createRandom()
      await f.usdc.mint(late.address, 100n * USDC)
      await expect(
        f.program.publishInput(sale.saleId, encodeBidInput(await bidData(f, sale, late, 1, true))),
      ).to.be.revertedWithCustomError(f.errors, 'InputDeadlineReached')
      const unlinked = await createSale(f, { saleId: 40n, noRoundTwo: true })
      await expect(f.program.publishInput(unlinked.saleId, data)).to.be.revertedWithCustomError(f.errors, 'RoundTwoNotLinked')
    })

    it('refuses bad bid fields', async () => {
      const sale = await createSale(f)
      const bidder = f.ethers.Wallet.createRandom()
      await f.usdc.mint(bidder.address, 1000n * USDC)
      const good = await bidData(f, sale, bidder, 1, true)
      const send = (input: object) => f.program.publishInput(sale.saleId, encodeBidInput(input as Parameters<typeof encodeBidInput>[0]))
      await expect(send({ ...good, bidder: '0x0000000000000000000000000000000000000000' })).to.be.revertedWithCustomError(
        f.errors,
        'BidderIsZero',
      )
      await expect(send({ ...good, ciphertext1: '0x' })).to.be.revertedWithCustomError(f.errors, 'EmptyInputData')
      await expect(send({ ...good, ciphertext2: '0x' })).to.be.revertedWithCustomError(f.errors, 'EmptyInputData')
      await expect(send({ ...good, bidCommitment: `0x${'ff'.repeat(32)}` })).to.be.revertedWithCustomError(f.errors, 'InvalidBidCommitment')
      // Tier 3 is unused and tier 4 does not exist.
      await expect(send({ ...good, tier: 3 })).to.be.revertedWithCustomError(f.errors, 'InvalidTier')
      await expect(send({ ...good, tier: 4 })).to.be.revert(f.ethers)
      // The signature binds the tier, the ciphertexts and the commitments: a relayer cannot change them.
      await expect(send({ ...good, tier: 0 })).to.be.revertedWithCustomError(f.errors, 'InvalidSignature')
      await expect(send({ ...good, ciphertext1: '0x1234' })).to.be.revertedWithCustomError(f.errors, 'InvalidSignature')
      await expect(send({ ...good, bidCommitment: nextWord(f) })).to.be.revertedWithCustomError(f.errors, 'InvalidSignature')
      // A signature of someone else.
      const other = f.ethers.Wallet.createRandom()
      const forged = await bidData(f, sale, other, 1, true)
      await expect(send({ ...good, signature: forged.signature })).to.be.revertedWithCustomError(f.errors, 'InvalidSignature')
      // A direct bid comes from its bidder.
      const direct = await bidData(f, sale, f.actors[0], 1, false)
      await expect(f.program.connect(f.actors[1]).publishInput(sale.saleId, encodeBidInput(direct))).to.be.revertedWithCustomError(
        f.errors,
        'SenderNotBidder',
      )
      // A proof that the verifier rejects.
      await expect(send({ ...good, proof: '0x02' })).to.be.revertedWithCustomError(f.bidVerifier, 'ProofRejected')
      await send(good)
      expect(await f.program.bidCount(sale.saleId)).to.equal(1n)
    })

    it('lets an address bid once per sale, and a bid in two sales', async () => {
      const first = await createSale(f)
      const second = await createSale(f, { saleId: 30n })
      await placeBid(f, first, { step: 1, budget: 5, direct: f.actors[0] })
      await f.usdc.mint(f.actors[0].address, 10n * USDC)
      await f.usdc.connect(f.actors[0]).approve(f.programAddress, 10n * USDC)
      await expect(
        f.program.connect(f.actors[0]).publishInput(first.saleId, encodeBidInput(await bidData(f, first, f.actors[0], 0, false))),
      ).to.be.revertedWithCustomError(f.errors, 'AlreadyBid')
      await placeBid(f, second, { step: 1, budget: 5, direct: f.actors[0] })
      expect(await f.program.bidCount(second.saleId)).to.equal(1n)
    })

    it('survives a permit that someone used first, and fails without allowance', async () => {
      const sale = await createSale(f)
      const bidder = f.ethers.Wallet.createRandom()
      await f.usdc.mint(bidder.address, 200n * USDC)
      const input = await bidData(f, sale, bidder, 0, true)
      // Front-run: the relayer's rival uses the permit first.
      await f.usdc.permit(
        bidder.address,
        f.programAddress,
        10n * USDC,
        input.permit.deadline,
        input.permit.v,
        input.permit.r,
        input.permit.s,
      )
      await f.program.publishInput(sale.saleId, encodeBidInput(input))
      expect(await f.program.bidCount(sale.saleId)).to.equal(1n)
      // A bad permit and no allowance: the transfer fails.
      const poor = f.ethers.Wallet.createRandom()
      await f.usdc.mint(poor.address, 200n * USDC)
      const bad = await bidData(f, sale, poor, 0, true)
      await expect(f.program.publishInput(sale.saleId, encodeBidInput({ ...bad, permit: { ...bad.permit, v: 0 } }))).to.be.revert(f.ethers)
    })

    it('takes 85 bidders and refuses the 86th', async function () {
      this.timeout(600_000)
      const sale = await createSale(f)
      for (let i = 0; i < 85; i++) await placeBid(f, sale, { step: i % 8, budget: 1 })
      expect(await f.program.bidCount(sale.saleId)).to.equal(85n)
      const late = f.ethers.Wallet.createRandom()
      await f.usdc.mint(late.address, 100n * USDC)
      await expect(
        f.program.publishInput(sale.saleId, encodeBidInput(await bidData(f, sale, late, 0, true))),
      ).to.be.revertedWithCustomError(f.errors, 'TooManyBidders')
    })
  })

  describe('rounds', () => {
    it('walks the phases of a sale', async () => {
      const sale = await saleWith(f, CAPPED)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Bidding)
      await closeInputs(f, sale)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Round1)
      await expect(f.program.publishProbes(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'OutputNotPublished')
      await decryptRound1(f, sale)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Probing)
      await f.program.publishProbes(sale.saleId)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Round2)
      await expect(f.program.clear(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'OutputNotPublished')
      await decryptRound2(f, sale)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Clearable)
      await f.program.clear(sale.saleId)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Cleared)
    })

    it('publishes the probes of the search, and puts the config into round 2', async () => {
      const sale = await saleWith(f, CAPPED)
      await closeInputs(f, sale)
      await decryptRound1(f, sale)
      const expected = searchRound1(sale.grid, [0n, 0n, 800n, 0n, 800n, 0n, 400n, 0n, ...Array(8).fill(0n)])
      expect(expected).to.deep.equal({ valid: true, lo: 4, hi: 6, probeMask2: 0b100000 })
      await expect(f.program.publishProbes(sale.saleId))
        .to.emit(f.program, 'ProbesPublished')
        .withArgs(
          sale.saleId,
          sale.round2Id,
          4,
          6,
          0b100000,
          `0x${Buffer.from('interfold-token-launch-config-v1').toString('hex')}02080020`,
        )
      const info = await f.program.probeInfo(sale.saleId)
      expect([info.lo, info.hi, info.probeMask1, info.probeMask2]).to.deep.equal([4n, 6n, 0b1010100n, 0b100000n])
      expect(info.sums1[2]).to.equal(800n)
      expect(info.sums1[4]).to.equal(800n)
      expect(info.sums1[6]).to.equal(400n)
      expect(info.sums1[3]).to.equal(0n)
      // The config leaf of round 2 was replaced; the bids stay.
      expect((await f.program.inputs(sale.round2Id)).numberOfLeaves).to.equal(BigInt(CAPPED.length + 1))
    })

    it('refuses to repeat a step, and to clear before the probes', async () => {
      const sale = await saleWith(f, CAPPED)
      await publishProbes(f, sale)
      await expect(f.program.publishProbes(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'WrongPhase').withArgs(PHASE.Round2)
      await expect(f.program.clear(sale.round2Id)).to.be.revertedWithCustomError(f.errors, 'WrongPhase')
      await decryptRound2(f, sale)
      await f.program.clear(sale.saleId)
      await expect(f.program.clear(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'WrongPhase').withArgs(PHASE.Cleared)
    })

    it('refuses to clear before the probes of the same sale', async () => {
      const sale = await saleWith(f, CAPPED)
      await closeInputs(f, sale)
      await decryptRound1(f, sale)
      await expect(f.program.clear(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'WrongPhase').withArgs(PHASE.Probing)
    })

    it('aborts a sale whose round 2 was never linked', async () => {
      const sale = await createSale(f, { noRoundTwo: true })
      await closeInputs(f, sale)
      await f.interfold.setPlaintext(sale.saleId, rawPlaintext({}))
      await expect(f.program.publishProbes(sale.saleId)).to.emit(f.program, 'SaleAborted').withArgs(sale.saleId, ABORT.NoRoundTwo)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Aborted)
    })

    it('aborts when round 1 is not a demand curve', async () => {
      const sale = await saleWith(f, [{ step: 7, budget: 3 }])
      await closeInputs(f, sale)
      // Level 2 holds 1, level 4 holds 2: the sums increase with the level.
      await f.interfold.setPlaintext(sale.saleId, rawPlaintext({ [2 * 6]: 1, [4 * 6]: 2, 96: 1 }))
      await expect(f.program.publishProbes(sale.saleId)).to.emit(f.program, 'SaleAborted').withArgs(sale.saleId, ABORT.InvalidRound1Output)
    })

    it('aborts when a cell or a counted flag cannot be real', async () => {
      const bigCell = await saleWith(f, [{ step: 7, budget: 3 }])
      await closeInputs(f, bigCell)
      // One bid: a cell is at most 3.
      await f.interfold.setPlaintext(bigCell.saleId, rawPlaintext({ [2 * 6]: 4, 96: 1 }))
      await expect(f.program.publishProbes(bigCell.saleId))
        .to.emit(f.program, 'SaleAborted')
        .withArgs(bigCell.saleId, ABORT.InvalidRound1Output)

      const badFlag = await createSale(f, { saleId: 50n })
      await placeBid(f, badFlag, { step: 7, budget: 3 })
      await closeInputs(f, badFlag)
      // The flag of bid 1 is set, but there is only bid 0.
      await f.interfold.setPlaintext(badFlag.saleId, rawPlaintext({ 96: 2 }))
      await expect(f.program.publishProbes(badFlag.saleId))
        .to.emit(f.program, 'SaleAborted')
        .withArgs(badFlag.saleId, ABORT.InvalidRound1Output)
    })

    it('aborts when round 2 does not merge into a demand curve', async () => {
      const sale = await saleWith(f, CAPPED)
      await publishProbes(f, sale)
      // Level 5 (the only level of round 2) reveals more than level 4 of round 1.
      await f.interfold.setPlaintext(sale.round2Id, rawPlaintext({ [5 * 6]: 3, [5 * 6 + 1]: 3, [5 * 6 + 2]: 3, 96: 31 }))
      await expect(f.program.clear(sale.saleId)).to.emit(f.program, 'SaleAborted').withArgs(sale.saleId, ABORT.InvalidRound2Output)
    })

    it('aborts and forfeits when a bid is counted in one round only', async () => {
      const sale = await saleWith(f, CAPPED)
      await publishProbes(f, sale)
      const counted = sale.bids.filter((bid) => bid.index !== 2)
      await decryptRound2(f, sale, counted)
      await expect(f.program.clear(sale.saleId)).to.emit(f.program, 'SaleAborted').withArgs(sale.saleId, ABORT.CountedSetMismatch)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Aborted)
      // Bid 2 forfeits its escrow to the creator; the others get theirs back.
      await expect(f.program.refundEscrow(sale.saleId, 2)).to.be.revertedWithCustomError(f.errors, 'Forfeited')
      const before = await f.usdc.balanceOf(f.creator.address)
      await expect(f.program.withdrawForfeited(sale.saleId))
        .to.emit(f.program, 'ForfeitedWithdrawn')
        .withArgs(sale.saleId, f.creator.address, 100n * USDC)
      expect((await f.usdc.balanceOf(f.creator.address)) - before).to.equal(100n * USDC)
      await expect(f.program.withdrawForfeited(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NothingToWithdraw')
      await expect(f.program.connect(f.actors[0]).withdrawForfeited(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NotCreator')
      for (const bid of sale.bids.filter((b) => b.index !== 2)) {
        await f.program.refundEscrow(sale.saleId, bid.index)
        expect(await f.usdc.balanceOf(bid.bidder)).to.equal(BigInt(bid.escrow) * USDC)
      }
      await f.program.refundSupply(sale.saleId)
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(0n)
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(0n)
    })

    it('returns every fund when an E3 fails', async () => {
      const sale = await saleWith(f, CAPPED)
      await expect(f.program.refundEscrow(sale.saleId, 0)).to.be.revertedWithCustomError(f.errors, 'WrongPhase').withArgs(PHASE.Bidding)
      await expect(f.program.refundSupply(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'WrongPhase')
      await f.interfold.setStage(sale.round2Id, 6)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Failed)
      for (const bid of sale.bids) {
        await expect(f.program.refundEscrow(sale.saleId, bid.index)).to.emit(f.program, 'EscrowRefunded')
        await expect(f.program.refundEscrow(sale.saleId, bid.index)).to.be.revertedWithCustomError(f.errors, 'AlreadyRefunded')
      }
      await expect(f.program.refundEscrow(sale.saleId, 99)).to.be.revertedWithCustomError(f.errors, 'InvalidBidIndex')
      await expect(f.program.connect(f.actors[0]).refundSupply(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NotCreator')
      await f.program.refundSupply(sale.saleId)
      await expect(f.program.refundSupply(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NothingToWithdraw')
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(0n)
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(0n)
    })

    it('a failed round 1 fails the sale too', async () => {
      const sale = await saleWith(f, CAPPED)
      await f.interfold.setStage(sale.saleId, 6)
      expect(await f.program.phase(sale.saleId)).to.equal(PHASE.Failed)
      await expect(f.program.claim(sale.saleId, '0x')).to.be.revert(f.ethers)
    })
  })

  describe('compute proof', () => {
    it('refuses a round-2 proof before the probes are published', async () => {
      const sale = await saleWith(f, CAPPED)
      const zero = `0x${'00'.repeat(32)}`
      await expect(f.program.verify(sale.round2Id, zero, zero, '0x')).to.be.revertedWithCustomError(f.errors, 'ProbesNotPublished')
      await expect(f.program.verify(999n, zero, zero, '0x')).to.be.revertedWithCustomError(f.errors, 'E3DoesNotExist')
    })
  })

  describe('clearing', () => {
    for (const [name, specs, kind] of [
      ['capped', CAPPED, KIND_CAPPED],
      ['uncapped', UNCAPPED, KIND_UNCAPPED],
      ['undersubscribed', UNDERSUBSCRIBED, KIND_UNDERSUBSCRIBED],
    ] as const) {
      it(`clears a ${name} sale like the SDK reference`, async () => {
        const sale = await saleWith(f, specs)
        await clearSale(f, sale)
        const reference = simulateSale(sale.grid, sale.bids)
        const onChain = await readClearing(f, sale)
        expect(onChain.kind).to.equal(kind)
        expect(onChain).to.deep.equal(reference.clearing)
        expect(onChain.sold <= sale.grid.supply).to.equal(true)
        const info = await f.program.clearing(sale.saleId)
        expect(info.cleared).to.equal(true)
        expect(info.countedMask).to.equal((1n << BigInt(specs.length)) - 1n)
        expect(info.root).to.equal(await f.program.claimRoot(sale.saleId))
        const now = BigInt(await f.time.latest())
        expect(info.claimDeadline).to.equal(now + BigInt(30 * DAY))
        expect(info.marginalDeadline).to.equal(kind === KIND_CAPPED ? now + BigInt(3 * DAY) : now)
      })
    }

    it('emits SaleCleared with the revealed sums, the counted set and the known levels', async () => {
      const sale = await saleWith(f, CAPPED)
      await publishProbes(f, sale)
      await decryptRound2(f, sale)
      const clearing = simulateSale(sale.grid, sale.bids).clearing!
      // Round 1 knows levels 2, 4 and 6; round 2 knows level 5.
      const sums = Array.from({ length: 16 }, (_, l) => BigInt({ 2: 800, 4: 800, 5: 800, 6: 400 }[l] ?? 0))
      await expect(f.program.clear(sale.saleId))
        .to.emit(f.program, 'SaleCleared')
        .withArgs(sale.saleId, clearing.kind, clearing.step, clearing.pStar, clearing.sold, 0b11111n, 0b1110100, sums)
    })

    it('a clear with no bids is undersubscribed and sells nothing', async () => {
      const sale = await createSale(f)
      await clearSale(f, sale)
      const info = await f.program.clearing(sale.saleId)
      expect(info.kind).to.equal(KIND_UNDERSUBSCRIBED)
      expect(info.sold).to.equal(0n)
      await f.program.withdrawUnsold(sale.saleId)
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(0n)
    })
  })

  describe('claims', () => {
    it('pays an uncapped sale: tokens at the uniform price and the refund, to fresh addresses', async () => {
      const sale = await saleWith(f, UNCAPPED)
      await clearSale(f, sale)
      const reference = simulateSale(sale.grid, sale.bids)
      for (const bid of sale.bids) {
        const { data, tx } = await claim(f, sale, { bid })
        await expect(tx).to.emit(f.program, 'Claimed')
        const expected = reference.outcomes[bid.index]
        expect(await balance(f.saleToken, data.recipient)).to.equal(expected.tokens)
        expect(await balance(f.usdc, data.recipient)).to.equal(expected.refund)
        expect(expected.cmp).to.equal(2)
      }
      expect(await f.program.proceedsAvailable(sale.saleId)).to.equal(reference.outcomes.reduce((sum, o) => sum + o.paid, 0n))
    })

    it('passes the 11 public inputs of the claim proof, in order', async () => {
      const sale = await saleWith(f, UNCAPPED)
      await clearSale(f, sale)
      const info = await f.program.clearing(sale.saleId)
      const data = await claimData(f, sale, { bid: sale.bids[0] })
      const word = (value: bigint | number | string) => toHex(BigInt(value), { size: 32 })
      await f.claimVerifier.expect([
        word(info.root),
        word(info.countedMask),
        word(sale.saleId),
        word(info.step),
        data.nullifier,
        word(data.recipient),
        word(100),
        word(50),
        word(0),
        word(2),
        word(0),
      ])
      await f.program.claim(sale.saleId, encodeClaimData(data))
      await expect(f.program.claim(sale.saleId, encodeClaimData({ ...data, nullifier: nextWord(f) }))).to.be.revertedWithCustomError(
        f.claimVerifier,
        'PublicInputsMismatch',
      )
    })

    it('refuses a nullifier twice, a claim before clear and after the window', async () => {
      const sale = await saleWith(f, UNCAPPED)
      await expect(claim(f, sale, { bid: sale.bids[0], cmp: 2 }).then((c) => c.tx)).to.be.revertedWithCustomError(f.errors, 'NotCleared')
      await clearSale(f, sale)
      const { data, tx } = await claim(f, sale, { bid: sale.bids[0] })
      await tx
      await expect(
        f.program.claim(sale.saleId, encodeClaimData({ ...data, recipient: f.actors[0].address as Hex })),
      ).to.be.revertedWithCustomError(f.errors, 'NullifierUsed')
      expect(await f.program.nullifierUsed(sale.saleId, data.nullifier)).to.equal(true)
      await f.time.increase(30 * DAY + 10)
      await expect(claim(f, sale, { bid: sale.bids[1] }).then((c) => c.tx)).to.be.revertedWithCustomError(f.errors, 'ClaimWindowClosed')
    })

    it('refuses claim values that cannot come from a bid', async () => {
      const sale = await saleWith(f, UNCAPPED)
      await clearSale(f, sale)
      const bid = sale.bids[0]
      const refuse = async (spec: Parameters<typeof claim>[2]) =>
        expect(claim(f, sale, spec).then((c) => c.tx)).to.be.revertedWithCustomError(f.errors, 'InvalidClaim')
      await refuse({ bid, cmp: 3 as 2 })
      await refuse({ bid, budgetUnits: 101 })
      await refuse({ bid, cmp: 0, budgetUnits: 5 })
      await refuse({ bid, cmp: 2, budgetUnits: 0 })
      await refuse({ bid, escrowUnits: 50 })
      await refuse({ bid, escrowUnits: 0 })
      // Only a registration publishes an index.
      await refuse({ bid, indexPlusOne: 1 })
    })

    it('a bid with cmp 0 (below the step) gets its whole escrow back', async () => {
      const sale = await saleWith(f, [...UNCAPPED, { step: 0, budget: 20 }])
      await clearSale(f, sale)
      const reference = simulateSale(sale.grid, sale.bids)
      expect(reference.outcomes[3].cmp).to.equal(0)
      const { data, tx } = await claim(f, sale, { bid: sale.bids[3] })
      await expect(tx)
        .to.emit(f.program, 'Claimed')
        .withArgs(sale.saleId, data.nullifier, data.recipient, 0n, 0n, 100n * 0n + 100n * USDC)
      expect(await balance(f.usdc, data.recipient)).to.equal(100n * USDC)
    })

    it('previewClaim matches what the claim pays', async () => {
      const sale = await saleWith(f, UNCAPPED)
      await expect(f.program.previewClaim(sale.saleId, 2, 50, 100)).to.be.revertedWithCustomError(f.errors, 'NotCleared')
      await clearSale(f, sale)
      const [tokens, paid, refund] = await f.program.previewClaim(sale.saleId, 2, 50, 100)
      const { data, tx } = await claim(f, sale, { bid: sale.bids[0] })
      await expect(tx).to.emit(f.program, 'Claimed').withArgs(sale.saleId, data.nullifier, data.recipient, tokens, paid, refund)
      await expect(f.program.previewClaim(sale.saleId, 3, 50, 100)).to.be.revertedWithCustomError(f.errors, 'InvalidClaim')
    })
  })

  describe('marginal claims', () => {
    async function cappedCleared() {
      const sale = await saleWith(f, CAPPED)
      await clearSale(f, sale)
      return sale
    }

    it('a claim at the clearing step registers inside the window and pays nothing yet', async () => {
      const sale = await cappedCleared()
      const { data, tx } = await claim(f, sale, { bid: sale.bids[1] })
      expect(data.cmp).to.equal(1)
      expect(data.indexPlusOne).to.equal(2)
      await expect(tx).to.emit(f.program, 'MarginalRegistered').withArgs(sale.saleId, 1, 100, data.recipient)
      expect(await balance(f.saleToken, data.recipient)).to.equal(0n)
      expect(await balance(f.usdc, data.recipient)).to.equal(0n)
      expect(await f.program.nullifierUsed(sale.saleId, data.nullifier)).to.equal(true)
      const info = await f.program.marginalInfo(sale.saleId, 1)
      expect([info.registered, info.budgetUnits, info.recipient, info.paid]).to.deep.equal([true, 100n, data.recipient, false])
      expect(await f.program.proceedsAvailable(sale.saleId)).to.equal(0n)
    })

    it('the claim proof sees reveal_index = 1 and the index inside the window', async () => {
      const sale = await cappedCleared()
      const info = await f.program.clearing(sale.saleId)
      const data = await claimData(f, sale, { bid: sale.bids[2] })
      const word = (value: bigint | number | string) => toHex(BigInt(value), { size: 32 })
      await f.claimVerifier.expect([
        word(info.root),
        word(info.countedMask),
        word(sale.saleId),
        word(5),
        data.nullifier,
        word(data.recipient),
        word(100),
        word(100),
        word(1),
        word(1),
        word(3),
      ])
      await f.program.claim(sale.saleId, encodeClaimData(data))
    })

    it('immediate claims of a capped sale: above the step pays in full, below refunds', async () => {
      const sale = await saleWith(f, [...CAPPED, { step: 0, budget: 30 }])
      await clearSale(f, sale)
      const reference = simulateSale(sale.grid, sale.bids)
      for (const index of [0, 5]) {
        const bid = sale.bids[index]
        const { data, tx } = await claim(f, sale, { bid })
        await tx
        expect(data.indexPlusOne).to.equal(0)
        expect(await balance(f.saleToken, data.recipient)).to.equal(reference.outcomes[index].tokens)
        expect(await balance(f.usdc, data.recipient)).to.equal(reference.outcomes[index].refund)
      }
      // The bid above the step bought 400 / 6 tokens at the uniform price.
      expect(reference.outcomes[0].tokens).to.equal((400n * USDC * 10n ** 18n) / (6n * USDC))
    })

    it('refuses a registration without an index, with a wrong index, or twice', async () => {
      const sale = await cappedCleared()
      const bid = sale.bids[1]
      const refuse = async (spec: Parameters<typeof claim>[2], error: string) =>
        expect(
          claim(f, sale, spec).then((c) => c.tx),
          error,
        ).to.be.revertedWithCustomError(f.errors, error)
      await refuse({ bid, indexPlusOne: 0 }, 'InvalidClaim')
      await refuse({ bid, indexPlusOne: 6 }, 'InvalidClaim')
      // A claim above the step cannot publish an index.
      await refuse({ bid: sale.bids[0], indexPlusOne: 1 }, 'InvalidClaim')
      await (
        await claim(f, sale, { bid })
      ).tx
      await refuse({ bid }, 'AlreadyRegistered')
    })

    it('pays after the window, first bid first, whatever the order of registration', async () => {
      const sale = await cappedCleared()
      const reference = simulateSale(sale.grid, sale.bids)
      // Register 4, 2, 3, 1: reverse of the index order, mixed.
      for (const index of [4, 2, 3, 1]) await (await claim(f, sale, { bid: sale.bids[index] })).tx
      await expect(f.program.payMarginal(sale.saleId, 1)).to.be.revertedWithCustomError(f.errors, 'MarginalWindowOpen')
      await f.time.increase(3 * DAY + 1)
      const recipients = new Map<number, string>()
      for (const index of [1, 2, 3, 4]) recipients.set(index, (await f.program.marginalInfo(sale.saleId, index))[2])
      // The preview is the payout.
      const [tokens, paid, refund] = await f.program.previewMarginal(sale.saleId, 3)
      await expect(f.program.payMarginal(sale.saleId, 3))
        .to.emit(f.program, 'MarginalPaid')
        .withArgs(sale.saleId, 3, recipients.get(3), tokens, paid, refund)
      for (const index of [4, 1, 2]) await f.program.payMarginal(sale.saleId, index)
      for (const index of [1, 2, 3, 4]) {
        const expected = reference.outcomes[index]
        expect(await balance(f.saleToken, recipients.get(index)!), `tokens of bid ${index}`).to.equal(expected.tokens)
        expect(await balance(f.usdc, recipients.get(index)!), `refund of bid ${index}`).to.equal(expected.refund)
      }
      // The first two take 16.67 tokens each, the third the two base units that are left, the fourth nothing.
      expect(reference.outcomes[3].tokens).to.equal(2n)
      expect(reference.outcomes[4].tokens).to.equal(0n)
      const total = [1, 2, 3, 4].reduce((sum, index) => sum + reference.outcomes[index].tokens, 0n)
      expect(total).to.equal((await readClearing(f, sale)).remaining)
      expect(await f.program.proceedsAvailable(sale.saleId)).to.equal([1, 2, 3, 4].reduce((sum, i) => sum + reference.outcomes[i].paid, 0n))
    })

    it('pays only the registered claims: an unregistered bid does not take its place', async () => {
      const sale = await cappedCleared()
      // Only bids 3 and 4 register. Bids 1 and 2 never claim, so bid 3 is first.
      for (const index of [4, 3]) await (await claim(f, sale, { bid: sale.bids[index] })).tx
      await f.time.increase(3 * DAY + 1)
      const amounts = marginalFills(
        sale.grid,
        await readClearing(f, sale),
        [3, 4].map((index) => ({ index, budgetUnits: 100, escrowUnits: 100 })),
      )
      for (const [position, index] of [3, 4].entries()) {
        const [tokens, paid, refund] = await f.program.previewMarginal(sale.saleId, index)
        expect([tokens, paid, refund]).to.deep.equal([amounts[position].tokens, amounts[position].paid, amounts[position].refund])
      }
      expect(amounts[0].tokens).to.equal((100n * USDC * 10n ** 18n) / (6n * USDC))
      expect(amounts[1].tokens).to.equal(amounts[0].tokens)
    })

    it('refuses payMarginal for an unregistered index, twice, or after the claim window', async () => {
      const sale = await cappedCleared()
      await (
        await claim(f, sale, { bid: sale.bids[1] })
      ).tx
      await f.time.increase(3 * DAY + 1)
      await expect(f.program.payMarginal(sale.saleId, 2)).to.be.revertedWithCustomError(f.errors, 'NotRegistered')
      await f.program.payMarginal(sale.saleId, 1)
      await expect(f.program.payMarginal(sale.saleId, 1)).to.be.revertedWithCustomError(f.errors, 'AlreadyPaid')
      expect((await f.program.marginalInfo(sale.saleId, 1))[3]).to.equal(true)
      await (
        await claim(f, sale, { bid: sale.bids[2], indexPlusOne: 0 })
      ).tx
    })

    it('a marginal claim after the window is refund-only and immediate', async () => {
      const sale = await cappedCleared()
      await f.time.increase(3 * DAY + 1)
      const { data, tx } = await claim(f, sale, { bid: sale.bids[1] })
      expect(data.indexPlusOne).to.equal(0)
      await expect(tx)
        .to.emit(f.program, 'Claimed')
        .withArgs(sale.saleId, data.nullifier, data.recipient, 0n, 0n, 100n * USDC)
      expect(await balance(f.usdc, data.recipient)).to.equal(100n * USDC)
      // An index at this point is refused.
      await expect(claim(f, sale, { bid: sale.bids[2], indexPlusOne: 3 }).then((c) => c.tx)).to.be.revertedWithCustomError(
        f.errors,
        'InvalidClaim',
      )
      const [tokens, , refund] = await f.program.previewClaim(sale.saleId, 1, 100, 100)
      expect([tokens, refund]).to.deep.equal([0n, 100n * USDC])
    })

    it('a registered claim cannot be paid after the claim window', async () => {
      const sale = await cappedCleared()
      await (
        await claim(f, sale, { bid: sale.bids[1] })
      ).tx
      await f.time.increase(30 * DAY + 10)
      await expect(f.program.payMarginal(sale.saleId, 1)).to.be.revertedWithCustomError(f.errors, 'ClaimWindowClosed')
    })

    it('random registrations in random order always follow the order of the bid index', async () => {
      const sale = await createSale(f)
      await placeBids(f, sale, [{ step: 7, budget: 400 }, ...Array.from({ length: 12 }, (_, i) => ({ step: 5, budget: 20 + 7 * i }))])
      await clearSale(f, sale)
      const clearing = await readClearing(f, sale)
      expect(clearing.kind).to.equal(KIND_CAPPED)
      let seed = 12345
      const next = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32
      const marginal = sale.bids.filter((bid) => bid.step === 5).sort(() => next() - 0.5)
      const registered = marginal.filter(() => next() < 0.6)
      for (const bid of registered) await (await claim(f, sale, { bid })).tx
      await f.time.increase(3 * DAY + 1)
      const expected = marginalFills(
        sale.grid,
        clearing,
        registered.map((bid) => ({ index: bid.index, budgetUnits: bid.budget, escrowUnits: bid.escrow })),
      )
      let total = 0n
      for (const [position, bid] of registered.entries()) {
        await f.program.payMarginal(sale.saleId, bid.index)
        const info = await f.program.marginalInfo(sale.saleId, bid.index)
        const got: ClaimAmounts = { tokens: await balance(f.saleToken, info[2]), paid: 0n, refund: await balance(f.usdc, info[2]) }
        expect(got.tokens, `bid ${bid.index}`).to.equal(expected[position].tokens)
        expect(got.refund, `bid ${bid.index}`).to.equal(expected[position].refund)
        total += got.tokens
      }
      expect(total <= clearing.remaining).to.equal(true)
    })
  })

  describe('refunds and creator withdrawals', () => {
    it('refuses a dropped-bid refund before clear', async () => {
      const sale = await saleWith(f, CAPPED)
      await publishProbes(f, sale)
      await decryptRound2(f, sale)
      const counted = sale.bids.filter((bid) => bid.index !== 4)
      await decryptRound1(f, sale, counted).catch(() => undefined)
      await expect(f.program.refundDropped(sale.saleId, 4)).to.be.revertedWithCustomError(f.errors, 'NotCleared')
    })

    it('a bid that no round counted is refunded after clear', async () => {
      const sale = await createSale(f)
      await placeBids(f, sale, CAPPED)
      await closeInputs(f, sale)
      const counted = sale.bids.filter((bid) => bid.index !== 4)
      await decryptRound1(f, sale, counted)
      await f.program.publishProbes(sale.saleId)
      await decryptRound2(f, sale, counted)
      await f.program.clear(sale.saleId)
      const info = await f.program.clearing(sale.saleId)
      expect(info.countedMask).to.equal(0b01111n)
      await expect(f.program.refundDropped(sale.saleId, 0)).to.be.revertedWithCustomError(f.errors, 'NotDropped')
      await expect(f.program.refundDropped(sale.saleId, 9)).to.be.revertedWithCustomError(f.errors, 'InvalidBidIndex')
      await expect(f.program.refundDropped(sale.saleId, 4))
        .to.emit(f.program, 'DroppedRefunded')
        .withArgs(sale.saleId, 4, sale.bids[4].bidder, 100n * USDC)
      await expect(f.program.refundDropped(sale.saleId, 4)).to.be.revertedWithCustomError(f.errors, 'AlreadyRefunded')
      expect(await f.usdc.balanceOf(sale.bids[4].bidder)).to.equal(100n * USDC)
    })

    it('lets the creator take proceeds, unsold tokens and, after the window, the rest, down to zero', async () => {
      const sale = await saleWith(f, THIN)
      await clearSale(f, sale)
      const reference = simulateSale(sale.grid, sale.bids)
      const paid = reference.outcomes.reduce((sum, o) => sum + o.paid, 0n)
      // The first two claim; the third does not.
      for (const index of [0, 1]) await (await claim(f, sale, { bid: sale.bids[index] })).tx
      await expect(f.program.connect(f.actors[0]).withdrawProceeds(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NotCreator')
      const before = await f.usdc.balanceOf(f.creator.address)
      await f.program.withdrawProceeds(sale.saleId)
      expect((await f.usdc.balanceOf(f.creator.address)) - before).to.equal(reference.outcomes[0].paid + reference.outcomes[1].paid)
      await expect(f.program.withdrawProceeds(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NothingToWithdraw')
      const soldTokens = (await readClearing(f, sale)).sold
      const unsoldBefore = await f.saleToken.balanceOf(f.creator.address)
      await f.program.withdrawUnsold(sale.saleId)
      expect((await f.saleToken.balanceOf(f.creator.address)) - unsoldBefore).to.equal(sale.grid.supply - soldTokens)
      await expect(f.program.withdrawUnsold(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NothingToWithdraw')
      await expect(f.program.sweep(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'ClaimWindowOpen')
      await f.time.increase(30 * DAY + 10)
      const usdcBefore = await f.usdc.balanceOf(f.creator.address)
      const saleBefore = await f.saleToken.balanceOf(f.creator.address)
      await expect(f.program.connect(f.actors[0]).sweep(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NotCreator')
      await f.program.sweep(sale.saleId)
      // The unclaimed bid: its tokens, its payment and its refund all go to the creator.
      expect((await f.saleToken.balanceOf(f.creator.address)) - saleBefore).to.equal(reference.outcomes[2].tokens)
      expect((await f.usdc.balanceOf(f.creator.address)) - usdcBefore).to.equal(reference.outcomes[2].paid + reference.outcomes[2].refund)
      expect(paid).to.be.greaterThan(0n)
      await expect(f.program.sweep(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'AlreadySwept')
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(0n)
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(0n)
    })

    it('leaves nothing in the program after a capped sale with dropped and unregistered bids', async () => {
      const sale = await createSale(f)
      await placeBids(f, sale, [...CAPPED, { step: 2, budget: 10 }])
      await closeInputs(f, sale)
      const counted = sale.bids.filter((bid) => bid.index !== 5)
      await decryptRound1(f, sale, counted)
      await f.program.publishProbes(sale.saleId)
      await decryptRound2(f, sale, counted)
      await f.program.clear(sale.saleId)
      const reference = simulateSale(sale.grid, counted)
      const clearing = await readClearing(f, sale)
      expect(clearing).to.deep.equal(reference.clearing)
      // Bid 0 claims; bids 1 and 2 register, 3 and 4 do not; bid 5 was dropped.
      await (
        await claim(f, sale, { bid: sale.bids[0] })
      ).tx
      for (const index of [1, 2]) await (await claim(f, sale, { bid: sale.bids[index] })).tx
      await f.program.refundDropped(sale.saleId, 5)
      await f.time.increase(3 * DAY + 1)
      for (const index of [1, 2]) await f.program.payMarginal(sale.saleId, index)
      await f.program.withdrawProceeds(sale.saleId)
      // A capped sale sells the whole supply: nothing is unsold.
      await expect(f.program.withdrawUnsold(sale.saleId)).to.be.revertedWithCustomError(f.errors, 'NothingToWithdraw')
      await f.time.increase(30 * DAY)
      await f.program.sweep(sale.saleId)
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(0n)
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(0n)
    })

    it('keeps two sales apart', async () => {
      const first = await saleWith(f, UNCAPPED)
      const second = await createSale(f, { saleId: 70n })
      await placeBids(f, second, UNDERSUBSCRIBED)
      await clearSale(f, first)
      await clearSale(f, second)
      await (
        await claim(f, first, { bid: first.bids[0] })
      ).tx
      await (
        await claim(f, second, { bid: second.bids[0] })
      ).tx
      await f.time.increase(30 * DAY + 10)
      await f.program.sweep(first.saleId)
      await f.program.sweep(second.saleId)
      expect(await f.usdc.balanceOf(f.programAddress)).to.equal(0n)
      expect(await f.saleToken.balanceOf(f.programAddress)).to.equal(0n)
    })
  })

  describe('gas', () => {
    it('reports the gas of the main calls', async () => {
      const sale = await createSale(f)
      const gas: Record<string, bigint> = {}
      const first = await placeBid(f, sale, { step: 7, budget: 400 })
      gas.publishInput = first.receipt!.gasUsed
      for (const spec of CAPPED.slice(1)) await placeBid(f, sale, spec)
      await closeInputs(f, sale)
      await decryptRound1(f, sale)
      gas.publishProbes = (await (await f.program.publishProbes(sale.saleId)).wait())!.gasUsed
      await decryptRound2(f, sale)
      gas.clear = (await (await f.program.clear(sale.saleId)).wait())!.gasUsed
      gas.claimImmediate = (await (await claim(f, sale, { bid: sale.bids[0] })).tx.then((tx) => tx.wait()))!.gasUsed
      gas.claimRegister = (await (await claim(f, sale, { bid: sale.bids[1] })).tx.then((tx) => tx.wait()))!.gasUsed
      await (
        await claim(f, sale, { bid: sale.bids[2] })
      ).tx
      await (
        await claim(f, sale, { bid: sale.bids[3] })
      ).tx
      await f.time.increase(3 * DAY + 1)
      gas.payMarginalLast = (await (await f.program.payMarginal(sale.saleId, 3)).wait())!.gasUsed
      const size = ((await f.ethers.provider.getCode(f.programAddress)).length - 2) / 2
      console.log('      gas', Object.fromEntries(Object.entries(gas).map(([k, v]) => [k, Number(v)])), 'program bytes', size)
      expect(size).to.be.lessThan(24_576)
    })
  })
})
