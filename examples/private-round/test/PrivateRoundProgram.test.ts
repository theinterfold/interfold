// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { type Hex, encodeAbiParameters, keccak256, parseAbiParameters, stringToHex, zeroAddress } from 'viem'
import { roundConfigInput } from '../sdk/src/layout'
import { escrowOf } from '../sdk/src/clearing'
import {
  E3_ID,
  ESCROW,
  KEY,
  LOT,
  LOTS,
  PRICES,
  U18,
  type Fixture,
  bid,
  bidData,
  bidPublicInputs,
  createRound,
  deployFixture,
  deposit,
  fund,
  inputsHashOf,
  makeBid,
  requestRound,
  roundSale,
  signBid,
  signPermit,
} from './fixture'
import { MAX_BIDDERS, encodeRawParams, filled } from './helpers'

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
const SUPPLY = LOT * BigInt(LOTS)
const AMOUNT_LIMIT = 2n ** 112n

describe('PrivateRoundProgram', () => {
  describe('request', () => {
    it('pulls the supply from the requester and stores the round', async () => {
      const fixture = await deployFixture()
      const { program, creator, saleToken, usdc, programAddress } = fixture
      const { e3Id, tx } = await requestRound(fixture, { reserveStep: 1, minLots: 2 })
      await expect(tx())
        .to.emit(program, 'SaleCreated')
        .withArgs(
          e3Id,
          creator.address,
          4,
          [...PRICES, ...Array(12).fill(0n)],
          await saleToken.getAddress(),
          await usdc.getAddress(),
          LOT,
          LOTS,
          1,
          2,
          ESCROW,
          'Unit test round',
          zeroAddress,
        )
      expect(await saleToken.balanceOf(programAddress)).to.equal(SUPPLY)
      expect(await saleToken.balanceOf(creator.address)).to.equal(0n)
      const sale = await program.sale(e3Id)
      expect(sale.levels).to.equal(4n)
      expect(sale.creator).to.equal(creator.address)
      expect(sale.title).to.equal('Unit test round')
      expect(sale.saleToken).to.equal(await saleToken.getAddress())
      expect(sale.paymentToken).to.equal(await usdc.getAddress())
      expect(sale.lot).to.equal(LOT)
      expect(sale.lots).to.equal(BigInt(LOTS))
      expect(sale.reserveStep).to.equal(1n)
      expect(sale.minLots).to.equal(2n)
      expect(sale.supply).to.equal(SUPPLY)
      expect(sale.escrow).to.equal(ESCROW)
      expect(sale.gate).to.equal(zeroAddress)
      expect(sale.saleUnit).to.equal(U18)
      expect([...(await program.salePrices(e3Id))]).to.deep.equal([...PRICES, ...Array(12).fill(0n)])
      // Leaf 0 is the configuration leaf.
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(1n)
    })

    it('has the constants of the spec', async () => {
      const { program } = await deployFixture()
      expect(await program.TREE_DEPTH()).to.equal(20n)
      expect(await program.LEVELS()).to.equal(16n)
      expect(await program.MAX_BIDDERS()).to.equal(13n)
      expect(await program.MAX_BIDS_PER_BIDDER()).to.equal(3n)
      expect(await program.MAX_LOTS()).to.equal(12n)
      expect(await program.PHASE1_WINDOW()).to.equal(2n * 86400n)
      expect(await program.PHASE2_WINDOW()).to.equal(2n * 86400n)
      expect(await program.CLAIM_WINDOW()).to.equal(30n * 86400n)
      expect(await program.CONFIG_DOMAIN()).to.equal(stringToHex('interfold-private-round-config-v1'))
      expect(await program.BID_TYPEHASH()).to.equal(
        keccak256(stringToHex('Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)')),
      )
    })

    it('derives the escrow from the price of one lot at the highest step, rounded up', async () => {
      const fixture = await deployFixture()
      // One lot is a third of a token: 0.333... tokens at 3.333333 USDC is not a whole number of base units.
      const lot = 333_333_333_333_333_333n
      const prices = [1_000_001n, 2_500_003n, 3_333_333n]
      const e3Id = await createRound(fixture, { lot, prices, lots: 5, minLots: 2, reserveStep: 1 })
      const expected = escrowOf({ ...roundSale({ lot, prices, lots: 5 }) })
      const sale = await fixture.program.sale(e3Id)
      expect(sale.escrow).to.equal(expected)
      expect(sale.escrow * U18).to.be.greaterThanOrEqual(lot * 3_333_333n)
      expect((sale.escrow - 1n) * U18).to.be.lessThan(lot * 3_333_333n)
      expect(sale.supply).to.equal(lot * 5n)
    })

    it('reads the decimals of the sale token', async () => {
      const fixture = await deployFixture()
      const six = await fixture.ethers.deployContract('MockDecimalsToken', [6])
      // Approve the six-decimal token, then request.
      const supply = LOT * BigInt(LOTS)
      await (await six.mint(fixture.creator.address, supply)).wait()
      await (await six.approve(fixture.programAddress, supply)).wait()
      await (await fixture.interfold.setE3(E3_ID, 2n ** 40n, KEY, fixture.creator.address)).wait()
      const params = encodeRawParams({
        prices: PRICES,
        saleToken: (await six.getAddress()) as Hex,
        lot: LOT,
        lots: LOTS,
        reserveStep: 0,
        minLots: 1,
        paymentToken: (await fixture.usdc.getAddress()) as Hex,
      })
      await (await fixture.interfold.request(E3_ID, fixture.programAddress, params)).wait()
      const sale = await fixture.program.sale(E3_ID)
      expect(sale.saleUnit).to.equal(10n ** 6n)
      expect(sale.escrow).to.equal((LOT * 4_000_000n + 10n ** 6n - 1n) / 10n ** 6n)
    })

    it('has the shared configuration leaf and bid leaf', async () => {
      const { program } = await deployFixture()
      for (const [levels, reserveStep, lots, minLots] of [
        [4, 0, 3, 1],
        [16, 15, 12, 12],
        [2, 1, 1, 1],
      ]) {
        const input = roundConfigInput({ levels, reserveStep, lots, minLots })
        expect(input.length).to.equal(2 + 2 * 37)
        expect(await program.configLeaf(levels, reserveStep, lots, minLots)).to.equal(BigInt(keccak256(input)) % FIELD)
      }
      // The vector of `program/src/lib.rs` and auction-e2e.
      expect(await program.inputLeaf(filled(0x11), filled(0x22), '0x3333333333333333333333333333333333333333', 2)).to.equal(
        0x0b8ba63e8917dfb3f66cfcc1b0be5d3a8f8613ba8092d690a43b84daec02b94an,
      )
    })

    describe('bad parameters', () => {
      const cases: [string, string, Parameters<typeof requestRound>[1]][] = [
        ['one price step', 'InvalidLevels', { prices: [1n], reserveStep: 0 }],
        ['prices that do not rise', 'InvalidPrices', { prices: [2n, 2n, 3n] }],
        ['prices that fall', 'InvalidPrices', { prices: [3n, 2n, 4n] }],
        ['a zero first price', 'InvalidPrices', { prices: [0n, 2n] }],
        ['a top price above 2^112', 'InvalidPrices', { prices: [1n, AMOUNT_LIMIT + 1n], lot: 1n }],
        ['zero lots', 'InvalidLots', { lots: 0, minLots: 0 }],
        ['13 lots', 'InvalidLots', { lots: 13, minLots: 1 }],
        ['zero minimum lots', 'InvalidLots', { minLots: 0 }],
        ['a minimum above the lots', 'InvalidLots', { lots: 3, minLots: 4 }],
        ['a reserve step at the levels', 'InvalidReserve', { reserveStep: 4 }],
        ['a zero lot', 'InvalidAmount', { lot: 0n }],
        ['a lot above 2^112', 'InvalidAmount', { lot: AMOUNT_LIMIT + 1n, lots: 1, minLots: 1 }],
        ['a supply above 2^112', 'InvalidAmount', { lot: AMOUNT_LIMIT / 2n + 1n, lots: 2, minLots: 1 }],
        ['an empty title', 'InvalidTitle', { title: '' }],
        ['a title of 81 bytes', 'InvalidTitle', { title: 'x'.repeat(81) }],
        ['a gate that is not a contract', 'InvalidGate', { gate: '0x00000000000000000000000000000000000000aa' }],
        ['a gate configuration without a gate', 'GateConfigWithoutGate', { gateConfig: '0x1234' }],
        ['a sale token that is not a contract', 'InvalidToken', { saleToken: '0x00000000000000000000000000000000000000aa' }],
        ['a payment token that is not a contract', 'InvalidToken', { paymentToken: '0x00000000000000000000000000000000000000aa' }],
      ]

      for (const [name, error, options] of cases) {
        it(`rejects ${name}`, async () => {
          const fixture = await deployFixture()
          const config = await fixture.ethers.getContractAt('RoundConfig', fixture.programAddress)
          // A request with these options fails inside `validate`, before the supply is pulled.
          const { tx } = await requestRound(fixture, { noApproval: true, ...options })
          await expect(tx()).to.be.revertedWithCustomError(config, error)
        })
      }

      it('rejects a payment token equal to the sale token', async () => {
        const fixture = await deployFixture()
        const config = await fixture.ethers.getContractAt('RoundConfig', fixture.programAddress)
        const { tx } = await requestRound(fixture, { noApproval: true, paymentToken: (await fixture.saleToken.getAddress()) as Hex })
        await expect(tx()).to.be.revertedWithCustomError(config, 'InvalidToken')
      })

      it('rejects a sale token with more than 30 decimals', async () => {
        const fixture = await deployFixture()
        const config = await fixture.ethers.getContractAt('RoundConfig', fixture.programAddress)
        const token = await fixture.ethers.deployContract('MockDecimalsToken', [31])
        const { tx } = await requestRound(fixture, { noApproval: true, saleToken: (await token.getAddress()) as Hex })
        await expect(tx()).to.be.revertedWithCustomError(config, 'InvalidToken')
      })

      it('rejects levels above 16 and prices after the last step', async () => {
        const fixture = await deployFixture()
        const config = await fixture.ethers.getContractAt('RoundConfig', fixture.programAddress)
        // `levels = 17` does not fit the grid of 16 steps.
        await expect((await requestRound(fixture, { noApproval: true, prices: PRICES, levels: 17 })).tx()).to.be.revertedWithCustomError(
          config,
          'InvalidLevels',
        )
        // A price after the last step must be zero: `levels = 3` with four prices.
        await expect((await requestRound(fixture, { noApproval: true, prices: PRICES, levels: 3 })).tx()).to.be.revertedWithCustomError(
          config,
          'InvalidPrices',
        )
      })

      it('accepts the limits of every parameter', async () => {
        const fixture = await deployFixture()
        const prices = Array.from({ length: 16 }, (_, i) => AMOUNT_LIMIT - 15n + BigInt(i))
        const lot = AMOUNT_LIMIT / 12n
        const e3Id = await createRound(fixture, { prices, lot, lots: 12, minLots: 12, reserveStep: 15, title: 'x'.repeat(80) })
        const sale = await fixture.program.sale(e3Id)
        expect(sale.levels).to.equal(16n)
        expect(sale.supply).to.equal(lot * 12n)
        expect(sale.title).to.have.length(80)
        // 2^112 as the top price, and a supply of exactly 2^112.
        const second = await deployFixture()
        const e3 = await createRound(second, { prices: [1n, AMOUNT_LIMIT], lot: AMOUNT_LIMIT / 2n, lots: 2, minLots: 1, reserveStep: 0 })
        expect((await second.program.sale(e3)).supply).to.equal(AMOUNT_LIMIT)
      })
    })

    it('fails when the requester has not approved the supply', async () => {
      const fixture = await deployFixture()
      await expect((await requestRound(fixture, { noApproval: true })).tx()).to.be.revert(fixture.ethers)
    })

    it('rejects a caller that is not Interfold, and a second request of the same E3', async () => {
      const fixture = await deployFixture()
      const { e3Id, params } = await requestRound(fixture)
      await expect(fixture.program.connect(fixture.actors[0]).validate(e3Id, 0n, '0x', '0x', params)).to.be.revertedWithCustomError(
        fixture.program,
        'CallerNotAuthorized',
      )
      await createRound(fixture)
      await expect(fixture.interfold.request(e3Id, fixture.programAddress, params)).to.be.revertedWithCustomError(
        fixture.program,
        'E3AlreadyInitialized',
      )
    })

    it('configures the gate of the round', async () => {
      const fixture = await deployFixture()
      const gate = await fixture.ethers.deployContract('MerkleAllowlistGate')
      const members = [fixture.actors[0].address, fixture.actors[1].address].sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1))
      const gateConfig = encodeAbiParameters(parseAbiParameters('address[]'), [members as Hex[]])
      const { tx } = await requestRound(fixture, { gate: (await gate.getAddress()) as Hex, gateConfig })
      await expect(tx()).to.emit(gate, 'AllowlistSet')
      expect((await fixture.program.sale(E3_ID)).gate).to.equal(await gate.getAddress())
    })
  })

  describe('deposit', () => {
    it('takes the escrow once and numbers the bidders', async () => {
      const fixture = await deployFixture()
      const { program, usdc, programAddress, actors } = fixture
      const e3Id = await createRound(fixture)
      const [alice, bob] = actors
      await fund(fixture, alice)
      await fund(fixture, bob)
      await expect(program.connect(bob).deposit(e3Id, '0x')).to.emit(program, 'Deposited').withArgs(e3Id, bob.address, 0n)
      await expect(program.connect(alice).deposit(e3Id, '0x')).to.emit(program, 'Deposited').withArgs(e3Id, alice.address, 1n)
      expect(await usdc.balanceOf(programAddress)).to.equal(2n * ESCROW)
      expect(await usdc.balanceOf(alice.address)).to.equal(0n)
      expect(await program.bidderCount(e3Id)).to.equal(2n)
      expect(await program.bidderAt(e3Id, 0n)).to.equal(bob.address)
      expect(await program.bidderIndex(e3Id, alice.address)).to.equal(1n)
      expect(await program.deposited(e3Id, alice.address)).to.equal(true)
      expect(await program.deposited(e3Id, fixture.relayer.address)).to.equal(false)
      await expect(program.connect(alice).deposit(e3Id, '0x')).to.be.revertedWithCustomError(program, 'AlreadyDeposited')
    })

    it('fails without allowance, and after the input window', async () => {
      const fixture = await deployFixture()
      const e3Id = await createRound(fixture, { inputDeadline: 2n ** 40n })
      const [alice] = fixture.actors
      await expect(fixture.program.connect(alice).deposit(e3Id, '0x')).to.be.revert(fixture.ethers)
      await fund(fixture, alice)
      await (await fixture.interfold.setInputDeadline(e3Id, 1n)).wait()
      await expect(fixture.program.connect(alice).deposit(e3Id, '0x')).to.be.revertedWithCustomError(
        fixture.program,
        'InputDeadlineReached',
      )
    })

    it('rejects a deposit in a round that does not exist', async () => {
      const fixture = await deployFixture()
      await expect(fixture.program.connect(fixture.actors[0]).deposit(99n, '0x')).to.be.revertedWithCustomError(
        fixture.program,
        'E3DoesNotExist',
      )
      const { v, r, s } = await signPermit(fixture, fixture.actors[0], ESCROW, 2n ** 40n)
      await expect(
        fixture.program.connect(fixture.relayer).depositFor(99n, fixture.actors[0].address, '0x', 2n ** 40n, v, r, s),
      ).to.be.revertedWithCustomError(fixture.program, 'E3DoesNotExist')
    })

    it('takes a deposit for a bidder with an EIP-2612 permit, sent by a relayer', async () => {
      const fixture = await deployFixture()
      const { program, usdc, relayer, actors, programAddress } = fixture
      const e3Id = await createRound(fixture)
      const [alice] = actors
      await (await usdc.mint(alice.address, ESCROW)).wait()
      const deadline = 2n ** 40n
      const { v, r, s } = await signPermit(fixture, alice, ESCROW, deadline)
      await expect(program.connect(relayer).depositFor(e3Id, alice.address, '0x', deadline, v, r, s))
        .to.emit(program, 'Deposited')
        .withArgs(e3Id, alice.address, 0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(ESCROW)
      expect(await usdc.balanceOf(alice.address)).to.equal(0n)
    })

    it('tolerates a permit that someone else already used, and rejects a bad one', async () => {
      const fixture = await deployFixture()
      const { program, usdc, relayer, actors } = fixture
      const e3Id = await createRound(fixture)
      const [alice, bob] = actors
      await (await usdc.mint(alice.address, ESCROW)).wait()
      const deadline = 2n ** 40n
      const { v, r, s } = await signPermit(fixture, alice, ESCROW, deadline)
      // A front-runner submits the permit alone: the allowance exists, and the deposit still works.
      await (await usdc.permit(alice.address, fixture.programAddress, ESCROW, deadline, v, r, s)).wait()
      await expect(program.connect(relayer).depositFor(e3Id, alice.address, '0x', deadline, v, r, s)).to.emit(program, 'Deposited')
      // A permit of another owner gives no allowance for bob.
      await (await usdc.mint(bob.address, ESCROW)).wait()
      await expect(program.connect(relayer).depositFor(e3Id, bob.address, '0x', deadline, v, r, s)).to.be.revert(fixture.ethers)
    })

    it('accepts 13 bidders and rejects the 14th', async () => {
      const fixture = await deployFixture()
      const { program, usdc, relayer, ethers } = fixture
      const e3Id = await createRound(fixture)
      const deadline = 2n ** 40n
      for (let i = 0; i < MAX_BIDDERS; i++) {
        const wallet = ethers.Wallet.createRandom(ethers.provider)
        await (await usdc.mint(wallet.address, ESCROW)).wait()
        const { v, r, s } = await signPermit(fixture, wallet, ESCROW, deadline)
        await (await program.connect(relayer).depositFor(e3Id, wallet.address, '0x', deadline, v, r, s)).wait()
      }
      expect(await program.bidderCount(e3Id)).to.equal(13n)
      const extra = ethers.Wallet.createRandom(ethers.provider)
      await (await usdc.mint(extra.address, ESCROW)).wait()
      const { v, r, s } = await signPermit(fixture, extra, ESCROW, deadline)
      await expect(program.connect(relayer).depositFor(e3Id, extra.address, '0x', deadline, v, r, s)).to.be.revertedWithCustomError(
        program,
        'TooManyBidders',
      )
      await (await usdc.connect(fixture.actors[0]).approve(fixture.programAddress, ESCROW)).wait()
      await (await usdc.mint(fixture.actors[0].address, ESCROW)).wait()
      await expect(program.connect(fixture.actors[0]).deposit(e3Id, '0x')).to.be.revertedWithCustomError(program, 'TooManyBidders')
    })
  })

  describe('bids', () => {
    it('takes a bid of two ciphertexts: two leaves, with the proof inputs from storage', async () => {
      const fixture = await deployFixture()
      const { program, bidVerifier, actors } = fixture
      const e3Id = await createRound(fixture, { reserveStep: 2, minLots: 2 })
      const [alice, bob] = actors
      await deposit(fixture, alice)
      await deposit(fixture, bob)
      const made = makeBid(bob.address, 2)
      // Bob has the index 1 and his first bid has the version 1. The mock pins all 11 public inputs.
      await (await bidVerifier.expect(bidPublicInputs(made, e3Id, { levels: 4, reserveStep: 2 }, 1, 1))).wait()
      await expect(program.connect(bob).publishInput(e3Id, bidData(made)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(e3Id, bob.address, 1n, 1n, 1n, made.ciphertexts, made.ctCommitments, made.bidCommitment)
      expect(await program.bidCount(e3Id, bob.address)).to.equal(1n)
      expect(await program.bidCommitments(e3Id, bob.address, 1n)).to.equal(made.bidCommitment)
      // The configuration leaf, then two leaves for the bid.
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(3n)
      // Alice's bid comes next: its first leaf is leaf 3.
      const second = makeBid(alice.address, 9)
      await (await bidVerifier.expect(bidPublicInputs(second, e3Id, { levels: 4, reserveStep: 2 }, 0, 1))).wait()
      await expect(program.connect(alice).publishInput(e3Id, bidData(second)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(e3Id, alice.address, 1n, 0n, 3n, second.ciphertexts, second.ctCommitments, second.bidCommitment)
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(5n)
    })

    it('rejects a bid whose public input differs from storage', async () => {
      const fixture = await deployFixture()
      const { program, bidVerifier, actors } = fixture
      const e3Id = await createRound(fixture, { reserveStep: 1 })
      const [alice] = actors
      await deposit(fixture, alice)
      const made = makeBid(alice.address, 3)
      const good = bidPublicInputs(made, e3Id, { levels: 4, reserveStep: 1 }, 0, 1)
      // Each of the 11 inputs is checked in turn: a pinned value that differs makes the call revert.
      for (let slot = 0; slot < good.length; slot++) {
        const wrong = [...good]
        wrong[slot] = filled(0x99)
        await (await bidVerifier.expect(wrong)).wait()
        await expect(program.connect(alice).publishInput(e3Id, bidData(made)), `input ${slot}`).to.be.revertedWithCustomError(
          bidVerifier,
          'PublicInputsMismatch',
        )
      }
      await (await bidVerifier.expect(good)).wait()
      await expect(program.connect(alice).publishInput(e3Id, bidData(made))).to.emit(program, 'BidSubmitted')
    })

    it('numbers the versions of updates and allows three bids', async () => {
      const fixture = await deployFixture()
      const { program, bidVerifier, actors } = fixture
      const e3Id = await createRound(fixture)
      const [alice] = actors
      await deposit(fixture, alice)
      for (let version = 1; version <= 3; version++) {
        const made = makeBid(alice.address, version)
        await (await bidVerifier.expect(bidPublicInputs(made, e3Id, { levels: 4, reserveStep: 0 }, 0, version))).wait()
        await (await program.connect(alice).publishInput(e3Id, bidData(made))).wait()
        expect(await program.bidCommitments(e3Id, alice.address, BigInt(version))).to.equal(made.bidCommitment)
      }
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(7n)
      await (await bidVerifier.reset()).wait()
      await expect(program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 4)))).to.be.revertedWithCustomError(
        program,
        'TooManyBids',
      )
    })

    it('needs a deposit, the bidder as sender, a good proof, two ciphertexts and an open window', async () => {
      const fixture = await deployFixture()
      const { program, actors, relayer } = fixture
      const e3Id = await createRound(fixture)
      const [alice, bob] = actors
      await expect(program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'NotDeposited',
      )
      await deposit(fixture, alice)
      await expect(program.connect(relayer).publishInput(e3Id, bidData(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'SenderNotBidder',
      )
      await expect(
        program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 1), { proof: '0x02' })),
      ).to.be.revertedWithCustomError(fixture.bidVerifier, 'ProofRejected')
      const made = makeBid(alice.address, 1)
      await expect(
        program.connect(alice).publishInput(e3Id, bidData(made, { ciphertexts: [made.ciphertexts[0], '0x'] })),
      ).to.be.revertedWithCustomError(program, 'EmptyInputData')
      const raw = (ciphertexts: Hex[], commitments: Hex[]) =>
        encodeAbiParameters(parseAbiParameters('address, bytes[], bytes32[], bytes32, bytes, bytes, bytes'), [
          alice.address as Hex,
          ciphertexts,
          commitments,
          made.bidCommitment,
          '0x01',
          '0x',
          '0x',
        ])
      const [ct0, ct1] = made.ciphertexts
      const [c0, c1] = made.ctCommitments
      await expect(program.connect(alice).publishInput(e3Id, raw([ct0], [c0, c1]))).to.be.revertedWithCustomError(
        program,
        'InvalidBidShape',
      )
      await expect(program.connect(alice).publishInput(e3Id, raw([ct0, ct1], [c0]))).to.be.revertedWithCustomError(
        program,
        'InvalidBidShape',
      )
      await expect(program.connect(alice).publishInput(e3Id, raw([ct0, ct1, ct1], [c0, c1, c1]))).to.be.revertedWithCustomError(
        program,
        'InvalidBidShape',
      )
      await expect(program.connect(alice).publishInput(e3Id, bidData(makeBid(zeroAddress, 1)))).to.be.revertedWithCustomError(
        program,
        'BidderIsZero',
      )
      await expect(program.connect(bob).publishInput(e3Id, bidData(makeBid(bob.address, 1)))).to.be.revertedWithCustomError(
        program,
        'NotDeposited',
      )
      await (await fixture.interfold.setInputDeadline(e3Id, 1n)).wait()
      await expect(program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'InputDeadlineReached',
      )
    })

    it('takes a relayed bid with the bidder signature over both ciphertexts, once', async () => {
      const fixture = await deployFixture()
      const { program, actors, relayer } = fixture
      const e3Id = await createRound(fixture)
      const [alice, bob] = actors
      await deposit(fixture, alice)
      const made = makeBid(alice.address, 5)
      const signature = await signBid(fixture, alice, e3Id, 1, inputsHashOf(made))
      expect(await program.bidDigest(e3Id, alice.address, 1, inputsHashOf(made))).to.match(/^0x[0-9a-f]{64}$/)
      await expect(program.connect(relayer).publishInput(e3Id, bidData(made, { signature })))
        .to.emit(program, 'BidSubmitted')
        .withArgs(e3Id, alice.address, 1n, 0n, 1n, made.ciphertexts, made.ctCommitments, made.bidCommitment)
      // The same signature is useless for the next version.
      await expect(program.connect(relayer).publishInput(e3Id, bidData(made, { signature }))).to.be.revertedWithCustomError(
        program,
        'InvalidSignature',
      )
      const next = makeBid(alice.address, 6)
      const nextSignature = await signBid(fixture, alice, e3Id, 2, inputsHashOf(next))
      // A relayer cannot swap either ciphertext, either commitment or the bid commitment of a signed bid.
      const other = makeBid(alice.address, 9)
      const swaps = [
        { ciphertexts: [next.ciphertexts[0], other.ciphertexts[1]] as const },
        { ciphertexts: [other.ciphertexts[0], next.ciphertexts[1]] as const },
        { ctCommitments: [next.ctCommitments[0], other.ctCommitments[1]] as const },
        { ctCommitments: [other.ctCommitments[0], next.ctCommitments[1]] as const },
        { ciphertexts: [next.ciphertexts[1], next.ciphertexts[0]] as const },
        { bidCommitment: other.bidCommitment },
      ]
      for (const swap of swaps) {
        await expect(
          program.connect(relayer).publishInput(e3Id, bidData({ ...next, ...swap }, { signature: nextSignature })),
        ).to.be.revertedWithCustomError(program, 'InvalidSignature')
      }
      // A signature of another account is rejected.
      await expect(
        program.connect(relayer).publishInput(e3Id, bidData(next, { signature: await signBid(fixture, bob, e3Id, 2, inputsHashOf(next)) })),
      ).to.be.revertedWithCustomError(program, 'InvalidSignature')
      await expect(program.connect(relayer).publishInput(e3Id, bidData(next, { signature: nextSignature }))).to.emit(
        program,
        'BidSubmitted',
      )
    })

    it('applies the gate at the deposit and at the bid', async () => {
      const fixture = await deployFixture()
      const { program, actors } = fixture
      const [alice, bob, carol] = actors
      const gate = await fixture.ethers.deployContract('MerkleAllowlistGate')
      const members = [alice.address, bob.address].sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1)) as Hex[]
      const leaf = (member: string) => keccak256(member as Hex)
      const proofFor = (member: string) => {
        const other = members.find((m) => m.toLowerCase() !== member.toLowerCase()) as Hex
        return encodeAbiParameters(parseAbiParameters('bytes32[]'), [[leaf(other)]])
      }
      const gateConfig = encodeAbiParameters(parseAbiParameters('address[]'), [members])
      const e3Id = await createRound(fixture, { gate: (await gate.getAddress()) as Hex, gateConfig })
      await fund(fixture, alice)
      await fund(fixture, carol)
      await expect(program.connect(carol).deposit(e3Id, proofFor(alice.address))).to.be.revertedWithCustomError(
        program,
        'BidderNotEligible',
      )
      await expect(program.connect(alice).deposit(e3Id, proofFor(alice.address))).to.emit(program, 'Deposited')
      // A proof that the gate cannot read is rejected.
      await expect(program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 1), { gateProof: '0x' }))).to.be.revert(
        fixture.ethers,
      )
      const wrongProof = encodeAbiParameters(parseAbiParameters('bytes32[]'), [[filled(1)]])
      await expect(
        program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 1), { gateProof: wrongProof })),
      ).to.be.revertedWithCustomError(program, 'BidderNotEligible')
      await expect(
        program.connect(alice).publishInput(e3Id, bidData(makeBid(alice.address, 1), { gateProof: proofFor(alice.address) })),
      ).to.emit(program, 'BidSubmitted')
    })

    it('keeps the bids of two rounds apart', async () => {
      const fixture = await deployFixture()
      const { program, actors } = fixture
      const first = await createRound(fixture)
      const second = await createRound(fixture, { e3Id: E3_ID + 1n, reserveStep: 1 })
      const [alice] = actors
      await deposit(fixture, alice, first)
      await expect(program.connect(alice).publishInput(second, bidData(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'NotDeposited',
      )
      await bid(fixture, alice, 1, first)
      expect(await program.bidCount(first, alice.address)).to.equal(1n)
      expect(await program.bidCount(second, alice.address)).to.equal(0n)
      expect((await program.inputs(second)).numberOfLeaves).to.equal(1n)
    })
  })

  describe('a failed E3', () => {
    it('gives the escrows and the supply back', async () => {
      const fixture = await deployFixture()
      const { program, usdc, saleToken, interfold, actors, creator } = fixture
      const e3Id = await createRound(fixture)
      const [alice] = actors
      await deposit(fixture, alice, e3Id)
      await expect(program.refundEscrow(e3Id, alice.address)).to.be.revertedWithCustomError(program, 'E3NotFailed')
      await (await interfold.setStage(e3Id, 6)).wait()
      await expect(program.refundEscrow(e3Id, alice.address)).to.emit(program, 'EscrowRefunded').withArgs(e3Id, alice.address, ESCROW)
      expect(await usdc.balanceOf(alice.address)).to.equal(ESCROW)
      await expect(program.refundEscrow(e3Id, alice.address)).to.be.revertedWithCustomError(program, 'AlreadyClaimed')
      await expect(program.refundEscrow(e3Id, creator.address)).to.be.revertedWithCustomError(program, 'NotDeposited')
      await expect(program.connect(alice).refundSupply(e3Id)).to.be.revertedWithCustomError(program, 'NotCreator')
      await expect(program.connect(creator).refundSupply(e3Id)).to.emit(program, 'SupplyRefunded').withArgs(e3Id, creator.address, SUPPLY)
      expect(await saleToken.balanceOf(creator.address)).to.equal(SUPPLY)
      await expect(program.connect(creator).refundSupply(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      expect(await saleToken.balanceOf(fixture.programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(fixture.programAddress)).to.equal(0n)
    })

    it('leaves the other rounds alone', async () => {
      const fixture = await deployFixture()
      const { program, usdc, saleToken, interfold, actors, creator } = fixture
      const failed = await createRound(fixture)
      const live = await createRound(fixture, { e3Id: E3_ID + 1n })
      await deposit(fixture, actors[0], failed)
      await deposit(fixture, actors[1], live)
      await (await interfold.setStage(failed, 6)).wait()
      await (await program.refundEscrow(failed, actors[0].address)).wait()
      await (await program.connect(creator).refundSupply(failed)).wait()
      // The live round still holds its supply and its escrow.
      expect(await saleToken.balanceOf(fixture.programAddress)).to.equal(SUPPLY)
      expect(await usdc.balanceOf(fixture.programAddress)).to.equal(ESCROW)
      await expect(program.refundEscrow(live, actors[1].address)).to.be.revertedWithCustomError(program, 'E3NotFailed')
    })
  })

  describe('compute verification', () => {
    it('declares its interfaces', async () => {
      const { program } = await deployFixture()
      expect(await program.supportsInterface('0x01ffc9a7')).to.equal(true)
      expect(await program.supportsInterface('0xffffffff')).to.equal(false)
      expect(await program.ENCRYPTION_SCHEME_ID()).to.equal(keccak256(stringToHex('fhe.rs:BFV')))
    })
  })
})
