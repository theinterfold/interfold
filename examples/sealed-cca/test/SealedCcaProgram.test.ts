// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { type Hex, encodeAbiParameters, keccak256, parseAbiParameters, zeroAddress } from 'viem'
import {
  BN254_R,
  ESCROW,
  E3_ID,
  E3_ID_ABOVE_FIELD,
  KEY,
  PRICES,
  SUPPLY,
  U18,
  VK_ANCHOR,
  type Fixture,
  createSale,
  deployFixture,
  fund,
  requestSale,
  signBid,
  signPermit,
} from './fixture'
import {
  KIND_CAPPED,
  KIND_UNDERSUBSCRIBED,
  KIND_UNCAPPED,
  MAX_BIDDERS,
  demandCurve,
  encodeBidInput,
  encodeClaim,
  encodeSaleParams,
  filled,
  outputPlaintext,
  referenceClear,
  referenceOutcome,
  compare,
} from './helpers'

const bytes32 = (value: bigint | number | string) => `0x${BigInt(value).toString(16).padStart(64, '0')}` as Hex

/** The bid of one actor: bytes that stand for a ciphertext and its commitments. */
function makeBid(bidder: string, seed: number) {
  return {
    bidder: bidder as Hex,
    ciphertext: `0x${seed.toString(16).padStart(2, '0').repeat(16)}` as Hex,
    ctCommitment: filled(seed),
    bidCommitment: filled(0x80 + seed),
  }
}

/** The public inputs of the bid proof, in the order of `circuits/PUBLIC_INPUTS.md`: `e3_id` is `e3Id mod r`. */
function bidPublicInputs(bid: ReturnType<typeof makeBid>, e3Id: bigint, levels: number, index: number, version: number): Hex[] {
  return [
    bid.ctCommitment,
    bid.bidCommitment,
    bytes32(bid.bidder),
    bytes32(e3Id % BN254_R),
    bytes32(levels),
    bytes32(index),
    bytes32(version),
    KEY,
    VK_ANCHOR,
  ]
}

/** `keccak256(abi.encode(ctCommitment, bidCommitment, keccak256(ciphertext)))`: what a relayed bid signs. */
const inputsHashOf = (bid: ReturnType<typeof makeBid>) =>
  keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32, bytes32, bytes32'), [bid.ctCommitment, bid.bidCommitment, keccak256(bid.ciphertext)]),
  )

async function deposit(fixture: Fixture, actor: Fixture['actors'][number], e3Id = E3_ID) {
  await fund(fixture, actor)
  await (await fixture.program.connect(actor).deposit(e3Id, '0x')).wait()
}

async function bid(fixture: Fixture, actor: Fixture['actors'][number], seed: number, e3Id = E3_ID, bidCommitment?: Hex) {
  const made = { ...makeBid(actor.address, seed), ...(bidCommitment && { bidCommitment }) }
  await (await fixture.program.connect(actor).publishInput(e3Id, encodeBidInput(made))).wait()
  return made
}

describe('SealedCcaProgram', () => {
  describe('request', () => {
    it('pulls the supply from the requester and stores the sale', async () => {
      const fixture = await deployFixture()
      const { program, creator, saleToken, usdc, programAddress } = fixture
      const { e3Id, tx } = await requestSale(fixture)
      await expect(tx())
        .to.emit(program, 'SaleCreated')
        .withArgs(
          e3Id,
          creator.address,
          0,
          4,
          [...PRICES, ...Array(12).fill(0n)],
          await saleToken.getAddress(),
          await usdc.getAddress(),
          SUPPLY,
          ESCROW,
          'Unit test sale',
          zeroAddress,
        )
      expect(await saleToken.balanceOf(programAddress)).to.equal(SUPPLY)
      expect(await saleToken.balanceOf(creator.address)).to.equal(0n)
      const sale = await program.sale(e3Id)
      expect(sale.revealMode).to.equal(0n)
      expect(sale.levels).to.equal(4n)
      expect(sale.creator).to.equal(creator.address)
      expect(sale.supply).to.equal(SUPPLY)
      expect(sale.escrow).to.equal(ESCROW)
      expect(sale.saleUnit).to.equal(U18)
      expect([...(await program.salePrices(e3Id))].slice(0, 5)).to.deep.equal([...PRICES, 0n])
      // Leaf 0 is the configuration leaf.
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(1n)
    })

    it('has the shared configuration leaf and bid leaf', async () => {
      const { program } = await deployFixture()
      const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
      const config = BigInt(keccak256(`0x${Buffer.from('interfold-sealed-cca-config-v1').toString('hex')}00`)) % field
      expect(await program.configLeaf(0)).to.equal(config)
      // The vector of `program/src/lib.rs` and auction-e2e.
      expect(await program.inputLeaf(filled(0x11), filled(0x22), '0x3333333333333333333333333333333333333333', 2)).to.equal(
        0x0b8ba63e8917dfb3f66cfcc1b0be5d3a8f8613ba8092d690a43b84daec02b94an,
      )
    })

    it('rejects reveal mode 1 and bad parameters', async () => {
      const fixture = await deployFixture()
      const saleConfig = await fixture.ethers.getContractAt('SaleConfig', fixture.programAddress)
      await expect((await requestSale(fixture, { revealMode: 1 })).tx()).to.be.revertedWithCustomError(saleConfig, 'RevealModeUnsupported')
      await expect((await requestSale(fixture, { prices: [1n] })).tx()).to.be.revertedWithCustomError(saleConfig, 'InvalidLevels')
      await expect((await requestSale(fixture, { prices: [2n, 2n] })).tx()).to.be.revertedWithCustomError(saleConfig, 'InvalidPrices')
      await expect((await requestSale(fixture, { prices: [0n, 2n] })).tx()).to.be.revertedWithCustomError(saleConfig, 'InvalidPrices')
      await expect((await requestSale(fixture, { supply: 0n })).tx()).to.be.revertedWithCustomError(saleConfig, 'InvalidAmount')
      await expect((await requestSale(fixture, { escrow: 0n })).tx()).to.be.revertedWithCustomError(saleConfig, 'InvalidAmount')
      await expect((await requestSale(fixture, { supply: 2n ** 112n + 1n })).tx()).to.be.revertedWithCustomError(
        saleConfig,
        'InvalidAmount',
      )
      // The gate must be a contract.
      await expect((await requestSale(fixture, { gate: '0x00000000000000000000000000000000000000aa' })).tx()).to.be.revertedWithCustomError(
        saleConfig,
        'InvalidGate',
      )
      await expect((await requestSale(fixture, { gateConfig: '0x1234' })).tx()).to.be.revertedWithCustomError(
        saleConfig,
        'GateConfigWithoutGate',
      )
    })

    it('rejects prices after the last step that are not zero', async () => {
      const fixture = await deployFixture()
      const saleConfig = await fixture.ethers.getContractAt('SaleConfig', fixture.programAddress)
      const { e3Id } = await requestSale(fixture)
      const params = encodeSaleParams({
        prices: PRICES,
        saleToken: (await fixture.saleToken.getAddress()) as Hex,
        supply: SUPPLY,
        paymentToken: (await fixture.usdc.getAddress()) as Hex,
        escrow: ESCROW,
      })
      // Put a price in the slot of step 4 by editing the encoded array: the prices start at word 2.
      const word = 2 + 4
      const edited = `0x${params.slice(2, 2 + 64 * word)}${'0'.repeat(63)}1${params.slice(2 + 64 * (word + 1))}` as Hex
      await expect(fixture.interfold.request(e3Id, fixture.programAddress, edited)).to.be.revertedWithCustomError(
        saleConfig,
        'InvalidPrices',
      )
    })

    it('fails when the requester has not approved the supply', async () => {
      const fixture = await deployFixture()
      await expect((await requestSale(fixture, { noApproval: true })).tx()).to.be.revert(fixture.ethers)
    })

    it('rejects a caller that is not Interfold, and a second request of the same E3', async () => {
      const fixture = await deployFixture()
      const { e3Id, params } = await requestSale(fixture)
      await expect(fixture.program.connect(fixture.actors[0]).validate(e3Id, 0n, '0x', '0x', params)).to.be.revertedWithCustomError(
        fixture.program,
        'CallerNotAuthorized',
      )
      await createSale(fixture)
      await expect(fixture.interfold.request(e3Id, fixture.programAddress, params)).to.be.revertedWithCustomError(
        fixture.program,
        'E3AlreadyInitialized',
      )
    })
  })

  describe('deposit', () => {
    it('takes the escrow once and numbers the bidders', async () => {
      const fixture = await deployFixture()
      const { program, usdc, programAddress, actors } = fixture
      const e3Id = await createSale(fixture)
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
      const e3Id = await createSale(fixture, { inputDeadline: 2n ** 40n })
      const [alice] = fixture.actors
      await expect(fixture.program.connect(alice).deposit(e3Id, '0x')).to.be.revert(fixture.ethers)
      await fund(fixture, alice)
      await (await fixture.interfold.setInputDeadline(e3Id, 1n)).wait()
      await expect(fixture.program.connect(alice).deposit(e3Id, '0x')).to.be.revertedWithCustomError(
        fixture.program,
        'InputDeadlineReached',
      )
    })

    it('takes a deposit for a bidder with an EIP-2612 permit, sent by a relayer', async () => {
      const fixture = await deployFixture()
      const { program, usdc, relayer, actors, programAddress } = fixture
      const e3Id = await createSale(fixture)
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
      const e3Id = await createSale(fixture)
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

    it('accepts 112 bidders and rejects the 113th', async () => {
      const fixture = await deployFixture()
      const { program, usdc, relayer, ethers } = fixture
      const e3Id = await createSale(fixture)
      const deadline = 2n ** 40n
      for (let i = 0; i < MAX_BIDDERS; i++) {
        const wallet = ethers.Wallet.createRandom(ethers.provider)
        await (await usdc.mint(wallet.address, ESCROW)).wait()
        const { v, r, s } = await signPermit(fixture, wallet, ESCROW, deadline)
        await (await program.connect(relayer).depositFor(e3Id, wallet.address, '0x', deadline, v, r, s)).wait()
      }
      expect(await program.bidderCount(e3Id)).to.equal(BigInt(MAX_BIDDERS))
      const extra = ethers.Wallet.createRandom(ethers.provider)
      await (await usdc.mint(extra.address, ESCROW)).wait()
      const { v, r, s } = await signPermit(fixture, extra, ESCROW, deadline)
      await expect(program.connect(relayer).depositFor(e3Id, extra.address, '0x', deadline, v, r, s)).to.be.revertedWithCustomError(
        program,
        'TooManyBidders',
      )
    })
  })

  describe('bids', () => {
    it('takes a bid after a deposit, with the proof inputs from storage', async () => {
      const fixture = await deployFixture()
      const { program, bidVerifier, actors } = fixture
      const e3Id = await createSale(fixture)
      const [alice, bob] = actors
      await deposit(fixture, alice)
      await deposit(fixture, bob)
      const made = makeBid(bob.address, 2)
      // Bob has the index 1 and his first bid has the version 1.
      await (await bidVerifier.expect(bidPublicInputs(made, e3Id, 4, 1, 1))).wait()
      await expect(program.connect(bob).publishInput(e3Id, encodeBidInput(made)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(e3Id, bob.address, 1n, 1n, made.ciphertext, made.ctCommitment, made.bidCommitment)
      expect(await program.bidCount(e3Id, bob.address)).to.equal(1n)
      expect(await program.bidCommitments(e3Id, bob.address, 1n)).to.equal(made.bidCommitment)
      // The config leaf and one leaf per bid.
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(2n)
      const leaf = await program.inputLeaf(keccak256(made.ciphertext), made.ctCommitment, bob.address, 1)
      expect(leaf).to.not.equal(0n)
    })

    it('passes e3Id mod r to the bid verifier when the E3 id is above the field', async () => {
      const fixture = await deployFixture()
      const { program, bidVerifier, actors } = fixture
      expect(E3_ID_ABOVE_FIELD >= BN254_R).to.equal(true)
      const e3Id = await createSale(fixture, { e3Id: E3_ID_ABOVE_FIELD })
      const [alice] = actors
      await deposit(fixture, alice, e3Id)
      const made = makeBid(alice.address, 3)
      // The circuit takes a field element, so the verifier must see the reduced id, not the 256-bit one.
      await (await bidVerifier.expect(bidPublicInputs(made, e3Id, 4, 0, 1))).wait()
      await expect(program.connect(alice).publishInput(e3Id, encodeBidInput(made)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(e3Id, alice.address, 1n, 0n, made.ciphertext, made.ctCommitment, made.bidCommitment)
      // Storage and events keep the full id.
      expect(await program.bidCount(e3Id, alice.address)).to.equal(1n)
      expect(await program.bidCommitments(e3Id, alice.address, 1n)).to.equal(made.bidCommitment)
    })

    it('numbers the versions of updates and allows three bids', async () => {
      const fixture = await deployFixture()
      const { program, bidVerifier, actors } = fixture
      const e3Id = await createSale(fixture)
      const [alice] = actors
      await deposit(fixture, alice)
      for (let version = 1; version <= 3; version++) {
        const made = makeBid(alice.address, version)
        await (await bidVerifier.expect(bidPublicInputs(made, e3Id, 4, 0, version))).wait()
        await (await program.connect(alice).publishInput(e3Id, encodeBidInput(made))).wait()
        expect(await program.bidCommitments(e3Id, alice.address, BigInt(version))).to.equal(made.bidCommitment)
      }
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(4n)
      await (await bidVerifier.reset()).wait()
      await expect(program.connect(alice).publishInput(e3Id, encodeBidInput(makeBid(alice.address, 4)))).to.be.revertedWithCustomError(
        program,
        'TooManyBids',
      )
    })

    it('needs a deposit, the bidder as sender, a good proof and an open window', async () => {
      const fixture = await deployFixture()
      const { program, actors, relayer } = fixture
      const e3Id = await createSale(fixture)
      const [alice, bob] = actors
      await expect(program.connect(alice).publishInput(e3Id, encodeBidInput(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'NotDeposited',
      )
      await deposit(fixture, alice)
      await expect(program.connect(relayer).publishInput(e3Id, encodeBidInput(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'SenderNotBidder',
      )
      await expect(
        program.connect(alice).publishInput(e3Id, encodeBidInput({ ...makeBid(alice.address, 1), proof: '0x02' })),
      ).to.be.revertedWithCustomError(fixture.bidVerifier, 'ProofRejected')
      await expect(
        program.connect(alice).publishInput(e3Id, encodeBidInput({ ...makeBid(alice.address, 1), ciphertext: '0x' })),
      ).to.be.revertedWithCustomError(program, 'EmptyInputData')
      await expect(program.connect(alice).publishInput(e3Id, encodeBidInput(makeBid(zeroAddress, 1)))).to.be.revertedWithCustomError(
        program,
        'BidderIsZero',
      )
      await expect(program.connect(bob).publishInput(e3Id, encodeBidInput(makeBid(bob.address, 1)))).to.be.revertedWithCustomError(
        program,
        'NotDeposited',
      )
      await (await fixture.interfold.setInputDeadline(e3Id, 1n)).wait()
      await expect(program.connect(alice).publishInput(e3Id, encodeBidInput(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'InputDeadlineReached',
      )
    })

    it('takes a relayed bid with the bidder signature, once', async () => {
      const fixture = await deployFixture()
      const { program, actors, relayer } = fixture
      const e3Id = await createSale(fixture)
      const [alice, bob] = actors
      await deposit(fixture, alice)
      const made = makeBid(alice.address, 5)
      const signature = await signBid(fixture, alice, e3Id, 1, inputsHashOf(made))
      expect(await program.bidDigest(e3Id, alice.address, 1, inputsHashOf(made))).to.be.a('string')
      await expect(program.connect(relayer).publishInput(e3Id, encodeBidInput({ ...made, signature })))
        .to.emit(program, 'BidSubmitted')
        .withArgs(e3Id, alice.address, 1n, 0n, made.ciphertext, made.ctCommitment, made.bidCommitment)
      // The same signature is useless for the next version.
      await expect(program.connect(relayer).publishInput(e3Id, encodeBidInput({ ...made, signature }))).to.be.revertedWithCustomError(
        program,
        'InvalidSignature',
      )
      // A relayer cannot swap the ciphertext of a signed bid.
      const next = makeBid(alice.address, 6)
      const nextSignature = await signBid(fixture, alice, e3Id, 2, inputsHashOf(next))
      await expect(
        program
          .connect(relayer)
          .publishInput(e3Id, encodeBidInput({ ...next, ciphertext: makeBid(alice.address, 9).ciphertext, signature: nextSignature })),
      ).to.be.revertedWithCustomError(program, 'InvalidSignature')
      // A signature of another account is rejected.
      await expect(
        program
          .connect(relayer)
          .publishInput(e3Id, encodeBidInput({ ...next, signature: await signBid(fixture, bob, e3Id, 2, inputsHashOf(next)) })),
      ).to.be.revertedWithCustomError(program, 'InvalidSignature')
      await expect(program.connect(relayer).publishInput(e3Id, encodeBidInput({ ...next, signature: nextSignature }))).to.emit(
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
      const e3Id = await createSale(fixture, { gate: (await gate.getAddress()) as Hex, gateConfig })
      await fund(fixture, alice)
      await fund(fixture, carol)
      await expect(program.connect(carol).deposit(e3Id, proofFor(alice.address))).to.be.revertedWithCustomError(
        program,
        'BidderNotEligible',
      )
      await expect(program.connect(alice).deposit(e3Id, proofFor(alice.address))).to.emit(program, 'Deposited')
      // A proof that the gate cannot read is rejected.
      await expect(
        program.connect(alice).publishInput(e3Id, encodeBidInput({ ...makeBid(alice.address, 1), gateProof: '0x' })),
      ).to.be.revert(fixture.ethers)
      const wrongProof = encodeAbiParameters(parseAbiParameters('bytes32[]'), [[filled(1)]])
      await expect(
        program.connect(alice).publishInput(e3Id, encodeBidInput({ ...makeBid(alice.address, 1), gateProof: wrongProof })),
      ).to.be.revertedWithCustomError(program, 'BidderNotEligible')
      await expect(
        program.connect(alice).publishInput(e3Id, encodeBidInput({ ...makeBid(alice.address, 1), gateProof: proofFor(alice.address) })),
      ).to.emit(program, 'BidSubmitted')
    })
  })

  /** A sale with bidders at the steps `steps`, all counted at their first bid; bidder `i` is `actors[i]`. */
  async function playSale(
    fixture: Fixture,
    steps: number[],
    options: {
      e3Id?: bigint
      countedVersions?: number[]
      extraBids?: Record<number, number>
      firstBidCommitments?: Record<number, Hex>
    } = {},
  ) {
    const e3Id = await createSale(fixture, { e3Id: options.e3Id })
    const made = []
    for (let i = 0; i < steps.length; i++) {
      const actor = fixture.actors[i]
      await deposit(fixture, actor, e3Id)
      made.push([await bid(fixture, actor, i + 1, e3Id, options.firstBidCommitments?.[i])])
      for (let extra = 0; extra < (options.extraBids?.[i] ?? 0); extra++) made[i].push(await bid(fixture, actor, 40 + 3 * i + extra, e3Id))
    }
    const counted = options.countedVersions ?? steps.map(() => 1)
    const countedSteps = steps.filter((_, i) => counted[i] > 0)
    const plaintext = outputPlaintext(demandCurve(countedSteps), counted)
    await (await fixture.interfold.setPlaintext(e3Id, plaintext)).wait()
    return { e3Id, made, counted, countedSteps }
  }

  describe('clearing and claims', () => {
    it('clears an uncapped sale and pays winners and losers', async () => {
      const fixture = await deployFixture()
      const { program, actors, usdc, saleToken, claimVerifier, creator, programAddress } = fixture
      // alice 3, bob 2, carol 2 and dave 0 bid; erin deposits and bids but is dropped; frank only deposits.
      const steps = [3, 2, 2, 0, 1, 1]
      const { e3Id, made } = await playSale(fixture, steps, { countedVersions: [1, 1, 1, 1, 0, 0] })
      const [alice, bob, carol, dave, erin, frank] = actors
      const countedSteps = [3, 2, 2, 0]
      const expected = referenceClear({
        prices: PRICES,
        c: demandCurve(countedSteps).slice(0, 4).map(BigInt),
        supply: SUPPLY,
        escrow: ESCROW,
        unit: U18,
      })
      expect(expected.kind).to.equal(KIND_UNCAPPED)

      // Nothing is cleared before `clear`, and the views know it.
      expect((await program.clearing(e3Id)).cleared).to.equal(false)
      await expect(program.countedVersion(e3Id, alice.address)).to.be.revertedWithCustomError(program, 'NotCleared')
      const c = demandCurve(countedSteps)
      await expect(program.clear(e3Id)).to.emit(program, 'SaleCleared').withArgs(e3Id, expected.pStar, expected.kind, expected.step, c)
      const cleared = await program.clearing(e3Id)
      expect([
        cleared.cleared,
        cleared.kind,
        cleared.step,
        cleared.pStar,
        cleared.fullTokens,
        cleared.marginalTokens,
        cleared.soldTotal,
      ]).to.deep.equal([
        true,
        BigInt(expected.kind),
        BigInt(expected.step),
        expected.pStar,
        expected.fullTokens,
        expected.marginalTokens,
        expected.sold,
      ])
      expect(await program.countedVersion(e3Id, alice.address)).to.equal(1n)
      expect(await program.countedVersion(e3Id, erin.address)).to.equal(0n)

      // A winner claims with a proof of cmp: the verifier must see the counted commitment, bidder, e3Id, k and cmp.
      const k = expected.step
      await (
        await claimVerifier.expect([made[1][0].bidCommitment, bytes32(bob.address), bytes32(e3Id % BN254_R), bytes32(k), bytes32(2)])
      ).wait()
      const bobOutcome = referenceOutcome(expected, 2, ESCROW, U18)
      await expect(program.connect(creator).claim(e3Id, bob.address, encodeClaim(compare(2, k))))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, bob.address, bobOutcome.tokens, bobOutcome.paid, bobOutcome.refund)
      expect(await saleToken.balanceOf(bob.address)).to.equal(bobOutcome.tokens)
      expect(await usdc.balanceOf(bob.address)).to.equal(bobOutcome.refund)
      // Twice is not possible.
      await expect(program.claim(e3Id, bob.address, encodeClaim(compare(2, k)))).to.be.revertedWithCustomError(program, 'AlreadyClaimed')

      // The same claim for another bidder with the wrong public inputs is rejected by the verifier.
      await expect(program.claim(e3Id, carol.address, encodeClaim(2))).to.be.revertedWithCustomError(claimVerifier, 'PublicInputsMismatch')
      await (await claimVerifier.reset()).wait()
      await expect(program.claim(e3Id, carol.address, encodeClaim(3))).to.be.revertedWithCustomError(program, 'InvalidComparison')
      await expect(program.claim(e3Id, carol.address, encodeClaim(2, '0x02'))).to.be.revertedWithCustomError(claimVerifier, 'ProofRejected')
      await (await program.claim(e3Id, carol.address, encodeClaim(compare(2, k)))).wait()
      await (await program.claim(e3Id, alice.address, encodeClaim(compare(3, k)))).wait()
      // A loser (step 0 < k = 1) gets the whole escrow back.
      await expect(program.claim(e3Id, dave.address, encodeClaim(compare(0, k))))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, dave.address, 0n, 0n, ESCROW)
      expect(await usdc.balanceOf(dave.address)).to.equal(ESCROW)
      // A dropped bidder and a depositor that never bid get the whole escrow, with no proof at all.
      await expect(program.claim(e3Id, erin.address, '0x'))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, erin.address, 0n, 0n, ESCROW)
      await expect(program.claim(e3Id, frank.address, '0x'))
        .to.emit(program, 'Claimed')
        .withArgs(e3Id, frank.address, 0n, 0n, ESCROW)
      await expect(program.claim(e3Id, fixture.relayer.address, '0x')).to.be.revertedWithCustomError(program, 'NotDeposited')

      // The creator takes the payments and the unsold tokens; nothing stays behind.
      const winners = referenceOutcome(expected, 3, ESCROW, U18)
      const proceeds = 3n * winners.paid
      expect(await program.proceedsAvailable(e3Id)).to.equal(proceeds)
      await expect(program.connect(alice).withdrawProceeds(e3Id)).to.be.revertedWithCustomError(program, 'NotCreator')
      await expect(program.connect(creator).withdrawProceeds(e3Id))
        .to.emit(program, 'ProceedsWithdrawn')
        .withArgs(e3Id, creator.address, proceeds)
      await expect(program.connect(creator).withdrawProceeds(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      expect(await usdc.balanceOf(creator.address)).to.equal(proceeds)
      const unsold = SUPPLY - expected.sold
      expect(await program.unsoldAmount(e3Id)).to.equal(unsold)
      await expect(program.connect(creator).withdrawUnsold(e3Id))
        .to.emit(program, 'UnsoldWithdrawn')
        .withArgs(e3Id, creator.address, unsold)
      await expect(program.connect(creator).withdrawUnsold(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      expect(await saleToken.balanceOf(creator.address)).to.equal(unsold)
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(0n)
    })

    it('clears a capped sale: full winners, marginal bidders and a loser', async () => {
      const fixture = await deployFixture()
      const { program, actors, usdc, saleToken, creator, programAddress } = fixture
      // alice at the top, four at step 1, frank at step 0.
      const steps = [3, 1, 1, 1, 1, 0]
      const { e3Id } = await playSale(fixture, steps)
      const expected = referenceClear({
        prices: PRICES,
        c: demandCurve(steps).slice(0, 4).map(BigInt),
        supply: SUPPLY,
        escrow: ESCROW,
        unit: U18,
      })
      expect(expected.kind).to.equal(KIND_CAPPED)
      expect(expected.step).to.equal(1)
      expect(expected.marginalTokens).to.equal((SUPPLY - expected.fullTokens) / 4n) // sold 25 + 4 * 18.75 = 100
      // The first claim clears the sale.
      const [alice, bob] = actors
      await expect(program.claim(e3Id, alice.address, encodeClaim(compare(3, 1)))).to.emit(program, 'SaleCleared')
      for (let i = 1; i < steps.length; i++) {
        const actor = actors[i]
        await (await program.claim(e3Id, actor.address, encodeClaim(compare(steps[i], expected.step)))).wait()
        const outcome = referenceOutcome(expected, steps[i], ESCROW, U18)
        expect(await saleToken.balanceOf(actor.address), `bidder ${i} tokens`).to.equal(outcome.tokens)
        expect(await usdc.balanceOf(actor.address), `bidder ${i} refund`).to.equal(outcome.refund)
      }
      expect(await saleToken.balanceOf(alice.address)).to.equal(expected.fullTokens)
      expect(await saleToken.balanceOf(bob.address)).to.equal(expected.marginalTokens)
      // The marginal bidders pay less than the escrow: 18.75 tokens at 2.00 is 37.50.
      expect(await usdc.balanceOf(bob.address)).to.equal(ESCROW - 37_500_000n)
      await (await program.connect(creator).withdrawProceeds(e3Id)).wait()
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(0n)
    })

    it('refunds the creator when the sale is undersubscribed', async () => {
      const fixture = await deployFixture()
      const { program, actors, usdc, saleToken, creator, programAddress } = fixture
      // One bidder buys 50 of the 100 tokens at the lowest price.
      const { e3Id } = await playSale(fixture, [2])
      const [alice] = actors
      // Everybody is filled at the lowest price and no proof is needed.
      await (await program.claim(e3Id, alice.address, '0x')).wait()
      const cleared = await program.clearing(e3Id)
      expect(cleared.kind).to.equal(0n)
      expect(cleared.pStar).to.equal(PRICES[0])
      expect(await saleToken.balanceOf(alice.address)).to.equal(50n * U18)
      expect(await usdc.balanceOf(alice.address)).to.equal(0n)
      await (await program.connect(creator).withdrawProceeds(e3Id)).wait()
      expect(await usdc.balanceOf(creator.address)).to.equal(ESCROW)
      await expect(program.connect(creator).withdrawUnsold(e3Id))
        .to.emit(program, 'UnsoldWithdrawn')
        .withArgs(e3Id, creator.address, 50n * U18)
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(0n)
    })

    it('verifies a real claim proof for an E3 id above the field', async () => {
      const vectors = JSON.parse(
        readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../sdk/test-vectors/claims-e3-above-field.json'), 'utf8'),
      ) as {
        e3Id: string
        bidder: Hex
        bidCommitment: Hex
        claims: { b: number; k: number; cmp: number; proof: Hex; publicInputs: Hex[] }[]
      }
      expect(BigInt(vectors.e3Id)).to.equal(E3_ID_ABOVE_FIELD)
      // The proofs come from the SDK with the real claim circuit; the program verifies them with the generated verifier.
      const fixture = await deployFixture({ realClaimVerifier: true })
      const { program, actors } = fixture
      const [alice] = actors
      expect(alice.address).to.equal(vectors.bidder)
      // Alice bids the step of the vectors; her commitment is the one the SDK computed with `e3Id mod r`.
      const steps = [vectors.claims[0].b, 3, 2, 0]
      const { e3Id } = await playSale(fixture, steps, { e3Id: E3_ID_ABOVE_FIELD, firstBidCommitments: { 0: vectors.bidCommitment } })
      await (await program.clear(e3Id)).wait()
      const k = Number((await program.clearing(e3Id)).step)
      const proven = vectors.claims.find((claim) => claim.k === k)!
      expect(proven.cmp).to.equal(compare(steps[0], k))
      expect(BigInt(proven.publicInputs[2])).to.equal(E3_ID_ABOVE_FIELD % BN254_R)
      await expect(program.claim(e3Id, alice.address, encodeClaim(proven.cmp, proven.proof)))
        .to.emit(program, 'Claimed')
        .withArgs(
          e3Id,
          alice.address,
          (tokens: bigint) => tokens > 0n,
          (paid: bigint) => paid > 0n,
          (refund: bigint) => refund >= 0n,
        )
    })

    it('uses the bid commitment of the counted version of an updated bid', async () => {
      const fixture = await deployFixture()
      const { program, actors, claimVerifier } = fixture
      // Alice bids three times; the program counted version 2.
      const { e3Id, made } = await playSale(fixture, [2, 1, 0], { countedVersions: [2, 1, 1], extraBids: { 0: 2 } })
      const [alice] = actors
      await (await program.clear(e3Id)).wait()
      expect(await program.countedVersion(e3Id, alice.address)).to.equal(2n)
      const k = Number((await program.clearing(e3Id)).step)
      await (
        await claimVerifier.expect([
          made[0][1].bidCommitment,
          bytes32(alice.address),
          bytes32(e3Id % BN254_R),
          bytes32(k),
          bytes32(compare(2, k)),
        ])
      ).wait()
      await (await program.claim(e3Id, alice.address, encodeClaim(compare(2, k)))).wait()
    })

    it('clears a full sale of 112 bidders in one transaction', async () => {
      const fixture = await deployFixture()
      const { program, usdc, relayer, ethers, interfold } = fixture
      const e3Id = await createSale(fixture)
      const deadline = 2n ** 40n
      const steps: number[] = []
      const wallets = []
      for (let i = 0; i < MAX_BIDDERS; i++) {
        const wallet = ethers.Wallet.createRandom(ethers.provider)
        wallets.push(wallet)
        await (await usdc.mint(wallet.address, ESCROW)).wait()
        const { v, r, s } = await signPermit(fixture, wallet, ESCROW, deadline)
        await (await program.connect(relayer).depositFor(e3Id, wallet.address, '0x', deadline, v, r, s)).wait()
        // Bids are spread over the four steps.
        steps.push(i % 4)
        const made = makeBid(wallet.address, (i % 100) + 1)
        const signature = await signBid(fixture, wallet, e3Id, 1, inputsHashOf(made))
        await (await program.connect(relayer).publishInput(e3Id, encodeBidInput({ ...made, signature }))).wait()
      }
      await (
        await interfold.setPlaintext(
          e3Id,
          outputPlaintext(
            demandCurve(steps),
            steps.map(() => 1),
          ),
        )
      ).wait()
      const receipt = await (await program.clear(e3Id)).wait()
      const expected = referenceClear({
        prices: PRICES,
        c: demandCurve(steps).slice(0, 4).map(BigInt),
        supply: SUPPLY,
        escrow: ESCROW,
        unit: U18,
      })
      const cleared = await program.clearing(e3Id)
      expect([cleared.kind, cleared.step, cleared.pStar]).to.deep.equal([BigInt(expected.kind), BigInt(expected.step), expected.pStar])
      expect(await program.countedVersion(e3Id, wallets[111].address)).to.equal(1n)
      // The decoding of 128 slots fits a block with a wide margin.
      expect(receipt?.gasUsed ?? 0n).to.be.lessThan(8_000_000n)
    })

    it('rejects an output that does not fit the sale', async () => {
      const fixture = await deployFixture()
      const { program, interfold } = fixture
      const e3Id = await createSale(fixture)
      await expect(program.clear(e3Id)).to.be.revertedWithCustomError(program, 'OutputNotPublished')
      await expect(program.claim(e3Id, fixture.actors[0].address, '0x')).to.be.revertedWithCustomError(program, 'OutputNotPublished')
      await deposit(fixture, fixture.actors[0], e3Id)
      await bid(fixture, fixture.actors[0], 1, e3Id)
      // A counted version above the bids of the bidder.
      await (await interfold.setPlaintext(e3Id, outputPlaintext(demandCurve([1]), [2]))).wait()
      await expect(program.clear(e3Id)).to.be.revertedWithCustomError(
        await fixture.ethers.getContractAt('SaleOutput', fixture.programAddress),
        'InvalidOutput',
      )
      // A curve that counts more bidders than are counted.
      await (await interfold.setPlaintext(e3Id, outputPlaintext(demandCurve([1, 1]), [1]))).wait()
      await expect(program.clear(e3Id)).to.be.revertedWithCustomError(
        await fixture.ethers.getContractAt('SaleOutput', fixture.programAddress),
        'InvalidOutput',
      )
      // A curve that rises, a curve above the levels, and a plaintext of the wrong length.
      const rising = demandCurve([1])
      rising[1] = 0
      rising[2] = 1
      await (await interfold.setPlaintext(e3Id, outputPlaintext(rising, [1]))).wait()
      await expect(program.clear(e3Id)).to.be.revert(fixture.ethers)
      const tall = demandCurve([1])
      tall[5] = 0
      tall[4] = 1
      tall[3] = 1
      tall[2] = 1
      await (await interfold.setPlaintext(e3Id, outputPlaintext(tall, [1]))).wait()
      await expect(program.clear(e3Id)).to.be.revert(fixture.ethers)
      await (await interfold.setPlaintext(e3Id, '0x1234')).wait()
      await expect(program.clear(e3Id)).to.be.revert(fixture.ethers)
      // The right output works.
      await (await interfold.setPlaintext(e3Id, outputPlaintext(demandCurve([1]), [1]))).wait()
      await expect(program.clear(e3Id)).to.emit(program, 'SaleCleared')
    })
  })

  describe('claim window and sweep', () => {
    const DAY = 24n * 3600n
    const WINDOW = 30n * DAY

    /** Mines a block with the timestamp `at`, or the next second if the chain is already past it. */
    async function mineAt(fixture: Fixture, at: bigint) {
      const latest = BigInt((await fixture.ethers.provider.getBlock('latest'))!.timestamp)
      await fixture.ethers.provider.send('evm_setNextBlockTimestamp', [Number(at > latest ? at : latest + 1n)])
      await fixture.ethers.provider.send('evm_mine', [])
    }

    // alice 3, four bidders at 1 and frank 0 are counted; gina is dropped; hank only deposits.
    const STEPS = [3, 1, 1, 1, 1, 0, 1, 1]
    const COUNTED = [1, 1, 1, 1, 1, 1, 0, 0]

    it('opens the window at clear, and closes it for every claim path', async () => {
      const fixture = await deployFixture()
      const { program, actors } = fixture
      const { e3Id } = await playSale(fixture, STEPS, { countedVersions: COUNTED })
      expect(await program.CLAIM_WINDOW()).to.equal(WINDOW)
      expect((await program.clearing(e3Id)).claimDeadline).to.equal(0n)

      const receipt = await (await program.clear(e3Id)).wait()
      const clearedAt = BigInt((await fixture.ethers.provider.getBlock(receipt!.blockNumber))!.timestamp)
      const deadline = clearedAt + WINDOW
      await expect(program.clear(e3Id)).not.to.emit(program, 'ClaimWindowOpened')
      expect((await program.clearing(e3Id)).claimDeadline).to.equal(deadline)
      const logs = await program.queryFilter(program.filters.ClaimWindowOpened(e3Id))
      expect(logs.map((log) => log.args.deadline)).to.deep.equal([deadline])

      // The last second of the window still works, with and without a proof.
      await mineAt(fixture, deadline - 1n)
      const [alice, , , , , , gina, hank] = actors
      const k = (await program.clearing(e3Id)).step
      await fixture.ethers.provider.send('evm_setNextBlockTimestamp', [Number(deadline)])
      await (await program.claim(e3Id, alice.address, encodeClaim(compare(3, Number(k))))).wait()
      expect(await fixture.saleToken.balanceOf(alice.address)).to.be.greaterThan(0n)
      // One second later every path is closed: a proof claim, and the refunds with no proof.
      await mineAt(fixture, deadline + 1n)
      await expect(program.claim(e3Id, actors[1].address, encodeClaim(compare(1, Number(k))))).to.be.revertedWithCustomError(
        program,
        'ClaimWindowClosed',
      )
      await expect(program.claim(e3Id, gina.address, '0x'))
        .to.be.revertedWithCustomError(program, 'ClaimWindowClosed')
        .withArgs(deadline)
      await expect(program.claim(e3Id, hank.address, '0x')).to.be.revertedWithCustomError(program, 'ClaimWindowClosed')
    })

    it('keeps the deadline of the first clear', async () => {
      const fixture = await deployFixture()
      const { program, actors } = fixture
      const { e3Id } = await playSale(fixture, STEPS, { countedVersions: COUNTED })
      const k = 1
      await (await program.claim(e3Id, actors[0].address, encodeClaim(compare(3, k)))).wait()
      const first = (await program.clearing(e3Id)).claimDeadline
      await mineAt(fixture, first - 100n)
      await (await program.claim(e3Id, actors[1].address, encodeClaim(compare(1, k)))).wait()
      expect((await program.clearing(e3Id)).claimDeadline).to.equal(first)
    })

    it('sweeps exactly what is left: unclaimed winners, losers, dropped and deposit-only bidders', async () => {
      const fixture = await deployFixture()
      const { program, actors, usdc, saleToken, creator, programAddress } = fixture
      const { e3Id } = await playSale(fixture, STEPS, { countedVersions: COUNTED })
      const expected = referenceClear({
        prices: PRICES,
        c: demandCurve([3, 1, 1, 1, 1, 0]).slice(0, 4).map(BigInt),
        supply: SUPPLY,
        escrow: ESCROW,
        unit: U18,
      })
      expect(expected.kind).to.equal(KIND_CAPPED)
      const k = expected.step
      await (await program.clear(e3Id)).wait()
      const deadline = (await program.clearing(e3Id)).claimDeadline

      // Claimed: alice (full), bob (marginal), gina (dropped, no proof). Unclaimed: carol, dave, erin
      // (marginal), frank (loser) and hank (deposit only).
      const [alice, bob, , , , , gina] = actors
      await (await program.claim(e3Id, alice.address, encodeClaim(compare(3, k)))).wait()
      await (await program.claim(e3Id, bob.address, encodeClaim(compare(1, k)))).wait()
      await (await program.claim(e3Id, gina.address, '0x')).wait()
      const full = referenceOutcome(expected, 3, ESCROW, U18)
      const marginal = referenceOutcome(expected, 1, ESCROW, U18)

      // The creator takes the unsold tokens and a part of the proceeds before the sweep.
      expect(expected.sold).to.equal(SUPPLY) // a capped sale sells all the supply here
      await (await program.connect(creator).withdrawProceeds(e3Id)).wait()
      const proceedsTaken = await usdc.balanceOf(creator.address)
      expect(proceedsTaken).to.equal(full.paid + marginal.paid)
      // Carol's claim adds proceeds after the first withdrawal.
      const carol = actors[2]
      await (await program.claim(e3Id, carol.address, encodeClaim(compare(1, k)))).wait()
      expect(await program.proceedsAvailable(e3Id)).to.equal(marginal.paid)

      await expect(program.connect(creator).sweep(e3Id)).to.be.revertedWithCustomError(program, 'ClaimWindowOpen').withArgs(deadline)
      // The sweep is a transaction of the block at `deadline`: the window is still open.
      await mineAt(fixture, deadline - 1n)
      await expect(program.connect(creator).sweep(e3Id)).to.be.revertedWithCustomError(program, 'ClaimWindowOpen')
      await mineAt(fixture, deadline + 1n)
      await expect(program.connect(actors[0]).sweep(e3Id)).to.be.revertedWithCustomError(program, 'NotCreator')

      // Unclaimed: dave and erin (marginal tokens each), frank and hank (whole escrow).
      const saleTokens = 2n * marginal.tokens
      const paymentTokens = 2n * ESCROW /* frank, hank */ + 2n * ESCROW /* dave, erin */ + marginal.paid /* carol, not withdrawn */
      expect(await saleToken.balanceOf(programAddress)).to.equal(saleTokens)
      expect(await usdc.balanceOf(programAddress)).to.equal(paymentTokens)
      const creatorSale = await saleToken.balanceOf(creator.address)
      await expect(program.connect(creator).sweep(e3Id))
        .to.emit(program, 'Swept')
        .withArgs(e3Id, creator.address, saleTokens, paymentTokens)
      expect(await saleToken.balanceOf(creator.address)).to.equal(creatorSale + saleTokens)
      expect(await usdc.balanceOf(creator.address)).to.equal(proceedsTaken + paymentTokens)
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(0n)

      // Once. Nothing else moves: no claim, no withdrawal.
      expect(await program.swept(e3Id)).to.equal(true)
      await expect(program.connect(creator).sweep(e3Id)).to.be.revertedWithCustomError(program, 'AlreadySwept')
      await expect(program.claim(e3Id, actors[3].address, encodeClaim(compare(1, k)))).to.be.revertedWithCustomError(
        program,
        'ClaimWindowClosed',
      )
      await expect(program.connect(creator).withdrawProceeds(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
      await expect(program.connect(creator).withdrawUnsold(e3Id)).to.be.revertedWithCustomError(program, 'NothingToWithdraw')
    })

    it('sweeps the unsold tokens too when the creator did not take them, and not twice when they did', async () => {
      // Undersubscribed: the unsold part is large.
      const fixture = await deployFixture()
      const { program, actors, usdc, saleToken, creator, programAddress } = fixture
      // One counted bidder, so the demand is below the supply; the second depositor is dropped.
      const steps = [2, 0]
      const counted = [1, 0]
      const { e3Id } = await playSale(fixture, steps, { countedVersions: counted })
      const expected = referenceClear({
        prices: PRICES,
        c: demandCurve([2]).slice(0, 4).map(BigInt),
        supply: SUPPLY,
        escrow: ESCROW,
        unit: U18,
      })
      expect(expected.kind).to.equal(KIND_UNDERSUBSCRIBED)
      await (await program.clear(e3Id)).wait()
      const deadline = (await program.clearing(e3Id)).claimDeadline
      await (await program.claim(e3Id, actors[0].address, '0x')).wait()
      const outcome = referenceOutcome(expected, 2, ESCROW, U18)
      await mineAt(fixture, deadline + 1n)
      const unsold = SUPPLY - expected.sold
      // Case 1: the creator did not take the unsold tokens: the sweep sends them, and the dropped bidder's escrow.
      await expect(program.connect(creator).sweep(e3Id))
        .to.emit(program, 'Swept')
        .withArgs(e3Id, creator.address, unsold, ESCROW + outcome.paid)
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(0n)
      expect(await saleToken.balanceOf(creator.address)).to.equal(unsold)

      // Case 2: the creator took the unsold tokens first: the sweep must not send them again. Nobody claims.
      const second = await playSale(fixture, steps, { e3Id: E3_ID + 1n, countedVersions: counted })
      await (await program.clear(second.e3Id)).wait()
      const deadline2 = (await program.clearing(second.e3Id)).claimDeadline
      await (await program.connect(creator).withdrawUnsold(second.e3Id)).wait()
      await mineAt(fixture, deadline2 + 1n)
      await expect(program.connect(creator).sweep(second.e3Id))
        .to.emit(program, 'Swept')
        .withArgs(second.e3Id, creator.address, outcome.tokens, 2n * ESCROW)
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      expect(await usdc.balanceOf(programAddress)).to.equal(0n)
    })

    it('needs a cleared sale to sweep', async () => {
      const fixture = await deployFixture()
      const { program, creator } = fixture
      const e3Id = await createSale(fixture)
      await expect(program.connect(creator).sweep(e3Id)).to.be.revertedWithCustomError(program, 'NotCleared')
    })

    it('keeps concurrent sales apart', async () => {
      const fixture = await deployFixture()
      const { program, actors, usdc, saleToken, creator, programAddress } = fixture
      const steps = [3, 1, 1, 1, 1, 0]
      const first = await playSale(fixture, steps)
      const second = await playSale(fixture, steps, { e3Id: E3_ID + 1n })
      const expected = referenceClear({
        prices: PRICES,
        c: demandCurve(steps).slice(0, 4).map(BigInt),
        supply: SUPPLY,
        escrow: ESCROW,
        unit: U18,
      })
      const k = expected.step
      await (await program.clear(first.e3Id)).wait()
      await (await program.clear(second.e3Id)).wait()
      // The two sales hold two supplies and twelve escrows.
      expect(await saleToken.balanceOf(programAddress)).to.equal(2n * SUPPLY)
      expect(await usdc.balanceOf(programAddress)).to.equal(12n * ESCROW)

      // In the first sale only alice claims. In the second sale all claim.
      await (await program.claim(first.e3Id, actors[0].address, encodeClaim(compare(3, k)))).wait()
      for (let i = 0; i < steps.length; i++) {
        await (await program.claim(second.e3Id, actors[i].address, encodeClaim(compare(steps[i], k)))).wait()
      }
      const deadline = (await program.clearing(first.e3Id)).claimDeadline
      await mineAt(fixture, deadline + 1n)
      // The sweep of the first sale cannot touch the second sale. The second sale has the proceeds still held.
      const secondProceeds = await program.proceedsAvailable(second.e3Id)
      expect(secondProceeds).to.be.greaterThan(0n)
      const full = referenceOutcome(expected, 3, ESCROW, U18)
      const before = await usdc.balanceOf(programAddress)
      await (await program.connect(creator).sweep(first.e3Id)).wait()
      expect(await usdc.balanceOf(programAddress)).to.equal(secondProceeds)
      expect(before - (await usdc.balanceOf(programAddress))).to.equal(5n * ESCROW + full.paid)
      expect(await saleToken.balanceOf(programAddress)).to.equal(0n)
      // The second sale still pays its proceeds, and then its sweep has nothing left.
      await expect(program.connect(creator).withdrawProceeds(second.e3Id))
        .to.emit(program, 'ProceedsWithdrawn')
        .withArgs(second.e3Id, creator.address, secondProceeds)
      await mineAt(fixture, (await program.clearing(second.e3Id)).claimDeadline + 1n)
      await expect(program.connect(creator).sweep(second.e3Id)).to.emit(program, 'Swept').withArgs(second.e3Id, creator.address, 0n, 0n)
    })
  })

  describe('a failed E3', () => {
    it('gives the escrows and the supply back', async () => {
      const fixture = await deployFixture()
      const { program, usdc, saleToken, interfold, actors, creator } = fixture
      const e3Id = await createSale(fixture)
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
    })
  })

  describe('compute verification', () => {
    it('declares its interfaces', async () => {
      const { program } = await deployFixture()
      expect(await program.supportsInterface('0x01ffc9a7')).to.equal(true)
      expect(await program.ENCRYPTION_SCHEME_ID()).to.equal(keccak256(`0x${Buffer.from('fhe.rs:BFV').toString('hex')}`))
    })
  })
})
