// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { type Hex, encodeAbiParameters, keccak256, parseAbiParameters, sha256, zeroAddress } from 'viem'
import {
  BUYER_ROLE,
  E3_ID,
  KEY,
  LEVELS,
  MIN_PRICE,
  SELLER_ROLE,
  STEP_PRICE,
  TITLE,
  VK_ANCHOR,
  type Fixture,
  createNegotiation,
  deployFixture,
  makeOffer,
  offerData,
  offerPublicInputs,
  requestNegotiation,
  signOffer,
  submit,
} from './fixture'
import { bytes32, coefficientsToPlaintext, plaintextOfSlots, rng, slotsToCoefficients, slotsWithSums } from './helpers'
import { combineOffers, expectedOutcome, offerSlots, Role } from '../sdk/src/layout'
import { configLeaf, inputLeaf, offerInputsHash, OFFER_TYPES } from '../sdk/src/negotiation'

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** The published plaintext of the negotiation between a seller and a buyer with private steps and shares. */
function outputOf(sellerStep: number, buyerStep: number, sellerShare: number, buyerShare: number): Hex {
  const seller = offerSlots(Role.Seller, sellerStep, sellerShare)
  const buyer = offerSlots(Role.Buyer, buyerStep, buyerShare)
  return plaintextOfSlots(combineOffers(seller, buyer))
}

/** Both parties send their offers directly. */
async function bothOffers(fixture: Fixture, e3Id = E3_ID) {
  const seller = makeOffer(fixture.seller.address, 1)
  const buyer = makeOffer(fixture.buyer.address, 2)
  await submit(fixture, fixture.seller, seller, e3Id)
  await submit(fixture, fixture.buyer, buyer, e3Id)
  return { seller, buyer }
}

describe('NegotiationProgram', () => {
  describe('request', () => {
    it('stores the terms, inserts the configuration leaf and emits NegotiationCreated', async () => {
      const fixture = await deployFixture()
      const { program, creator, seller, buyer } = fixture
      const { e3Id, tx } = await requestNegotiation(fixture)
      await expect(tx())
        .to.emit(program, 'NegotiationCreated')
        .withArgs(e3Id, creator.address, seller.address, buyer.address, LEVELS, MIN_PRICE, STEP_PRICE, TITLE)
      const terms = await program.negotiation(e3Id)
      expect([terms.creator, terms.seller, terms.buyer, terms.levels, terms.minPrice, terms.stepPrice, terms.title]).to.deep.equal([
        creator.address,
        seller.address,
        buyer.address,
        BigInt(LEVELS),
        MIN_PRICE,
        STEP_PRICE,
        TITLE,
      ])
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(1n)
      expect(await program.offerSubmitted(e3Id, SELLER_ROLE)).to.equal(false)
      expect(await program.offerSubmitted(e3Id, BUYER_ROLE)).to.equal(false)
      const outcome = await program.outcome(e3Id)
      expect([outcome.settled, outcome.matched, outcome.step, outcome.price]).to.deep.equal([false, false, 0n, 0n])
    })

    it('accepts the smallest and the largest grid, and the largest price below 2^128', async () => {
      const fixture = await deployFixture()
      await createNegotiation(fixture, { e3Id: 1n, levels: 2 })
      await createNegotiation(fixture, { e3Id: 2n, levels: 16 })
      // minPrice + stepPrice * (levels - 1) = 2^128 - 1.
      await createNegotiation(fixture, { e3Id: 3n, levels: 16, minPrice: 2n ** 128n - 1n - 15n * 1000n, stepPrice: 1000n })
      await createNegotiation(fixture, { e3Id: 4n, levels: 2, minPrice: 0n, stepPrice: 1n })
      expect((await fixture.program.negotiation(2n)).levels).to.equal(16n)
    })

    it('rejects parties that are zero or equal', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer } = fixture
      for (const options of [
        { seller: zeroAddress },
        { buyer: zeroAddress },
        { seller: seller.address, buyer: seller.address },
        { seller: buyer.address, buyer: buyer.address },
      ]) {
        await expect((await requestNegotiation(fixture, options)).tx()).to.be.revertedWithCustomError(program, 'InvalidParties')
      }
    })

    it('rejects a grid with fewer than 2 or more than 16 levels', async () => {
      const fixture = await deployFixture()
      for (const levels of [0, 1, 17, 255]) {
        await expect((await requestNegotiation(fixture, { levels })).tx())
          .to.be.revertedWithCustomError(fixture.program, 'InvalidLevels')
          .withArgs(levels)
      }
    })

    it('rejects prices that are zero, or that reach 2^128', async () => {
      const fixture = await deployFixture()
      const { program } = fixture
      const limit = 2n ** 128n
      for (const options of [
        { stepPrice: 0n },
        { minPrice: limit },
        { minPrice: 2n ** 255n },
        { stepPrice: limit },
        { stepPrice: 2n ** 255n },
        // minPrice + stepPrice * (levels - 1) = 2^128.
        { levels: 16, minPrice: limit - 15n * 1000n, stepPrice: 1000n },
        { levels: 2, minPrice: limit - 1n, stepPrice: 1n },
      ]) {
        await expect((await requestNegotiation(fixture, options)).tx()).to.be.revertedWithCustomError(program, 'InvalidPrices')
      }
    })

    it('rejects a caller that is not Interfold, and a second request of the same E3', async () => {
      const fixture = await deployFixture()
      const { e3Id, params } = await requestNegotiation(fixture)
      await expect(fixture.program.connect(fixture.stranger).validate(e3Id, 0n, '0x', '0x', params)).to.be.revertedWithCustomError(
        fixture.program,
        'CallerNotAuthorized',
      )
      await createNegotiation(fixture)
      await expect(fixture.interfold.request(e3Id, fixture.programAddress, params)).to.be.revertedWithCustomError(
        fixture.program,
        'E3AlreadyInitialized',
      )
    })

    it('returns the encryption scheme of Interfold', async () => {
      const fixture = await deployFixture()
      const { e3Id, params } = await requestNegotiation(fixture)
      expect(await fixture.interfold.request.staticCall(e3Id, fixture.programAddress, params)).to.equal(
        keccak256(`0x${Buffer.from('fhe.rs:BFV').toString('hex')}`),
      )
    })

    it('supports the program, availability and ERC-165 interfaces only', async () => {
      const { program } = await deployFixture()
      expect(await program.supportsInterface('0x01ffc9a7')).to.equal(true)
      expect(await program.supportsInterface('0xffffffff')).to.equal(false)
    })
  })

  describe('leaves', () => {
    it('has the configuration leaf and the offer leaf of the SDK', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer } = fixture
      expect(await program.configLeaf()).to.equal(configLeaf())
      expect(configLeaf()).to.equal(BigInt(keccak256(`0x${Buffer.from('interfold-negotiation-config-v1').toString('hex')}`)) % FIELD)
      const offer = makeOffer(buyer.address, 5)
      for (const [party, role] of [
        [seller.address, SELLER_ROLE],
        [buyer.address, BUYER_ROLE],
      ] as const) {
        for (const index of [0, 1, 2]) {
          const expected = inputLeaf({
            ciphertext: offer.ciphertexts[index],
            commitment: offer.commitments[index],
            party: party as Hex,
            role,
            index,
          })
          expect(await program.inputLeaf(keccak256(offer.ciphertexts[index]), offer.commitments[index], party, role, index)).to.equal(
            expected,
          )
        }
      }
    })

    it('hashes the metadata as party || uint40(role * 256 + index)', async () => {
      const { program } = await deployFixture()
      const hash = `0x${'11'.repeat(32)}` as Hex
      const commitment = `0x${'22'.repeat(32)}` as Hex
      const party = `0x${'33'.repeat(20)}` as Hex
      for (const [role, index] of [
        [0, 0],
        [0, 2],
        [1, 1],
      ] as const) {
        const metadata = (BigInt(role) * 256n + BigInt(index)).toString(16).padStart(10, '0')
        const expected = BigInt(sha256(`0x${hash.slice(2)}${commitment.slice(2)}${party.slice(2)}${metadata}`)) % FIELD
        expect(await program.inputLeaf(hash, commitment, party, role, index)).to.equal(expected)
      }
      // The vector of `program/src/lib.rs` (`the_offer_leaf_matches_the_solidity_vector`).
      expect(await program.inputLeaf(hash, commitment, party, 1, 2)).to.equal(
        0x0eba2162cee5e04f2618586cb772d9e10e735f55391b893d5a351b5d2d94a9c6n,
      )
    })
  })

  describe('offers', () => {
    it('takes the offer of the seller and of the buyer, and inserts three leaves for each', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer } = fixture
      const e3Id = await createNegotiation(fixture)
      const sellerOffer = makeOffer(seller.address, 1)
      const buyerOffer = makeOffer(buyer.address, 2)
      await expect(program.connect(seller).publishInput(e3Id, offerData(sellerOffer)))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(e3Id, seller.address, SELLER_ROLE, 1n, sellerOffer.ciphertexts, sellerOffer.commitments)
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(4n)
      expect(await program.offerSubmitted(e3Id, SELLER_ROLE)).to.equal(true)
      expect(await program.offerSubmitted(e3Id, BUYER_ROLE)).to.equal(false)
      await expect(program.connect(buyer).publishInput(e3Id, offerData(buyerOffer)))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(e3Id, buyer.address, BUYER_ROLE, 4n, buyerOffer.ciphertexts, buyerOffer.commitments)
      expect((await program.inputs(e3Id)).numberOfLeaves).to.equal(7n)
      expect(await program.offerSubmitted(e3Id, BUYER_ROLE)).to.equal(true)
      expect(await program.offerSubmitted(e3Id, 2)).to.equal(false)
    })

    it('takes the buyer first, and the leaves follow the order of the offers', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer } = fixture
      const e3Id = await createNegotiation(fixture)
      const buyerOffer = makeOffer(buyer.address, 2)
      const sellerOffer = makeOffer(seller.address, 1)
      await expect(program.connect(buyer).publishInput(e3Id, offerData(buyerOffer)))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(e3Id, buyer.address, BUYER_ROLE, 1n, buyerOffer.ciphertexts, buyerOffer.commitments)
      await expect(program.connect(seller).publishInput(e3Id, offerData(sellerOffer)))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(e3Id, seller.address, SELLER_ROLE, 4n, sellerOffer.ciphertexts, sellerOffer.commitments)
    })

    it('passes the public inputs of the circuit to the verifier, in order', async () => {
      const fixture = await deployFixture()
      const { offerVerifier, seller, buyer } = fixture
      const e3Id = await createNegotiation(fixture, { levels: 12 })
      const sellerOffer = makeOffer(seller.address, 1)
      const buyerOffer = makeOffer(buyer.address, 2)
      // The mock reverts for any other public inputs: a wrong order, role, levels, key or anchor fails.
      await (await offerVerifier.expect(offerPublicInputs(buyerOffer, BUYER_ROLE, 12))).wait()
      await expect(fixture.program.connect(seller).publishInput(e3Id, offerData(sellerOffer))).to.be.revertedWithCustomError(
        offerVerifier,
        'PublicInputsMismatch',
      )
      await (await offerVerifier.expect(offerPublicInputs(sellerOffer, SELLER_ROLE, 12))).wait()
      await (await fixture.program.connect(seller).publishInput(e3Id, offerData(sellerOffer))).wait()
      await (await offerVerifier.expect(offerPublicInputs(buyerOffer, BUYER_ROLE, 12))).wait()
      await (await fixture.program.connect(buyer).publishInput(e3Id, offerData(buyerOffer))).wait()
      expect(offerPublicInputs(sellerOffer, SELLER_ROLE, 12)).to.have.length(8)
      expect(offerPublicInputs(sellerOffer, SELLER_ROLE, 12).slice(5)).to.deep.equal([bytes32(12), KEY, VK_ANCHOR])
    })

    it('rejects a proof that the verifier rejects, with a revert or with false', async () => {
      const fixture = await deployFixture()
      const { program, offerVerifier, seller } = fixture
      const e3Id = await createNegotiation(fixture)
      const offer = makeOffer(seller.address, 1)
      await expect(program.connect(seller).publishInput(e3Id, offerData({ ...offer, proof: '0x02' }))).to.be.revertedWithCustomError(
        offerVerifier,
        'ProofRejected',
      )
      await (await offerVerifier.setAccepting(false)).wait()
      await expect(program.connect(seller).publishInput(e3Id, offerData(offer))).to.be.revertedWithCustomError(program, 'InvalidOfferProof')
      expect(await program.offerSubmitted(e3Id, SELLER_ROLE)).to.equal(false)
    })

    it('rejects a second offer of the same role, and an address that is not a party', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer, stranger, relayer } = fixture
      const e3Id = await createNegotiation(fixture)
      const offer = makeOffer(seller.address, 1)
      await submit(fixture, seller, offer, e3Id)
      await expect(program.connect(seller).publishInput(e3Id, offerData(makeOffer(seller.address, 3))))
        .to.be.revertedWithCustomError(program, 'AlreadySubmitted')
        .withArgs(seller.address, SELLER_ROLE)
      // A relayed second offer fails in the same way.
      const second = makeOffer(seller.address, 4)
      await expect(program.connect(relayer).publishInput(e3Id, offerData(second, await signOffer(fixture, seller, e3Id, second))))
        .to.be.revertedWithCustomError(program, 'AlreadySubmitted')
        .withArgs(seller.address, SELLER_ROLE)
      await expect(program.connect(stranger).publishInput(e3Id, offerData(makeOffer(stranger.address, 5))))
        .to.be.revertedWithCustomError(program, 'NotAParty')
        .withArgs(stranger.address)
      await expect(program.connect(stranger).publishInput(e3Id, offerData(makeOffer(zeroAddress, 5))))
        .to.be.revertedWithCustomError(program, 'NotAParty')
        .withArgs(zeroAddress)
      // The buyer can still send.
      await submit(fixture, buyer, makeOffer(buyer.address, 6), e3Id)
    })

    it('rejects a direct offer that another address sends', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer, stranger } = fixture
      const e3Id = await createNegotiation(fixture)
      await expect(program.connect(stranger).publishInput(e3Id, offerData(makeOffer(seller.address, 1))))
        .to.be.revertedWithCustomError(program, 'SenderNotParty')
        .withArgs(stranger.address, seller.address)
      // The buyer cannot send the offer of the seller.
      await expect(program.connect(buyer).publishInput(e3Id, offerData(makeOffer(seller.address, 1))))
        .to.be.revertedWithCustomError(program, 'SenderNotParty')
        .withArgs(buyer.address, seller.address)
      expect(await program.offerSubmitted(e3Id, SELLER_ROLE)).to.equal(false)
    })

    it('takes a relayed offer with the signature of the party, and anyone may send it', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer, relayer } = fixture
      const e3Id = await createNegotiation(fixture)
      const sellerOffer = makeOffer(seller.address, 1)
      const buyerOffer = makeOffer(buyer.address, 2)
      const signature = await signOffer(fixture, seller, e3Id, sellerOffer)
      await expect(program.connect(relayer).publishInput(e3Id, offerData(sellerOffer, signature)))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(e3Id, seller.address, SELLER_ROLE, 1n, sellerOffer.ciphertexts, sellerOffer.commitments)
      await expect(program.connect(seller).publishInput(e3Id, offerData(buyerOffer, await signOffer(fixture, buyer, e3Id, buyerOffer))))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(e3Id, buyer.address, BUYER_ROLE, 4n, buyerOffer.ciphertexts, buyerOffer.commitments)
    })

    it('has the digest of the SDK typed data', async () => {
      const fixture = await deployFixture()
      const { program, seller } = fixture
      const offer = makeOffer(seller.address, 1)
      const inputsHash = offerInputsHash(offer.commitments, offer.ciphertexts)
      const typed = { name: 'NegotiationProgram', version: '1', chainId: fixture.chainId, verifyingContract: fixture.programAddress }
      const expected = fixture.ethers.TypedDataEncoder.hash(
        typed,
        { Offer: [...OFFER_TYPES.Offer] },
        { e3Id: E3_ID, party: seller.address, inputsHash },
      )
      expect(await program.offerDigest(E3_ID, seller.address, inputsHash)).to.equal(expected)
      expect(inputsHash).to.equal(
        keccak256(
          encodeAbiParameters(parseAbiParameters('bytes32[], bytes32, bytes32, bytes32'), [
            offer.commitments,
            ...(offer.ciphertexts.map((ciphertext) => keccak256(ciphertext)) as [Hex, Hex, Hex]),
          ]),
        ),
      )
    })

    it('rejects a signature of another signer, and a signature for other bytes, another E3 or another party', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer, relayer, stranger } = fixture
      const e3Id = await createNegotiation(fixture)
      const other = await createNegotiation(fixture, { e3Id: 8n })
      const offer = makeOffer(seller.address, 1)
      const bySomeoneElse = await signOffer(fixture, stranger, e3Id, offer)
      await expect(program.connect(relayer).publishInput(e3Id, offerData(offer, bySomeoneElse)))
        .to.be.revertedWithCustomError(program, 'InvalidSignature')
        .withArgs(seller.address)
      // The buyer signs the offer of the seller.
      await expect(
        program.connect(relayer).publishInput(e3Id, offerData(offer, await signOffer(fixture, buyer, e3Id, offer))),
      ).to.be.revertedWithCustomError(program, 'InvalidSignature')
      // A signature for the E3 `other` does not work for `e3Id`.
      const forOther = await signOffer(fixture, seller, other, offer)
      await expect(program.connect(relayer).publishInput(e3Id, offerData(offer, forOther))).to.be.revertedWithCustomError(
        program,
        'InvalidSignature',
      )
      const signature = await signOffer(fixture, seller, e3Id, offer)
      // The relayer changes a ciphertext, a commitment or the order.
      const swappedCiphertext = { ...offer, ciphertexts: [offer.ciphertexts[0], offer.ciphertexts[1], '0xdeadbeef' as Hex] }
      const swappedCommitment = { ...offer, commitments: [offer.commitments[0], offer.commitments[1], bytes32(99)] }
      const swappedOrder = { ...offer, ciphertexts: [offer.ciphertexts[1], offer.ciphertexts[0], offer.ciphertexts[2]] }
      for (const changed of [swappedCiphertext, swappedCommitment, swappedOrder]) {
        await expect(program.connect(relayer).publishInput(e3Id, offerData(changed, signature))).to.be.revertedWithCustomError(
          program,
          'InvalidSignature',
        )
      }
      // A malformed signature fails too.
      await expect(program.connect(relayer).publishInput(e3Id, offerData(offer, '0x1234'))).to.be.revertedWithCustomError(
        program,
        'InvalidSignature',
      )
      // The right signature works.
      await (await program.connect(relayer).publishInput(e3Id, offerData(offer, signature))).wait()
    })

    it('rejects a wrong number of ciphertexts or commitments, and an empty ciphertext', async () => {
      const fixture = await deployFixture()
      const { program, seller } = fixture
      const e3Id = await createNegotiation(fixture)
      const offer = makeOffer(seller.address, 1)
      const encode = (ciphertexts: Hex[], commitments: Hex[]) =>
        encodeAbiParameters(parseAbiParameters('address, bytes[], bytes32[], bytes, bytes'), [
          seller.address as Hex,
          ciphertexts,
          commitments,
          '0x01',
          '0x',
        ])
      const shapes: [Hex[], Hex[]][] = [
        [[], []],
        [offer.ciphertexts.slice(0, 1), offer.commitments.slice(0, 1)],
        [offer.ciphertexts.slice(0, 2), offer.commitments.slice(0, 2)],
        [offer.ciphertexts.slice(0, 2), offer.commitments],
        [offer.ciphertexts, offer.commitments.slice(0, 2)],
        [[...offer.ciphertexts, offer.ciphertexts[0]], offer.commitments],
        [offer.ciphertexts, [...offer.commitments, offer.commitments[0]]],
      ]
      for (const [ciphertexts, commitments] of shapes) {
        await expect(program.connect(seller).publishInput(e3Id, encode(ciphertexts, commitments))).to.be.revertedWithCustomError(
          program,
          'InvalidOfferShape',
        )
      }
      await expect(
        program.connect(seller).publishInput(e3Id, encode([offer.ciphertexts[0], '0x', offer.ciphertexts[2]], offer.commitments)),
      ).to.be.revertedWithCustomError(program, 'EmptyInputData')
      expect(await program.offerSubmitted(e3Id, SELLER_ROLE)).to.equal(false)
    })

    it('rejects an offer after the input window, for a direct and a relayed offer, and for an unknown E3', async () => {
      const fixture = await deployFixture()
      const { program, interfold, seller, buyer, relayer } = fixture
      const e3Id = await createNegotiation(fixture)
      const offer = makeOffer(seller.address, 1)
      await (await interfold.setInputDeadline(e3Id, 1n)).wait()
      await expect(program.connect(seller).publishInput(e3Id, offerData(offer))).to.be.revertedWithCustomError(
        program,
        'InputDeadlineReached',
      )
      await expect(
        program.connect(relayer).publishInput(e3Id, offerData(offer, await signOffer(fixture, seller, e3Id, offer))),
      ).to.be.revertedWithCustomError(program, 'InputDeadlineReached')
      await expect(program.connect(buyer).publishInput(99n, offerData(makeOffer(buyer.address, 2)))).to.be.revertedWithCustomError(
        program,
        'E3DoesNotExist',
      )
    })

    it('takes an offer up to the second of the deadline', async () => {
      const fixture = await deployFixture()
      const { program, interfold, seller } = fixture
      const e3Id = await createNegotiation(fixture)
      const latest = BigInt((await fixture.ethers.provider.getBlock('latest'))!.timestamp)
      await (await interfold.setInputDeadline(e3Id, latest + 2n)).wait()
      await (await program.connect(seller).publishInput(e3Id, offerData(makeOffer(seller.address, 1)))).wait()
      expect(await program.offerSubmitted(e3Id, SELLER_ROLE)).to.equal(true)
    })

    it('keeps the two negotiations apart', async () => {
      const fixture = await deployFixture()
      const { program, seller, buyer } = fixture
      const first = await createNegotiation(fixture, { e3Id: 1n })
      // The second negotiation has the roles the other way round.
      const second = await createNegotiation(fixture, { e3Id: 2n, seller: buyer.address, buyer: seller.address })
      await submit(fixture, seller, makeOffer(seller.address, 1), first)
      expect(await program.offerSubmitted(first, SELLER_ROLE)).to.equal(true)
      expect(await program.offerSubmitted(second, SELLER_ROLE)).to.equal(false)
      await expect(program.connect(seller).publishInput(second, offerData(makeOffer(seller.address, 1))))
        .to.emit(program, 'OfferSubmitted')
        .withArgs(
          second,
          seller.address,
          BUYER_ROLE,
          1n,
          makeOffer(seller.address, 1).ciphertexts,
          makeOffer(seller.address, 1).commitments,
        )
    })

    it('reports the gas of publishInput with the mock verifier', async () => {
      const fixture = await deployFixture()
      const e3Id = await createNegotiation(fixture)
      const receipt = await submit(fixture, fixture.seller, makeOffer(fixture.seller.address, 1), e3Id)
      console.log(`      gas publishInput (mock verifier): ${receipt!.gasUsed}`)
      expect(receipt!.gasUsed).to.be.lessThan(1_000_000n)
    })
  })

  describe('settle', () => {
    /** Creates a negotiation of `levels`, publishes `plaintext` and settles. */
    async function settleWith(fixture: Fixture, plaintext: Hex, levels = LEVELS, e3Id = E3_ID) {
      await createNegotiation(fixture, { e3Id, levels })
      await (await fixture.interfold.setPlaintext(e3Id, plaintext)).wait()
      return fixture.program.settle(e3Id)
    }

    it('settles a match: the level and the price', async () => {
      const fixture = await deployFixture()
      const { program } = fixture
      const e3Id = await createNegotiation(fixture)
      await bothOffers(fixture)
      // Seller 2, buyer 6, shares 5 and 9: the pointer is 12, so the level of the least `i xor 12` in [2, 6] wins.
      const expected = expectedOutcome(2, 6, 5, 9)
      expect(expected.matched).to.equal(true)
      await (await fixture.interfold.setPlaintext(e3Id, outputOf(2, 6, 5, 9))).wait()
      const price = MIN_PRICE + BigInt(expected.step!) * STEP_PRICE
      const tx = await program.connect(fixture.stranger).settle(e3Id)
      await expect(tx).to.emit(program, 'Settled').withArgs(e3Id, true, expected.step, price)
      const outcome = await program.outcome(e3Id)
      expect([outcome.settled, outcome.matched, outcome.step, outcome.price]).to.deep.equal([true, true, BigInt(expected.step!), price])
      const receipt = await tx.wait()
      console.log(`      gas settle (match): ${receipt!.gasUsed}`)
    })

    it('settles no match: only the match bit', async () => {
      const fixture = await deployFixture()
      const { program } = fixture
      const e3Id = await createNegotiation(fixture)
      await (await fixture.interfold.setPlaintext(e3Id, outputOf(5, 3, 1, 2))).wait()
      const tx = await program.settle(e3Id)
      await expect(tx).to.emit(program, 'Settled').withArgs(e3Id, false, 0, 0)
      const outcome = await program.outcome(e3Id)
      expect([outcome.settled, outcome.matched, outcome.step, outcome.price]).to.deep.equal([true, false, 0n, 0n])
      console.log(`      gas settle (no match): ${(await tx.wait())!.gasUsed}`)
    })

    it('settles level 0 as a match and the highest level of 16 with its price', async () => {
      const fixture = await deployFixture()
      // Seller 0, buyer 0: the only level is 0. It is a match, and the price is minPrice.
      await expect(await settleWith(fixture, outputOf(0, 0, 3, 4), 16, 1n))
        .to.emit(fixture.program, 'Settled')
        .withArgs(1n, true, 0, MIN_PRICE)
      // Seller 15, buyer 15: level 15.
      await expect(await settleWith(fixture, outputOf(15, 15, 3, 4), 16, 2n))
        .to.emit(fixture.program, 'Settled')
        .withArgs(2n, true, 15, MIN_PRICE + 15n * STEP_PRICE)
    })

    it('settles every pair of steps of 16 levels as the rule says', async () => {
      const fixture = await deployFixture()
      const random = rng(0xc0ffee)
      let e3Id = 100n
      let matches = 0
      for (let s = 0; s < 16; s++) {
        for (let b = 0; b < 16; b++) {
          const sellerShare = random() % 16
          const buyerShare = random() % 16
          const expected = expectedOutcome(s, b, sellerShare, buyerShare)
          await createNegotiation(fixture, { e3Id, levels: 16 })
          await (await fixture.interfold.setPlaintext(e3Id, outputOf(s, b, sellerShare, buyerShare))).wait()
          await (await fixture.program.settle(e3Id)).wait()
          const outcome = await fixture.program.outcome(e3Id)
          expect(outcome.settled).to.equal(true)
          expect(outcome.matched, `s=${s} b=${b}`).to.equal(expected.matched)
          expect(outcome.step, `s=${s} b=${b}`).to.equal(BigInt(expected.step ?? 0))
          expect(outcome.price, `s=${s} b=${b}`).to.equal(expected.matched ? MIN_PRICE + BigInt(expected.step!) * STEP_PRICE : 0n)
          if (expected.matched) matches++
          e3Id++
        }
      }
      expect(matches).to.equal(136)
    })

    it('rejects settle before the plaintext is published, and for an unknown E3', async () => {
      const fixture = await deployFixture()
      const e3Id = await createNegotiation(fixture)
      await expect(fixture.program.settle(e3Id)).to.be.revertedWithCustomError(fixture.program, 'OutputNotPublished')
      await expect(fixture.program.settle(99n)).to.be.revertedWithCustomError(fixture.program, 'E3DoesNotExist')
      expect((await fixture.program.outcome(e3Id)).settled).to.equal(false)
    })

    it('rejects a second settle, with the same or another plaintext', async () => {
      const fixture = await deployFixture()
      const e3Id = await createNegotiation(fixture)
      await (await fixture.interfold.setPlaintext(e3Id, outputOf(1, 4, 0, 0))).wait()
      await (await fixture.program.settle(e3Id)).wait()
      const before = await fixture.program.outcome(e3Id)
      await expect(fixture.program.settle(e3Id)).to.be.revertedWithCustomError(fixture.program, 'AlreadySettled')
      await (await fixture.interfold.setPlaintext(e3Id, outputOf(5, 3, 0, 0))).wait()
      await expect(fixture.program.connect(fixture.stranger).settle(e3Id)).to.be.revertedWithCustomError(fixture.program, 'AlreadySettled')
      const after = await fixture.program.outcome(e3Id)
      expect([after.matched, after.step, after.price]).to.deep.equal([before.matched, before.step, before.price])
    })

    describe('an invalid output', () => {
      /** The output slots that have the level sums `sums`. */
      const withSums = (sums: number[]): Hex => plaintextOfSlots(slotsWithSums(sums, rng(7)))

      it('has two levels set', async () => {
        const fixture = await deployFixture()
        const sums = new Array<number>(16).fill(0)
        sums[1] = 1
        sums[4] = 1
        await expect(settleWith(fixture, withSums(sums))).to.be.revertedWithCustomError(fixture.program, 'InvalidOutput')
        expect((await fixture.program.outcome(E3_ID)).settled).to.equal(false)
      })

      it('has a level sum that is not 0 or 1', async () => {
        const fixture = await deployFixture()
        for (const [n, value] of [2, 3, 256].entries()) {
          const sums = new Array<number>(16).fill(0)
          sums[2] = value
          await expect(settleWith(fixture, withSums(sums), LEVELS, BigInt(n + 1))).to.be.revertedWithCustomError(
            fixture.program,
            'InvalidOutput',
          )
        }
      })

      it('sets a level from `levels` on', async () => {
        const fixture = await deployFixture()
        for (const [n, level] of [LEVELS, LEVELS + 1, 15].entries()) {
          const sums = new Array<number>(16).fill(0)
          sums[level] = 1
          await expect(settleWith(fixture, withSums(sums), LEVELS, BigInt(n + 1))).to.be.revertedWithCustomError(
            fixture.program,
            'InvalidOutput',
          )
        }
        // The same level is valid on a grid that has it.
        const sums = new Array<number>(16).fill(0)
        sums[LEVELS] = 1
        await expect(await settleWith(fixture, withSums(sums), LEVELS + 1, 10n))
          .to.emit(fixture.program, 'Settled')
          .withArgs(10n, true, LEVELS, MIN_PRICE + BigInt(LEVELS) * STEP_PRICE)
      })

      it('has a single slot set (the groups of the level do not sum to 0 or 1)', async () => {
        const fixture = await deployFixture()
        const slots = new Array<number>(128).fill(0)
        slots[3 * 16 + 2] = 5
        await expect(settleWith(fixture, plaintextOfSlots(slots))).to.be.revertedWithCustomError(fixture.program, 'InvalidOutput')
      })

      it('has the wrong length, or a coefficient from 257 on', async () => {
        const fixture = await deployFixture()
        const valid = coefficientsToPlaintext(slotsToCoefficients(new Array(128).fill(0)))
        await expect(settleWith(fixture, valid.slice(0, -16) as Hex, LEVELS, 1n)).to.be.revertedWithCustomError(
          fixture.program,
          'InvalidPlaintextLength',
        )
        const coefficients = new Array<number>(128).fill(0)
        coefficients[5] = 257
        await expect(settleWith(fixture, coefficientsToPlaintext(coefficients), LEVELS, 2n))
          .to.be.revertedWithCustomError(fixture.program, 'CoefficientOutOfRange')
          .withArgs(5)
        // A non-zero byte above the second one of a coefficient is out of range.
        const high = `0x${'00'.repeat(5 * 8 + 2)}01${'00'.repeat(1024 - 5 * 8 - 3)}` as Hex
        await expect(settleWith(fixture, high, LEVELS, 3n))
          .to.be.revertedWithCustomError(fixture.program, 'CoefficientOutOfRange')
          .withArgs(5)
      })

      it('can be settled when the zero vector is the output (no match)', async () => {
        const fixture = await deployFixture()
        await expect(await settleWith(fixture, withSums(new Array<number>(16).fill(0))))
          .to.emit(fixture.program, 'Settled')
          .withArgs(E3_ID, false, 0, 0)
      })
    })
  })
})
