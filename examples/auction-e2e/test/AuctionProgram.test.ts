// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import hre from 'hardhat'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import {
  type AbiParameter,
  type Hex,
  concatHex,
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  parseAbiParameters,
  sha256,
  toHex,
  zeroAddress,
  zeroHash,
} from 'viem'
import {
  type BidInput,
  allowlistProof,
  bidInputsHash,
  bidTypedData,
  encodeAllowlistConfig,
  encodeBidInput,
  evenPrices,
} from '@interfold/auction'
import { AuctionProgram__factory } from '../types/factories/contracts'

const PROOF = '0x01'
const E3_ID = 5n
const KEY = `0x${'ab'.repeat(32)}` as const
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
const E3_PROGRAM_PARAMS = '0x1234'
/** The first-price auction: a bidder sends `ge`, `gt` and a `mask`. */
const FIRST_PRICE_TYPE = 0
/** The second-price auction with mask providers: a bidder sends `ge` and `gt`. */
const PROVIDER_TYPE = 1
/** The second-price auction with no providers: a bidder sends `ge`, `gt` and two shares. */
const QNR_TYPE = 2
const TYPES = [FIRST_PRICE_TYPE, PROVIDER_TYPE, QNR_TYPE]
/** The ciphertexts of one bid, by type. */
const ROLES = [3, 2, 4]
const MASK_VERSION = 0xffffffff

/** `bytes32` filled with one byte. */
const filled = (byte: number): Hex => `0x${byte.toString(16).padStart(2, '0').repeat(32)}`
/** An address as the 32-byte word of a verifier's public input. */
const word = (address: string): Hex => `0x${'00'.repeat(12)}${address.slice(2).toLowerCase()}`
const level = (levels: number): Hex => `0x${'00'.repeat(31)}${levels.toString(16).padStart(2, '0')}`

/**
 * The request's `customParams` with the provider list: `abi.encode(uint8 auctionType, uint8 levels,
 * uint256[16] prices, string title, address gate, bytes gateConfig, address[] providers)`.
 */
function encodeParams(type: number, providers: readonly string[] = [], gate: Hex = zeroAddress, gateConfig: Hex = '0x'): Hex {
  const prices = evenPrices(1n, 1n, 4)
  const padded = [...prices, ...Array.from({ length: 16 - prices.length }, () => 0n)]
  const abi: readonly AbiParameter[] = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
  return encodeAbiParameters(abi, [type, prices.length, padded, 'Unit test', gate, gateConfig, providers])
}

/**
 * The root `InternalLazyIMT._root` gives for `leaves`: a Poseidon tree of the smallest depth, at least
 * 1, that holds them, padded with the zero leaf 0.
 */
function treeRoot(leaves: readonly bigint[]): bigint {
  let nodes = [...leaves]
  let zero = 0n
  let depth = 1
  while (2 ** depth < leaves.length) depth++
  for (let level = 0; level < depth; level++) {
    const next: bigint[] = []
    for (let i = 0; i < nodes.length; i += 2) next.push(poseidon2([nodes[i], nodes[i + 1] ?? zero]))
    nodes = next
    zero = poseidon2([zero, zero])
  }
  return nodes[0]
}

describe('AuctionProgram bids', () => {
  async function setup(options: { type?: number; allowlisted?: ('alice' | 'bob')[]; providers?: number; deadline?: bigint } = {}) {
    const { ethers } = await hre.network.connect()
    const [owner, alice, bob, carol, dave, relayer, outsider, p1, p2, p3, p4, ...rest] = await ethers.getSigners()
    const providerSigners = [p1, p2, p3, p4]
    const type = options.type ?? FIRST_PRICE_TYPE
    const providers = (type === PROVIDER_TYPE ? providerSigners.slice(0, options.providers ?? 2) : []).map((signer) => signer.address)
    const interfold = await ethers.deployContract('MockInterfold', [options.deadline ?? 2n ** 40n, KEY, owner.address])
    const receiptVerifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
    const availability = await ethers.deployContract('MockDataAvailabilityVerifier')
    const verifier2 = await ethers.deployContract('MockBidVerifier')
    const verifier3 = await ethers.deployContract('MockBidVerifier')
    const verifier4 = await ethers.deployContract('MockBidVerifier')
    const maskVerifier = await ethers.deployContract('MockBidVerifier')
    const poseidon = await ethers.deployContract('PoseidonT3')
    const vkAnchor2 = filled(0xcc)
    const vkAnchor3 = filled(0xcd)
    const vkAnchorMask = filled(0xcf)
    const vkAnchorQnr = filled(0xd0)
    const factory = await ethers.getContractFactory(
      AuctionProgram__factory.abi,
      AuctionProgram__factory.linkBytecode({ 'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': await poseidon.getAddress() }),
      owner,
    )
    const program = AuctionProgram__factory.connect(
      await (
        await factory.deploy(
          await interfold.getAddress(),
          await receiptVerifier.getAddress(),
          await receiptVerifier.imageId(),
          await verifier2.getAddress(),
          await verifier3.getAddress(),
          await verifier4.getAddress(),
          await maskVerifier.getAddress(),
          vkAnchor2,
          vkAnchor3,
          vkAnchorMask,
          vkAnchorQnr,
          await availability.getAddress(),
        )
      ).getAddress(),
      owner,
    )
    const gate = await ethers.deployContract('MerkleAllowlistGate')
    const gated = options.allowlisted !== undefined
    const members = (options.allowlisted ?? []).map((name) => ({ alice, bob })[name].address)
    const customParams = encodeParams(
      type,
      providers,
      gated ? ((await gate.getAddress()) as Hex) : zeroAddress,
      gated ? encodeAllowlistConfig(members) : '0x',
    )
    const created = await program.validate(E3_ID, 0n, E3_PROGRAM_PARAMS, '0x', customParams)
    await created.wait()
    const chainId = Number((await ethers.provider.getNetwork()).chainId)
    const programAddress = (await program.getAddress()) as Hex
    const roles = ROLES[type]
    const makeBid = (bidder: string, seed: number, extra: { gateProof?: Hex; signature?: Hex; proof?: Hex } = {}) => {
      const ciphertexts = Array.from({ length: roles }, (_, r) => `0x${(seed * 16 + r + 1).toString(16).padStart(2, '0').repeat(8)}` as Hex)
      const commitments = Array.from({ length: roles }, (_, r) => filled(seed * 16 + r + 1))
      return {
        bidder: bidder as Hex,
        ciphertexts,
        commitments,
        proof: extra.proof ?? (PROOF as Hex),
        gateProof: extra.gateProof ?? ('0x' as Hex),
        signature: extra.signature ?? ('0x' as Hex),
      }
    }
    /** The one-ciphertext input of a provider: `bidder` is the provider. */
    const makeMask = (provider: string, seed: number, extra: { gateProof?: Hex; signature?: Hex; proof?: Hex } = {}) => ({
      bidder: provider as Hex,
      ciphertexts: [`0x${(0xa0 + seed).toString(16).repeat(8)}` as Hex],
      commitments: [filled(0xa0 + seed)],
      proof: extra.proof ?? (PROOF as Hex),
      gateProof: extra.gateProof ?? ('0x' as Hex),
      signature: extra.signature ?? ('0x' as Hex),
    })
    /** Sends the mask of every provider, so that bids are open. Sends nothing for the types 0 and 2. */
    const openBids = async () => {
      for (const [seed, signer] of providerSigners.slice(0, providers.length).entries()) {
        await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeMask(signer.address, seed + 1)))
      }
    }
    /** The verifier and the anchor that a bid of this auction's type must reach. */
    const route = [
      { verifier: verifier3, anchor: vkAnchor3 },
      { verifier: verifier2, anchor: vkAnchor2 },
      { verifier: verifier4, anchor: vkAnchorQnr },
    ][type]
    const anchors = [vkAnchor2, vkAnchor3, vkAnchorMask, vkAnchorQnr]
    /** Whether the input root of the auction is the root of exactly `leaves`: the root is only visible to `verify`. */
    const hasLeaves = async (leaves: readonly bigint[]) => {
      const proof = encodeAbiParameters(parseAbiParameters('bytes, bytes32, bytes32'), [
        '0x',
        keccak256(E3_PROGRAM_PARAMS),
        toHex(treeRoot(leaves), { size: 32 }),
      ])
      try {
        return await program.verify(E3_ID, zeroHash, zeroHash, proof)
      } catch {
        return false
      }
    }
    return {
      ethers,
      owner,
      alice,
      bob,
      carol,
      dave,
      relayer,
      outsider,
      providerSigners,
      providers,
      extraSigners: rest,
      program,
      programAddress,
      created,
      chainId,
      makeBid,
      makeMask,
      hasLeaves,
      verifier2,
      verifier3,
      verifier4,
      maskVerifier,
      vkAnchor2,
      vkAnchor3,
      vkAnchorMask,
      vkAnchorQnr,
      gate,
      roles,
      openBids,
      route,
      anchors,
    }
  }

  it('matches the shared leaf vector', async () => {
    const { program } = await setup()
    // The same vector `program/src/lib.rs` and `sdk/src/selection.ts` test.
    expect(await program.inputLeaf(filled(0x11), filled(0x22), '0x3333333333333333333333333333333333333333', 2)).to.equal(
      0x0b8ba63e8917dfb3f66cfcc1b0be5d3a8f8613ba8092d690a43b84daec02b94an,
    )
  })

  it('takes a direct bid, then updates, and numbers the leaves, for every type', async () => {
    for (const type of TYPES) {
      const { program, alice, makeBid, openBids, route, roles, providers } = await setup({ type, providers: 2 })
      await openBids()
      // The configuration leaf and the masks come first.
      const before = BigInt(1 + providers.length)
      const first = makeBid(alice.address, 1)
      // The verifier gets the commitments, the bidder, levels, the committee key and the anchor.
      await route.verifier.expect([...first.commitments, word(alice.address), level(4), KEY, route.anchor])
      const tx = await program.connect(alice).publishInput(E3_ID, encodeBidInput(first))
      await expect(tx).to.emit(program, 'BidSubmitted').withArgs(E3_ID, alice.address, 1n, before, first.ciphertexts, first.commitments)
      expect(await program.bidCount(E3_ID, alice.address)).to.equal(1n)
      expect(await program.bidderCount(E3_ID)).to.equal(1n)
      expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(before + BigInt(roles))

      for (const version of [2n, 3n]) {
        await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(first)))
          .to.emit(program, 'BidSubmitted')
          .withArgs(E3_ID, alice.address, version, before + BigInt(roles) * (version - 1n), first.ciphertexts, first.commitments)
      }
      // The bidder counts once; a fourth bid is too many.
      expect(await program.bidderCount(E3_ID)).to.equal(1n)
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(first))).to.be.revertedWithCustomError(program, 'TooManyBids')
    }
  })

  it('rejects a bad shape, a foreign sender and a bad proof', async () => {
    const { program, alice, bob, makeBid, ethers } = await setup()
    const bid = makeBid(alice.address, 1)
    await expect(program.connect(bob).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(program, 'SenderNotBidder')
    await expect(
      program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, ciphertexts: bid.ciphertexts.slice(1) })),
    ).to.be.revertedWithCustomError(program, 'InvalidBidShape')
    await expect(
      program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, ciphertexts: ['0x', ...bid.ciphertexts.slice(1)] })),
    ).to.be.revertedWithCustomError(program, 'EmptyInputData')
    await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, proof: '0x02' }))).to.be.revert(ethers)
  })

  it('takes only as many ciphertexts as the type has roles', async () => {
    for (const type of TYPES) {
      const { program, alice, makeBid, openBids, roles } = await setup({ type, providers: 1 })
      await openBids()
      const bid = makeBid(alice.address, 1)
      for (const length of [0, 1, 2, 3, 4, 5].filter((count) => count !== roles)) {
        const ciphertexts = Array.from({ length }, (_, i) => bid.ciphertexts[i % roles])
        const commitments = Array.from({ length }, (_, i) => bid.commitments[i % roles])
        await expect(
          program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, ciphertexts, commitments })),
        ).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      }
      // The commitments must match the ciphertexts.
      await expect(
        program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, commitments: bid.commitments.slice(1) })),
      ).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      expect(await program.bidCount(E3_ID, alice.address)).to.equal(0n)
    }
  })

  it('takes 8 bidders of every type, refuses a ninth, and still takes an update', async () => {
    for (const type of TYPES) {
      const { program, alice, bob, carol, dave, relayer, outsider, extraSigners, makeBid, openBids } = await setup({ type, providers: 2 })
      await openBids()
      const bidders = [alice, bob, carol, dave, relayer, outsider, extraSigners[0], extraSigners[1], extraSigners[2]]
      for (const [seed, signer] of bidders.slice(0, 8).entries()) {
        await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeBid(signer.address, seed + 1)))
      }
      expect(await program.bidderCount(E3_ID)).to.equal(8n)
      await expect(
        program.connect(bidders[8]).publishInput(E3_ID, encodeBidInput(makeBid(bidders[8].address, 9))),
      ).to.be.revertedWithCustomError(program, 'TooManyBidders')
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(makeBid(alice.address, 1)))).to.emit(program, 'BidSubmitted')
      expect(await program.bidderCount(E3_ID)).to.equal(8n)
    }
  })

  it('takes a relayed bid and checks the signature, the version and the bytes', async () => {
    const { program, programAddress, chainId, alice, bob, relayer, makeBid } = await setup()
    const bid = makeBid(alice.address, 1)
    const inputsHash = bidInputsHash(bid.commitments, bid.ciphertexts)
    const sign = (signer: typeof alice, version: number, hash: Hex = inputsHash) =>
      signer.signTypedData(
        { name: 'AuctionProgram', version: '1', chainId, verifyingContract: programAddress },
        {
          Bid: [
            { name: 'e3Id', type: 'uint256' },
            { name: 'bidder', type: 'address' },
            { name: 'version', type: 'uint32' },
            { name: 'inputsHash', type: 'bytes32' },
          ],
        },
        { e3Id: E3_ID, bidder: alice.address, version, inputsHash: hash },
      ) as Promise<Hex>

    // `bidTypedData` is the digest the contract computes.
    const typed = bidTypedData(chainId, programAddress, E3_ID, alice.address as Hex, 1, inputsHash)
    expect(await program.bidDigest(E3_ID, alice.address, 1, inputsHash)).to.equal(hashTypedData(typed))

    const good = { ...bid, signature: await sign(alice, 1) }
    // Another signer, another version, other bytes: all rejected.
    await expect(
      program.connect(relayer).publishInput(E3_ID, encodeBidInput({ ...bid, signature: await sign(bob as typeof alice, 1) })),
    ).to.be.revertedWithCustomError(program, 'InvalidSignature')
    await expect(
      program.connect(relayer).publishInput(E3_ID, encodeBidInput({ ...bid, signature: await sign(alice, 2) })),
    ).to.be.revertedWithCustomError(program, 'InvalidSignature')
    const swapped = { ...good, ciphertexts: [bid.ciphertexts[1], bid.ciphertexts[0], bid.ciphertexts[2]] }
    await expect(program.connect(relayer).publishInput(E3_ID, encodeBidInput(swapped))).to.be.revertedWithCustomError(
      program,
      'InvalidSignature',
    )
    expect(keccak256(good.ciphertexts[0])).to.not.equal(keccak256(good.ciphertexts[1]))

    await expect(program.connect(relayer).publishInput(E3_ID, encodeBidInput(good)))
      .to.emit(program, 'BidSubmitted')
      .withArgs(E3_ID, alice.address, 1n, 1n, good.ciphertexts, good.commitments)
    // The signature of version 1 is useless once the bidder has bid again.
    await expect(program.connect(relayer).publishInput(E3_ID, encodeBidInput(good))).to.be.revertedWithCustomError(
      program,
      'InvalidSignature',
    )
    expect(await program.bidCount(E3_ID, alice.address)).to.equal(1n)
  })

  it('sends each type to its own verifier and its own anchor', async () => {
    for (const type of TYPES) {
      const { program, alice, makeBid, openBids, route, anchors, verifier2, verifier3, verifier4 } = await setup({ type, providers: 1 })
      await openBids()
      const bid = makeBid(alice.address, 1)
      const publicInputs = [...bid.commitments, word(alice.address), level(4), KEY]
      // The verifiers of the other types reject any input but this one, so only the right verifier passes the bid.
      for (const other of [verifier2, verifier3, verifier4].filter((verifier) => verifier !== route.verifier)) {
        await other.expect([filled(1)])
      }
      // The right verifier takes only the right anchor: the anchor of any other circuit fails the bid.
      for (const anchor of anchors.filter((candidate) => candidate !== route.anchor)) {
        await route.verifier.expect([...publicInputs, anchor])
        await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(
          route.verifier,
          'PublicInputsMismatch',
        )
      }
      expect(await program.bidCount(E3_ID, alice.address)).to.equal(0n)
      await route.verifier.expect([...publicInputs, route.anchor])
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.emit(program, 'BidSubmitted')
      expect(await program.bidCount(E3_ID, alice.address)).to.equal(1n)
    }
  })

  it('lets only allowlisted bidders in', async () => {
    const { program, alice, bob, outsider, makeBid, gate, programAddress, ethers } = await setup({ allowlisted: ['alice', 'bob'] })
    const members = [alice.address, bob.address]
    // The gate learned the list when the auction was created.
    expect(await gate.roots(programAddress, E3_ID)).to.not.equal(`0x${'00'.repeat(32)}`)
    expect((await program.auctions(E3_ID)).gate).to.equal(await gate.getAddress())

    await expect(
      program
        .connect(alice)
        .publishInput(E3_ID, encodeBidInput(makeBid(alice.address, 1, { gateProof: allowlistProof(members, alice.address) }))),
    ).to.emit(program, 'BidSubmitted')
    // No proof, the proof of another member, and a non-member with a member's proof.
    await expect(program.connect(bob).publishInput(E3_ID, encodeBidInput(makeBid(bob.address, 2)))).to.be.revert(ethers)
    await expect(
      program
        .connect(bob)
        .publishInput(E3_ID, encodeBidInput(makeBid(bob.address, 2, { gateProof: allowlistProof(members, alice.address) }))),
    ).to.be.revertedWithCustomError(program, 'BidderNotEligible')
    await expect(
      program
        .connect(outsider)
        .publishInput(E3_ID, encodeBidInput(makeBid(outsider.address, 3, { gateProof: allowlistProof(members, alice.address) }))),
    ).to.be.revertedWithCustomError(program, 'BidderNotEligible')
    await expect(
      program
        .connect(bob)
        .publishInput(E3_ID, encodeBidInput(makeBid(bob.address, 2, { gateProof: allowlistProof(members, bob.address) }))),
    ).to.emit(program, 'BidSubmitted')
  })

  it('refuses gate config without a gate and a gate without code', async () => {
    const { program, outsider } = await setup()
    const params = (gate: Hex, config: Hex) => encodeParams(FIRST_PRICE_TYPE, [], gate, config)
    await expect(program.validate(6n, 0n, E3_PROGRAM_PARAMS, '0x', params(zeroAddress, '0x1234'))).to.be.revertedWithCustomError(
      program,
      'GateConfigWithoutGate',
    )
    await expect(program.validate(6n, 0n, E3_PROGRAM_PARAMS, '0x', params(outsider.address as Hex, '0x'))).to.be.revertedWithCustomError(
      program,
      'InvalidGate',
    )
  })

  describe('the three types', () => {
    const DOMAIN = '0x696e746572666f6c642d61756374696f6e2d636f6e6669672d7631'

    it('numbers the types 0 to 2, with their roles and the bidder limit', async () => {
      const { program } = await setup()
      expect(await program.AUCTION_FIRST_PRICE()).to.equal(BigInt(FIRST_PRICE_TYPE))
      expect(await program.AUCTION_PROVIDER_SECOND_PRICE()).to.equal(BigInt(PROVIDER_TYPE))
      expect(await program.AUCTION_QNR_SECOND_PRICE()).to.equal(BigInt(QNR_TYPE))
      // `ge`, `gt`, `mask`; `ge`, `gt`; `ge`, `gt`, `share`, `share`.
      expect(await Promise.all(TYPES.map((type) => program.roleCount(type)))).to.deep.equal([3n, 2n, 4n])
      expect(await Promise.all(TYPES.map((type) => program.maxBidders(type)))).to.deep.equal([8n, 8n, 8n])
    })

    it('refuses the type 3 and above', async () => {
      const { program } = await setup()
      for (const type of [3, 4, 255]) {
        await expect(program.roleCount(type)).to.be.revertedWithCustomError(program, 'UnknownAuctionType')
        await expect(program.maxBidders(type)).to.be.revertedWithCustomError(program, 'UnknownAuctionType')
        await expect(program.validate(40n, 0n, E3_PROGRAM_PARAMS, '0x', encodeParams(type))).to.be.revertedWithCustomError(
          program,
          'UnknownAuctionType',
        )
      }
    })

    it('creates each type with the config leaf CONFIG_DOMAIN || id', async () => {
      const leaves: bigint[] = []
      for (const type of TYPES) {
        const { program, created, providers, hasLeaves } = await setup({ type, providers: 2 })
        await expect(created).to.emit(program, 'AuctionCreated')
        if (type === PROVIDER_TYPE) await expect(created).to.emit(program, 'MaskProvidersSet').withArgs(E3_ID, providers)
        else await expect(created).to.not.emit(program, 'MaskProvidersSet')
        expect((await program.auctions(E3_ID)).auctionType).to.equal(BigInt(type))
        expect(await program.CONFIG_DOMAIN()).to.equal(DOMAIN)

        // The type byte is the id; the providers follow as 20 raw bytes each.
        const input = concatHex([DOMAIN, toHex(type, { size: 1 }), ...providers.map((provider) => provider.toLowerCase() as Hex)])
        expect(await program.configInput(type, providers)).to.equal(input)
        const leaf = await program.configLeaf(type, providers)
        expect(leaf).to.equal(BigInt(keccak256(input)) % FIELD)
        // Leaf 0 is that leaf, and the auction has no other leaf yet.
        expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(1n)
        expect(await hasLeaves([leaf])).to.equal(true)
        for (const other of TYPES.filter((candidate) => candidate !== type)) {
          expect(await hasLeaves([await program.configLeaf(other, [])])).to.equal(false)
        }
        leaves.push(leaf)
      }
      expect(new Set(leaves).size).to.equal(TYPES.length)
    })

    it('matches the shared config leaf vectors', async () => {
      const { program } = await setup()
      // The vectors `program/src/lib.rs` and `sdk/src/layout.ts` test as well.
      expect(keccak256(concatHex([DOMAIN, '0x00']))).to.equal('0x7cb4b680799f9a657bac884e1e32705f63553405504316f74d41fe7405521933')
      expect(await program.configLeaf(FIRST_PRICE_TYPE, [])).to.equal(0x1bec199ab73c5a120b0bfce11b2fbfa512ed63745cd035d4c57e134c25521931n)
      expect(await program.configLeaf(PROVIDER_TYPE, [])).to.equal(0x04584f96228a1ea3762ebf79ae1cc47f032f2dd1103c11e6c57bb0825775a0d4n)
      expect(await program.configLeaf(QNR_TYPE, [])).to.equal(0x049d6b6876506c830bbd2ac2de0bab04c890d8c97a125c2add0b1e8adef5da65n)
    })
  })

  describe('type 1: second-price, mask providers', () => {
    const p1 = '0x1111111111111111111111111111111111111111'
    const p2 = '0x2222222222222222222222222222222222222222'
    const DOMAIN = '0x696e746572666f6c642d61756374696f6e2d636f6e6669672d7631'

    it('builds the config input with 20 raw bytes per provider', async () => {
      const { program } = await setup()
      // The vector `program/src/lib.rs` and `sdk/src/layout.ts` test as well.
      const input = concatHex([DOMAIN, '0x01', p1, p2])
      expect(input).to.equal(
        '0x696e746572666f6c642d61756374696f6e2d636f6e6669672d76310111111111111111111111111111111111111111112222222222222222222222222222222222222222',
      )
      expect(await program.configInput(PROVIDER_TYPE, [p1, p2])).to.equal(input)
      expect(keccak256(input)).to.equal('0xc35ec886d8a9aa1b8ee8253c137ea4da5393c43cd7a1e2cd1e7adf4e08af0746')
      expect(await program.configLeaf(PROVIDER_TYPE, [p1, p2])).to.equal(
        0x01cd8ebb53e32974ada70e620d794365b2c4231af0bc20880ef308fe48af0742n,
      )
      // The order of the providers is part of the leaf.
      expect(await program.configLeaf(PROVIDER_TYPE, [p2, p1])).to.not.equal(await program.configLeaf(PROVIDER_TYPE, [p1, p2]))
    })

    it('stores the providers and puts the config leaf with them first', async () => {
      const { program, created, providers, outsider, hasLeaves } = await setup({ type: PROVIDER_TYPE, providers: 2 })
      await expect(created).to.emit(program, 'MaskProvidersSet').withArgs(E3_ID, providers)
      await expect(created).to.emit(program, 'AuctionCreated')
      expect(await program.auctionProviders(E3_ID)).to.deep.equal(providers)
      for (const provider of providers) {
        expect(await program.isProvider(E3_ID, provider)).to.equal(true)
        expect(await program.maskSubmitted(E3_ID, provider)).to.equal(false)
      }
      expect(await program.isProvider(E3_ID, outsider.address)).to.equal(false)
      expect(await program.maskCount(E3_ID)).to.equal(0n)
      expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(1n)
      // Leaf 0 is the config leaf of this provider list, not of another.
      expect(await hasLeaves([await program.configLeaf(PROVIDER_TYPE, providers)])).to.equal(true)
      expect(await hasLeaves([await program.configLeaf(PROVIDER_TYPE, [...providers].reverse())])).to.equal(false)
      expect(await hasLeaves([await program.configLeaf(PROVIDER_TYPE, [])])).to.equal(false)
    })

    it('takes 1 to 4 providers', async () => {
      const { program, providerSigners } = await setup()
      for (const [index, count] of [1, 2, 3, 4].entries()) {
        const list = providerSigners.slice(0, count).map((signer) => signer.address)
        await expect(program.validate(10n + BigInt(index), 0n, E3_PROGRAM_PARAMS, '0x', encodeParams(PROVIDER_TYPE, list)))
          .to.emit(program, 'MaskProvidersSet')
          .withArgs(10n + BigInt(index), list)
        expect(await program.auctionProviders(10n + BigInt(index))).to.deep.equal(list)
      }
    })

    it('refuses a bad provider list', async () => {
      const { program, providerSigners, extraSigners } = await setup()
      const [a, b, c, d] = providerSigners.map((signer) => signer.address)
      const fifth = extraSigners[0].address
      const create = (type: number, providers: string[], id = 20n) =>
        program.validate(id, 0n, E3_PROGRAM_PARAMS, '0x', encodeParams(type, providers))
      // None, five, the zero address, and a repeated address (adjacent or not).
      for (const providers of [[], [a, b, c, d, fifth], [a, zeroAddress], [zeroAddress], [a, a], [a, b, a], [a, b, c, b]]) {
        await expect(create(PROVIDER_TYPE, providers)).to.be.revertedWithCustomError(program, 'InvalidProviders')
      }
      // The types 0 and 2 have no providers.
      for (const type of [FIRST_PRICE_TYPE, QNR_TYPE]) {
        for (const providers of [[a], [a, b], [a, b, c, d], [zeroAddress]]) {
          await expect(create(type, providers)).to.be.revertedWithCustomError(program, 'InvalidProviders')
        }
        await expect(create(type, [], 21n + BigInt(type))).to.emit(program, 'AuctionCreated')
      }
      await expect(create(3, [a])).to.be.revertedWithCustomError(program, 'UnknownAuctionType')
      // Nothing of a refused request stays.
      expect(await program.auctionProviders(20n)).to.deep.equal([])
      expect(await program.isProvider(20n, a)).to.equal(false)
    })

    it('takes the masks in submission order, then the bids, as the leaves', async () => {
      const {
        program,
        alice,
        bob,
        providerSigners,
        providers,
        makeMask,
        makeBid,
        maskVerifier,
        verifier2,
        vkAnchorMask,
        vkAnchor2,
        hasLeaves,
      } = await setup({ type: PROVIDER_TYPE, providers: 2 })
      const [provider1, provider2] = providerSigners
      const configLeaf = await program.configLeaf(PROVIDER_TYPE, providers)
      const leaf = (ciphertext: Hex, commitment: Hex, owner: string, version: number) =>
        program.inputLeaf(keccak256(ciphertext), commitment, owner, version)

      // The second provider sends first, so its mask is leaf 1.
      const mask2 = makeMask(provider2.address, 2)
      await maskVerifier.expect([mask2.commitments[0], word(provider2.address), KEY, vkAnchorMask])
      await expect(program.connect(provider2).publishInput(E3_ID, encodeBidInput(mask2)))
        .to.emit(program, 'MaskSubmitted')
        .withArgs(E3_ID, provider2.address, 1n, mask2.ciphertexts[0], mask2.commitments[0])
      expect(await program.maskCount(E3_ID)).to.equal(1n)
      expect(await program.maskSubmitted(E3_ID, provider2.address)).to.equal(true)
      expect(await program.maskSubmitted(E3_ID, provider1.address)).to.equal(false)

      const mask1 = makeMask(provider1.address, 1)
      await maskVerifier.expect([mask1.commitments[0], word(provider1.address), KEY, vkAnchorMask])
      await expect(program.connect(provider1).publishInput(E3_ID, encodeBidInput(mask1)))
        .to.emit(program, 'MaskSubmitted')
        .withArgs(E3_ID, provider1.address, 2n, mask1.ciphertexts[0], mask1.commitments[0])
      expect(await program.maskCount(E3_ID)).to.equal(2n)
      // A mask is not a bid: no bidder, no bid count.
      expect(await program.bidderCount(E3_ID)).to.equal(0n)
      expect(await program.bidCount(E3_ID, provider1.address)).to.equal(0n)

      const leaf2 = await leaf(mask2.ciphertexts[0], mask2.commitments[0], provider2.address, MASK_VERSION)
      const leaf1 = await leaf(mask1.ciphertexts[0], mask1.commitments[0], provider1.address, MASK_VERSION)
      expect(await hasLeaves([configLeaf, leaf2, leaf1])).to.equal(true)
      expect(await hasLeaves([configLeaf, leaf1, leaf2])).to.equal(false)

      // The bids come after, 2 leaves each, with the versions 1 to 3.
      const bid = makeBid(alice.address, 1)
      await verifier2.expect([...bid.commitments, word(alice.address), level(4), KEY, vkAnchor2])
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(E3_ID, alice.address, 1n, 3n, bid.ciphertexts, bid.commitments)
      const bobBid = makeBid(bob.address, 2)
      await verifier2.expect([...bobBid.commitments, word(bob.address), level(4), KEY, vkAnchor2])
      await expect(program.connect(bob).publishInput(E3_ID, encodeBidInput(bobBid)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(E3_ID, bob.address, 1n, 5n, bobBid.ciphertexts, bobBid.commitments)
      const leaves = [configLeaf, leaf2, leaf1]
      for (const [owner, input] of [
        [alice.address, bid],
        [bob.address, bobBid],
      ] as const) {
        for (const [r, ciphertext] of input.ciphertexts.entries()) leaves.push(await leaf(ciphertext, input.commitments[r], owner, 1))
      }
      expect(await hasLeaves(leaves)).to.equal(true)
      expect(await program.bidderCount(E3_ID)).to.equal(2n)
    })

    it('gives a mask the version 0xFFFFFFFF in its 25-byte metadata', async () => {
      const { program } = await setup()
      const ciphertextHash = filled(0x11)
      const commitment = filled(0x22)
      const provider = '0x3333333333333333333333333333333333333333'
      // metadata = provider (20 bytes) || uint40 big-endian version = 00 ff ff ff ff
      const expected = BigInt(sha256(concatHex([ciphertextHash, commitment, provider, '0x00ffffffff']))) % FIELD
      expect(await program.inputLeaf(ciphertextHash, commitment, provider, MASK_VERSION)).to.equal(expected)
      expect(await program.MASK_VERSION()).to.equal(BigInt(MASK_VERSION))
    })

    it('refuses every bid until all masks are in, then takes bids', async () => {
      const { program, alice, bob, providerSigners, makeMask, makeBid } = await setup({ type: PROVIDER_TYPE, providers: 2 })
      const [provider1, provider2] = providerSigners
      const bid = makeBid(alice.address, 1)
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(program, 'MasksPending')
      await program.connect(provider1).publishInput(E3_ID, encodeBidInput(makeMask(provider1.address, 1)))
      // One mask of two.
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(program, 'MasksPending')
      await program.connect(provider2).publishInput(E3_ID, encodeBidInput(makeMask(provider2.address, 2)))
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.emit(program, 'BidSubmitted')
      await expect(program.connect(bob).publishInput(E3_ID, encodeBidInput(makeBid(bob.address, 2)))).to.emit(program, 'BidSubmitted')
      expect(await program.bidderCount(E3_ID)).to.equal(2n)
    })

    it('opens bids after the one mask of a single-provider auction', async () => {
      const { program, alice, providerSigners, makeMask, makeBid } = await setup({ type: PROVIDER_TYPE, providers: 1 })
      const bid = makeBid(alice.address, 1)
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(program, 'MasksPending')
      await program.connect(providerSigners[0]).publishInput(E3_ID, encodeBidInput(makeMask(providerSigners[0].address, 1)))
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(E3_ID, alice.address, 1n, 2n, bid.ciphertexts, bid.commitments)
    })

    it('opens bids after the four masks of a four-provider auction', async () => {
      const { program, alice, providerSigners, makeMask, makeBid } = await setup({ type: PROVIDER_TYPE, providers: 4 })
      const bid = makeBid(alice.address, 1)
      for (const [seed, signer] of providerSigners.entries()) {
        await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(program, 'MasksPending')
        await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeMask(signer.address, seed + 1)))
      }
      expect(await program.maskCount(E3_ID)).to.equal(4n)
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(E3_ID, alice.address, 1n, 5n, bid.ciphertexts, bid.commitments)
    })

    it('rejects a mask of a wrong shape, from a wrong sender, twice, or with a bad proof', async () => {
      const { program, providerSigners, relayer, makeMask, maskVerifier, vkAnchorMask, ethers } = await setup({
        type: PROVIDER_TYPE,
        providers: 2,
      })
      const [provider1, provider2] = providerSigners
      const mask = makeMask(provider1.address, 1)
      const send = (signer: typeof provider1, input: BidInput) => program.connect(signer).publishInput(E3_ID, encodeBidInput(input))

      // Two ciphertexts or none, and the commitments out of step.
      await expect(send(provider1, { ...mask, ciphertexts: [...mask.ciphertexts, ...mask.ciphertexts] })).to.be.revertedWithCustomError(
        program,
        'InvalidBidShape',
      )
      await expect(send(provider1, { ...mask, ciphertexts: [] })).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      await expect(send(provider1, { ...mask, commitments: [...mask.commitments, ...mask.commitments] })).to.be.revertedWithCustomError(
        program,
        'InvalidBidShape',
      )
      await expect(send(provider1, { ...mask, commitments: [] })).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      // A gate proof or a signature is not part of a mask.
      await expect(send(provider1, { ...mask, gateProof: '0x01' })).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      await expect(send(provider1, { ...mask, signature: '0x01' })).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      await expect(send(relayer, { ...mask, signature: `0x${'11'.repeat(65)}` })).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      await expect(send(provider1, { ...mask, ciphertexts: ['0x'] })).to.be.revertedWithCustomError(program, 'EmptyInputData')
      // Only the provider sends its mask: not another provider, not a relayer.
      await expect(send(provider2, mask)).to.be.revertedWithCustomError(program, 'SenderNotBidder')
      await expect(send(relayer, mask)).to.be.revertedWithCustomError(program, 'SenderNotBidder')
      // A bad proof, and public inputs the verifier does not accept.
      await expect(send(provider1, { ...mask, proof: '0x02' })).to.be.revert(ethers)
      await maskVerifier.expect([filled(0x99), word(provider1.address), KEY, vkAnchorMask])
      await expect(send(provider1, mask)).to.be.revert(ethers)
      await maskVerifier.expect([mask.commitments[0], word(provider2.address), KEY, vkAnchorMask])
      await expect(send(provider1, mask)).to.be.revert(ethers)
      // Nothing of the failures stays.
      expect(await program.maskCount(E3_ID)).to.equal(0n)
      expect(await program.maskSubmitted(E3_ID, provider1.address)).to.equal(false)
      expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(1n)

      await maskVerifier.expect([mask.commitments[0], word(provider1.address), KEY, vkAnchorMask])
      await expect(send(provider1, mask)).to.emit(program, 'MaskSubmitted')
      // A second mask of the same provider, even another one.
      await expect(send(provider1, mask)).to.be.revertedWithCustomError(program, 'MaskAlreadySubmitted').withArgs(provider1.address)
      await expect(send(provider1, makeMask(provider1.address, 7))).to.be.revertedWithCustomError(program, 'MaskAlreadySubmitted')
      expect(await program.maskCount(E3_ID)).to.equal(1n)
      expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(2n)
    })

    it('does not let a provider bid, or anyone else send a mask', async () => {
      const { program, alice, providerSigners, relayer, makeMask, makeBid } = await setup({ type: PROVIDER_TYPE, providers: 2 })
      const [provider1, provider2] = providerSigners
      for (const signer of providerSigners.slice(0, 2)) {
        await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeMask(signer.address, 1)))
      }
      // A provider's address takes only the mask path: a two-ciphertext bid is the wrong shape.
      await expect(
        program.connect(provider1).publishInput(E3_ID, encodeBidInput(makeBid(provider1.address, 1))),
      ).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      await expect(
        program.connect(relayer).publishInput(E3_ID, encodeBidInput(makeBid(provider2.address, 1, { signature: `0x${'11'.repeat(65)}` }))),
      ).to.be.revertedWithCustomError(program, 'InvalidBidShape')
      expect(await program.bidCount(E3_ID, provider1.address)).to.equal(0n)
      expect(await program.bidderCount(E3_ID)).to.equal(0n)
      // A bidder who is not a provider cannot send a one-ciphertext mask: it is a bid of the wrong shape.
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(makeMask(alice.address, 3)))).to.be.revertedWithCustomError(
        program,
        'InvalidBidShape',
      )
      expect(await program.maskCount(E3_ID)).to.equal(2n)
    })

    it('refuses a non-provider mask while masks are pending', async () => {
      const { program, alice, makeMask } = await setup({ type: PROVIDER_TYPE, providers: 2 })
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(makeMask(alice.address, 3)))).to.be.revertedWithCustomError(
        program,
        'MasksPending',
      )
      expect(await program.maskCount(E3_ID)).to.equal(0n)
    })

    it('counts bidders, not providers: 8 bidders fit, a ninth does not', async () => {
      const { program, alice, bob, carol, dave, relayer, outsider, extraSigners, providerSigners, makeMask, makeBid } = await setup({
        type: PROVIDER_TYPE,
        providers: 4,
      })
      for (const [seed, signer] of providerSigners.entries()) {
        await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeMask(signer.address, seed + 1)))
      }
      const bidders = [alice, bob, carol, dave, relayer, outsider, extraSigners[0], extraSigners[1], extraSigners[2]]
      for (const [seed, signer] of bidders.slice(0, 8).entries()) {
        await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeBid(signer.address, seed + 1)))
      }
      expect(await program.bidderCount(E3_ID)).to.equal(8n)
      await expect(
        program.connect(bidders[8]).publishInput(E3_ID, encodeBidInput(makeBid(bidders[8].address, 9))),
      ).to.be.revertedWithCustomError(program, 'TooManyBidders')
      // A bidder still updates: 4 mask leaves would not count against its 3 versions.
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(makeBid(alice.address, 1)))).to.emit(program, 'BidSubmitted')
    })

    it('closes masks and bids at the input deadline', async () => {
      const { program, alice, providerSigners, makeMask, makeBid } = await setup({ type: PROVIDER_TYPE, providers: 1, deadline: 1n })
      await expect(
        program.connect(providerSigners[0]).publishInput(E3_ID, encodeBidInput(makeMask(providerSigners[0].address, 1))),
      ).to.be.revertedWithCustomError(program, 'InputDeadlineReached')
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(makeBid(alice.address, 1)))).to.be.revertedWithCustomError(
        program,
        'InputDeadlineReached',
      )
    })

    it('leaves the types 0 and 2 without masks: a bid is a bid', async () => {
      for (const type of [FIRST_PRICE_TYPE, QNR_TYPE]) {
        const { program, alice, makeBid, roles } = await setup({ type })
        expect(await program.auctionProviders(E3_ID)).to.deep.equal([])
        expect(await program.isProvider(E3_ID, alice.address)).to.equal(false)
        await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(makeBid(alice.address, 1))))
          .to.emit(program, 'BidSubmitted')
          .withArgs(E3_ID, alice.address, 1n, 1n, makeBid(alice.address, 1).ciphertexts, makeBid(alice.address, 1).commitments)
        expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(BigInt(1 + roles))
        expect(await program.maskCount(E3_ID)).to.equal(0n)
      }
    })
  })

  describe('type 2: second-price, no providers', () => {
    it('takes a bid of 4 ciphertexts at once, with no mask and no other leaf', async () => {
      const { program, alice, makeBid, roles } = await setup({ type: QNR_TYPE })
      expect(roles).to.equal(4)
      const bid = makeBid(alice.address, 1)
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(E3_ID, alice.address, 1n, 1n, bid.ciphertexts, bid.commitments)
      expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(5n)
      expect(await program.maskCount(E3_ID)).to.equal(0n)
    })
  })
})
