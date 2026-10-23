// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import hre from 'hardhat'
import { type Hex, hashTypedData, keccak256, zeroAddress } from 'viem'
import {
  AuctionType,
  allowlistProof,
  bidInputsHash,
  bidTypedData,
  encodeAllowlistConfig,
  encodeAuctionParams,
  encodeBidInput,
  evenPrices,
} from '@interfold/auction'
import { AuctionProgram__factory } from '../types/factories/contracts'

const PROOF = '0x01'
const E3_ID = 5n
const KEY = `0x${'ab'.repeat(32)}` as const

/** `bytes32` filled with one byte. */
const filled = (byte: number): Hex => `0x${byte.toString(16).padStart(2, '0').repeat(32)}`

describe('AuctionProgram bids', () => {
  async function setup(options: { type?: AuctionType; allowlisted?: ('alice' | 'bob')[] } = {}) {
    const { ethers } = await hre.network.connect()
    const [owner, alice, bob, carol, dave, relayer, outsider] = await ethers.getSigners()
    const type = options.type ?? AuctionType.FirstPrice
    const interfold = await ethers.deployContract('MockInterfold', [2n ** 40n, KEY, owner.address])
    const receiptVerifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
    const availability = await ethers.deployContract('MockDataAvailabilityVerifier')
    const verifier3 = await ethers.deployContract('MockBidVerifier')
    const verifier4 = await ethers.deployContract('MockBidVerifier')
    const poseidon = await ethers.deployContract('PoseidonT3')
    const vkAnchor3 = filled(0xcd)
    const vkAnchor4 = filled(0xce)
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
          await verifier3.getAddress(),
          await verifier4.getAddress(),
          vkAnchor3,
          vkAnchor4,
          await availability.getAddress(),
        )
      ).getAddress(),
      owner,
    )
    const gate = await ethers.deployContract('MerkleAllowlistGate')
    const gated = options.allowlisted !== undefined
    const members = (options.allowlisted ?? []).map((name) => ({ alice, bob })[name].address)
    const customParams = encodeAuctionParams(
      type,
      evenPrices(1n, 1n, 4),
      'Unit test',
      gated ? ((await gate.getAddress()) as Hex) : zeroAddress,
      gated ? encodeAllowlistConfig(members) : '0x',
    )
    await (await program.validate(E3_ID, 0n, '0x1234', '0x', customParams)).wait()
    const chainId = Number((await ethers.provider.getNetwork()).chainId)
    const programAddress = (await program.getAddress()) as Hex
    const roles = type === AuctionType.RatioSecondPrice ? 4 : 3
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
    return {
      ethers,
      owner,
      alice,
      bob,
      carol,
      dave,
      relayer,
      outsider,
      program,
      programAddress,
      chainId,
      makeBid,
      verifier3,
      verifier4,
      vkAnchor3,
      vkAnchor4,
      gate,
      roles,
    }
  }

  it('matches the shared leaf vector', async () => {
    const { program } = await setup()
    // The same vector `program/src/lib.rs` and `sdk/src/selection.ts` test.
    expect(await program.inputLeaf(filled(0x11), filled(0x22), '0x3333333333333333333333333333333333333333', 2)).to.equal(
      0x0b8ba63e8917dfb3f66cfcc1b0be5d3a8f8613ba8092d690a43b84daec02b94an,
    )
  })

  it('takes a direct bid, then updates, and numbers the leaves', async () => {
    const { program, alice, makeBid, verifier3, vkAnchor3, roles } = await setup()
    const first = makeBid(alice.address, 1)
    // The verifier gets the commitments, the bidder, levels, the committee key and the anchor.
    await verifier3.expect([
      ...first.commitments,
      `0x${'00'.repeat(12)}${alice.address.slice(2).toLowerCase()}`,
      `0x${'00'.repeat(31)}04`,
      KEY,
      vkAnchor3,
    ])
    const tx = await program.connect(alice).publishInput(E3_ID, encodeBidInput(first))
    await expect(tx).to.emit(program, 'BidSubmitted').withArgs(E3_ID, alice.address, 1n, 1n, first.ciphertexts, first.commitments)
    expect(await program.bidCount(E3_ID, alice.address)).to.equal(1n)
    expect(await program.bidderCount(E3_ID)).to.equal(1n)
    expect((await program.inputs(E3_ID)).numberOfLeaves).to.equal(BigInt(1 + roles))

    await verifier3.expect([
      ...first.commitments,
      `0x${'00'.repeat(12)}${alice.address.slice(2).toLowerCase()}`,
      `0x${'00'.repeat(31)}04`,
      KEY,
      vkAnchor3,
    ])
    for (const version of [2n, 3n]) {
      await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(first)))
        .to.emit(program, 'BidSubmitted')
        .withArgs(E3_ID, alice.address, version, 1n + BigInt(roles) * (version - 1n), first.ciphertexts, first.commitments)
    }
    // The bidder counts once; a fourth bid is too many.
    expect(await program.bidderCount(E3_ID)).to.equal(1n)
    await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(first))).to.be.revertedWithCustomError(program, 'TooManyBids')
  })

  it('rejects a bad shape, a foreign sender, a bad proof and a fifth bidder', async () => {
    const { program, alice, bob, carol, dave, relayer, makeBid, ethers } = await setup()
    const bid = makeBid(alice.address, 1)
    await expect(program.connect(bob).publishInput(E3_ID, encodeBidInput(bid))).to.be.revertedWithCustomError(program, 'SenderNotBidder')
    await expect(
      program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, ciphertexts: bid.ciphertexts.slice(1) })),
    ).to.be.revertedWithCustomError(program, 'InvalidBidShape')
    await expect(
      program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, ciphertexts: ['0x', ...bid.ciphertexts.slice(1)] })),
    ).to.be.revertedWithCustomError(program, 'EmptyInputData')
    await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput({ ...bid, proof: '0x02' }))).to.be.revert(ethers)
    // Four bidders fit a region auction.
    for (const [seed, signer] of [alice, bob, carol, dave].entries()) {
      await program.connect(signer).publishInput(E3_ID, encodeBidInput(makeBid(signer.address, seed + 1)))
    }
    await expect(program.connect(relayer).publishInput(E3_ID, encodeBidInput(makeBid(relayer.address, 9)))).to.be.revertedWithCustomError(
      program,
      'TooManyBidders',
    )
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

  it('uses the four-role verifier for the second-price ratio type', async () => {
    const { program, alice, makeBid, verifier3, verifier4, vkAnchor4 } = await setup({ type: AuctionType.RatioSecondPrice })
    const bid = makeBid(alice.address, 1)
    // The 3-role verifier would reject any other inputs, so the bid passes only through verifier 4,
    // with the anchor of the 4-role circuits.
    await verifier3.expect([filled(1)])
    await verifier4.expect([
      ...bid.commitments,
      `0x${'00'.repeat(12)}${alice.address.slice(2).toLowerCase()}`,
      `0x${'00'.repeat(31)}04`,
      KEY,
      vkAnchor4,
    ])
    await expect(program.connect(alice).publishInput(E3_ID, encodeBidInput(bid))).to.emit(program, 'BidSubmitted')
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
    const params = (gate: Hex, config: Hex) => encodeAuctionParams(AuctionType.FirstPrice, evenPrices(1n, 1n, 4), 'Unit test', gate, config)
    await expect(program.validate(6n, 0n, '0x1234', '0x', params(zeroAddress, '0x1234'))).to.be.revertedWithCustomError(
      program,
      'GateConfigWithoutGate',
    )
    await expect(program.validate(6n, 0n, '0x1234', '0x', params(outsider.address as Hex, '0x'))).to.be.revertedWithCustomError(
      program,
      'InvalidGate',
    )
  })
})
