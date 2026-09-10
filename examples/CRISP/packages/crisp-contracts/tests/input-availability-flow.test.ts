// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import type { CRISPProgram, HonkVerifier } from '../types'
import {
  abiCoder,
  deployContract,
  deployCRISPProgram,
  deployMockInterfold,
  ethers,
  increaseTimeTo,
  inputCommitmentPayload,
  inputCommitmentTypes,
  latestTimestamp,
  setNextTimestamp,
} from './utils'

const FINALIZATION_WINDOW = 30
const PRODUCTION_FINALIZATION_WINDOW = 10_800

describe('CRISP input availability flow', function () {
  async function openRound() {
    const mockInterfold = await deployMockInterfold()
    const mockHonk = (await deployContract('MockHonkVerifier')) as unknown as HonkVerifier
    const program = await deployCRISPProgram({
      mockInterfold,
      honkVerifier: mockHonk,
      onchainHonkVerifier: mockHonk,
      availabilityFinalizationWindow: FINALIZATION_WINDOW,
    })
    const now = await latestTimestamp()
    const start = now + 5
    const end = start + 3_700
    await (await mockInterfold.setInputWindow(start, end)).wait()
    const e3Id = await mockInterfold.nextE3Id()
    await (await mockInterfold.request(await program.getAddress())).wait()
    await (await mockInterfold.setCommitteePublicKey(ethers.id('committee-key'))).wait()
    await (await program.setMerkleRoot(e3Id, 1)).wait()
    await increaseTimeTo(start)

    return { program, mockInterfold, e3Id, start, end }
  }

  async function input(
    program: CRISPProgram,
    e3Id: bigint,
    suffix = 'one',
    slotAddress = ethers.Wallet.createRandom().address,
    parentIndexPlusOne = 0,
  ) {
    const encryptedVoteCommitment = ethers.id(`commitment-${suffix}`)
    const ciphertext = ethers.hexlify(ethers.toUtf8Bytes(`ciphertext-${suffix}`))
    const encryptedVoteHash = ethers.keccak256(ciphertext)
    const stagedEnvelope = abiCoder.encode(
      ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'bytes'],
      ['0x01', slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne, ciphertext],
    )
    const commitmentPayload = await inputCommitmentPayload(program, e3Id, stagedEnvelope)
    return {
      program,
      e3Id,
      slotAddress,
      encryptedVoteCommitment,
      encryptedVoteHash,
      ciphertext,
      parentIndexPlusOne,
      commitmentPayload,
    }
  }

  it('accepts the proof first and lets another account finalize availability later', async function () {
    const { program, e3Id } = await openRound()
    const ballot = await input(program, e3Id)
    const [, finalizer] = await ethers.getSigners()

    await expect(program.publishInput(e3Id, ballot.commitmentPayload)).to.emit(program, 'InputCommitted')
    expect(await program.isInputCommitted(e3Id, ballot.encryptedVoteHash, ballot.encryptedVoteCommitment, ballot.slotAddress, 0)).to.equal(
      true,
    )
    expect((await program.getRoundData(e3Id)).numberOfVotes).to.equal(1n)
    expect(await program.pendingInputCount(e3Id)).to.equal(1n)

    await expect(
      program
        .connect(finalizer)
        .finalizeInput(e3Id, ballot.slotAddress, ballot.encryptedVoteCommitment, ballot.encryptedVoteHash, 0, ballot.ciphertext),
    ).to.emit(program, 'InputPublished')

    expect((await program.getRoundData(e3Id)).numberOfVotes).to.equal(1n)
    expect(await program.pendingInputCount(e3Id)).to.equal(0n)
    expect(await program.isInputPublished(e3Id, ballot.encryptedVoteHash, ballot.encryptedVoteCommitment, ballot.slotAddress, 0)).to.equal(
      true,
    )
  })

  it('reserves indices immediately so pending masks and revotes keep their parent chain', async function () {
    const { program, e3Id } = await openRound()
    const slot = ethers.Wallet.createRandom().address
    const first = await input(program, e3Id, 'first', slot)
    await (await program.publishInput(e3Id, first.commitmentPayload)).wait()

    const second = await input(program, e3Id, 'second', slot, 1)
    await (await program.publishInput(e3Id, second.commitmentPayload)).wait()

    expect((await program.getRoundData(e3Id)).numberOfVotes).to.equal(2n)
    expect(await program.pendingInputCount(e3Id)).to.equal(2n)
    expect(await program.getSlotIndex(e3Id, slot)).to.equal(1n)
    expect(await program.inputCommitmentOf(e3Id, slot, 0)).to.equal(first.encryptedVoteCommitment)
    expect(await program.inputCommitmentOf(e3Id, slot, 1)).to.equal(second.encryptedVoteCommitment)

    await expect(program.verify(e3Id, ethers.ZeroHash, ethers.ZeroHash, '0x'))
      .to.be.revertedWithCustomError(program, 'InputAvailabilityPending')
      .withArgs(2)
  })

  it('rejects a proof commitment not attested by the configured availability service', async function () {
    const { program, e3Id } = await openRound()
    const ballot = await input(program, e3Id)
    const decoded = abiCoder.decode(inputCommitmentTypes, ballot.commitmentPayload)
    const [, wrongSigner] = await ethers.getSigners()
    const inputId = await program.inputId(e3Id, decoded[3], decoded[2], decoded[1], decoded[4])
    const network = await ethers.provider.getNetwork()
    const wrongAttestation = await wrongSigner.signTypedData(
      { name: 'CRISP', version: '1', chainId: network.chainId, verifyingContract: await program.getAddress() },
      {
        InputAvailability: [
          { name: 'e3Id', type: 'uint256' },
          { name: 'inputId', type: 'bytes32' },
          { name: 'expiresAt', type: 'uint64' },
        ],
      },
      { e3Id, inputId, expiresAt: decoded[5] },
    )
    const forged = abiCoder.encode(inputCommitmentTypes, [
      decoded[0],
      decoded[1],
      decoded[2],
      decoded[3],
      decoded[4],
      decoded[5],
      wrongAttestation,
    ])

    await expect(program.publishInput(e3Id, forged)).to.be.revertedWithCustomError(program, 'InvalidInputAvailabilityAttestation')
  })

  it('rejects an availability promise at its exact expiry', async function () {
    const { program, e3Id } = await openRound()
    const expiry = BigInt((await latestTimestamp()) + 20)
    const ballot = await input(program, e3Id)
    const payload = await inputCommitmentPayload(
      program,
      e3Id,
      abiCoder.encode(
        ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'bytes'],
        [
          '0x01',
          ballot.slotAddress,
          ballot.encryptedVoteCommitment,
          ballot.encryptedVoteHash,
          ballot.parentIndexPlusOne,
          ballot.ciphertext,
        ],
      ),
      expiry,
    )

    await setNextTimestamp(Number(expiry))
    await expect(program.publishInput(e3Id, payload))
      .to.be.revertedWithCustomError(program, 'InputAvailabilityAttestationExpired')
      .withArgs(expiry)
  })

  it('accepts an availability promise one second before its expiry', async function () {
    const { program, e3Id } = await openRound()
    const expiry = BigInt((await latestTimestamp()) + 20)
    const ballot = await input(program, e3Id)
    const stagedEnvelope = abiCoder.encode(
      ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'bytes'],
      ['0x01', ballot.slotAddress, ballot.encryptedVoteCommitment, ballot.encryptedVoteHash, ballot.parentIndexPlusOne, ballot.ciphertext],
    )
    const payload = await inputCommitmentPayload(program, e3Id, stagedEnvelope, expiry)

    await setNextTimestamp(Number(expiry - 1n))
    await expect(program.publishInput(e3Id, payload)).to.emit(program, 'InputCommitted')
  })

  it('binds the availability promise expiry into the signer attestation', async function () {
    const { program, e3Id } = await openRound()
    const ballot = await input(program, e3Id)
    const decoded = abiCoder.decode(inputCommitmentTypes, ballot.commitmentPayload)
    const altered = abiCoder.encode(inputCommitmentTypes, [
      decoded[0],
      decoded[1],
      decoded[2],
      decoded[3],
      decoded[4],
      decoded[5] + 1n,
      decoded[6],
    ])

    await expect(program.publishInput(e3Id, altered)).to.be.revertedWithCustomError(program, 'InvalidInputAvailabilityAttestation')
  })

  it('accepts the last commitment second and closes at the finalization tail', async function () {
    const { program, e3Id, end } = await openRound()
    const deadline = end - FINALIZATION_WINDOW
    await increaseTimeTo(deadline - 2)
    const accepted = await input(program, e3Id, 'last-accepted')
    const refused = await input(program, e3Id, 'first-refused')
    expect(await program.inputCommitmentDeadline(e3Id)).to.equal(deadline)

    await setNextTimestamp(deadline - 1)
    await expect(program.publishInput(e3Id, accepted.commitmentPayload, { gasLimit: 5_000_000 })).to.emit(program, 'InputCommitted')

    await setNextTimestamp(deadline)
    await expect(program.publishInput(e3Id, refused.commitmentPayload, { gasLimit: 5_000_000 }))
      .to.be.revertedWithCustomError(program, 'InputCommitmentDeadlinePassed')
      .withArgs(e3Id, deadline)
  })

  it('allows delayed finalization through the exact compute deadline', async function () {
    const { program, e3Id, end } = await openRound()
    const ballot = await input(program, e3Id)
    await (await program.publishInput(e3Id, ballot.commitmentPayload)).wait()

    await setNextTimestamp(end + 100)
    await expect(
      program.finalizeInput(e3Id, ballot.slotAddress, ballot.encryptedVoteCommitment, ballot.encryptedVoteHash, 0, ballot.ciphertext),
    ).to.emit(program, 'InputPublished')
  })

  it('rejects delayed finalization one second after the compute deadline', async function () {
    const { program, e3Id, end } = await openRound()
    const ballot = await input(program, e3Id)
    await (await program.publishInput(e3Id, ballot.commitmentPayload)).wait()

    await setNextTimestamp(end + 101)
    await expect(
      program.finalizeInput(e3Id, ballot.slotAddress, ballot.encryptedVoteCommitment, ballot.encryptedVoteHash, 0, ballot.ciphertext),
    )
      .to.be.revertedWithCustomError(program, 'InputDeadlinePassed')
      .withArgs(e3Id, end + 100)
  })

  it('rejects a request that cannot leave one hour to vote after committee setup', async function () {
    const mockInterfold = await deployMockInterfold()
    const mockHonk = (await deployContract('MockHonkVerifier')) as unknown as HonkVerifier
    const program = await deployCRISPProgram({
      mockInterfold,
      honkVerifier: mockHonk,
      onchainHonkVerifier: mockHonk,
      availabilityFinalizationWindow: FINALIZATION_WINDOW,
    })
    const now = await latestTimestamp()
    const start = now + 5
    const end = start + FINALIZATION_WINDOW + 3_599
    await (await mockInterfold.setInputWindow(start, end)).wait()

    await expect(mockInterfold.request(await program.getAddress()))
      .to.be.revertedWithCustomError(program, 'VotingWindowTooShort')
      .withArgs(0, start, end - FINALIZATION_WINDOW, 3_600)
  })

  it('accepts the exact production minimum after the full committee timeout budget', async function () {
    const mockInterfold = await deployMockInterfold()
    const mockHonk = (await deployContract('MockHonkVerifier')) as unknown as HonkVerifier
    const program = await deployCRISPProgram({
      mockInterfold,
      honkVerifier: mockHonk,
      onchainHonkVerifier: mockHonk,
      availabilityFinalizationWindow: PRODUCTION_FINALIZATION_WINDOW,
    })
    await (await mockInterfold.setCommitteeSetupWindows(3_600, 600, 21_600)).wait()
    const now = await latestTimestamp()
    // setInputWindow mines one block, then request mines the block at this timestamp.
    const requestAt = now + 2
    await (await mockInterfold.setInputWindow(requestAt, requestAt + 40_200)).wait()

    await (await mockInterfold.request(await program.getAddress())).wait()
    expect(await mockInterfold.nextE3Id()).to.equal(1)
  })

  it('rejects rounds that do not leave time for both voting and finalization', async function () {
    const { program, mockInterfold, e3Id } = await openRound()
    const now = await latestTimestamp()
    await (await mockInterfold.setInputWindow(now, now + FINALIZATION_WINDOW)).wait()

    await expect(program.inputCommitmentDeadline(e3Id))
      .to.be.revertedWithCustomError(program, 'InputWindowTooShort')
      .withArgs(e3Id, FINALIZATION_WINDOW, FINALIZATION_WINDOW + 1)
  })
})
