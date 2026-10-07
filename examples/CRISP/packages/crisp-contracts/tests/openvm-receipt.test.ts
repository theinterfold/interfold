// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { network } from 'hardhat'

const { ethers } = await network.connect()

const abi = ethers.AbiCoder.defaultAbiCoder()
const word = (value: number | bigint) => ethers.zeroPadValue(ethers.toBeHex(value), 32)
const exeCommit = word(1)
const vmCommit = word(2)
const proofData = `0x${'ab'.repeat(1760)}`
const seal = (data = proofData, version = 1) => abi.encode(['uint8', 'bytes'], [version, data])
const journalDigest = (words: string[]) => ethers.sha256(abi.encode(['bytes32[9]'], [words]))

async function deployAdapter() {
  const verifier = await ethers.deployContract('MockOpenVmCallVerifier')
  const adapter = await ethers.deployContract('OpenVmReceiptVerifier', [await verifier.getAddress(), exeCommit, vmCommit])
  return { verifier, adapter, imageId: await adapter.imageId() }
}

async function programFactory() {
  const poseidon = await ethers.deployContract('PoseidonT3')
  return ethers.getContractFactory('CRISPProgram', {
    libraries: {
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': await poseidon.getAddress(),
    },
  })
}

describe('OpenVM receipt verifier (call oracle, not proof verification)', () => {
  it('passes the journal digest to the Halo2 verifier as its only public value', async () => {
    const { verifier, adapter, imageId } = await deployAdapter()
    const words = Array.from({ length: 9 }, (_, index) => word(index + 1))
    await verifier.setExpectedCall(journalDigest(words), proofData, exeCommit, vmCommit)
    await expect(adapter.verify(seal(), imageId, journalDigest(words))).not.to.revert(ethers)

    for (let index = 0; index < words.length; index++) {
      const changed = [...words]
      changed[index] = word(BigInt(changed[index]) ^ 1n)
      await expect(adapter.verify(seal(), imageId, journalDigest(changed))).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')
    }
  })

  it('binds the image identity to both commitments and the verifier', async () => {
    const { verifier, adapter, imageId } = await deployAdapter()
    expect(imageId).to.equal(
      ethers.keccak256(
        abi.encode(
          ['bytes32', 'address', 'bytes32', 'bytes32'],
          [ethers.keccak256(ethers.toUtf8Bytes('INTERFOLD_OPENVM_RECEIPT_V1')), await verifier.getAddress(), exeCommit, vmCommit],
        ),
      ),
    )
    const secondVerifier = await ethers.deployContract('MockOpenVmCallVerifier')
    const words = Array.from({ length: 9 }, (_, index) => word(index))
    await verifier.setExpectedCall(journalDigest(words), proofData, exeCommit, vmCommit)
    for (const args of [
      [await secondVerifier.getAddress(), exeCommit, vmCommit],
      [await verifier.getAddress(), word(3), vmCommit],
      [await verifier.getAddress(), exeCommit, word(3)],
    ]) {
      const other = await ethers.deployContract('OpenVmReceiptVerifier', args)
      expect(await other.imageId()).not.to.equal(imageId)
      await expect(other.verify(seal(), await other.imageId(), journalDigest(words))).to.be.revertedWithCustomError(
        verifier,
        'UnexpectedOpenVmCall',
      )
    }
    await expect(adapter.verify(seal(), word(100), journalDigest(words))).to.be.revertedWithCustomError(adapter, 'WrongImageId')
  })

  it('rejects invalid configuration and noncanonical seals', async () => {
    const { verifier, adapter, imageId } = await deployAdapter()
    const [signer] = await ethers.getSigners()
    const factory = await ethers.getContractFactory('OpenVmReceiptVerifier')
    await expect(factory.deploy(await signer.getAddress(), exeCommit, vmCommit)).to.be.revertedWithCustomError(adapter, 'InvalidVerifier')
    const modulus = '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'
    for (const [exe, vm] of [
      [word(0), vmCommit],
      [exeCommit, word(0)],
      [modulus, vmCommit],
      [exeCommit, modulus],
    ]) {
      await expect(factory.deploy(await verifier.getAddress(), exe, vm)).to.be.revertedWithCustomError(adapter, 'InvalidAppCommitment')
    }
    const words = Array.from({ length: 9 }, (_, index) => word(index))
    const digest = journalDigest(words)
    await verifier.setExpectedCall(digest, proofData, exeCommit, vmCommit)
    await expect(adapter.verify(seal(proofData, 2), imageId, digest)).to.be.revertedWithCustomError(adapter, 'InvalidSealVersion')
    await expect(adapter.verify(`${seal()}00`, imageId, digest)).to.be.revertedWithCustomError(adapter, 'InvalidSealEncoding')
    // The earlier layout also carried the nine journal words. It decodes, but it is not canonical.
    const withWords = abi.encode(['uint8', 'bytes', 'bytes32[9]'], [1, proofData, words])
    await expect(adapter.verify(withWords, imageId, digest)).to.be.revertedWithCustomError(adapter, 'InvalidSealEncoding')
    await expect(adapter.verify(seal('0x'), imageId, digest)).to.be.revertedWithCustomError(adapter, 'InvalidProofDataLength')
    await expect(adapter.verify('0x', imageId, digest)).to.revert(ethers)
    await expect(adapter.verify(seal(`0x${'cd'.repeat(1760)}`), imageId, digest)).to.be.revertedWithCustomError(
      verifier,
      'UnexpectedOpenVmCall',
    )
  })

  it('refuses a receipt identity that the receipt verifier does not accept', async () => {
    const { adapter, imageId } = await deployAdapter()
    const [owner] = await ethers.getSigners()
    const honk = await ethers.deployContract('MockHonkVerifier')
    const availability = await ethers.deployContract('MockCrispDataAvailabilityVerifier')
    const protocolFactory = await ethers.getContractFactory('OpenVmBfvCiphertextVerifier')
    const program = await programFactory()
    const deployProgram = (id: string) =>
      program.deploy(owner.address, adapter.target, honk.target, honk.target, availability.target, 0, owner.address, id)
    for (const id of [word(0), word(999)]) {
      await expect(protocolFactory.deploy(adapter.target, id)).to.be.revertedWithCustomError(protocolFactory, 'InvalidImageId')
      await expect(deployProgram(id)).to.be.revertedWithCustomError(program, 'InvalidImageId')
    }
    await expect(protocolFactory.deploy(adapter.target, imageId)).not.to.revert(ethers)
    await expect(deployProgram(imageId)).not.to.revert(ethers)
  })

  it('preserves the protocol and CRISP application verification calls', async () => {
    const { verifier, adapter, imageId } = await deployAdapter()
    const [owner] = await ethers.getSigners()
    const controller = await ethers.deployContract('MockInterfold')
    const honk = await ethers.deployContract('MockHonkVerifier')
    const availability = await ethers.deployContract('MockCrispDataAvailabilityVerifier')
    const factory = await programFactory()
    const program = await factory.deploy(
      await owner.getAddress(),
      await adapter.getAddress(),
      await honk.getAddress(),
      await honk.getAddress(),
      await availability.getAddress(),
      0,
      await owner.getAddress(),
      imageId,
    )
    await controller.registerE3Program(await program.getAddress())
    await program.bindInterfold(await controller.getAddress())
    await controller.setCommitteePublicKey(word(55))
    await controller.request(await program.getAddress())
    const protocol = await ethers.deployContract('OpenVmBfvCiphertextVerifier', [await adapter.getAddress(), imageId])

    const words = [
      word(31337),
      ethers.zeroPadValue(await controller.getAddress(), 32),
      word(0),
      await controller.ENCRYPTION_SCHEME_ID(),
      word(55),
      word(66),
      word(77),
      ethers.keccak256('0x'),
      '0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864',
    ]
    await verifier.setExpectedCall(journalDigest(words), proofData, exeCommit, vmCommit)
    const envelope = (paramsHash = words[7], inputRoot = words[8]) =>
      abi.encode(['bytes', 'bytes32', 'bytes32'], [seal(), paramsHash, inputRoot])
    const protocolCall = (values = words, proof = envelope(), caller?: string) =>
      ethers.provider.call({
        to: protocol.target,
        from: caller ?? controller.target,
        data: protocol.interface.encodeFunctionData('verify', [
          BigInt(values[2]),
          values[3],
          values[7],
          values[4],
          values[5],
          values[6],
          proof,
        ]),
      })
    expect(abi.decode(['bool'], await protocolCall())[0]).to.equal(true)
    expect(await program.verify(0, words[5], words[6], envelope())).to.equal(true)

    // A changed journal field changes the digest, which the Halo2 verifier then rejects.
    for (const index of [2, 3, 4, 5, 6]) {
      const changed = [...words]
      changed[index] = word(BigInt(changed[index]) ^ 1n)
      await expect(protocolCall(changed)).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')
    }
    expect(abi.decode(['bool'], await protocolCall([...words.slice(0, 7), word(999), words[8]]))[0]).to.equal(false)
    await expect(protocolCall(words, envelope(), await owner.getAddress())).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')
    await expect(program.verify(0, word(999), words[6], envelope())).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')
    await expect(program.verify(0, words[5], word(999), envelope())).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')
    await expect(program.verify(0, words[5], words[6], envelope(word(999)))).to.be.revertedWithCustomError(program, 'InvalidComputeContext')
    await expect(program.verify(0, words[5], words[6], envelope(words[7], word(999)))).to.be.revertedWithCustomError(
      program,
      'InvalidComputeContext',
    )
    await expect(protocolCall(words, envelope(words[7], word(999)))).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')

    // Moving the program to another receipt verifier moves its identity with it.
    const other = await ethers.deployContract('OpenVmReceiptVerifier', [await verifier.getAddress(), word(3), vmCommit])
    await program.setOpenVmVerifier(await other.getAddress())
    expect(await program.imageId()).to.equal(await other.imageId())
    await expect(program.verify(0, words[5], words[6], envelope())).to.be.revertedWithCustomError(verifier, 'UnexpectedOpenVmCall')
  })
})
