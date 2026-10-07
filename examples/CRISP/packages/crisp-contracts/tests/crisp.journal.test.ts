// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { deployCRISPProgram, deployHonkVerifier, deployMockInterfold, deployMockComputeReceiptVerifier, ethers } from './utils'

describe('CRISP journal', () => {
  it('should match the journal returned by the OpenVM guest', async () => {
    const ciphertextHash = ethers.hexlify(Uint8Array.from({ length: 32 }, (_, index) => index))
    const ciphertextCommitment = ethers.hexlify(Uint8Array.from({ length: 32 }, (_, index) => index + 32))
    const paramsHash = ethers.keccak256('0x')
    const inputRoot = '0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864'
    const committeePublicKey = `0x${'33'.repeat(32)}`
    const encryptionSchemeId = ethers.keccak256(ethers.toUtf8Bytes('fhe.rs:BFV'))

    const mockInterfold = await deployMockInterfold()
    await mockInterfold.setCommitteePublicKey(committeePublicKey)
    const chainId = (await ethers.provider.getNetwork()).chainId
    const journal = ethers.concat([
      ethers.zeroPadValue(ethers.toBeHex(chainId), 32),
      ethers.zeroPadValue(await mockInterfold.getAddress(), 32),
      ethers.zeroPadValue(ethers.toBeHex(0), 32),
      encryptionSchemeId,
      committeePublicKey,
      ciphertextHash,
      ciphertextCommitment,
      paramsHash,
      inputRoot,
    ])
    const journalDigest = ethers.sha256(journal)

    const honkVerifier = await deployHonkVerifier()
    const computeVerifier = await deployMockComputeReceiptVerifier()
    await computeVerifier.setExpectedJournalDigest(journalDigest)
    const program = await deployCRISPProgram({ mockInterfold, honkVerifier, computeVerifier })
    const e3Id = await mockInterfold.nextE3Id()
    await mockInterfold.request(await program.getAddress())

    const proof = ethers.AbiCoder.defaultAbiCoder().encode(['bytes', 'bytes32', 'bytes32'], ['0x', paramsHash, inputRoot])
    await program.verify(e3Id, ciphertextHash, ciphertextCommitment, proof)
  })
})
