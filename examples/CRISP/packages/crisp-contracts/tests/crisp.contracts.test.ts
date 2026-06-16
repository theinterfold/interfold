// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  hashLeaf,
  generateBFVKeys,
  SIGNATURE_MESSAGE,
  generateVoteProof,
  getAddressFromSignature,
  encodeSolidityProof,
  generateMerkleTree,
  SIGNATURE_MESSAGE_HASH,
  generateMaskVoteProof,
  destroyBBApi,
} from '@crisp-e3/sdk'
import type { ProofData } from '@crisp-e3/sdk'
import { expect } from 'chai'
import { deployCRISPProgram, deployHonkVerifier, deployMockInterfold, ethers } from './utils'
import type { CRISPProgram, HonkVerifier, MockInterfold } from '../types'

let keys = generateBFVKeys()
let publicKey = keys.publicKey

describe('CRISP Contracts', function () {
  // Allow time for contract deployments + proof generation in before()
  this.timeout(600000)

  let honkVerifier: HonkVerifier
  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram
  let signature: `0x${string}`
  let address: string
  let leaves: bigint[]
  let voteProof: ProofData
  let maskProof: ProofData
  const balance = 100n
  const vote = [10, 0]

  before(async function () {
    // Deploy contracts once
    mockInterfold = await deployMockInterfold()
    honkVerifier = await deployHonkVerifier()
    crispProgram = await deployCRISPProgram({ mockInterfold, honkVerifier })

    // Compute signature, address, and leaves once
    const [signer] = await ethers.getSigners()
    signature = (await signer.signMessage(SIGNATURE_MESSAGE)) as `0x${string}`
    address = await getAddressFromSignature(signature, SIGNATURE_MESSAGE_HASH)
    leaves = [...[10n, 20n, 30n], hashLeaf(address, balance)]

    // Generate proofs once
    voteProof = await generateVoteProof({
      vote,
      publicKey,
      signature,
      merkleLeaves: leaves,
      balance,
      messageHash: SIGNATURE_MESSAGE_HASH,
      slotAddress: address,
    })

    maskProof = await generateMaskVoteProof({
      publicKey,
      merkleLeaves: leaves,
      balance,
      slotAddress: address,
      numOptions: 2,
    })
  })

  after(() => {
    destroyBBApi()
  })

  describe('decode tally', () => {
    it('should decode a tally correctly', async () => {
      const e3Id = await mockInterfold.nextE3Id()
      await mockInterfold.request(await crispProgram.getAddress())

      const tally =
        '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000300000000000000000000000000000003000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000030000000000000003000000000000000300000000000000030000000000000003000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

      await mockInterfold.setPlaintextOutput(tally)

      const decodedTally1 = await crispProgram.decodeTally(e3Id)

      expect(decodedTally1[0]).to.equal(10000000000n)
      expect(decodedTally1[1]).to.equal(30000000000n)
    })
  })

  describe('validate input', () => {
    it('should verify the proof correctly with the crisp verifier', async function () {
      const verifyGas = await honkVerifier.verify.estimateGas(voteProof.proof, voteProof.publicInputs)
      console.log(`[bench-gas] crisp_user_verify=${verifyGas.toString()}`)
      const isValid = await honkVerifier.verify(voteProof.proof, voteProof.publicInputs)

      expect(isValid).to.be.true
    })

    it('should verify the proof for a vote mask', async function () {
      const isValid = await honkVerifier.verify(maskProof.proof, maskProof.publicInputs)

      expect(isValid).to.be.true
    })

    it('should validate input correctly', async function () {
      const e3Id = await mockInterfold.nextE3Id()
      await mockInterfold.request(await crispProgram.getAddress())

      const merkleTree = generateMerkleTree(leaves)

      await mockInterfold.setCommitteePublicKey(voteProof.publicInputs[6])

      const encodedProof = encodeSolidityProof(voteProof)

      await crispProgram.setMerkleRoot(e3Id, merkleTree.root)

      await crispProgram.publishInput(e3Id, encodedProof)
    })
  })
})
