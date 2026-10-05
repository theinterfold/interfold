// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import type { CRISPProgram, HonkVerifier } from '../types'
import { abiCoder, deployContract, deployCRISPProgram, deployMockInterfold, ethers, inputCommitmentPayload } from './utils'

type RelayLimits = { maxInputsPerSlot: number; maxInputsPerRound: number }

/** A round with proofs mocked. */
async function openRound(relayLimits?: RelayLimits) {
  const mockInterfold = await deployMockInterfold()
  const mockHonk = (await deployContract('MockHonkVerifier')) as unknown as HonkVerifier
  const program = await deployCRISPProgram({ mockInterfold, honkVerifier: mockHonk, onchainHonkVerifier: mockHonk, relayLimits })
  const e3Id = await mockInterfold.nextE3Id()
  await (await mockInterfold.request(await program.getAddress())).wait()
  await (await mockInterfold.setCommitteePublicKey(ethers.id('committee-key'))).wait()
  await (await program.setMerkleRoot(e3Id, 1)).wait()
  return { program, e3Id }
}

let nonce = 0

/** The `publishInput` payload of one input, attested by the availability signer. */
async function payload(program: CRISPProgram, e3Id: bigint, slot: string, parentIndexPlusOne = 0) {
  nonce += 1
  const ciphertext = ethers.hexlify(ethers.toUtf8Bytes(`ciphertext-${nonce}`))
  const envelope = abiCoder.encode(
    ['bytes', 'address', 'bytes32', 'bytes32', 'uint40', 'bytes'],
    ['0x01', slot, ethers.id(`commitment-${nonce}`), ethers.keccak256(ciphertext), parentIndexPlusOne, ciphertext],
  )
  return inputCommitmentPayload(program, e3Id, envelope)
}

const newSlot = () => ethers.Wallet.createRandom().address

describe('CRISP input admission', function () {
  describe('relay caps', function () {
    it('lets only one of two relays holding the last round allowance commit', async function () {
      const { program, e3Id } = await openRound({ maxInputsPerSlot: 5, maxInputsPerRound: 2 })
      await (await program.publishInput(e3Id, await payload(program, e3Id, newSlot()))).wait()

      // Two server instances share the relay key. Each prepares an input before either sends,
      // as two independent local ledgers would both admit it.
      const first = await payload(program, e3Id, newSlot())
      const second = await payload(program, e3Id, newSlot())

      await (await program.publishInput(e3Id, first)).wait()
      await expect(program.publishInput(e3Id, second)).to.be.revertedWithCustomError(program, 'RelayLimitReached')
      expect(await program.relayedInputCountOf(e3Id)).to.equal(2n)

      // The voter's wallet still sends the refused input.
      const [, voter] = await ethers.getSigners()
      await expect(program.connect(voter).publishInput(e3Id, second)).to.emit(program, 'InputCommitted')
      expect(await program.relayedInputCountOf(e3Id)).to.equal(2n)
    })

    it('caps relayed inputs to one slot without counting inputs that wallets send', async function () {
      const { program, e3Id } = await openRound({ maxInputsPerSlot: 1, maxInputsPerRound: 10 })
      const [, voter] = await ethers.getSigners()
      const slot = newSlot()

      await (await program.publishInput(e3Id, await payload(program, e3Id, slot))).wait()
      await (await program.connect(voter).publishInput(e3Id, await payload(program, e3Id, slot, 1))).wait()
      expect(await program.relayedInputsOf(e3Id, slot)).to.equal(1n)

      const relayedUpdate = await payload(program, e3Id, slot, 2)
      await expect(program.publishInput(e3Id, relayedUpdate))
        .to.be.revertedWithCustomError(program, 'RelayLimitReached')
        .withArgs(e3Id, slot)

      // Another slot still has its own allowance.
      await (await program.publishInput(e3Id, await payload(program, e3Id, newSlot()))).wait()
      expect(await program.relayedInputCountOf(e3Id)).to.equal(2n)
    })
  })
})
