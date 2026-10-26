// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { HardhatEthers } from '@nomicfoundation/hardhat-ethers/types'
import hre from 'hardhat'
import { type Hex, toHex } from 'viem'
import { deployProgramLibraries } from '../deploy/libraries'
import { ClaimTree } from '../sdk/src/merkle'
import { ClearingHarness__factory } from '../types/factories/contracts/mocks'

interface ProofFile {
  bid: { proof: Hex; publicInputs: Hex[] }
  claim: { proof: Hex; publicInputs: Hex[] }
  claimMarginal: { proof: Hex; publicInputs: Hex[] }
}

const fixture = JSON.parse(
  readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../sdk/test-vectors/proofs.json'), 'utf8'),
) as ProofFile
const num = (value: Hex) => BigInt(value)
const RECIPIENT = '0x90F79bf6EB2c4f870365E785982E1f101E93b906'
const BIDDER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'

/** Deploys a generated verifier with the two libraries it links. */
async function deployVerifier(ethers: HardhatEthers, kind: 'Bid' | 'Claim') {
  const source = `contracts/verifiers/TokenLaunch${kind}Verifier.sol`
  const libraries: Record<string, string> = {}
  for (const library of ['ZKTranscriptLib', 'RelationsLib']) {
    const deployed = await ethers.deployContract(`${source}:${library}${kind}`)
    libraries[`project/${source}:${library}${kind}`] = await deployed.getAddress()
  }
  return ethers.deployContract(`${source}:TokenLaunch${kind}Verifier`, [], { libraries })
}

async function deployHarness(ethers: HardhatEthers) {
  const [owner] = await ethers.getSigners()
  const poseidon = await ethers.deployContract('PoseidonT3')
  const links = await deployProgramLibraries(ethers, await poseidon.getAddress())
  const factory = await ethers.getContractFactory(
    ClearingHarness__factory.abi,
    ClearingHarness__factory.linkBytecode({
      'project/contracts/libraries/SaleClearing.sol:SaleClearing': links['project/contracts/libraries/SaleClearing.sol:SaleClearing'],
      'project/contracts/libraries/SaleOutput.sol:SaleOutput': links['project/contracts/libraries/SaleOutput.sol:SaleOutput'],
      'project/contracts/libraries/ProbeSearch.sol:ProbeSearch': links['project/contracts/libraries/ProbeSearch.sol:ProbeSearch'],
      'project/contracts/libraries/ProofInputs.sol:ProofInputs': links['project/contracts/libraries/ProofInputs.sol:ProofInputs'],
    }),
    owner,
  )
  return ClearingHarness__factory.connect(await (await factory.deploy()).getAddress(), owner)
}

const bump = (value: Hex): Hex => toHex(BigInt(value) + 1n, { size: 32 })

// The real proofs of `circuits/` (sdk/test-vectors/proofs.json).
describe('Generated verifiers', () => {
  it('accepts the bid proof and rejects any changed public input', async () => {
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier(ethers, 'Bid')
    expect(fixture.bid.publicInputs).to.have.length(11)
    expect(await verifier.verify(fixture.bid.proof, fixture.bid.publicInputs)).to.equal(true)
    for (let index = 0; index < 11; index++) {
      const changed = fixture.bid.publicInputs.map((input, i) => (i === index ? bump(input) : input))
      await expect(verifier.verify(fixture.bid.proof, changed), `public input ${index}`).to.be.revert(ethers)
    }
  })

  it('accepts the claim proofs and rejects any changed public input', async () => {
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier(ethers, 'Claim')
    for (const proof of [fixture.claim, fixture.claimMarginal]) {
      expect(proof.publicInputs).to.have.length(11)
      expect(await verifier.verify(proof.proof, proof.publicInputs)).to.equal(true)
      for (let index = 0; index < 11; index++) {
        const changed = proof.publicInputs.map((input, i) => (i === index ? bump(input) : input))
        await expect(verifier.verify(proof.proof, changed), `public input ${index}`).to.be.revert(ethers)
      }
    }
  })

  it('verifies a bid with the public inputs that the program builds', async () => {
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier(ethers, 'Bid')
    const harness = await deployHarness(ethers)
    const p = fixture.bid.publicInputs
    const bid = {
      bidder: BIDDER,
      tier: 0,
      ciphertext1: '0x01',
      ciphertext2: '0x02',
      ctCommitment1: p[0],
      ctCommitment2: p[1],
      bidCommitment: p[2],
      proof: fixture.bid.proof,
      signature: '0x',
      permitDeadline: 0,
      v: 0,
      r: toHex(0, { size: 32 }),
      s: toHex(0, { size: 32 }),
    }
    const context = {
      saleId: num(p[4]),
      index: num(p[6]),
      levels: num(p[5]),
      escrowUnits: num(p[7]),
      key1: p[8],
      key2: p[9],
      vkAnchor: p[10],
    }
    await harness.verifyBid(await verifier.getAddress(), bid, context)
    await expect(harness.verifyBid(await verifier.getAddress(), bid, { ...context, index: 3 })).to.be.revert(ethers)
    await expect(harness.verifyBid(await verifier.getAddress(), { ...bid, bidder: RECIPIENT }, context)).to.be.revert(ethers)
  })

  it('verifies the claims with the public inputs that the program builds', async () => {
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier(ethers, 'Claim')
    const harness = await deployHarness(ethers)
    const tree = ClaimTree.from([123n, 456n, num(fixture.bid.publicInputs[2]), 789n])
    for (const [name, proof, reveal] of [
      ['immediate', fixture.claim, false],
      ['marginal', fixture.claimMarginal, true],
    ] as const) {
      const p = proof.publicInputs
      expect(num(p[0]), name).to.equal(tree.root)
      const claim = {
        proof: proof.proof,
        nullifier: p[4],
        recipient: RECIPIENT,
        escrowUnits: num(p[6]),
        budgetUnits: num(p[7]),
        cmp: num(p[9]),
        indexPlusOne: num(p[10]),
      }
      const context = { saleId: num(p[2]), root: num(p[0]), countedMask: num(p[1]), step: num(p[3]), reveal }
      await harness.verifyClaim(await verifier.getAddress(), claim, context)
      // The contract's view of the window is part of the proof.
      await expect(harness.verifyClaim(await verifier.getAddress(), claim, { ...context, reveal: !reveal }), name).to.be.revert(ethers)
      await expect(harness.verifyClaim(await verifier.getAddress(), { ...claim, recipient: BIDDER }, context), name).to.be.revert(ethers)
    }
  })
})
