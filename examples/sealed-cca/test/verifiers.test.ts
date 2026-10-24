// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import hre from 'hardhat'

interface ProofFixture {
  bid: { proof: string; publicInputs: string[] }
  claims: { b: number; k: number; cmp: number; proof: string; publicInputs: string[] }[]
}

const fixture = JSON.parse(
  readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../sdk/test-vectors/proofs.json'), 'utf8'),
) as ProofFixture

/** Deploys a generated verifier with the two libraries it links. */
async function deployVerifier(kind: 'Bid' | 'Claim') {
  const { ethers } = await hre.network.connect()
  const source = `contracts/verifiers/SealedCca${kind}Verifier.sol`
  const libraries: Record<string, string> = {}
  for (const library of ['ZKTranscriptLib', 'RelationsLib']) {
    const deployed = await ethers.deployContract(`${source}:${library}${kind}`)
    libraries[`project/${source}:${library}${kind}`] = await deployed.getAddress()
  }
  return ethers.deployContract(`${source}:SealedCca${kind}Verifier`, [], { libraries })
}

// The real proofs of `circuits/`: the program passes the same public inputs, in the same order.
describe('Generated verifiers', () => {
  it('accepts the bid proof of the fixture and rejects a changed public input', async () => {
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier('Bid')
    expect(fixture.bid.publicInputs).to.have.length(9)
    expect(await verifier.verify(fixture.bid.proof, fixture.bid.publicInputs)).to.equal(true)
    for (const index of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
      const changed = [...fixture.bid.publicInputs]
      changed[index] = `0x${(BigInt(changed[index]) + 1n).toString(16).padStart(64, '0')}`
      await expect(verifier.verify(fixture.bid.proof, changed), `public input ${index}`).to.be.revert(ethers)
    }
  })

  it('accepts the claim proofs of the fixture and rejects a changed comparison', async () => {
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier('Claim')
    expect(fixture.claims.length).to.be.greaterThan(1)
    for (const claim of fixture.claims) {
      expect(claim.publicInputs).to.have.length(5)
      expect(await verifier.verify(claim.proof, claim.publicInputs), `b=${claim.b} k=${claim.k}`).to.equal(true)
      const changed = [...claim.publicInputs]
      changed[4] = `0x${((claim.cmp + 1) % 3).toString(16).padStart(64, '0')}`
      await expect(verifier.verify(claim.proof, changed)).to.be.revert(ethers)
    }
  })
})
