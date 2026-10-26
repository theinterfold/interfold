// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import hre from 'hardhat'

interface ProofFixture {
  offer: { proof: string; publicInputs: string[] }
}

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const proofsFile = path.join(root, 'sdk/test-vectors/proofs.json')
const verifierSource = 'contracts/verifiers/NegotiationOfferVerifier.sol'

/** Deploys the generated verifier with the two libraries it links. */
async function deployVerifier() {
  const { ethers } = await hre.network.connect()
  const libraries: Record<string, string> = {}
  for (const library of ['ZKTranscriptLib', 'RelationsLib']) {
    const deployed = await ethers.deployContract(`${verifierSource}:${library}Offer`)
    libraries[`project/${verifierSource}:${library}Offer`] = await deployed.getAddress()
  }
  return ethers.deployContract(`${verifierSource}:NegotiationOfferVerifier`, [], { libraries })
}

// The real proof of `circuits/`: the program passes the same public inputs, in the same order.
describe('Generated verifier', function () {
  before(function () {
    // `circuits/compile.sh` writes the verifier, and `sdk/test-vectors/proofs.json` comes from the offer prover.
    if (!existsSync(proofsFile) || !existsSync(path.join(root, verifierSource))) this.skip()
  })

  it('accepts the offer proof of the fixture and rejects a changed public input', async () => {
    const fixture = JSON.parse(readFileSync(proofsFile, 'utf8')) as ProofFixture
    const { ethers } = await hre.network.connect()
    const verifier = await deployVerifier()
    expect(fixture.offer.publicInputs).to.have.length(8)
    expect(await verifier.verify(fixture.offer.proof, fixture.offer.publicInputs)).to.equal(true)
    for (let index = 0; index < 8; index++) {
      const changed = [...fixture.offer.publicInputs]
      changed[index] = `0x${(BigInt(changed[index]) + 1n).toString(16).padStart(64, '0')}`
      await expect(verifier.verify(fixture.offer.proof, changed), `public input ${index}`).to.be.revert(ethers)
    }
  })
})
