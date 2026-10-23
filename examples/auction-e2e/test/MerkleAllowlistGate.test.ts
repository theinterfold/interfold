// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import hre from 'hardhat'
import { allowlistProof, allowlistRoot, encodeAllowlistConfig, sortedAllowlist } from '../shared/allowlist'

// The shared test vector: five members, so the odd node is promoted at two levels. The root is the
// one the TypeScript mirror and the Solidity gate must both produce.
const MEMBERS = [
  '0x1111111111111111111111111111111111111111',
  '0x2222222222222222222222222222222222222222',
  '0x3333333333333333333333333333333333333333',
  '0x4444444444444444444444444444444444444444',
  '0x5555555555555555555555555555555555555555',
] as const
const ROOT = '0x51c195465e71d4179b88473fc3a8a2f17fd66ea392d3965ad7b80f6fd03db0dd'
const OUTSIDER = '0x6666666666666666666666666666666666666666'

describe('MerkleAllowlistGate', () => {
  it('builds the root of the shared vector in TypeScript', () => {
    expect(allowlistRoot(MEMBERS)).to.equal(ROOT)
    // The order and the case of the input do not matter.
    expect(allowlistRoot([...MEMBERS].reverse().map((member) => member.toUpperCase().replace('0X', '0x')))).to.equal(ROOT)
    expect(sortedAllowlist([MEMBERS[1], MEMBERS[0], MEMBERS[1]])).to.have.length(2)
  })

  it('builds the same root on chain and accepts the TypeScript proofs', async () => {
    const { ethers } = await hre.network.connect()
    const gate = await ethers.deployContract('MerkleAllowlistGate')
    const e3Id = 7n
    // The gate keys its state by the caller, so the signer plays the program.
    const [program] = await ethers.getSigners()
    await expect(gate.configure(e3Id, encodeAllowlistConfig(MEMBERS)))
      .to.emit(gate, 'AllowlistSet')
      .withArgs(
        program.address,
        e3Id,
        ROOT,
        MEMBERS.map((member) => ethers.getAddress(member)),
      )
    expect(await gate.roots(program.address, e3Id)).to.equal(ROOT)

    for (const member of MEMBERS) {
      expect(await gate.isEligible(e3Id, member, allowlistProof(MEMBERS, member))).to.equal(true)
    }
    // A member's proof does not carry another address.
    expect(await gate.isEligible(e3Id, OUTSIDER, allowlistProof(MEMBERS, MEMBERS[0]))).to.equal(false)
    // Another E3 has no list.
    expect(await gate.isEligible(8n, MEMBERS[0], allowlistProof(MEMBERS, MEMBERS[0]))).to.equal(false)
    expect(() => allowlistProof(MEMBERS, OUTSIDER)).to.throw(/not on the allowlist/)
  })

  it('matches every list size from 1 to 33', async () => {
    const { ethers } = await hre.network.connect()
    const gate = await ethers.deployContract('MerkleAllowlistGate')
    const all = Array.from({ length: 33 }, (_, i) => ethers.getAddress(`0x${(i + 1).toString(16).padStart(40, '0')}`))
    for (let size = 1; size <= all.length; size++) {
      const members = all.slice(0, size)
      await gate.configure(BigInt(size), encodeAllowlistConfig(members))
      const [program] = await ethers.getSigners()
      expect(await gate.roots(program.address, BigInt(size))).to.equal(allowlistRoot(members))
      const last = members[size - 1]
      expect(await gate.isEligible(BigInt(size), last, allowlistProof(members, last))).to.equal(true)
    }
  })

  it('rejects a bad list and a second configuration', async () => {
    const { ethers } = await hre.network.connect()
    const gate = await ethers.deployContract('MerkleAllowlistGate')
    const encode = (members: string[]) => ethers.AbiCoder.defaultAbiCoder().encode(['address[]'], [members])
    await expect(gate.configure(1n, encode([]))).to.be.revertedWithCustomError(gate, 'EmptyAllowlist')
    await expect(gate.configure(1n, encode([MEMBERS[1], MEMBERS[0]]))).to.be.revertedWithCustomError(gate, 'MembersNotIncreasing')
    await expect(gate.configure(1n, encode([MEMBERS[0], MEMBERS[0]]))).to.be.revertedWithCustomError(gate, 'MembersNotIncreasing')
    const tooMany = Array.from({ length: 257 }, (_, i) => ethers.getAddress(`0x${(i + 1).toString(16).padStart(40, '0')}`))
    await expect(gate.configure(1n, encode(tooMany))).to.be.revertedWithCustomError(gate, 'AllowlistTooLarge')
    await gate.configure(1n, encodeAllowlistConfig(MEMBERS))
    await expect(gate.configure(1n, encodeAllowlistConfig(MEMBERS))).to.be.revertedWithCustomError(gate, 'AlreadyConfigured')
  })
})
