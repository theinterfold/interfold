// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { deployContract, deployCRISPProgram, ethers } from './utils'
import type { CRISPProgram } from '../types'

const CONSTANT = 0
const ONCHAIN = 2

/// `SelfRegistry` is an open census for ONCHAIN rounds: anyone registers themselves, once, and a
/// registered account reports a voting power of 1 at every timepoint. The timepoint is ignored on
/// purpose — the round snapshot is taken before anyone knew there was a round to register for, so
/// honouring it would freeze out everyone the registry exists to let in.
describe('SelfRegistry', function () {
  this.timeout(120000)

  let registry: any
  let accounts: Awaited<ReturnType<typeof ethers.getSigners>>

  beforeEach(async () => {
    registry = await deployContract('SelfRegistry')
    accounts = await ethers.getSigners()
  })

  it('reports zero power for an unregistered account, at any timepoint', async () => {
    expect(await registry.getPastVotes(accounts[0].address, 0)).to.equal(0n)
    expect(await registry.getPastVotes(accounts[0].address, 10n ** 18n)).to.equal(0n)
  })

  it('reports a power of one after registration, at any timepoint', async () => {
    await (await registry.register()).wait()

    // Including timepoints before the registration existed: the timepoint is deliberately
    // ignored, which is what admits voters who register during the input window.
    expect(await registry.getPastVotes(accounts[0].address, 0)).to.equal(1n)
    expect(await registry.getPastVotes(accounts[0].address, 10n ** 18n)).to.equal(1n)
    expect(await registry.isRegistered(accounts[0].address)).to.equal(true)
  })

  it('refuses a second registration', async () => {
    await (await registry.register()).wait()
    await expect(registry.register()).to.be.revertedWithCustomError(registry, 'AlreadyRegistered')
  })

  it('enumerates registrants in registration order', async () => {
    await (await registry.connect(accounts[0]).register()).wait()
    await (await registry.connect(accounts[1]).register()).wait()
    await (await registry.connect(accounts[2]).register()).wait()

    expect(await registry.totalRegistrants()).to.equal(3n)
    expect(await registry.registrantAt(1)).to.equal(accounts[1].address)
    expect(await registry.registrants(0, 3)).to.deep.equal([accounts[0].address, accounts[1].address, accounts[2].address])
  })

  it('clamps a page past the end instead of reverting', async () => {
    await (await registry.register()).wait()

    expect(await registry.registrants(0, 10)).to.deep.equal([accounts[0].address])
    expect(await registry.registrants(5, 10)).to.deep.equal([])
  })

  it('clamps a count that would overflow the page end', async () => {
    await (await registry.connect(accounts[0]).register()).wait()
    await (await registry.connect(accounts[1]).register()).wait()

    // `start + count` exceeds uint256; a naive sum would revert under checked arithmetic
    // instead of clamping to the end of the list.
    expect(await registry.registrants(1, ethers.MaxUint256)).to.deep.equal([accounts[1].address])
  })

  it('emits the registrant index', async () => {
    await expect(registry.connect(accounts[1]).register()).to.emit(registry, 'Registered').withArgs(accounts[1].address, 0)
    await expect(registry.connect(accounts[2]).register()).to.emit(registry, 'Registered').withArgs(accounts[2].address, 1)
  })

  /// The registry has no `decimals()` and no `clock()`, so `CRISPProgram.validate` must accept it
  /// through both fallbacks: a divisor of 1 and a block-number snapshot. This is the round shape
  /// the registry is meant for — CONSTANT credits of 1 and a floor of 1, one registrant one vote.
  it('validates as the token of an ONCHAIN round', async () => {
    const crispProgram: CRISPProgram = await deployCRISPProgram()
    const registryAddress = await registry.getAddress()

    const params = ethers.AbiCoder.defaultAbiCoder().encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      [registryAddress, 1n, 2, CONSTANT, 1n, ONCHAIN, 0n],
    )

    await (await crispProgram.validate(1, 0, '0x', '0x', params)).wait()

    expect(await crispProgram.censusModeOf(1)).to.equal(ONCHAIN)
    // No `decimals()` on the registry, so the divisor derives to 1.
    expect(await crispProgram.votingPowerDivisorOf(1)).to.equal(1n)
    // CONSTANT credits: every eligible slot weighs the configured 1.
    expect(await crispProgram.votingPowerOf(1, accounts[0].address)).to.equal(1n)
  })
})
