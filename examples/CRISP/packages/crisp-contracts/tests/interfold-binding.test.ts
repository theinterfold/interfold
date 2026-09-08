// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { deployCRISPProgram, deployMockInterfold, ethers } from './utils'

describe('CRISP Interfold binding', function () {
  it('binds once to the Interfold controller that registered the program', async function () {
    const [owner, other] = await ethers.getSigners()
    const mockInterfold = await deployMockInterfold()
    const program = await deployCRISPProgram({ mockInterfold, bindInterfold: false })
    const programAddress = await program.getAddress()
    const interfoldAddress = await mockInterfold.getAddress()

    expect(await program.owner()).to.equal(await owner.getAddress())
    expect(await program.interfold()).to.equal(ethers.ZeroAddress)

    await expect(program.connect(other).bindInterfold(interfoldAddress))
      .to.be.revertedWithCustomError(program, 'OwnableUnauthorizedAccount')
      .withArgs(await other.getAddress())
    await expect(program.bindInterfold(ethers.ZeroAddress)).to.be.revertedWithCustomError(program, 'InterfoldAddressZero')
    await expect(program.bindInterfold(await owner.getAddress())).to.be.revertedWithCustomError(program, 'InterfoldNotContract')
    await expect(program.bindInterfold(interfoldAddress)).to.be.revertedWithCustomError(program, 'ProgramNotRegistered')

    await (await mockInterfold.registerE3Program(programAddress)).wait()
    await expect(program.bindInterfold(interfoldAddress)).to.emit(program, 'InterfoldBound').withArgs(interfoldAddress)
    expect(await program.interfold()).to.equal(interfoldAddress)

    await expect(program.bindInterfold(interfoldAddress)).to.be.revertedWithCustomError(program, 'InterfoldAlreadyBound')
  })

  it('refuses to initialize round state for an E3 that Interfold assigned elsewhere', async function () {
    // ZEN2-12. `validate` accepts the owner as a caller. Without an assignment check the owner
    // could create parallel CRISP round state — input tree and params hash — for an E3 that
    // Interfold gave to a different program.
    const [, otherProgram] = await ethers.getSigners()
    const mockInterfold = await deployMockInterfold()
    const program = await deployCRISPProgram({ mockInterfold })
    const params = ethers.AbiCoder.defaultAbiCoder().encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      [ethers.ZeroAddress, 0n, 2, 0, 1, 0, 0],
    )

    // Interfold reports the E3 as assigned to a different program.
    await (await mockInterfold.setE3Program(otherProgram.address)).wait()
    await expect(program.validate(1, 0, '0x', '0x', params))
      .to.be.revertedWithCustomError(program, 'E3NotAssignedToProgram')
      .withArgs(1)

    // The same E3, once Interfold assigns it to this program, initializes normally.
    await (await mockInterfold.setE3Program(await program.getAddress())).wait()
    await (await program.validate(1, 0, '0x', '0x', params)).wait()
    expect((await program.getRoundData(1)).numOptions).to.equal(2)
  })
})
