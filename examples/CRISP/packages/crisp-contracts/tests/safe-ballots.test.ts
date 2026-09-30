// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { createSafe, deployCRISPProgram, deployMockInterfold, deploySafeContracts, ethers } from './utils'
import type { SafeDeployment } from './utils'
import type { CRISPProgram, MockInterfold, Safe } from '../types'

/// Mirror `MAX_SAFE_OWNERS` and `MAX_SAFE_SIGNERS` in CRISPProgram.sol.
const MAX_SAFE_OWNERS = 10
const MAX_SAFE_SIGNERS = 4
const COMMITMENT = ethers.id('ciphertext commitment')
const abi = ethers.AbiCoder.defaultAbiCoder()

/// The owner commitment `crisp_onchain` checks: the owners as 20-byte words, zero-padded to
/// `MAX_SAFE_OWNERS`, then the threshold as one byte.
const commitmentOf = (owners: string[], threshold: bigint) =>
  ethers.solidityPackedKeccak256(
    [...Array(MAX_SAFE_OWNERS).fill('address'), 'uint8'],
    [...owners, ...Array(MAX_SAFE_OWNERS - owners.length).fill(ethers.ZeroAddress), threshold],
  )

/// `ballotAuthorization` against real Safe 1.4.1 contracts. `onchain-census.test.ts` proves and
/// publishes Safe ballots against these values.
describe('CRISP Safe ballots', function () {
  let safeContracts: SafeDeployment
  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram
  let safe: string
  let e3Id: bigint

  const address = (label: string) => new ethers.Wallet(ethers.id(label)).address
  const newSafe = (owners: number, threshold: number) =>
    createSafe(
      safeContracts,
      Array.from({ length: owners }, (_, i) => address(`owner ${i}`)),
      threshold,
    )

  before(async function () {
    safeContracts = await deploySafeContracts()
    safe = await newSafe(3, 2)
    mockInterfold = await deployMockInterfold()
    crispProgram = await deployCRISPProgram({
      mockInterfold,
      safeProxyCodehashes: [ethers.keccak256(await ethers.provider.getCode(safe))],
      safeSingletons: [await safeContracts.singleton.getAddress()],
    })
    const token = await ethers.deployContract('MockVotesToken')
    const params = abi.encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      [token.target, 10n ** 17n, 2, 1, 1n, 2, 0n],
    )
    e3Id = await mockInterfold.nextE3Id()
    await (await mockInterfold.requestWithParams(await crispProgram.getAddress(), 2, params)).wait()
  })

  it('binds a Safe ballot to the Safe message hash and the current owners', async function () {
    const { safe: isSafe, digest, ownersCommitment } = await crispProgram.ballotAuthorization(e3Id, safe, COMMITMENT)
    const ballotDigest = await crispProgram.ballotDigest(e3Id, safe, COMMITMENT)
    const safeContract = safeContracts.singleton.attach(safe) as Safe

    expect(isSafe).to.equal(true)
    // The hash that the Safe's own `isValidSignature` checks the owner signatures against.
    expect(digest).to.equal(await safeContracts.handler.getMessageHashForSafe(safe, abi.encode(['bytes32'], [ballotDigest])))
    expect(ownersCommitment).to.equal(commitmentOf([...(await safeContract.getOwners())], await safeContract.getThreshold()))
  })

  it('makes any other slot its own single owner, over the ballot digest', async function () {
    const wallet = address('wallet')
    const authorization = await crispProgram.ballotAuthorization(e3Id, wallet, COMMITMENT)

    expect([...authorization]).to.deep.equal([false, await crispProgram.ballotDigest(e3Id, wallet, COMMITMENT), commitmentOf([wallet], 1n)])
  })

  /// Any contract can answer `getOwners()` with any list, so neither check alone identifies a Safe.
  it('needs both an accepted proxy code hash and an accepted singleton', async function () {
    const otherSingleton = await ethers.deployContract('@safe-global/safe-contracts/contracts/Safe.sol:Safe')
    const proxy = await createSafe(safeContracts, [address('owner 0')], 1, otherSingleton)
    expect(await crispProgram.isSafe(proxy)).to.equal(false)

    // The Safe proxy code plus one byte, pointing at the accepted singleton.
    const lookalike = address('lookalike')
    await ethers.provider.send('hardhat_setCode', [lookalike, `${await ethers.provider.getCode(safe)}00`])
    await ethers.provider.send('hardhat_setStorageAt', [
      lookalike,
      '0x0',
      ethers.zeroPadValue(await safeContracts.singleton.getAddress(), 32),
    ])
    expect(await crispProgram.isSafe(lookalike)).to.equal(false)
  })

  it('refuses a Safe above the owner or threshold cap of the proof', async function () {
    const largest = await newSafe(MAX_SAFE_OWNERS, MAX_SAFE_SIGNERS)
    expect((await crispProgram.ballotAuthorization(e3Id, largest, COMMITMENT)).safe).to.equal(true)

    for (const [owners, threshold] of [
      [MAX_SAFE_OWNERS + 1, 1],
      [MAX_SAFE_SIGNERS + 1, MAX_SAFE_SIGNERS + 1],
    ]) {
      const oversized = await newSafe(owners, threshold)
      await expect(crispProgram.ballotAuthorization(e3Id, oversized, COMMITMENT))
        .to.be.revertedWithCustomError(crispProgram, 'SafeShapeUnsupported')
        .withArgs(oversized, owners, threshold)
    }
  })

  /// A census round keeps the `crisp` circuit, which checks one signature by the slot key.
  it('keeps a Safe slot of a census round on the ballot digest', async function () {
    const censusRound = await mockInterfold.nextE3Id()
    await (await mockInterfold.request(await crispProgram.getAddress())).wait()
    const authorization = await crispProgram.ballotAuthorization(censusRound, safe, COMMITMENT)

    expect([...authorization]).to.deep.equal([false, await crispProgram.ballotDigest(censusRound, safe, COMMITMENT), ethers.ZeroHash])
  })
})
