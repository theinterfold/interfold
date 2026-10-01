// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { createRequire } from 'node:module'
import { createSafe, deployCRISPProgram, deployMockInterfold, deploySafeContracts, ethers } from './utils'
import type { SafeDeployment } from './utils'
import type { CompatibilityFallbackHandler, CRISPProgram, MockInterfold, Safe, SafeProxyFactory } from '../types'
import { SAFE_PROXY_CODEHASHES } from '../deploy/safe'

/// Mirror `MAX_SAFE_OWNERS` and `MAX_SAFE_SIGNERS` in CRISPProgram.sol.
const MAX_SAFE_OWNERS = 10
const MAX_SAFE_SIGNERS = 4
const COMMITMENT = ethers.id('ciphertext commitment')
const abi = ethers.AbiCoder.defaultAbiCoder()
const loadArtifact = createRequire(import.meta.url)

/// The owner commitment `crisp_onchain` checks: the owners as 20-byte words, zero-padded to
/// `MAX_SAFE_OWNERS`, then the threshold as one byte.
const commitmentOf = (owners: string[], threshold: bigint) =>
  ethers.solidityPackedKeccak256(
    [...Array(MAX_SAFE_OWNERS).fill('address'), 'uint8'],
    [...owners, ...Array(MAX_SAFE_OWNERS - owners.length).fill(ethers.ZeroAddress), threshold],
  )

/// Safe 1.3.0 from its published build, which is the bytecode of its canonical deployments.
async function deploySafe130Contracts(): Promise<SafeDeployment> {
  const [signer] = await ethers.getSigners()
  const deploy = async (name: string) => {
    const artifact = loadArtifact(`@gnosis.pm/safe-contracts/build/artifacts/contracts/${name}.json`)
    return (await new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer).deploy()) as unknown
  }
  return {
    singleton: (await deploy('GnosisSafe.sol/GnosisSafe')) as Safe,
    factory: (await deploy('proxies/GnosisSafeProxyFactory.sol/GnosisSafeProxyFactory')) as SafeProxyFactory,
    handler: (await deploy('handler/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler')) as CompatibilityFallbackHandler,
  }
}

/// `ballotAuthorization` against real Safe 1.3.0 and 1.4.1 contracts. `onchain-census.test.ts`
/// proves and publishes Safe ballots against these values.
describe('CRISP Safe ballots', function () {
  let safeContracts: SafeDeployment
  let safe130Contracts: SafeDeployment
  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram
  let safe: string
  let safe130: string
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
    safe130Contracts = await deploySafe130Contracts()
    safe = await newSafe(3, 2)
    safe130 = await createSafe(safe130Contracts, [address('owner 0'), address('owner 1')], 2)
    mockInterfold = await deployMockInterfold()
    crispProgram = await deployCRISPProgram({
      mockInterfold,
      safeProxyCodehashes: [
        ethers.keccak256(await ethers.provider.getCode(safe)),
        ethers.keccak256(await ethers.provider.getCode(safe130)),
      ],
      safeSingletons: [await safeContracts.singleton.getAddress(), await safe130Contracts.singleton.getAddress()],
    })
    const token = await ethers.deployContract('MockVotesToken')
    const params = abi.encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      [token.target, 10n ** 17n, 2, 1, 1n, 2, 0n],
    )
    e3Id = await mockInterfold.nextE3Id()
    await (await mockInterfold.requestWithParams(await crispProgram.getAddress(), 2, params)).wait()
  })

  it('binds a Safe 1.3.0 or 1.4.1 ballot to the Safe message hash and the current owners', async function () {
    for (const [contracts, slot] of [
      [safeContracts, safe],
      [safe130Contracts, safe130],
    ] as const) {
      const { safe: isSafe, digest, ownersCommitment } = await crispProgram.ballotAuthorization(e3Id, slot, COMMITMENT)
      const ballotDigest = await crispProgram.ballotDigest(e3Id, slot, COMMITMENT)
      const safeContract = contracts.singleton.attach(slot) as Safe

      expect(isSafe).to.equal(true)
      // The hash that the Safe's own `isValidSignature` checks the owner signatures against.
      expect(digest).to.equal(await contracts.handler.getMessageHashForSafe(slot, abi.encode(['bytes32'], [ballotDigest])))
      expect(ownersCommitment).to.equal(commitmentOf([...(await safeContract.getOwners())], await safeContract.getThreshold()))
    }
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

  /// The deploy script accepts a Safe by the code hash of its proxy. The hashes must be those of
  /// the published Safe 1.3.0 and 1.4.1 proxies, which the canonical factories deploy on every chain.
  it('allowlists the proxy code of the published Safe 1.3.0 and 1.4.1 builds', function () {
    const runtime = (artifact: string) => ethers.keccak256(loadArtifact(`${artifact}.json`).deployedBytecode)
    expect(SAFE_PROXY_CODEHASHES).to.have.members([
      runtime('@gnosis.pm/safe-contracts/build/artifacts/contracts/proxies/GnosisSafeProxy.sol/GnosisSafeProxy'),
      runtime('@safe-global/safe-contracts/build/artifacts/contracts/proxies/SafeProxy.sol/SafeProxy'),
    ])
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

  /// The owners and threshold are read at publication, and every input of an ONCHAIN round goes
  /// through `ballotAuthorization`. So a Safe above a cap takes no vote and no mask until it
  /// returns to a supported shape, and new owners can sign the next ballot.
  it('follows a Safe that changes its shape during the round', async function () {
    const shifting = await newSafe(MAX_SAFE_SIGNERS + 1, MAX_SAFE_SIGNERS)
    const asSafe = (safeContracts.singleton.attach(shifting) as Safe).connect(await ethers.getImpersonatedSigner(shifting))
    await ethers.provider.send('hardhat_setBalance', [shifting, ethers.toQuantity(ethers.WeiPerEther)])
    const owners = await asSafe.getOwners()

    await (await asSafe.changeThreshold(MAX_SAFE_SIGNERS + 1)).wait()
    await expect(crispProgram.ballotAuthorization(e3Id, shifting, COMMITMENT)).to.be.revertedWithCustomError(
      crispProgram,
      'SafeShapeUnsupported',
    )

    await (await asSafe.changeThreshold(MAX_SAFE_SIGNERS)).wait()
    // The Safe owner list is a linked list; the sentinel address 0x…01 precedes the first owner.
    await (await asSafe.swapOwner(ethers.toBeHex(1, 20), owners[0], address('new owner'))).wait()
    expect((await crispProgram.ballotAuthorization(e3Id, shifting, COMMITMENT)).ownersCommitment).to.equal(
      commitmentOf([address('new owner'), ...owners.slice(1)], BigInt(MAX_SAFE_SIGNERS)),
    )
  })

  /// A census round keeps the `crisp` circuit, which checks one signature by the slot key.
  it('keeps a Safe slot of a census round on the ballot digest', async function () {
    const censusRound = await mockInterfold.nextE3Id()
    await (await mockInterfold.request(await crispProgram.getAddress())).wait()
    const authorization = await crispProgram.ballotAuthorization(censusRound, safe, COMMITMENT)

    expect([...authorization]).to.deep.equal([false, await crispProgram.ballotDigest(censusRound, safe, COMMITMENT), ethers.ZeroHash])
  })
})
