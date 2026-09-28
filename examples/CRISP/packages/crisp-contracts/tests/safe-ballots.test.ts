// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import type { BaseContract, Wallet } from 'ethers'
import { createSafe as createSafeWith, deployCRISPProgram, deployMockInterfold, deploySafeContracts, ethers } from './utils'
import type { SafeDeployment } from './utils'
import type {
  CompatibilityFallbackHandler,
  CRISPProgram,
  HonkVerifier,
  MockExpectingHonkVerifier,
  MockInterfold,
  MockVotesToken,
  Safe,
} from '../types'

const CUSTOM = 1
const ONCHAIN = 2
const NUM_OPTIONS = 2
/// Mirror `MAX_SAFE_OWNERS` and `MAX_SAFE_SIGNERS` in CRISPProgram.sol.
const MAX_SAFE_OWNERS = 10
const MAX_SAFE_SIGNERS = 3
/// ERC-1271 magic value.
const ERC1271_VALID = '0x1626ba7e'
const COMMITTEE_PUBLIC_KEY = ethers.id('committee public key')
const CIPHERTEXT_COMMITMENT = ethers.id('ciphertext commitment')
const CIPHERTEXT_HASH = ethers.id('ciphertext bytes')

const abi = ethers.AbiCoder.defaultAbiCoder()
const halves = (word: string) => [
  ethers.zeroPadValue(ethers.dataSlice(word, 0, 16), 32),
  ethers.zeroPadValue(ethers.dataSlice(word, 16, 32), 32),
]
const word = (value: bigint | string) => ethers.zeroPadValue(ethers.toBeHex(value), 32)

/// Every slot of a `CensusMode.ONCHAIN` round is authorised by its owners, in the proof. A Safe has
/// its own owners and threshold; any other slot is its own single owner.
///
/// These tests use real Safe 1.4.1 contracts and check what `CRISPProgram` builds for the circuit
/// against values computed by the Safe itself. The verifier is a mock that accepts exactly one list
/// of public inputs.
describe('CRISP Safe ballots', function () {
  this.timeout(120000)

  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram
  let verifier: MockExpectingHonkVerifier
  let token: MockVotesToken
  let safeContracts: SafeDeployment
  let singleton: Safe
  let handler: CompatibilityFallbackHandler
  let owners: Wallet[]
  let safe: string
  let eoa: string
  let e3Id: bigint

  const wallet = (label: string) => new ethers.Wallet(ethers.id(label), ethers.provider)

  /// Owners sorted by address, which is the order that Safe requires for signatures.
  const sorted = (wallets: Wallet[]) => [...wallets].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1))

  const createSafe = (safeOwners: string[], threshold: number, safeSingleton?: BaseContract) =>
    createSafeWith(safeContracts, safeOwners, threshold, safeSingleton)

  /// Sign `hash` with each owner, in ascending owner order, as Safe `checkSignatures` expects.
  const safeSignatures = (signers: Wallet[], hash: string) =>
    ethers.concat(sorted(signers).map((signer) => signer.signingKey.sign(hash).serialized))

  /// `keccak256(abi.encode(address[MAX_SAFE_OWNERS], uint256))`, the commitment the circuit checks.
  const commitmentOf = (ownerList: string[], threshold: bigint) =>
    ethers.keccak256(
      abi.encode(
        [`address[${MAX_SAFE_OWNERS}]`, 'uint256'],
        [[...ownerList, ...Array(MAX_SAFE_OWNERS - ownerList.length).fill(ethers.ZeroAddress)], threshold],
      ),
    )

  /// The owner commitment of a Safe, computed from the Safe itself.
  async function ownersCommitmentOf(account: string) {
    const safeContract = singleton.attach(account) as Safe
    return commitmentOf([...(await safeContract.getOwners())], await safeContract.getThreshold())
  }

  const encodeParams = () =>
    abi.encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      [token.target, 10n ** 17n, NUM_OPTIONS, CUSTOM, 1n, ONCHAIN, 0n],
    )

  const validate = (slot: string, roundId = e3Id) =>
    crispProgram.validateInputProof(roundId, '0x', slot, CIPHERTEXT_COMMITMENT, CIPHERTEXT_HASH, 0)

  /// Public inputs 0 to 7, which both fold circuits share.
  const commonInputs = async (slot: string, digest: string) => [
    ethers.ZeroHash,
    ...halves(digest),
    word(BigInt(slot)),
    word(await crispProgram.votingPowerOf(e3Id, slot)),
    word(1n),
    word(BigInt(NUM_OPTIONS)),
    CIPHERTEXT_COMMITMENT,
  ]

  before(async function () {
    safeContracts = await deploySafeContracts()
    ;({ singleton, handler } = safeContracts)
    owners = [wallet('safe owner 0'), wallet('safe owner 1'), wallet('safe owner 2')]
    safe = await createSafe(
      owners.map((owner) => owner.address),
      2,
    )
    eoa = await (await ethers.getSigners())[1].getAddress()

    verifier = (await ethers.deployContract('MockExpectingHonkVerifier')) as unknown as MockExpectingHonkVerifier
    mockInterfold = await deployMockInterfold()
    await (await mockInterfold.setCommitteePublicKey(COMMITTEE_PUBLIC_KEY)).wait()
    crispProgram = await deployCRISPProgram({
      mockInterfold,
      onchainHonkVerifier: verifier as unknown as HonkVerifier,
      safeProxyCodehashes: [ethers.keccak256(await ethers.provider.getCode(safe))],
      safeSingletons: [await singleton.getAddress()],
    })

    token = (await ethers.deployContract('MockVotesToken')) as unknown as MockVotesToken
    for (const slot of [safe, eoa]) await (await token.mint(slot, ethers.parseEther('50'))).wait()
    await ethers.provider.send('evm_mine', [])

    e3Id = await mockInterfold.nextE3Id()
    await (await mockInterfold.requestWithParams(await crispProgram.getAddress(), NUM_OPTIONS, encodeParams())).wait()
  })

  it('identifies a Safe by its proxy code and singleton', async function () {
    expect(await crispProgram.isSafe(safe)).to.equal(true)
    expect(await crispProgram.isSafe(eoa)).to.equal(false)
  })

  it('proves a Safe slot against the digest and owners that the Safe holds', async function () {
    const ballotDigest = await crispProgram.ballotDigest(e3Id, safe, CIPHERTEXT_COMMITMENT)
    // The Safe's own hash of the ballot digest: the message that `isValidSignature` checks.
    const safeMessageHash = await handler.getMessageHashForSafe(safe, abi.encode(['bytes32'], [ballotDigest]))
    const ownersCommitment = await ownersCommitmentOf(safe)

    const authorization = await crispProgram.ballotAuthorization(e3Id, safe, CIPHERTEXT_COMMITMENT)
    expect(authorization.safe).to.equal(true)
    expect(authorization.digest).to.equal(safeMessageHash)
    expect(authorization.ownersCommitment).to.equal(ownersCommitment)

    await (
      await verifier.setExpectedPublicInputs([
        ...(await commonInputs(safe, safeMessageHash)),
        ...halves(ownersCommitment),
        COMMITTEE_PUBLIC_KEY,
      ])
    ).wait()

    expect(await validate(safe)).to.equal(true)
  })

  /// The owners sign in their own wallets, off the Safe Transaction Service. The same signatures
  /// must satisfy the Safe, or an owner could not check what they sign with standard Safe tooling.
  it('asks the owners to sign what the Safe itself accepts', async function () {
    const ballotDigest = await crispProgram.ballotDigest(e3Id, safe, CIPHERTEXT_COMMITMENT)
    const { digest } = await crispProgram.ballotAuthorization(e3Id, safe, CIPHERTEXT_COMMITMENT)
    const signatures = safeSignatures(owners.slice(0, 2), digest)

    const asHandler = handler.attach(safe) as CompatibilityFallbackHandler
    expect(await asHandler['isValidSignature(bytes32,bytes)'](ballotDigest, signatures)).to.equal(ERC1271_VALID)
  })

  it('proves a wallet slot as its own single owner, over the ballot digest', async function () {
    const ballotDigest = await crispProgram.ballotDigest(e3Id, eoa, CIPHERTEXT_COMMITMENT)
    const ownersCommitment = commitmentOf([eoa], 1n)
    const authorization = await crispProgram.ballotAuthorization(e3Id, eoa, CIPHERTEXT_COMMITMENT)
    expect(authorization.safe).to.equal(false)
    expect(authorization.digest).to.equal(ballotDigest)
    expect(authorization.ownersCommitment).to.equal(ownersCommitment)

    await (
      await verifier.setExpectedPublicInputs([
        ...(await commonInputs(eoa, ballotDigest)),
        ...halves(ownersCommitment),
        COMMITTEE_PUBLIC_KEY,
      ])
    ).wait()

    expect(await validate(eoa)).to.equal(true)
  })

  /// Any contract can answer `getOwners()` with any list. Only the code of an accepted proxy makes
  /// the owner list trustworthy.
  it('does not treat a contract that answers like a Safe as a Safe', async function () {
    const lookalike = await ethers.deployContract('MockSafeLookalike', [
      await singleton.getAddress(),
      [(await ethers.getSigners())[0].address],
      1,
    ])
    expect(await lookalike.masterCopy()).to.equal(await singleton.getAddress())

    expect(await crispProgram.isSafe(await lookalike.getAddress())).to.equal(false)
    const slot = await lookalike.getAddress()
    const authorization = await crispProgram.ballotAuthorization(e3Id, slot, CIPHERTEXT_COMMITMENT)
    expect(authorization.safe).to.equal(false)
    // Its own owner list is ignored: the slot is its single owner, which a contract cannot sign for.
    expect(authorization.ownersCommitment).to.equal(commitmentOf([slot], 1n))
  })

  it('does not accept a Safe proxy whose singleton the deployment did not accept', async function () {
    const otherSingleton = await ethers.deployContract('@safe-global/safe-contracts/contracts/Safe.sol:Safe')
    const proxy = await createSafe([owners[0].address], 1, otherSingleton)

    expect(await ethers.provider.getCode(proxy)).to.equal(await ethers.provider.getCode(safe), 'same proxy code')
    expect(await crispProgram.isSafe(proxy)).to.equal(false)
  })

  /// The owner list is read when the ballot is published, not at the round snapshot, so the owners
  /// that control the Safe now are the ones that authorise it.
  it('commits to the owners and threshold that the Safe has at publication', async function () {
    const before = (await crispProgram.ballotAuthorization(e3Id, safe, CIPHERTEXT_COMMITMENT)).ownersCommitment

    const safeContract = singleton.attach(safe) as Safe
    const data = safeContract.interface.encodeFunctionData('changeThreshold', [3])
    const nonce = await safeContract.nonce()
    const txHash = await safeContract.getTransactionHash(safe, 0, data, 0, 0, 0, 0, ethers.ZeroAddress, ethers.ZeroAddress, nonce)
    await (
      await safeContract.execTransaction(
        safe,
        0,
        data,
        0,
        0,
        0,
        0,
        ethers.ZeroAddress,
        ethers.ZeroAddress,
        safeSignatures(owners.slice(0, 2), txHash),
      )
    ).wait()

    const after = (await crispProgram.ballotAuthorization(e3Id, safe, CIPHERTEXT_COMMITMENT)).ownersCommitment
    expect(after).to.not.equal(before)
    expect(after).to.equal(await ownersCommitmentOf(safe))
  })

  it('accepts a Safe with exactly the largest owner list and threshold', async function () {
    const signers = Array.from({ length: MAX_SAFE_OWNERS }, (_, i) => wallet(`full owner ${i}`).address)
    const full = await createSafe(signers, MAX_SAFE_SIGNERS)

    const authorization = await crispProgram.ballotAuthorization(e3Id, full, CIPHERTEXT_COMMITMENT)
    expect(authorization.safe).to.equal(true)
    expect(authorization.ownersCommitment).to.equal(await ownersCommitmentOf(full))
  })

  it('refuses a Safe with a threshold above the signature slots of the proof', async function () {
    const signers = [0, 1, 2, 3].map((i) => wallet(`high threshold owner ${i}`).address)
    const wide = await createSafe(signers, MAX_SAFE_SIGNERS + 1)

    await expect(crispProgram.ballotAuthorization(e3Id, wide, CIPHERTEXT_COMMITMENT))
      .to.be.revertedWithCustomError(crispProgram, 'SafeShapeUnsupported')
      .withArgs(wide, 4, MAX_SAFE_SIGNERS + 1)
  })

  it('refuses a Safe with more owners than the proof commits to', async function () {
    const signers = Array.from({ length: MAX_SAFE_OWNERS + 1 }, (_, i) => wallet(`large owner ${i}`).address)
    const large = await createSafe(signers, 1)

    await expect(crispProgram.ballotAuthorization(e3Id, large, CIPHERTEXT_COMMITMENT))
      .to.be.revertedWithCustomError(crispProgram, 'SafeShapeUnsupported')
      .withArgs(large, MAX_SAFE_OWNERS + 1, 1)
  })

  /// Owner authorisation exists for `CensusMode.ONCHAIN` only. A census round keeps its Merkle
  /// circuit, which checks one signature by the slot key.
  it('keeps a Safe slot of a census round on the census path', async function () {
    const censusRound = await mockInterfold.nextE3Id()
    await (await mockInterfold.request(await crispProgram.getAddress())).wait()

    const authorization = await crispProgram.ballotAuthorization(censusRound, safe, CIPHERTEXT_COMMITMENT)
    expect(authorization.safe).to.equal(false)
    expect(authorization.digest).to.equal(await crispProgram.ballotDigest(censusRound, safe, CIPHERTEXT_COMMITMENT))
    expect(authorization.ownersCommitment).to.equal(ethers.ZeroHash)
  })
})
