// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { generateBFVKeys, prepareBallot, finishBallotProof, encodeSolidityProof, destroyBBApi, verifyProof } from '@crisp-e3/sdk'
import type { ProofData } from '@crisp-e3/sdk'
import { setCircuits } from '@crisp-e3/sdk'
import { loadCircuits } from '@crisp-e3/sdk/insecure-512'

// The BFV-shaped circuits ship as a separate entry point per preset, so proving needs one
// installed. These tests run against the insecure-512 parameters the contracts are deployed with.
before(async () => {
  setCircuits(await loadCircuits())
})
import { expect } from 'chai'
import {
  deployCRISPProgram,
  deployHonkVerifier,
  deployMockInterfold,
  deployOnchainHonkVerifier,
  ethers,
  publishAvailableInput,
} from './utils'
import type { CRISPProgram, HonkVerifier, MockInterfold } from '../types'

const CUSTOM = 1
const ONCHAIN = 2

/// End-to-end coverage for `CensusMode.ONCHAIN`.
///
/// Every other suite substitutes the Merkle verifier for the ONCHAIN one (see `deployCRISPProgram`),
/// because the constructor only needs a non-zero address until a real ONCHAIN ballot is verified.
/// That substitution means nothing here was ever exercised: the `crisp_onchain` circuit, the
/// verifier generated from it, and the path in `publishInput` that reads voting power from the
/// token and hands it to the circuit as public input 4.
///
/// It also means a swapped constructor argument would be invisible — passing the same address
/// twice cannot detect an order mistake. The last test in this file pins that.
describe('CRISP on-chain census', function () {
  // Proof generation dominates; the same budget as the Merkle end-to-end suite.
  // 600s was a per-test budget, not a per-file one, and the tests are unevenly weighted: the
  // heaviest here generates three ballots where the lightest generates one. A CI runner proves
  // roughly 4x slower than a dev machine, which put the three-ballot test over the line while
  // every lighter test stayed comfortably inside it.
  //
  // A timeout here is also not contained. `destroyBBApi()` runs in `after()`, so one Barretenberg
  // instance is shared by the whole file, and mocha abandons a timed-out test without stopping the
  // proof it left in flight. The next test then fails inside witness generation with "Cannot
  // satisfy constraint" rather than a timeout of its own — the fold circuit asserts the inner
  // proofs verify, so a proof that came back from a contended instance fails there rather than
  // where it was produced. Treat a constraint error immediately after a timeout as fallout from
  // that timeout, not as a circuit bug. The per-leg `timeout-minutes` in CI is the real backstop
  // for a genuine hang, so this only needs to clear honest work.
  this.timeout(1_200_000)

  const keys = generateBFVKeys()
  const publicKey = keys.publicKey

  let mockInterfold: MockInterfold
  let honkVerifier: HonkVerifier
  let onchainHonkVerifier: HonkVerifier
  let crispProgram: CRISPProgram
  let token: any
  let voter: any
  let slotAddress: string
  let e3Id: bigint
  let votingPower: bigint
  let voteProof: ProofData

  const numOptions = 2
  const vote = [7, 0]

  /// Mirrors the tuple `CRISPProgram._initRound` decodes.
  const encodeParams = (opts: {
    token: string
    minVotingPower: bigint
    numOptions: number
    creditMode: number
    credits: bigint
    censusMode: number
  }) =>
    ethers.AbiCoder.defaultAbiCoder().encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      // A divisor of 0 asks for the smallest one that keeps the round below the plaintext modulus.
      [opts.token, opts.minVotingPower, opts.numOptions, opts.creditMode, opts.credits, opts.censusMode, 0n],
    )

  before(async function () {
    mockInterfold = await deployMockInterfold()
    honkVerifier = await deployHonkVerifier()
    onchainHonkVerifier = await deployOnchainHonkVerifier()
    crispProgram = await deployCRISPProgram({ mockInterfold, honkVerifier, onchainHonkVerifier })

    voter = (await ethers.getSigners())[0]
    slotAddress = await voter.getAddress()

    // The snapshot is `clock() - 1`, so the balance has to exist strictly before the round is
    // requested. Minting self-delegates, which ERC20Votes requires for any voting power at all.
    token = await ethers.deployContract('MockVotesToken')
    await token.waitForDeployment()
    await (await token.mint(slotAddress, ethers.parseEther('50'))).wait()
    // Move the clock so the mint lands at a settled timepoint.
    await ethers.provider.send('evm_mine', [])

    e3Id = await mockInterfold.nextE3Id()
    // The smallest divisor `validate` accepts. The floor must be worth at least one ballot unit.
    const minimumDivisor = (await token.totalSupply()) / (await mockInterfold.plaintextModulus()) + 1n
    // CUSTOM credits, so the weight the circuit enforces is the token balance itself rather than a
    // flat per-voter allowance. That is what makes this exercise the token read.
    const requestTx = await mockInterfold.requestWithParams(
      await crispProgram.getAddress(),
      numOptions,
      encodeParams({
        token: await token.getAddress(),
        minVotingPower: minimumDivisor,
        numOptions,
        creditMode: CUSTOM,
        credits: 1n,
        censusMode: ONCHAIN,
      }),
    )
    const receipt = await requestTx.wait()

    // There is no public getter for the snapshot, so derive it the way `_initRound` does:
    // `_previousTimepoint` is `token.clock() - 1`, and this token's clock is `block.timestamp`.
    const requestBlock = await ethers.provider.getBlock(receipt!.blockNumber)
    const snapshot = BigInt(requestBlock!.timestamp) - 1n

    const rawPower: bigint = await token.getPastVotes(slotAddress, snapshot)
    expect(rawPower, 'voter must hold power at the snapshot').to.be.greaterThan(0n)

    // The contract scales raw power into ballot units before handing it to the circuit, so the
    // prover has to use the same value. Read the divisor from the round rather than recomputing
    // it, which also pins the getter clients depend on.
    const divisor = await crispProgram.votingPowerDivisorOf(e3Id)
    expect(divisor, 'the minimum: supply / t + 1').to.equal(minimumDivisor)

    votingPower = rawPower / divisor

    voteProof = await buildOnchainProof(votingPower)
  })

  after(() => {
    destroyBBApi()
  })

  /// Builds a ballot for the ONCHAIN circuit at a caller-chosen voting power, so a test can prove
  /// a power the token does not agree with.
  async function buildOnchainProof(power: bigint): Promise<ProofData> {
    const prepared = await prepareBallot({
      censusMode: 'onchain',
      vote,
      publicKey,
      votingPower: power,
      slotAddress,
      isMaskVote: false,
      numOptions,
    })

    const digest = (await crispProgram.ballotDigest(e3Id, slotAddress, prepared.ctCommitment)) as `0x${string}`
    const domain = {
      name: 'CRISP',
      version: '1',
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await crispProgram.getAddress(),
    }
    const types = {
      Ballot: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'slot', type: 'address' },
        { name: 'ciphertextCommitment', type: 'bytes32' },
      ],
    }
    const signature = (await voter.signTypedData(domain, types, {
      e3Id,
      slot: slotAddress,
      ciphertextCommitment: prepared.ctCommitment,
    })) as `0x${string}`

    return finishBallotProof(prepared, digest, signature)
  }

  it('verifies an ONCHAIN ballot against the onchain verifier', async function () {
    const isValid = await onchainHonkVerifier.verify(voteProof.proof, voteProof.publicInputs)

    expect(isValid).to.be.true
  })

  /// The SDK checks the same proof off chain against the `crisp_onchain` fold key.
  it('verifies an ONCHAIN ballot with the SDK', async function () {
    expect(await verifyProof(voteProof, 'onchain')).to.be.true
  })

  /// The two circuits agree on every public input except index 4, so this is the one position that
  /// distinguishes them. Pinning it means a future layout change names the field instead of
  /// surfacing as an opaque verifier revert.
  it('puts the token voting power at public input 4', async function () {
    const pi = voteProof.publicInputs.map((v: string) => BigInt(v))

    expect(pi[3], 'slot_address').to.eq(BigInt(slotAddress))
    expect(pi[4], 'voting_power').to.eq(votingPower)
    expect(pi[5], 'is_first_vote').to.eq(1n)
    expect(pi[6], 'num_options').to.eq(BigInt(numOptions))
  })

  /// The contract is the single source of truth for the bound. A client proves against this
  /// number, so if it ever disagreed with what `publishInput` hands the circuit, every ballot
  /// would fail with nothing naming the cause.
  it('exposes the same power the circuit is given', async function () {
    const exposed = await crispProgram.votingPowerOf(e3Id, slotAddress)

    expect(exposed).to.equal(votingPower)
    expect(exposed).to.equal(BigInt(voteProof.publicInputs[4]))
  })

  /// The contract reads the power from the token rather than trusting the ballot. A proof built
  /// for a different power therefore fails, which is what stops a voter choosing their own weight.
  /// The mismatched power stays below the plaintext modulus, so the ballot is valid in every other
  /// way.
  ///
  /// The mismatched ballot goes first, while the slot is empty. After the honest ballot the slot would
  /// already hold a vote, so the mismatched ballot would also mismatch on `prev_ct_commitment` and
  /// `is_first_vote`: it would still revert, but not for the reason under test.
  it('publishes an ONCHAIN ballot and rejects one that proves a power the token does not report', async function () {
    const mismatched = await buildOnchainProof(votingPower - 1n)
    await (await mockInterfold.setCommitteePublicKey(mismatched.publicInputs[8])).wait()
    await expect(publishAvailableInput(crispProgram, e3Id, encodeSolidityProof(mismatched))).to.be.revert(ethers)

    // Positive control in the same round and the same slot: the honest power publishes. The only
    // difference between the two ballots is the power, so the revert above is attributable to it.
    await (await mockInterfold.setCommitteePublicKey(voteProof.publicInputs[8])).wait()
    await publishAvailableInput(crispProgram, e3Id, encodeSolidityProof(voteProof))
  })

  /// The check the shared-verifier substitution can never make: the two verifiers are not
  /// interchangeable. If the constructor arguments were ever swapped, ONCHAIN ballots would be
  /// checked by the Merkle verifier and this would be the test that noticed.
  it('is rejected by the Merkle verifier', async function () {
    await expect(honkVerifier.verify(voteProof.proof, voteProof.publicInputs)).to.be.revert(ethers)
  })
})
