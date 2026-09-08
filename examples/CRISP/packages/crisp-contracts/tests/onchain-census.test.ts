// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { generateBFVKeys, prepareBallot, finishBallotProof, encodeSolidityProof, destroyBBApi } from '@crisp-e3/sdk'
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
  let divisor: bigint
  let rawPower: bigint
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
    /// 0 means "derive the divisor from the token's decimals".
    votingPowerDivisor?: bigint
  }) =>
    ethers.AbiCoder.defaultAbiCoder().encode(
      ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
      [opts.token, opts.minVotingPower, opts.numOptions, opts.creditMode, opts.credits, opts.censusMode, opts.votingPowerDivisor ?? 0n],
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
    // CUSTOM credits, so the weight the circuit enforces is the token balance itself rather than a
    // flat per-voter allowance. That is what makes this exercise the token read.
    const requestTx = await mockInterfold.requestWithParams(
      await crispProgram.getAddress(),
      numOptions,
      encodeParams({
        token: await token.getAddress(),
        minVotingPower: 10n ** 17n,
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

    rawPower = await token.getPastVotes(slotAddress, snapshot)
    expect(rawPower, 'voter must hold power at the snapshot').to.be.greaterThan(0n)

    // The contract scales raw power into ballot units before handing it to the circuit, so the
    // prover has to use the same value. Read the divisor from the round rather than recomputing
    // it, which also pins the getter clients depend on.
    divisor = await crispProgram.votingPowerDivisorOf(e3Id)
    expect(divisor, 'derived from the token decimals: 10 ** (18 - 1)').to.equal(10n ** 17n)

    votingPower = rawPower / divisor

    voteProof = await buildOnchainProof(votingPower)
  })

  after(() => {
    destroyBBApi()
  })

  /// Builds a ballot for the ONCHAIN circuit at a caller-chosen voting power, so a test can prove
  /// a power the token does not agree with.
  async function buildOnchainProof(power: bigint, roundId: bigint = e3Id): Promise<ProofData> {
    const prepared = await prepareBallot({
      censusMode: 'onchain',
      vote,
      publicKey,
      votingPower: power,
      slotAddress,
      isMaskVote: false,
      numOptions,
    })

    const digest = (await crispProgram.ballotDigest(roundId, slotAddress, prepared.ctCommitment)) as `0x${string}`
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
      e3Id: roundId,
      slot: slotAddress,
      ciphertextCommitment: prepared.ctCommitment,
    })) as `0x${string}`

    return finishBallotProof(prepared, digest, signature)
  }

  /// Opens another ONCHAIN round over the same token, so a test can publish a first vote for a
  /// slot that has already voted in `e3Id`.
  async function openRound(): Promise<bigint> {
    const id = await mockInterfold.nextE3Id()
    await (
      await mockInterfold.requestWithParams(
        await crispProgram.getAddress(),
        numOptions,
        encodeParams({
          token: await token.getAddress(),
          minVotingPower: 10n ** 17n,
          numOptions,
          creditMode: CUSTOM,
          credits: 1n,
          censusMode: ONCHAIN,
        }),
      )
    ).wait()
    return id
  }

  it('verifies an ONCHAIN ballot against the onchain verifier', async function () {
    const isValid = await onchainHonkVerifier.verify(voteProof.proof, voteProof.publicInputs)

    expect(isValid).to.be.true
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

  it('publishes an ONCHAIN ballot end to end', async function () {
    await (await mockInterfold.setCommitteePublicKey(voteProof.publicInputs[8])).wait()

    await publishAvailableInput(crispProgram, e3Id, encodeSolidityProof(voteProof))
  })

  /// The contract reads the power from the token rather than trusting the ballot. A proof built
  /// for a different power therefore fails, which is what stops a voter inflating their own weight.
  ///
  /// Runs in a fresh round on purpose. Reusing `e3Id` would leave the slot already voted, so the
  /// inflated ballot would mismatch on `prev_ct_commitment` and `is_first_vote` too — it would
  /// still revert, but not for the reason under test.
  it('rejects a ballot proving a voting power the token does not report', async function () {
    const round = await openRound()

    const inflated = await buildOnchainProof(votingPower * 2n, round)
    await (await mockInterfold.setCommitteePublicKey(inflated.publicInputs[8])).wait()
    await expect(publishAvailableInput(crispProgram, round, encodeSolidityProof(inflated))).to.be.revert(ethers)

    // Positive control in the same round and the same slot: the honest power publishes. The only
    // difference between the two ballots is the power, so the revert above is attributable to it.
    const honest = await buildOnchainProof(votingPower, round)
    await (await mockInterfold.setCommitteePublicKey(honest.publicInputs[8])).wait()
    await publishAvailableInput(crispProgram, round, encodeSolidityProof(honest))
  })

  /// The divisor is what keeps token weighting meaningful. The circuit enforces
  /// `vote <= voting_power`, and the BFV encoding caps each choice at `2**(100/numOptions) - 1`
  /// (about 8.6e9 for three options). Raw power from an 18-decimal token is ~1e18 per token, so
  /// unscaled every holder would sit above that cap and weighting would flatten silently.
  it('scales raw power into ballot units', async function () {
    const perChoiceCap = 2n ** 33n - 1n

    expect(divisor, 'derived as 10 ** (18 - 1)').to.equal(10n ** 17n)
    expect(votingPower).to.equal(rawPower / divisor)

    // The point of the divisor: the raw value is orders of magnitude past the cap, the scaled one
    // is comfortably inside it. Without scaling every holder would be pinned at the cap and the
    // weighting would carry no information.
    expect(rawPower, 'raw power breaches the cap').to.be.greaterThan(perChoiceCap)
    expect(votingPower, 'scaled power fits under it').to.be.lessThan(perChoiceCap)
  })

  /// A requester that needs different precision names its own divisor; 0 means "derive it".
  it('honours an explicit divisor', async function () {
    const id = await mockInterfold.nextE3Id()
    await (
      await mockInterfold.requestWithParams(
        await crispProgram.getAddress(),
        numOptions,
        encodeParams({
          token: await token.getAddress(),
          // A coarser divisor demands a proportionally higher floor: the round is refused unless
          // clearing it is worth at least one ballot unit.
          minVotingPower: 10n ** 18n,
          numOptions,
          creditMode: CUSTOM,
          credits: 1n,
          censusMode: ONCHAIN,
          votingPowerDivisor: 10n ** 18n,
        }),
      )
    ).wait()

    expect(await crispProgram.votingPowerDivisorOf(id)).to.equal(10n ** 18n)
  })

  /// Only ONCHAIN scales. A Merkle round records no divisor, because its bound comes from the
  /// census leaf the coordinator has already scaled.
  it('records no divisor for a non-ONCHAIN round', async function () {
    const id = await mockInterfold.nextE3Id()
    await (await mockInterfold.request(await crispProgram.getAddress())).wait()

    expect(await crispProgram.votingPowerDivisorOf(id)).to.equal(0n)
  })

  /// The check the shared-verifier substitution can never make: the two verifiers are not
  /// interchangeable. If the constructor arguments were ever swapped, ONCHAIN ballots would be
  /// checked by the Merkle verifier and this would be the test that noticed.
  it('is rejected by the Merkle verifier', async function () {
    await expect(honkVerifier.verify(voteProof.proof, voteProof.publicInputs)).to.be.revert(ethers)
  })
})
