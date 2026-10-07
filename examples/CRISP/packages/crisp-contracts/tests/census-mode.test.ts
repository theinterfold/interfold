// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { deployCRISPProgram, deployMockInterfold, ethers } from './utils'
import type { CRISPProgram, MockInterfold } from '../types'

const CONSTANT = 0
const CUSTOM = 1
const TOKEN = 0
const BY_REQUESTER = 1
const ONCHAIN = 2

/// `censusMode` says where a round's electorate comes from, and it is declared rather than inferred.
///
/// A coordinator that probed every requester and fell back on failure would turn a broken census
/// provider into a token vote over the wrong voters — the round would run, and nothing would error.
/// Declaring it also means an impossible combination can be rejected here, in the transaction that
/// requests the E3, rather than by the coordinator minutes later after the fee has been paid.
describe('CRISPProgram census mode', function () {
  this.timeout(120000)

  let mockInterfold: MockInterfold
  let crispProgram: CRISPProgram
  let owner: string
  /// The BFV parameter blob Interfold hands `validate`, and the plaintext modulus inside it.
  let bfvParams: string
  let t: bigint

  const encode = (
    creditMode: number,
    censusMode?: number,
    numOptions = 2,
    opts: { token?: string; credits?: bigint; divisor?: bigint; minVotingPower?: bigint } = {},
  ) => {
    const types = ['address', 'uint256', 'uint256', 'uint256', 'uint256']
    const values: unknown[] = [opts.token ?? ethers.ZeroAddress, opts.minVotingPower ?? 0n, numOptions, creditMode, opts.credits ?? 1n]
    if (censusMode !== undefined) {
      types.push('uint256', 'uint256')
      // 0 means "use the smallest divisor that keeps the round below the plaintext modulus".
      values.push(censusMode, opts.divisor ?? 0n)
    }
    return ethers.AbiCoder.defaultAbiCoder().encode(types, values)
  }

  const validate = (e3Id: number, params: string) => crispProgram.validate(e3Id, 0, bfvParams, '0x', params)

  /// The smallest divisor that keeps the sum of every scaled balance below `t`.
  const minimumDivisor = (supply: bigint, modulus = t) => supply / modulus + 1n

  beforeEach(async () => {
    mockInterfold = await deployMockInterfold()
    crispProgram = await deployCRISPProgram({ mockInterfold })
    owner = (await ethers.getSigners())[0].address
    expect(await crispProgram.owner()).to.equal(owner, 'validate is owner-callable in these tests')
    bfvParams = await mockInterfold.e3ProgramParams()
    t = await mockInterfold.plaintextModulus()
  })

  /// Required, not optional. A caller that omits it must fail loudly rather than silently receive
  /// token discovery — which is the same silent-wrong-electorate failure this enum exists to stop,
  /// one level up.
  it('rejects params without a census mode', async () => {
    await expect(validate(1, encode(CONSTANT))).to.be.revert(ethers)
  })

  it('records a declared TOKEN mode', async () => {
    await validate(2, encode(CONSTANT, TOKEN))
    expect(await crispProgram.censusModeOf(2)).to.equal(TOKEN)
  })

  it('records a declared BY_REQUESTER mode', async () => {
    await validate(3, encode(CONSTANT, BY_REQUESTER))
    expect(await crispProgram.censusModeOf(3)).to.equal(BY_REQUESTER)
  })

  /// The pairing that cannot work: a requester-supplied census names who may vote, not how much
  /// each vote weighs. Rejected on chain so it costs nothing rather than failing in the indexer
  /// after the E3 has been paid for.
  it('rejects BY_REQUESTER with custom credits', async () => {
    await expect(validate(4, encode(CUSTOM, BY_REQUESTER))).to.be.revertedWithCustomError(crispProgram, 'CensusModeRequiresConstantCredits')
  })

  it('keeps census root publication owner-only', async () => {
    const [, availabilitySigner] = await ethers.getSigners()
    const program = await deployCRISPProgram({ inputAvailabilitySigner: availabilitySigner.address })
    await program.validate(7, 0, bfvParams, '0x', encode(CONSTANT, TOKEN))

    await expect(program.connect(availabilitySigner).setMerkleRoot(7, 123))
      .to.be.revertedWithCustomError(program, 'OwnableUnauthorizedAccount')
      .withArgs(availabilitySigner.address)
    await program.setMerkleRoot(7, 123)

    expect((await program.getRoundData(7)).merkleRoot).to.equal(123)
  })

  /// An unrecognised mode is a coordinator that would not know what to do. Better to refuse the
  /// round than to have it silently treated as a token vote.
  it('rejects an unknown census mode', async () => {
    await expect(validate(6, encode(CONSTANT, 3))).to.be.revertedWithCustomError(crispProgram, 'InvalidCensusMode')
  })

  /// The tally holds one total per option and a total is exact only below `t`. A CONSTANT round
  /// carries `credits` per input, so one ballot of `t` credits or more could wrap a total by itself.
  describe('constant credits and the plaintext modulus', () => {
    it('rejects credits at or above the plaintext modulus and accepts the largest below it', async () => {
      await expect(validate(30, encode(CONSTANT, TOKEN, 2, { credits: t })))
        .to.be.revertedWithCustomError(crispProgram, 'CreditsExceedPlaintextModulus')
        .withArgs(t, t)

      await validate(31, encode(CONSTANT, TOKEN, 2, { credits: t - 1n }))
    })

    it('sizes every round against the plaintext modulus of the registered parameters', async () => {
      // Credits of `t` are refused under the default blob, so acceptance here shows the modulus is
      // read from the blob.
      const votes = await ethers.deployContract('MockVotesToken')
      const wider = t * 1000n
      const widerParams = await mockInterfold.bfvParamsWithPlaintextModulus(wider)

      await crispProgram.validate(33, 0, widerParams, '0x', encode(CONSTANT, TOKEN, 2, { credits: t }))
      await crispProgram.validate(16, 0, widerParams, '0x', encode(CUSTOM, TOKEN, 2, { token: await votes.getAddress() }))

      expect(await crispProgram.votingPowerDivisorOf(16)).to.equal(minimumDivisor(await votes.totalSupply(), wider))
    })

    it('records no divisor for constant credits, whatever the request names', async () => {
      const votes = await ethers.deployContract('MockVotesToken')
      const token = await votes.getAddress()

      for (const [e3Id, census] of [
        [34, TOKEN],
        [24, ONCHAIN],
      ] as const) {
        await validate(e3Id, encode(CONSTANT, census, 2, { token, credits: 5n, divisor: 7n }))
        expect(await crispProgram.votingPowerDivisorOf(e3Id)).to.equal(0n)
      }
    })
  })

  /// CUSTOM credits weight each ballot by token voting power. The sum of every holder's scaled
  /// power must stay below `t`, which holds exactly when the divisor exceeds `supply / t`.
  describe('custom credits divisor', () => {
    it('rejects TOKEN with custom credits and no votes token', async () => {
      // No code at the address: refused before any call, by a named error.
      await expect(validate(10, encode(CUSTOM, TOKEN))).to.be.revertedWithCustomError(crispProgram, 'CustomCreditsRequireVotesToken')

      // Code, but no `getPastTotalSupply`: refused by the call itself.
      const plain = await ethers.deployContract('MockVotingToken')
      await expect(validate(11, encode(CUSTOM, TOKEN, 2, { token: await plain.getAddress() }))).to.be.revertedWithCustomError(
        crispProgram,
        'CustomCreditsRequireVotesToken',
      )
    })

    it('records the requested divisor or the minimum, and refuses less than the minimum', async () => {
      const votes = await ethers.deployContract('MockVotesToken')
      const token = await votes.getAddress()
      // `minimum - 1` is `supply / t`, whose scaled power can sum to `t` or more.
      const minimum = minimumDivisor(await votes.totalSupply())

      await expect(validate(12, encode(CUSTOM, TOKEN, 2, { token, divisor: minimum - 1n })))
        .to.be.revertedWithCustomError(crispProgram, 'VotingPowerDivisorBelowMinimum')
        .withArgs(minimum - 1n, minimum)

      for (const [e3Id, divisor, recorded] of [
        [13, minimum, minimum],
        [14, 0n, minimum],
        [15, 2n * minimum, 2n * minimum],
      ] as const) {
        const receipt = await (await validate(e3Id, encode(CUSTOM, TOKEN, 2, { token, divisor }))).wait()
        expect(await crispProgram.votingPowerDivisorOf(e3Id)).to.equal(recorded)
        // The coordinator reads the census here: the timepoint before the request, whose supply sized the divisor.
        expect(await crispProgram.snapshotOf(e3Id)).to.equal((await votes.clock({ blockTag: receipt!.blockNumber })) - 1n)
      }
    })
  })

  /// ONCHAIN reads every voter's power from the token, one input at a time. A round that names no
  /// token, or names something that cannot answer `getPastVotes`, accepts no ballot at all — so it
  /// is refused in the request transaction rather than after the fee is paid.
  describe('onchain census', () => {
    it('rejects ONCHAIN without a token', async () => {
      await expect(validate(20, encode(CUSTOM, ONCHAIN))).to.be.revertedWithCustomError(crispProgram, 'CensusModeRequiresToken')
    })

    it('rejects ONCHAIN with an address that holds no code', async () => {
      // An EOA. A call to a codeless address succeeds and returns nothing, so `clock()` fails
      // while decoding rather than inside the call — which `try/catch` does not cover. Without an
      // explicit code check the round is still refused, but by a bare panic rather than a named
      // error, which tells a requester nothing about what to fix.
      const eoa = (await ethers.getSigners())[1].address

      await expect(validate(25, encode(CUSTOM, ONCHAIN, 2, { token: eoa }))).to.be.revertedWithCustomError(
        crispProgram,
        'CensusModeRequiresToken',
      )
    })

    it('rejects ONCHAIN with a token that is not an ERC20Votes', async () => {
      // A plain ERC20. `_previousTimepoint` swallows the missing `clock()` and falls back to block
      // numbers, so without the probe this round would validate and then revert on every input.
      const plain = await ethers.deployContract('MockVotingToken')

      await expect(validate(21, encode(CUSTOM, ONCHAIN, 2, { token: await plain.getAddress() }))).to.be.revertedWithCustomError(
        crispProgram,
        'CensusModeRequiresToken',
      )
    })

    /// The floor is raw and the circuit bound is scaled, so they only agree when the floor is
    /// worth at least one ballot unit. Enforced when the round is requested rather than per input:
    /// a slot that cleared a sub-unit floor could publish (an all-zero ballot satisfies
    /// `vote <= 0`) but could never carry weight, which is disenfranchisement nothing would report.
    /// Checking per input would also break masking, which runs the same eligibility check.
    it('rejects an ONCHAIN floor below one ballot unit', async () => {
      const votes = await ethers.deployContract('MockVotesToken')
      await votes.waitForDeployment()
      const token = await votes.getAddress()
      const divisor = minimumDivisor(await votes.totalSupply())

      // A floor under the divisor admits sub-unit voters.
      await expect(validate(40, encode(CUSTOM, ONCHAIN, 2, { token, minVotingPower: divisor - 1n }))).to.be.revertedWithCustomError(
        crispProgram,
        'MinVotingPowerBelowScale',
      )

      // Exactly one ballot unit is enough.
      await validate(41, encode(CUSTOM, ONCHAIN, 2, { token, minVotingPower: divisor }))
      expect(await crispProgram.votingPowerDivisorOf(41)).to.equal(divisor)
    })

    it('rejects ONCHAIN with constant credits of zero', async () => {
      // `credits` becomes the voting-power bound the circuit enforces, so zero accepts only masks.
      const votes = await ethers.deployContract('MockVotesToken')

      await expect(
        validate(22, encode(CONSTANT, ONCHAIN, 2, { token: await votes.getAddress(), credits: 0n })),
      ).to.be.revertedWithCustomError(crispProgram, 'InvalidCredits')
    })
  })

  it('rejects fewer than two options', async () => {
    await expect(validate(9, encode(CONSTANT, TOKEN, 1))).to.be.revertedWithCustomError(crispProgram, 'InvalidNumOptions')
  })
})
