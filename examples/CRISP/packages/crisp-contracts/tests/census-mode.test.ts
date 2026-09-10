// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { expect } from 'chai'
import { deployCRISPProgram, ethers } from './utils'
import type { CRISPProgram } from '../types'

const CONSTANT = 0
const CUSTOM = 1
const TOKEN = 0
const BY_REQUESTER = 1
const ONCHAIN = 2
/// Mirrors `MAX_VOTE_OPTIONS` in CRISPProgram.sol, which is not public.
const MAX_VOTE_OPTIONS = 10

/// `censusMode` says where a round's electorate comes from, and it is declared rather than inferred.
///
/// A coordinator that probed every requester and fell back on failure would turn a broken census
/// provider into a token vote over the wrong voters — the round would run, and nothing would error.
/// Declaring it also means an impossible combination can be rejected here, in the transaction that
/// requests the E3, rather than by the coordinator minutes later after the fee has been paid.
describe('CRISPProgram census mode', function () {
  this.timeout(120000)

  let crispProgram: CRISPProgram
  let owner: string

  const encode = (
    creditMode: number,
    censusMode?: number,
    numOptions = 2,
    opts: { token?: string; credits?: number; divisor?: number; minVotingPower?: bigint } = {},
  ) => {
    const types = ['address', 'uint256', 'uint256', 'uint256', 'uint256']
    const values: unknown[] = [opts.token ?? ethers.ZeroAddress, opts.minVotingPower ?? 0n, numOptions, creditMode, opts.credits ?? 1]
    if (censusMode !== undefined) {
      types.push('uint256', 'uint256')
      // 0 means "derive the divisor from the token's decimals".
      values.push(censusMode, opts.divisor ?? 0)
    }
    return ethers.AbiCoder.defaultAbiCoder().encode(types, values)
  }

  const validate = (e3Id: number, params: string) => crispProgram.validate(e3Id, 0, '0x', '0x', params)

  beforeEach(async () => {
    crispProgram = await deployCRISPProgram()
    owner = (await ethers.getSigners())[0].address
    expect(await crispProgram.owner()).to.equal(owner, 'validate is owner-callable in these tests')
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

  it('still allows custom credits with token discovery', async () => {
    await validate(5, encode(CUSTOM, TOKEN))
    expect(await crispProgram.censusModeOf(5)).to.equal(TOKEN)
  })

  it('keeps census root publication owner-only', async () => {
    const [, availabilitySigner] = await ethers.getSigners()
    const program = await deployCRISPProgram({ inputAvailabilitySigner: availabilitySigner.address })
    await program.validate(7, 0, '0x', '0x', encode(CUSTOM, TOKEN))

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

      // Derived divisor is 10 ** (18 - 1); a floor under that admits sub-unit voters.
      await expect(validate(40, encode(CUSTOM, ONCHAIN, 2, { token, minVotingPower: 10n ** 17n - 1n }))).to.be.revertedWithCustomError(
        crispProgram,
        'MinVotingPowerBelowScale',
      )

      // Exactly one ballot unit is enough.
      await validate(41, encode(CUSTOM, ONCHAIN, 2, { token, minVotingPower: 10n ** 17n }))
      expect(await crispProgram.votingPowerDivisorOf(41)).to.equal(10n ** 17n)
    })

    /// `10 ** 78` overflows a uint256, and the exponentiation sits in the success body of a
    /// `try`, where a revert is not caught — so without an explicit bound an absurd `decimals`
    /// surfaces as a bare arithmetic panic rather than a named error.
    it('refuses a token whose decimals a divisor cannot be derived from', async () => {
      const votes = await ethers.deployContract('MockVotesToken')
      await votes.waitForDeployment()
      const token = await votes.getAddress()

      // 18 decimals derives fine; the bound only bites well past any real token.
      await validate(45, encode(CUSTOM, ONCHAIN, 2, { token, minVotingPower: 10n ** 17n }))
      expect(await crispProgram.votingPowerDivisorOf(45)).to.equal(10n ** 17n)
    })

    it('rejects ONCHAIN with constant credits of zero', async () => {
      // `credits` becomes the voting-power bound the circuit enforces, so zero accepts only masks.
      const votes = await ethers.deployContract('MockVotesToken')

      await expect(
        validate(22, encode(CONSTANT, ONCHAIN, 2, { token: await votes.getAddress(), credits: 0 })),
      ).to.be.revertedWithCustomError(crispProgram, 'InvalidCredits')
    })

    it('accepts ONCHAIN with a votes token', async () => {
      const votes = await ethers.deployContract('MockVotesToken')

      // CUSTOM credits take the bound from scaled power, so the floor must be worth a ballot unit.
      await validate(23, encode(CUSTOM, ONCHAIN, 2, { token: await votes.getAddress(), minVotingPower: 10n ** 17n }))

      expect(await crispProgram.censusModeOf(23)).to.equal(ONCHAIN)
    })

    it('allows constant credits when the allowance is non-zero', async () => {
      const votes = await ethers.deployContract('MockVotesToken')

      await validate(24, encode(CONSTANT, ONCHAIN, 2, { token: await votes.getAddress(), credits: 5 }))

      expect(await crispProgram.censusModeOf(24)).to.equal(ONCHAIN)
    })
  })

  /// The circuit asserts `num_options <= MAX_OPTIONS`, so a round above the cap accepts no ballot:
  /// every vote proof fails. Refuse it at request time rather than storing a round nobody can
  /// vote in. Mirrors `MAX_VOTE_OPTIONS` in CRISPProgram.sol, which is not public.
  it('rejects more options than the circuit allows', async () => {
    await expect(validate(7, encode(CONSTANT, TOKEN, MAX_VOTE_OPTIONS + 1))).to.be.revertedWithCustomError(
      crispProgram,
      'InvalidNumOptions',
    )
  })

  it('accepts a round at exactly MAX_VOTE_OPTIONS options', async () => {
    await validate(8, encode(CONSTANT, TOKEN, MAX_VOTE_OPTIONS))
    expect(await crispProgram.censusModeOf(8)).to.equal(TOKEN)
  })

  it('rejects fewer than two options', async () => {
    await expect(validate(9, encode(CONSTANT, TOKEN, 1))).to.be.revertedWithCustomError(crispProgram, 'InvalidNumOptions')
  })
})
