// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import hre from 'hardhat'
import type { PrivateRoundProgram } from '../types/contracts/PrivateRoundProgram'
import type { MockBidVerifier, MockInterfold, MockPaymentToken, MockSaleToken } from '../types/contracts/mocks'
import { type Hex, zeroAddress } from 'viem'
import type { HardhatEthers, HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/types'
import type { Wallet } from 'ethers'
import { MockInterfold__factory, MockSaleToken__factory, MockPaymentToken__factory } from '../types/factories/contracts/mocks'
import { PrivateRoundProgram__factory } from '../types/factories/contracts'
import { Outcome, bidInputsHash, encodeBidInput, encodeClaimData, outputSlotsFor, type RoundParams } from '../sdk/src/layout'
import { type RoundSale, compareBid, plainOutcome } from '../sdk/src/clearing'
import { bytes32, encodeRawParams, filled, plaintextOf } from './helpers'

export const E3_ID = 7n
export const KEY = filled(0xab)
export const VK_ANCHOR = filled(0xcd)
export const U18 = 10n ** 18n
/** Prices in USDC base units per whole sale token: 1.00, 2.00, 3.00 and 4.00 USDC. */
export const PRICES = [1_000_000n, 2_000_000n, 3_000_000n, 4_000_000n]
/** One lot is 10 sale tokens. */
export const LOT = 10n * U18
export const LOTS = 3
/** The escrow of a bidder: the price of one lot at the highest step, 10 tokens at 4.00. */
export const ESCROW = 40_000_000n
export const DAY = 24n * 3600n

/** What a test needs: the contracts, the actors and the helpers to run a round. */
export interface Fixture {
  ethers: HardhatEthers
  creator: HardhatEthersSigner
  actors: HardhatEthersSigner[]
  relayer: HardhatEthersSigner
  program: PrivateRoundProgram
  programAddress: Hex
  interfold: MockInterfold
  saleToken: MockSaleToken
  usdc: MockPaymentToken
  bidVerifier: MockBidVerifier
  claimVerifier: MockBidVerifier
  chainId: number
}

async function deployMockVerifier(ethers: HardhatEthers): Promise<MockBidVerifier> {
  return (await ethers.deployContract('MockBidVerifier')) as unknown as MockBidVerifier
}

/** Deploys the program with mock verifiers and a mock Interfold, and no round. */
export async function deployFixture(): Promise<Fixture> {
  const { ethers } = await hre.network.connect()
  const [creator, relayer, ...actors] = await ethers.getSigners()
  const interfold = await ethers.deployContract('MockInterfold')
  const receiptVerifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
  const availability = await ethers.deployContract('MockDataAvailabilityVerifier')
  const bidVerifier = await deployMockVerifier(ethers)
  const claimVerifier = await deployMockVerifier(ethers)
  const poseidon = await ethers.deployContract('PoseidonT3')
  const output = await ethers.deployContract('RoundOutput')
  const config = await ethers.deployContract('RoundConfig')
  const factory = await ethers.getContractFactory(
    PrivateRoundProgram__factory.abi,
    PrivateRoundProgram__factory.linkBytecode({
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': await poseidon.getAddress(),
      'project/contracts/libraries/RoundOutput.sol:RoundOutput': await output.getAddress(),
      'project/contracts/libraries/RoundConfig.sol:RoundConfig': await config.getAddress(),
    }),
    creator,
  )
  const deployed = await factory.deploy(
    await interfold.getAddress(),
    await receiptVerifier.getAddress(),
    await receiptVerifier.imageId(),
    await bidVerifier.getAddress(),
    await claimVerifier.getAddress(),
    VK_ANCHOR,
    await availability.getAddress(),
  )
  const programAddress = (await deployed.getAddress()) as Hex
  const saleToken = MockSaleToken__factory.connect(await (await ethers.deployContract('MockSaleToken')).getAddress(), creator)
  const usdc = MockPaymentToken__factory.connect(await (await ethers.deployContract('MockPaymentToken')).getAddress(), creator)
  return {
    ethers,
    creator,
    relayer,
    actors,
    program: PrivateRoundProgram__factory.connect(programAddress, creator),
    programAddress,
    interfold: MockInterfold__factory.connect(await interfold.getAddress(), creator),
    saleToken,
    usdc,
    bidVerifier,
    claimVerifier,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
  }
}

export interface RequestOptions {
  e3Id?: bigint
  prices?: bigint[]
  levels?: number
  lot?: bigint
  lots?: number
  reserveStep?: number
  minLots?: number
  title?: string
  gate?: Hex
  gateConfig?: Hex
  /** Replaces the sale token (for example a token with other decimals). */
  saleToken?: Hex
  paymentToken?: Hex
  /** Skip the approval of the supply. */
  noApproval?: boolean
  inputDeadline?: bigint
}

/** The sale parameters of a round: the SDK type, for the reference arithmetic. */
export function roundSale(options: RequestOptions = {}): RoundSale {
  return {
    prices: options.prices ?? PRICES,
    lot: options.lot ?? LOT,
    lots: options.lots ?? LOTS,
    reserveStep: options.reserveStep ?? 0,
    minLots: options.minLots ?? 1,
    saleDecimals: 18,
  }
}

export function roundParams(options: RequestOptions = {}): RoundParams {
  const sale = roundSale(options)
  return { levels: options.levels ?? sale.prices.length, reserveStep: sale.reserveStep, lots: sale.lots, minLots: sale.minLots }
}

/** The creator gets the supply, approves it, and Interfold requests the round: `validate` runs. */
export async function requestRound(fixture: Fixture, options: RequestOptions = {}) {
  const e3Id = options.e3Id ?? E3_ID
  const sale = roundSale(options)
  const supply = sale.lot * BigInt(sale.lots)
  await (await fixture.interfold.setE3(e3Id, options.inputDeadline ?? 2n ** 40n, KEY, fixture.creator.address)).wait()
  await (await fixture.saleToken.mint(fixture.creator.address, supply)).wait()
  if (!options.noApproval) await (await fixture.saleToken.approve(fixture.programAddress, supply)).wait()
  const params = encodeRawParams({
    levels: options.levels,
    prices: sale.prices as bigint[],
    saleToken: options.saleToken ?? ((await fixture.saleToken.getAddress()) as Hex),
    lot: sale.lot,
    lots: sale.lots,
    reserveStep: sale.reserveStep,
    minLots: sale.minLots,
    paymentToken: options.paymentToken ?? ((await fixture.usdc.getAddress()) as Hex),
    title: options.title,
    gate: options.gate ?? zeroAddress,
    gateConfig: options.gateConfig,
  })
  return { e3Id, params, tx: () => fixture.interfold.request(e3Id, fixture.programAddress, params) }
}

/** Requests a round and waits for it. */
export async function createRound(fixture: Fixture, options: RequestOptions = {}): Promise<bigint> {
  const { e3Id, tx } = await requestRound(fixture, options)
  await (await tx()).wait()
  return e3Id
}

/** Gives `holder` payment tokens, and approves the program. */
export async function fund(fixture: Fixture, holder: HardhatEthersSigner, amount = ESCROW) {
  await (await fixture.usdc.mint(holder.address, amount)).wait()
  await (await fixture.usdc.connect(holder).approve(fixture.programAddress, amount)).wait()
}

/** An EIP-2612 permit of `owner` for the program, split into `v`, `r` and `s`. */
export async function signPermit(fixture: Fixture, owner: Wallet | HardhatEthersSigner, value: bigint, deadline: bigint) {
  const token = (await fixture.usdc.getAddress()) as Hex
  const nonce = await fixture.usdc.nonces(owner.address)
  const signature = await owner.signTypedData(
    { name: 'Mock USDC', version: '1', chainId: fixture.chainId, verifyingContract: token },
    {
      Permit: [
        { name: 'owner', type: 'address' },
        { name: 'spender', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    { owner: owner.address, spender: fixture.programAddress, value, nonce, deadline },
  )
  const { v, r, s } = fixture.ethers.Signature.from(signature)
  return { v, r, s }
}

/** The EIP-712 signature of a relayed bid. */
export async function signBid(
  fixture: Fixture,
  bidder: Wallet | HardhatEthersSigner,
  e3Id: bigint,
  version: number,
  inputsHash: Hex,
): Promise<Hex> {
  return (await bidder.signTypedData(
    { name: 'PrivateRoundProgram', version: '1', chainId: fixture.chainId, verifyingContract: fixture.programAddress },
    {
      Bid: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'bidder', type: 'address' },
        { name: 'version', type: 'uint32' },
        { name: 'inputsHash', type: 'bytes32' },
      ],
    },
    { e3Id, bidder: bidder.address, version, inputsHash },
  )) as Hex
}

// ---------------------------------------------------------------------------------------------
// Bids
// ---------------------------------------------------------------------------------------------

/** The bid of one actor: bytes that stand for the bid ciphertext and the mask, and their commitments. */
export function makeBid(bidder: string, seed: number): MadeBid {
  const ct = (byte: number) => `0x${byte.toString(16).padStart(2, '0').repeat(16)}` as Hex
  return {
    bidder: bidder as Hex,
    ciphertexts: [ct(seed), ct(0x40 + seed)] as readonly [Hex, Hex],
    ctCommitments: [filled(seed), filled(0x40 + seed)] as readonly [Hex, Hex],
    bidCommitment: filled(0x80 + seed),
  }
}
/** The bid of one actor, from `makeBid`. */
export interface MadeBid {
  bidder: Hex
  ciphertexts: readonly [Hex, Hex]
  ctCommitments: readonly [Hex, Hex]
  bidCommitment: Hex
}

/** The public inputs of the bid proof, in the order of `circuits/PUBLIC_INPUTS.md`. */
export function bidPublicInputs(
  bid: MadeBid,
  e3Id: bigint,
  params: { levels: number; reserveStep: number },
  index: number,
  version: number,
): Hex[] {
  return [
    bid.ctCommitments[0],
    bid.ctCommitments[1],
    bid.bidCommitment,
    bytes32(bid.bidder),
    bytes32(e3Id),
    bytes32(params.levels),
    bytes32(params.reserveStep),
    bytes32(index),
    bytes32(version),
    KEY,
    VK_ANCHOR,
  ]
}

/** What a relayed bid signs. */
export const inputsHashOf = (bid: MadeBid) => bidInputsHash(bid.ctCommitments, bid.bidCommitment, bid.ciphertexts)

/** The `data` of `publishInput` for a made bid. */
export const bidData = (bid: MadeBid, extra: Partial<Parameters<typeof encodeBidInput>[0]> = {}) =>
  encodeBidInput({ ...bid, proof: '0x01', gateProof: '0x', signature: '0x', ...extra })

export async function deposit(fixture: Fixture, actor: HardhatEthersSigner, e3Id = E3_ID) {
  await fund(fixture, actor)
  await (await fixture.program.connect(actor).deposit(e3Id, '0x')).wait()
}

export async function bid(fixture: Fixture, actor: HardhatEthersSigner, seed: number, e3Id = E3_ID) {
  const made = makeBid(actor.address, seed)
  await (await fixture.program.connect(actor).publishInput(e3Id, bidData(made))).wait()
  return made
}

// ---------------------------------------------------------------------------------------------
// A played round
// ---------------------------------------------------------------------------------------------

export interface PlayOptions extends RequestOptions {
  /** The counted version of each bidder; the default is 1 for a bidder that bid and 0 for the others. */
  counted?: number[]
  /** The bids of each bidder; the default is the counted version, or 1. */
  bidsOf?: number[]
  /** The 128 output slots to publish, instead of the honest output of the bids. */
  slots?: readonly bigint[]
  /** Publish nothing: the output is not there yet. */
  noOutput?: boolean
}

export interface Played {
  e3Id: bigint
  sale: RoundSale
  params: RoundParams
  /** The step of each bidder that deposited; `null` for one that did not bid. */
  steps: (number | null)[]
  counted: number[]
  made: MadeBid[][]
  outcome: Outcome
  step: number | null
}

/**
 * A round where the bidder `i` is `actors[i]` and has the step `steps[i]` (`null`: deposits and does
 * not bid). It publishes the honest output of the counted bids, or `options.slots`.
 */
export async function playRound(fixture: Fixture, steps: (number | null)[], options: PlayOptions = {}): Promise<Played> {
  const e3Id = await createRound(fixture, options)
  const sale = roundSale(options)
  const params = roundParams(options)
  const counted = options.counted ?? steps.map((step) => (step === null ? 0 : 1))
  const made: MadeBid[][] = []
  for (let i = 0; i < steps.length; i++) {
    const actor = fixture.actors[i]
    await deposit(fixture, actor, e3Id)
    made.push([])
    const bids = steps[i] === null ? 0 : (options.bidsOf?.[i] ?? Math.max(counted[i], 1))
    for (let version = 1; version <= bids; version++) made[i].push(await bid(fixture, actor, 1 + 3 * i + version, e3Id))
  }
  const versions = Array.from({ length: 13 }, (_, i) => counted[i] ?? 0)
  const countedSteps = steps.filter((_, i) => counted[i] > 0) as number[]
  const plain = plainOutcome({ ...sale, levels: params.levels }, countedSteps)
  if (!options.noOutput) {
    const slots =
      options.slots ??
      outputSlotsFor(params, versions, plain.outcome as Outcome.NotMet | Outcome.Undersubscribed | Outcome.SoldOut, plain.step ?? undefined)
    await (await fixture.interfold.setPlaintext(e3Id, plaintextOf(slots))).wait()
  }
  return { e3Id, sale, params, steps, counted, made, outcome: plain.outcome, step: plain.step }
}

/** The `data` of a claim of the bidder `i` of a played round, from its true step. */
export async function claimData(fixture: Fixture, played: Played, i: number): Promise<Hex> {
  const { program } = fixture
  const actor = fixture.actors[i]
  const [needed, k] = await program.claimRequirement(played.e3Id, actor.address)
  if (!needed) return '0x'

  return encodeClaimData(compareBid(played.steps[i] as number, Number(k)), '0x01')
}

/** Mines a block with the timestamp `at`, or the next second if the chain is already past it. */
export async function mineAt(fixture: Fixture, at: bigint) {
  const latest = BigInt((await fixture.ethers.provider.getBlock('latest'))!.timestamp)
  await fixture.ethers.provider.send('evm_setNextBlockTimestamp', [Number(at > latest ? at : latest + 1n)])
  await fixture.ethers.provider.send('evm_mine', [])
}

/** The timestamp of the block of a receipt. */
export async function timeOf(fixture: Fixture, blockNumber: number): Promise<bigint> {
  return BigInt((await fixture.ethers.provider.getBlock(blockNumber))!.timestamp)
}
