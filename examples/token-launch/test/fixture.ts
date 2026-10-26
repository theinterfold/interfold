// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { HardhatEthers, HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/types'
import type { ContractTransactionResponse } from 'ethers'
import hre from 'hardhat'
import { type AbiParameter, type Hex, encodeAbiParameters, parseAbiParameters, toHex } from 'viem'
import { deployProgramLibraries } from '../deploy/libraries'
import { TokenLaunchProgram__factory } from '../types/factories/contracts'
import type { ITokenLaunch } from '../types/contracts/interfaces'
import type { MockBidVerifier, MockInterfold, MockPaymentToken, MockSaleToken } from '../types/contracts/mocks'
import type { TokenLaunchProgram } from '../types/contracts'
import { ITokenLaunch__factory } from '../types/factories/contracts/interfaces'
import {
  MockBidVerifier__factory,
  MockInterfold__factory,
  MockPaymentToken__factory,
  MockSaleToken__factory,
} from '../types/factories/contracts/mocks'
import { FLAG_BASE, FLAG_CELLS, bidSlots, coefficientsToPlaintext, keepMask, slotsToCoefficients } from '../sdk/src/layout'
import { type Clearing, compareStep } from '../sdk/src/clearing'
import { type Grid, coarseProbeMask } from '../sdk/src/probes'
import {
  type BidInput,
  bidInputsHash,
  bidTypedData,
  encodeBidInput,
  encodeClaimData,
  encodeLinkParams,
  encodeSaleParams,
  linearPrices,
} from '../sdk/src/sale'

export const KEY1 = `0x${'ab'.repeat(32)}` as Hex
export const KEY2 = `0x${'ac'.repeat(32)}` as Hex
export const VK_ANCHOR = `0x${'cd'.repeat(32)}` as Hex
export const U18 = 10n ** 18n
export const USDC = 1_000_000n
/** 1 USDC per budget unit; the escrow tiers are 10, 100 and 1000 USDC. */
export const TIERS = [10, 100, 1000]
export const FAR = 2n ** 40n
export const KIND_UNDERSUBSCRIBED = 0
export const KIND_CAPPED = 1
export const KIND_UNCAPPED = 2
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** The chain clock of the network helpers. */
export interface Clock {
  increase(seconds: number): Promise<unknown>
  latest(): Promise<number>
}

/** What a test needs: the contracts, the actors and the chain helpers. */
export interface Fixture {
  ethers: HardhatEthers
  time: Clock
  creator: HardhatEthersSigner
  relayer: HardhatEthersSigner
  /** Signers for direct bids and other callers. */
  actors: HardhatEthersSigner[]
  program: TokenLaunchProgram
  programAddress: Hex
  /** The program at its address with the ABI of `ITokenLaunch`: it knows the errors that the libraries raise. */
  errors: ITokenLaunch
  interfold: MockInterfold
  saleToken: MockSaleToken
  usdc: MockPaymentToken
  bidVerifier: MockBidVerifier
  claimVerifier: MockBidVerifier
  chainId: number
  /** Counter for unique commitments and nullifiers. */
  counter: { value: bigint }
}

/** Deploys the program with mock verifiers and a mock Interfold, and no sale. */
export async function deployFixture(): Promise<Fixture> {
  const { ethers, networkHelpers } = await hre.network.connect()
  const [creator, relayer, ...actors] = await ethers.getSigners()
  const interfold = MockInterfold__factory.connect(await (await ethers.deployContract('MockInterfold')).getAddress(), creator)
  const receiptVerifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
  const availability = await ethers.deployContract('MockDataAvailabilityVerifier')
  const bidVerifier = MockBidVerifier__factory.connect(await (await ethers.deployContract('MockBidVerifier')).getAddress(), creator)
  const claimVerifier = MockBidVerifier__factory.connect(await (await ethers.deployContract('MockBidVerifier')).getAddress(), creator)
  const poseidon = await ethers.deployContract('PoseidonT3')
  const links = await deployProgramLibraries(ethers, await poseidon.getAddress())
  const factory = await ethers.getContractFactory(TokenLaunchProgram__factory.abi, TokenLaunchProgram__factory.linkBytecode(links), creator)
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
    time: networkHelpers.time,
    creator,
    relayer,
    actors,
    program: TokenLaunchProgram__factory.connect(programAddress, creator),
    programAddress,
    errors: ITokenLaunch__factory.connect(programAddress, creator),
    interfold,
    saleToken,
    usdc,
    bidVerifier,
    claimVerifier,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    counter: { value: 1n },
  }
}

/** A sale as the tests track it: ids, the price grid, the tiers, and the bids placed so far. */
export interface TestSale {
  saleId: bigint
  round2Id: bigint
  grid: Grid
  tiers: number[]
  bids: TestBid[]
}

export interface TestBid {
  index: number
  bidder: string
  step: number
  budget: number
  /** The escrow of the tier, in budget units. */
  escrow: number
  tier: number
  bidCommitment: Hex
}

export interface SaleOptions {
  saleId?: bigint
  prices?: bigint[]
  supply?: bigint
  budgetUnit?: bigint
  tiers?: number[]
  title?: string
  inputDeadline?: bigint
  /** Do not request round 2. */
  noRoundTwo?: boolean
  noApproval?: boolean
}

export const DEFAULT_PRICES = linearPrices(1n * USDC, 8n * USDC, 8)

/** The `customParams` of the round-1 request of a sale of the fixture's tokens. */
export async function saleRequest(f: Fixture, options: SaleOptions = {}): Promise<Hex> {
  return encodeSaleParams({
    prices: options.prices ?? DEFAULT_PRICES,
    saleToken: (await f.saleToken.getAddress()) as Hex,
    supply: options.supply ?? 100n * U18,
    paymentToken: (await f.usdc.getAddress()) as Hex,
    budgetUnit: options.budgetUnit ?? USDC,
    tiers: options.tiers ?? TIERS,
    title: options.title ?? 'Demo sale',
  })
}

/** The role-1 body of a request with chosen raw fields: no SDK check, so a test can send what the contract must refuse. */
export interface RawSale {
  levels: number
  prices: bigint[]
  saleToken: Hex
  supply: bigint
  paymentToken: Hex
  budgetUnit: bigint
  tiers: number[]
  title: string
}

export async function rawSaleRequest(f: Fixture, override: Partial<RawSale> = {}): Promise<Hex> {
  const fields: RawSale = {
    levels: 8,
    prices: [...DEFAULT_PRICES, ...Array(8).fill(0n)],
    saleToken: (await f.saleToken.getAddress()) as Hex,
    supply: 100n * U18,
    paymentToken: (await f.usdc.getAddress()) as Hex,
    budgetUnit: USDC,
    tiers: [...TIERS, 0],
    title: 'Demo sale',
    ...override,
  }
  // Untyped parameters: `RawSale` may hold more or fewer than 16 prices, and the contract must refuse them.
  const abi: readonly AbiParameter[] = parseAbiParameters('uint8, uint256[16], address, uint256, address, uint256, uint16[4], string')
  const body = encodeAbiParameters(abi, [
    fields.levels,
    fields.prices,
    fields.saleToken,
    fields.supply,
    fields.paymentToken,
    fields.budgetUnit,
    fields.tiers,
    fields.title,
  ])
  return encodeAbiParameters(parseAbiParameters('uint8, bytes'), [1, body])
}

/** The creator gets the supply and approves it; Interfold requests round 1 and round 2: `validate` runs twice. */
export async function createSale(f: Fixture, options: SaleOptions = {}): Promise<TestSale> {
  const saleId = options.saleId ?? 7n
  const round2Id = saleId + 1n
  const supply = options.supply ?? 100n * U18
  const deadline = options.inputDeadline ?? FAR
  await (await f.saleToken.mint(f.creator.address, supply)).wait()
  if (!options.noApproval) await (await f.saleToken.approve(f.programAddress, supply)).wait()
  for (const [e3Id, key] of [
    [saleId, KEY1],
    [round2Id, KEY2],
  ] as const) {
    await (await f.interfold.setE3(e3Id, deadline, key, f.creator.address)).wait()
  }
  await (await f.interfold.request(saleId, f.programAddress, await saleRequest(f, options))).wait()
  if (!options.noRoundTwo) await (await f.interfold.request(round2Id, f.programAddress, encodeLinkParams(saleId))).wait()
  const prices = options.prices ?? DEFAULT_PRICES
  return {
    saleId,
    round2Id,
    grid: { prices, supply, budgetUnit: options.budgetUnit ?? USDC, saleDecimals: 18 },
    tiers: options.tiers ?? TIERS,
    bids: [],
  }
}

export interface BidSpec {
  step: number
  budget: number
  /** The tier index. Default: the smallest tier that covers the budget. */
  tier?: number
  /** Send the bid from this actor (a direct bid: needs no signature). Default: a fresh wallet, relayed with a permit. */
  direct?: HardhatEthersSigner
}

/** Unique 32-byte values below the field modulus. */
export function nextWord(f: Fixture): Hex {
  f.counter.value += 1n
  return toHex((f.counter.value * 7919n) % R, { size: 32 })
}

async function signPermit(f: Fixture, owner: Signer, value: bigint) {
  const nonce = await f.usdc.nonces(owner.address)
  const deadline = FAR
  const signature = await owner.signTypedData(
    { name: 'Mock USDC', version: '1', chainId: f.chainId, verifyingContract: await f.usdc.getAddress() },
    {
      Permit: [
        { name: 'owner', type: 'address' },
        { name: 'spender', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    { owner: owner.address, spender: f.programAddress, value, nonce, deadline },
  )
  const { v, r, s } = f.ethers.Signature.from(signature)
  return { deadline, v, r: r as Hex, s: s as Hex }
}

/** A relayed bid: signed by the bidder, with the permit of the escrow. */
export type SignedBid = BidInput & { signature: Hex; permit: NonNullable<BidInput['permit']> }

type Signer = { address: string; signTypedData: HardhatEthersSigner['signTypedData'] }

/** The `BidInput` of a bid for `bidder`; `sign` makes it a relayed bid with a permit. */
export async function bidData<Signed extends boolean>(
  f: Fixture,
  sale: TestSale,
  bidder: Signer,
  tier: number,
  sign: Signed,
): Promise<Signed extends true ? SignedBid : BidInput> {
  const input: BidInput = {
    bidder: bidder.address as Hex,
    tier,
    ciphertext1: `0x${(0x10 + tier).toString(16)}${'11'.repeat(15)}` as Hex,
    ciphertext2: `0x${(0x20 + tier).toString(16)}${'22'.repeat(15)}` as Hex,
    ctCommitment1: nextWord(f),
    ctCommitment2: nextWord(f),
    bidCommitment: nextWord(f),
    proof: '0x01',
  }
  if (!sign) return input as Signed extends true ? SignedBid : BidInput
  const escrow = BigInt(sale.tiers[tier]) * sale.grid.budgetUnit
  const typed = bidTypedData(
    f.chainId,
    f.programAddress,
    sale.saleId,
    input.bidder,
    tier,
    bidInputsHash(input.ctCommitment1, input.ctCommitment2, input.bidCommitment, input.ciphertext1, input.ciphertext2),
  )
  const signature = (await bidder.signTypedData({ ...typed.domain }, { Bid: [...typed.types.Bid] }, { ...typed.message })) as Hex
  return { ...input, signature, permit: await signPermit(f, bidder, escrow) } as Signed extends true ? SignedBid : BidInput
}

/** Places one bid and records it in `sale.bids`. */
export async function placeBid(f: Fixture, sale: TestSale, spec: BidSpec) {
  const tier = spec.tier ?? sale.tiers.findIndex((units) => units >= spec.budget)
  const escrow = BigInt(sale.tiers[tier]) * sale.grid.budgetUnit
  const bidder = spec.direct ?? f.ethers.Wallet.createRandom()
  await (await f.usdc.mint(bidder.address, escrow)).wait()
  let tx: Promise<ContractTransactionResponse>
  if (spec.direct) {
    await (await f.usdc.connect(spec.direct).approve(f.programAddress, escrow)).wait()
    const data = encodeBidInput(await bidData(f, sale, spec.direct, tier, false))
    tx = f.program.connect(spec.direct).publishInput(sale.saleId, data)
  } else {
    const input = await bidData(f, sale, bidder, tier, true)
    tx = f.program.connect(f.relayer).publishInput(sale.saleId, encodeBidInput(input))
  }
  const receipt = await (await tx).wait()
  const bid: TestBid = {
    index: sale.bids.length,
    bidder: bidder.address,
    step: spec.step,
    budget: spec.budget,
    escrow: sale.tiers[tier],
    tier,
    bidCommitment: (await f.program.bidInfo(sale.saleId, sale.bids.length))[2] as Hex,
  }
  sale.bids.push(bid)
  return { bid, receipt }
}

/** Places many bids with the specs; returns the bids. */
export async function placeBids(f: Fixture, sale: TestSale, specs: BidSpec[]): Promise<TestBid[]> {
  const bids: TestBid[] = []
  for (const spec of specs) bids.push((await placeBid(f, sale, spec)).bid)
  return bids
}

/** The plaintext that the committee decrypts: the sum of the bid slots, kept at the levels of `mask`. */
export function outputPlaintext(bids: readonly { step: number; budget: number; index: number }[], mask: number): Hex {
  const slots = new Array<number>(128).fill(0)
  for (const bid of bids) {
    const bidder = bidSlots(bid)
    for (let j = 0; j < 128; j++) slots[j] = (slots[j] + Number(bidder[j])) % 257
  }
  const keep = keepMask(mask)
  return coefficientsToPlaintext(slotsToCoefficients(slots.map((slot, j) => (slot * Number(keep[j])) % 257)))
}

/** The input window of both E3s ends. */
export async function closeInputs(f: Fixture, sale: TestSale) {
  const now = BigInt(await f.time.latest())
  await (await f.interfold.setInputDeadline(sale.saleId, now)).wait()
  await (await f.interfold.setInputDeadline(sale.round2Id, now)).wait()
  await f.time.increase(1)
}

/** Round 1 decrypts to the sums at the coarse levels over `counted` (default: all bids). */
export async function decryptRound1(f: Fixture, sale: TestSale, counted: readonly TestBid[] = sale.bids) {
  const plaintext = outputPlaintext(counted, coarseProbeMask(sale.grid.prices.length))
  await (await f.interfold.setPlaintext(sale.saleId, plaintext)).wait()
}

/** Round 2 decrypts to the sums at the levels that `publishProbes` fixed. */
export async function decryptRound2(f: Fixture, sale: TestSale, counted: readonly TestBid[] = sale.bids) {
  const { probeMask2 } = await f.program.probeInfo(sale.saleId)
  await (await f.interfold.setPlaintext(sale.round2Id, outputPlaintext(counted, Number(probeMask2)))).wait()
}

/** Closes the inputs, decrypts round 1, publishes the probes. */
export async function publishProbes(f: Fixture, sale: TestSale) {
  await closeInputs(f, sale)
  await decryptRound1(f, sale)
  return (await f.program.publishProbes(sale.saleId)).wait()
}

/** The whole path to a cleared sale. */
export async function clearSale(f: Fixture, sale: TestSale) {
  await publishProbes(f, sale)
  await decryptRound2(f, sale)
  return (await f.program.clear(sale.saleId)).wait()
}

export interface ClaimSpec {
  bid: TestBid
  /** Default: a fresh address. */
  recipient?: string
  nullifier?: Hex
  cmp?: 0 | 1 | 2
  budgetUnits?: number
  escrowUnits?: number
  indexPlusOne?: number
}

/** The honest claim of `bid` against the clearing (what the circuit would prove). */
export async function claimData(f: Fixture, sale: TestSale, spec: ClaimSpec) {
  const info = await f.program.clearing(sale.saleId)
  const cmp = spec.cmp ?? compareStep(spec.bid.step, Number(info.step))
  const reveal = Number(info.kind) === KIND_CAPPED && BigInt(await f.time.latest()) + 1n <= info.marginalDeadline
  return {
    proof: '0x01' as Hex,
    nullifier: spec.nullifier ?? nextWord(f),
    recipient: (spec.recipient ?? f.ethers.Wallet.createRandom().address) as Hex,
    escrowUnits: spec.escrowUnits ?? spec.bid.escrow,
    budgetUnits: spec.budgetUnits ?? (cmp === 0 ? 0 : spec.bid.budget),
    cmp,
    indexPlusOne: spec.indexPlusOne ?? (reveal && cmp === 1 ? spec.bid.index + 1 : 0),
  }
}

export async function claim(f: Fixture, sale: TestSale, spec: ClaimSpec, sender: HardhatEthersSigner = f.relayer) {
  const data = await claimData(f, sale, spec)
  return { data, tx: f.program.connect(sender).claim(sale.saleId, encodeClaimData(data)) }
}

/** The on-chain clearing as the TS mirror's `Clearing`. */
export async function readClearing(f: Fixture, sale: TestSale): Promise<Clearing> {
  const info = await f.program.clearing(sale.saleId)
  return { kind: Number(info.kind), step: Number(info.step), pStar: info.pStar, sold: info.sold, remaining: info.remaining }
}

export { FLAG_BASE, FLAG_CELLS }
