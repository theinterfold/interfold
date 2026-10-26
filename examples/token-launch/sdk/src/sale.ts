// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoders of `TokenLaunchProgram` (`contracts/interfaces/ITokenLaunch.sol` is the source of the
 * layouts): the `customParams` of the two requests of a sale, the `data` of a bid and of a claim, and the
 * EIP-712 message of a relayed bid.
 */
import { type Address, type Hex, type AbiParameter, encodeAbiParameters, keccak256, parseAbiParameters } from 'viem'
import { LEVELS_MAX, MAX_BUDGET_UNITS, MAX_TIERS, MIN_LEVELS } from './layout'

/** The largest supply, budget unit and price: `SaleConfig.MAX_AMOUNT`. It keeps every product of the clearing below 2^256. */
export const MAX_AMOUNT = 2n ** 112n
/** The longest title in bytes: `SaleConfig.MAX_TITLE_BYTES`. */
export const MAX_TITLE_BYTES = 80

// ---------------------------------------------------------------------------------------------
// Price grid and tiers
// ---------------------------------------------------------------------------------------------

/**
 * The prices of the steps: `MIN_LEVELS` to `LEVELS_MAX` strictly increasing positive whole numbers. Step `b`
 * costs `prices[b]` payment-token base units per `10^saleDecimals` sale-token base units. The creator picks
 * the length, `levels`; the bid circuit rejects a bid with `b >= levels`.
 */
export type PriceList = readonly bigint[]

/** Why `prices` is not a valid price list, or `null` when it is one. The contract applies the same rules. */
export function priceListError(prices: PriceList): string | null {
  if (prices.length < MIN_LEVELS || prices.length > LEVELS_MAX) {
    return `A price list has ${MIN_LEVELS} to ${LEVELS_MAX} prices, got ${prices.length}`
  }
  if (prices.some((price) => price <= 0n || price > MAX_AMOUNT)) return 'A price is a whole number from 1 to 2^112'
  const flat = prices.findIndex((price, level) => level > 0 && price <= prices[level - 1])
  if (flat > 0) return `Prices must increase: step ${flat} (${prices[flat]}) is not above step ${flat - 1} (${prices[flat - 1]})`
  return null
}

/** Evenly spaced prices: step `b` costs `start + b * step`, for `count` steps. */
export function evenPrices(start: bigint, step: bigint, count: number): bigint[] {
  return Array.from({ length: count }, (_, level) => start + BigInt(level) * step)
}

/**
 * `count` prices that rise linearly from `floor` (step 0) to `cap` (the last step), rounded down. The
 * result is a valid price list only if the rounded values increase strictly; check it with `priceListError`.
 */
export function linearPrices(floor: bigint, cap: bigint, count: number): bigint[] {
  if (!Number.isInteger(count) || count < MIN_LEVELS) throw new Error(`A price list has at least ${MIN_LEVELS} prices, got ${count}`)
  const span = BigInt(count - 1)
  return Array.from({ length: count }, (_, level) => floor + ((cap - floor) * BigInt(level)) / span)
}

/**
 * The price list of a sale from the contract's `levels` and its zero-padded `uint256[16]` prices
 * (the getter value and the event `prices`): the first `levels` prices.
 */
export function readPriceList(levels: number | bigint, prices: readonly bigint[]): bigint[] {
  const count = Number(levels)
  if (!Number.isInteger(count) || count < MIN_LEVELS || count > LEVELS_MAX) {
    throw new Error(`levels must be an integer in [${MIN_LEVELS}, ${LEVELS_MAX}], got ${levels}`)
  }
  return prices.slice(0, count)
}

/** The escrow tiers in budget units: 1 to `MAX_TIERS` strictly increasing whole numbers up to `MAX_BUDGET_UNITS`. */
export type TierList = readonly number[]

/** Why `tiers` is not a valid tier list, or `null` when it is one. */
export function tierListError(tiers: TierList): string | null {
  if (tiers.length < 1 || tiers.length > MAX_TIERS) return `A tier list has 1 to ${MAX_TIERS} tiers, got ${tiers.length}`
  if (tiers.some((tier) => !Number.isInteger(tier) || tier < 1 || tier > MAX_BUDGET_UNITS)) {
    return `A tier is a whole number of budget units from 1 to ${MAX_BUDGET_UNITS}`
  }
  const flat = tiers.findIndex((tier, i) => i > 0 && tier <= tiers[i - 1])
  if (flat > 0) return `Tiers must increase: tier ${flat} (${tiers[flat]}) is not above tier ${flat - 1} (${tiers[flat - 1]})`
  return null
}

/** The contract's `saleTiers` value (`uint16[4]`, zero-padded) as a tier list. */
export function readTierList(tiers: readonly (number | bigint)[]): number[] {
  return tiers.map(Number).filter((tier) => tier !== 0)
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

/** The sale a creator opens with the request of round 1. */
export interface SaleParams {
  prices: PriceList
  saleToken: Address
  /** The supply `S` in sale-token base units. */
  supply: bigint
  paymentToken: Address
  /** The value of one budget unit in payment-token base units. A bid has a budget of 1 to `X` units. */
  budgetUnit: bigint
  /** The escrow tiers in budget units. A bid escrows one tier: its budget is at most that tier. */
  tiers: TierList
  title: string
}

const customParamsAbi: readonly AbiParameter[] = parseAbiParameters('uint8, bytes')

/**
 * The `customParams` of the request of round 1: `abi.encode(uint8 1, bytes body)`,
 * `body = abi.encode(uint8 levels, uint256[16] prices, address saleToken, uint256 supply, address
 * paymentToken, uint256 budgetUnit, uint16[4] tiers, string title)`. `levels` is `prices.length`; the
 * unused prices and tiers are zero-padded, as the contract wants them.
 */
export function encodeSaleParams(params: SaleParams): Hex {
  const priceError = priceListError(params.prices)
  if (priceError) throw new Error(priceError)
  const tierError = tierListError(params.tiers)
  if (tierError) throw new Error(tierError)
  if (params.supply <= 0n || params.supply > MAX_AMOUNT) throw new Error('The supply is a whole number from 1 to 2^112')
  if (params.budgetUnit <= 0n || params.budgetUnit > MAX_AMOUNT) throw new Error('The budget unit is a whole number from 1 to 2^112')
  const titleBytes = new TextEncoder().encode(params.title).length
  if (titleBytes === 0 || titleBytes > MAX_TITLE_BYTES) throw new Error(`The title has 1 to ${MAX_TITLE_BYTES} bytes`)
  const prices = [...params.prices, ...Array.from({ length: LEVELS_MAX - params.prices.length }, () => 0n)]
  const tiers = [...params.tiers, ...Array.from({ length: MAX_TIERS - params.tiers.length }, () => 0)]
  const bodyAbi: readonly AbiParameter[] = parseAbiParameters('uint8, uint256[16], address, uint256, address, uint256, uint16[4], string')
  const body = encodeAbiParameters(bodyAbi, [
    params.prices.length,
    prices,
    params.saleToken,
    params.supply,
    params.paymentToken,
    params.budgetUnit,
    tiers,
    params.title,
  ])
  return encodeAbiParameters(customParamsAbi, [1, body])
}

/**
 * The `customParams` of the request of round 2: `abi.encode(uint8 2, abi.encode(uint256 saleId))`. The two
 * requests must share the requester, the input window and the committee size.
 */
export function encodeLinkParams(saleId: bigint): Hex {
  return encodeAbiParameters(customParamsAbi, [2, encodeAbiParameters(parseAbiParameters('uint256'), [saleId])])
}

// ---------------------------------------------------------------------------------------------
// Bids and claims
// ---------------------------------------------------------------------------------------------

/** What a bid publishes: the fields of `ITokenLaunch.BidInput`. */
export interface BidInput {
  bidder: Address
  /** The index of the escrow tier in `saleTiers`. */
  tier: number
  /** The ciphertext under the key of round 1 and its SAFE commitment (`bytes32`). */
  ciphertext1: Hex
  ciphertext2: Hex
  ctCommitment1: Hex
  ctCommitment2: Hex
  /** The commitment of the bid (`bytes32`): the leaf of the claim tree. */
  bidCommitment: Hex
  /** The pair bid proof. */
  proof: Hex
  /** The bidder's EIP-712 signature (`bidTypedData`) for a relayed bid; `0x` for a direct bid. */
  signature?: Hex
  /** The EIP-2612 permit of the escrow, used for a relayed bid. Omitted: no permit (the allowance must exist). */
  permit?: { deadline: bigint; v: number; r: Hex; s: Hex }
}

const zeroWord: Hex = `0x${'00'.repeat(32)}`

/** The `data` of `publishInput`: `abi.encode(ITokenLaunch.BidInput)`. */
export function encodeBidInput(input: BidInput): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters(
    '(address bidder, uint8 tier, bytes ciphertext1, bytes ciphertext2, bytes32 ctCommitment1, bytes32 ctCommitment2, bytes32 bidCommitment, bytes proof, bytes signature, uint256 permitDeadline, uint8 v, bytes32 r, bytes32 s)',
  )
  const permit = input.permit ?? { deadline: 0n, v: 0, r: zeroWord, s: zeroWord }
  return encodeAbiParameters(abi, [
    {
      bidder: input.bidder,
      tier: input.tier,
      ciphertext1: input.ciphertext1,
      ciphertext2: input.ciphertext2,
      ctCommitment1: input.ctCommitment1,
      ctCommitment2: input.ctCommitment2,
      bidCommitment: input.bidCommitment,
      proof: input.proof,
      signature: input.signature ?? '0x',
      permitDeadline: permit.deadline,
      v: permit.v,
      r: permit.r,
      s: permit.s,
    },
  ])
}

/**
 * `keccak256(abi.encode(ctCommitment1, ctCommitment2, bidCommitment, keccak256(ciphertext1), keccak256(ciphertext2)))`.
 * A relayed bid signs it, so a relayer cannot swap the bytes or the commitments.
 */
export function bidInputsHash(ctCommitment1: Hex, ctCommitment2: Hex, bidCommitment: Hex, ciphertext1: Hex, ciphertext2: Hex): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('bytes32, bytes32, bytes32, bytes32, bytes32')
  return keccak256(encodeAbiParameters(abi, [ctCommitment1, ctCommitment2, bidCommitment, keccak256(ciphertext1), keccak256(ciphertext2)]))
}

/** The EIP-712 message the bidder signs to let a relayer send a bid (`TokenLaunchProgram.bidDigest`). */
export function bidTypedData(chainId: number, program: Address, saleId: bigint, bidder: Address, tier: number, inputsHash: Hex) {
  return {
    domain: { name: 'TokenLaunchProgram', version: '1', chainId, verifyingContract: program },
    types: {
      Bid: [
        { name: 'saleId', type: 'uint256' },
        { name: 'bidder', type: 'address' },
        { name: 'tier', type: 'uint8' },
        { name: 'inputsHash', type: 'bytes32' },
      ],
    },
    primaryType: 'Bid',
    message: { saleId, bidder, tier, inputsHash },
  } as const
}

/** What a claim publishes: the fields of `ITokenLaunch.ClaimData`. */
export interface ClaimData {
  proof: Hex
  nullifier: Hex
  /** The fresh address that gets the tokens and the refund. */
  recipient: Address
  escrowUnits: number
  budgetUnits: number
  cmp: 0 | 1 | 2
  /** 0, except for a marginal claim inside the marginal window of a capped sale: the bid index + 1 (the proof publishes it). */
  indexPlusOne: number
}

/** The `data` of `claim`: `abi.encode(ITokenLaunch.ClaimData)`. */
export function encodeClaimData(data: ClaimData): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters(
    '(bytes proof, bytes32 nullifier, address recipient, uint16 escrowUnits, uint16 budgetUnits, uint8 cmp, uint8 indexPlusOne)',
  )
  return encodeAbiParameters(abi, [data])
}
