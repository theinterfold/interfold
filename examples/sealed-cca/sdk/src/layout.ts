// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoding the bidders, the bid circuit (`sealed_cca_bid`), the FHE program (`program/src/lib.rs`),
 * the program contract (`SlotCodec.sol`) and the result decoder share.
 *
 * All ciphertexts are SIMD-encoded over the 128 slots of the ring. A bid is ONE ciphertext. Its slots
 * hold the thermometer of the bid `b` (the index of the highest price step the bidder accepts) and the
 * bid version `v` in the slot of the bidder index `i`:
 *
 *   slot l  (l in 0..LEVELS)      1 if l <= b, else 0
 *   slot LEVELS + i               v, the version of this bid (1 to 3)
 *   every other slot              0
 *
 * The contract assigns `i` at the deposit of the bidder, and the bid proof binds `i` and `v`. The program
 * adds the selected ciphertexts (the latest version of each bidder that opens its commitment). After
 * the threshold decryption the slots are:
 *
 *   slot l  (l in 0..LEVELS)      c_l = the number of counted bidders with b >= l
 *   slot LEVELS + i               the counted version of the bidder i, or 0 if the bidder was dropped
 *
 * The committee publishes the plaintext as 128 polynomial coefficients; `decodeOutput` applies the
 * SIMD decode and reads the slots.
 *
 * The prices: step `l` costs `prices[l]` payment-token base units for `10^saleDecimals` sale-token
 * base units (one whole sale token).
 */
import {
  type AbiParameter,
  type Address,
  encodeAbiParameters,
  type Hex,
  keccak256,
  maxUint256,
  parseAbiParameters,
  toHex,
  zeroAddress,
} from 'viem'
import { decodePlaintextSlots } from '@interfold/sdk'

/** Polynomial degree, and so the slot count, of the insecure SIMD preset (param set 5). */
export const DEGREE = 128
/** Plaintext modulus of the same preset: prime, 1 mod 2 * DEGREE, so it supports SIMD. */
export const PLAINTEXT_MODULUS = 257
/** The preset name the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const
/** The most price steps of a sale, and the number of count slots. A bid is in `[0, LEVELS)`. */
export const LEVELS = 16
/** The fewest price steps of a sale. */
export const MIN_LEVELS = 2
/** The most bidders of a sale: the slots after the count slots. */
export const MAX_BIDDERS = DEGREE - LEVELS
/** The most bids of one bidder: the first bid and two updates. */
export const MAX_BIDS_PER_BIDDER = 3
/** Coefficients the committee publishes after decryption for this preset. */
export const OUTPUT_COEFFS = DEGREE

/** What a sale reveals. The values are the `uint8` the contract uses. */
export enum RevealMode {
  /** The decrypted output holds the demand at each price step and the counted version of each bidder. */
  DemandCurve = 0,
  /** Research: only the clearing is revealed. The contract rejects it (`RevealModeUnsupported`). */
  ClearingOnly = 1,
}

/** The slot of the bidder `bidderIndex`. */
export function bidderSlot(bidderIndex: number): number {
  assertBidderIndex(bidderIndex)
  return LEVELS + bidderIndex
}

export function assertBid(level: number): void {
  if (!Number.isInteger(level) || level < 0 || level >= LEVELS) {
    throw new Error(`A bid is a price step in [0, ${LEVELS}), got ${level}`)
  }
}

export function assertBidderIndex(bidderIndex: number): void {
  if (!Number.isInteger(bidderIndex) || bidderIndex < 0 || bidderIndex >= MAX_BIDDERS) {
    throw new Error(`A bidder index is in [0, ${MAX_BIDDERS}), got ${bidderIndex}`)
  }
}

export function assertVersion(version: number): void {
  if (!Number.isInteger(version) || version < 1 || version > MAX_BIDS_PER_BIDDER) {
    throw new Error(`A bid version is in [1, ${MAX_BIDS_PER_BIDDER}], got ${version}`)
  }
}

/** The SIMD slot values of the bid ciphertext: the thermometer of `level`, and `version` in the slot of `bidderIndex`. */
export function bidSlots(level: number, bidderIndex: number, version: number): BigUint64Array {
  assertBid(level)
  assertVersion(version)
  const slots = new BigUint64Array(DEGREE)
  for (let l = 0; l <= level; l++) slots[l] = 1n
  slots[bidderSlot(bidderIndex)] = BigInt(version)
  return slots
}

/** What the decrypted output holds. */
export interface SaleOutput {
  /** `counts[l]` is the number of counted bidders with a bid of at least `l`. */
  counts: bigint[]
  /** `counted[i]` is the counted version (1 to 3) of the bidder `i`, or 0 if the bidder was dropped or never bid. */
  counted: number[]
}

/** Reads the output slots: `counts` from the slots `0..LEVELS` and `counted` from the others. */
export function readOutputSlots(slots: readonly bigint[]): SaleOutput {
  if (slots.length !== DEGREE) throw new Error(`The output has ${DEGREE} slots, got ${slots.length}`)
  const counted = slots.slice(LEVELS).map((slot) => {
    if (slot > BigInt(MAX_BIDS_PER_BIDDER)) throw new Error(`A counted version is at most ${MAX_BIDS_PER_BIDDER}, got ${slot}`)
    return Number(slot)
  })
  return { counts: slots.slice(0, LEVELS), counted }
}

/** The inverse of `readOutputSlots`. */
export function outputSlots({ counts, counted }: SaleOutput): bigint[] {
  if (counts.length !== LEVELS || counted.length !== MAX_BIDDERS) throw new Error('The output has 16 counts and 112 counted versions')
  return [...counts, ...counted.map(BigInt)]
}

/**
 * The output the program must produce for the selected bids: the slot-wise sum of their plaintexts,
 * mod `t`. `bids` are the selected ones (one per counted bidder). The tests of the program and the
 * contract use it.
 */
export function expectedOutput(bids: readonly { level: number; bidderIndex: number; version: number }[]): SaleOutput {
  const sum = new Array<bigint>(DEGREE).fill(0n)
  for (const { level, bidderIndex, version } of bids) {
    bidSlots(level, bidderIndex, version).forEach((slot, i) => {
      sum[i] = (sum[i] + slot) % BigInt(PLAINTEXT_MODULUS)
    })
  }
  return readOutputSlots(sum)
}

/**
 * Decodes the plaintext output the committee published (hex of 128 u64-LE polynomial coefficients)
 * into the counts and the counted versions.
 */
export async function decodeOutput(plaintextOutput: string): Promise<SaleOutput> {
  const hex = plaintextOutput.startsWith('0x') ? plaintextOutput.slice(2) : plaintextOutput
  return readOutputSlots(await decodePlaintextSlots(`0x${hex}`, PRESET))
}

/** The BN254 scalar field `r`: the modulus of a Noir `Field` and of a Honk public input. */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/**
 * An E3 id as a field element: `e3Id mod r`. An E3 id has 256 bits and is above `r` with a probability of about 81%,
 * so the circuits and the commitment take it reduced, as `SealedCcaProgram` passes it to the verifiers. The contract
 * storage, the events and the EIP-712 `Bid` keep the full `e3Id`.
 */
export const e3Field = (e3Id: bigint): bigint => e3Id % BN254_R

/** A random value below the BN254 field, for the salt of a bid commitment: 31 random bytes as `0x` hex of 32 bytes. */
export function bidSalt(): Hex {
  const bytes = new Uint8Array(31)
  crypto.getRandomValues(bytes)
  // `toHex` with a size would pad on the right; the value must stay below 2^248.
  return `0x00${toHex(bytes).slice(2)}`
}

/**
 * The prices of the steps: 2 to `LEVELS` strictly increasing positive whole numbers. Step `b` costs
 * `prices[b]` payment-token base units per `10^saleDecimals` sale-token base units. The creator picks
 * the length, `levels`; the bid circuit rejects a bid `b >= levels`.
 */
export type PriceList = readonly bigint[]

/** Why `prices` is not a valid price list, or `null` when it is one. The contract applies the same rules to `uint256` values. */
export function priceListError(prices: PriceList): string | null {
  if (prices.length < MIN_LEVELS || prices.length > LEVELS) {
    return `A price list has ${MIN_LEVELS} to ${LEVELS} prices, got ${prices.length}`
  }
  if (prices.some((price) => price <= 0n || price > maxUint256)) return 'A price is a whole number from 1 to 2^256 - 1'
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
  if (!Number.isInteger(count) || count < MIN_LEVELS || count > LEVELS) {
    throw new Error(`levels must be an integer in [${MIN_LEVELS}, ${LEVELS}], got ${levels}`)
  }
  return prices.slice(0, count)
}

/** The sale a creator opens. */
export interface SaleParams {
  revealMode?: RevealMode
  prices: PriceList
  saleToken: Address
  /** The supply `S` in sale-token base units. */
  supply: bigint
  paymentToken: Address
  /** The escrow `E` of every bid in payment-token base units. */
  escrow: bigint
  title: string
  gate?: Address
  gateConfig?: Hex
}

/**
 * The request's `customParams`: `abi.encode(uint8 revealMode, uint8 levels, uint256[16] prices,
 * address saleToken, uint256 supply, address paymentToken, uint256 escrow, string title, address gate,
 * bytes gateConfig)`. `levels` is `prices.length`; the contract wants the unused prices to be zero, so
 * they are padded. With the zero `gate` anyone may bid, and `gateConfig` must be empty.
 */
export function encodeSaleParams(params: SaleParams): Hex {
  const error = priceListError(params.prices)
  if (error) throw new Error(error)
  if (params.supply <= 0n) throw new Error('The supply must be positive')
  if (params.escrow <= 0n) throw new Error('The escrow must be positive')
  const padded = [...params.prices, ...Array.from({ length: LEVELS - params.prices.length }, () => 0n)]
  const abi: readonly AbiParameter[] = parseAbiParameters(
    'uint8, uint8, uint256[16], address, uint256, address, uint256, string, address, bytes',
  )
  return encodeAbiParameters(abi, [
    params.revealMode ?? RevealMode.DemandCurve,
    params.prices.length,
    padded,
    params.saleToken,
    params.supply,
    params.paymentToken,
    params.escrow,
    params.title,
    params.gate ?? zeroAddress,
    params.gateConfig ?? '0x',
  ])
}

/** What a bid publishes: `SealedCcaProgram.publishInput` decodes it. */
export interface BidInput {
  bidder: Address
  ciphertext: Hex
  /** The SAFE commitment of the ciphertext (`bytes32`). */
  ctCommitment: Hex
  /** The commitment of the bid (`bytes32`): `poseidon2([BID_DOMAIN, b, salt, bidder, e3Field(e3Id)])`. */
  bidCommitment: Hex
  /** The bid proof. */
  proof: Hex
  /** What the sale's gate asks for; `0x` when the sale has no gate. */
  gateProof: Hex
  /** The bidder's EIP-712 signature (`bidTypedData`) for a relayed bid; `0x` for a direct bid. */
  signature: Hex
}

/**
 * The `data` of `SealedCcaProgram.publishInput`: `abi.encode(address bidder, bytes ciphertext,
 * bytes32 ctCommitment, bytes32 bidCommitment, bytes proof, bytes gateProof, bytes signature)`.
 */
export function encodeBidInput(input: BidInput): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('address, bytes, bytes32, bytes32, bytes, bytes, bytes')
  return encodeAbiParameters(abi, [
    input.bidder,
    input.ciphertext,
    input.ctCommitment,
    input.bidCommitment,
    input.proof,
    input.gateProof,
    input.signature,
  ])
}

/**
 * `keccak256(abi.encode(bytes32 ctCommitment, bytes32 bidCommitment, bytes32 keccak256(ciphertext)))`.
 * A relayed bid signs it, so a relayer cannot swap the bytes or the commitments.
 */
export function bidInputsHash(ctCommitment: Hex, bidCommitment: Hex, ciphertext: Hex): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('bytes32, bytes32, bytes32')
  return keccak256(encodeAbiParameters(abi, [ctCommitment, bidCommitment, keccak256(ciphertext)]))
}

/**
 * The EIP-712 message the bidder signs to let a relayer send a bid: `SealedCcaProgram.bidDigest`.
 * `version` is the version the bid will get, `bidCount + 1`. Pass the result to `signTypedData`.
 */
export function bidTypedData(chainId: number, program: Address, e3Id: bigint, bidder: Address, version: number, inputsHash: Hex) {
  return {
    domain: { name: 'SealedCcaProgram', version: '1', chainId, verifyingContract: program },
    types: {
      Bid: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'bidder', type: 'address' },
        { name: 'version', type: 'uint32' },
        { name: 'inputsHash', type: 'bytes32' },
      ],
    },
    primaryType: 'Bid',
    message: { e3Id, bidder, version, inputsHash },
  } as const
}

/** `abi.encode(uint8 cmp, bytes proof)`: the `data` of `SealedCcaProgram.claim`. */
export function encodeClaimData(cmp: 0 | 1 | 2, proof: Hex): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('uint8, bytes')
  return encodeAbiParameters(abi, [cmp, proof])
}
