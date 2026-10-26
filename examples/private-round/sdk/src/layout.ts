// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoding that the bidders, the bid circuit (`private_round_bid`), the FHE program
 * (`program/src/lib.rs`), the program contract (`RoundOutput.sol`) and the result decoder share.
 *
 * All ciphertexts are SIMD-encoded over the 128 slots of the ring. A bid is TWO ciphertexts.
 *
 * Role 0, the bid. The bidder wants one lot and accepts the price steps up to `b` (the index of the
 * highest price step). The reserve step `rho` is public:
 *
 *   slot g * 16 + l   for g in 0..COPIES, l in 0..LEVELS     1 if l <= b, else 0   (6 copies of the thermometer)
 *   slot 96 + k       for k in 0..GATE_COPIES                 1 if b >= rho, else 0
 *   slot 115 + i                                              the version of the bid (1 to 3), i the bidder index
 *   every other slot                                          0
 *
 * Role 1, the mask: 128 slots, each uniform in [0, 257), chosen by the bidder.
 *
 * The program adds the selected bid ciphertexts (`C`) and the selected masks (`R`), and tests every
 * lane `c` of `C` with a polynomial that is zero exactly on one side of a public threshold, times `R`.
 * After the threshold decryption a lane slot is zero or uniform. The committee never sees a count.
 * See `decodeRound` for what the slots mean.
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
  bytesToHex,
  encodeAbiParameters,
  type Hex,
  keccak256,
  maxUint256,
  parseAbiParameters,
  stringToBytes,
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
/** The most price steps of a sale, and the number of slots of one thermometer. A bid is in `[0, LEVELS)`. */
export const LEVELS = 16
/** The fewest price steps of a sale. */
export const MIN_LEVELS = 2
/** The copies of every lane. A lane is read as zero only if all copies are zero. */
export const COPIES = 6
/** The first slot of the gate lanes (one lane per copy). */
export const GATE_BASE = COPIES * LEVELS
/** The number of gate lanes. */
export const GATE_COPIES = COPIES
/** The slot of the version of bidder 0. Bidder `i` is at `VERSION_BASE + i`. */
export const VERSION_BASE = DEGREE - 13
/** The most bidders of a round. It keeps the lane polynomial at 8 leaves, which is depth 3. */
export const MAX_BIDDERS = 13
/** The most bids of one bidder: the first bid and two updates. */
export const MAX_BIDS_PER_BIDDER = 3
/** The most lots of a round. A round with more lots than `MAX_BIDDERS - 1` cannot be oversubscribed. */
export const MAX_LOTS = MAX_BIDDERS - 1
/** Coefficients the committee publishes after decryption for this preset. */
export const OUTPUT_COEFFS = DEGREE
/** The prefix of the configuration input. `PrivateRoundProgram.CONFIG_DOMAIN` and `CONFIG_DOMAIN` in `program/src/lib.rs` are the same bytes. */
export const CONFIG_DOMAIN = 'interfold-private-round-config-v1'

/** What the round decided. The values are the `uint8` the contract uses. */
export enum Outcome {
  /** The reserve was not met: nothing sells, everybody gets the escrow back. Nothing else is revealed. */
  NotMet = 0,
  /** The reserve was met, but fewer than `lots` bidders accept the reserve price: they get one lot each at the reserve price. */
  Undersubscribed = 1,
  /** `lots` or more bidders accept the clearing step: one price for everyone. */
  SoldOut = 2,
  /** The decrypted output is not a valid output of the program. Treated like `NotMet`. */
  Aborted = 3,
}

/** The public parameters that the program reads from input 0 and the bid circuit reads from its public inputs. */
export interface RoundParams {
  /** The number of price steps, 2 to 16. */
  levels: number
  /** The reserve price step: the round needs `minLots` bidders at this step or above. */
  reserveStep: number
  /** The lots for sale, 1 to `MAX_LOTS`. */
  lots: number
  /** The minimum number of bidders at the reserve step or above, 1 to `lots`. */
  minLots: number
}

export function assertRoundParams({ levels, reserveStep, lots, minLots }: RoundParams): void {
  if (!Number.isInteger(levels) || levels < MIN_LEVELS || levels > LEVELS) {
    throw new Error(`A round has ${MIN_LEVELS} to ${LEVELS} price steps, got ${levels}`)
  }
  if (!Number.isInteger(reserveStep) || reserveStep < 0 || reserveStep >= levels) {
    throw new Error(`The reserve step is in [0, ${levels}), got ${reserveStep}`)
  }
  if (!Number.isInteger(lots) || lots < 1 || lots > MAX_LOTS) throw new Error(`A round sells 1 to ${MAX_LOTS} lots, got ${lots}`)
  if (!Number.isInteger(minLots) || minLots < 1 || minLots > lots) {
    throw new Error(`The minimum raise is 1 to ${lots} lots, got ${minLots}`)
  }
}

/** Input 0 of a round: the domain bytes, then `levels`, `reserveStep`, `lots` and `minLots` as one byte each. */
export function roundConfigInput(params: RoundParams): Hex {
  assertRoundParams(params)
  const { levels, reserveStep, lots, minLots } = params
  return bytesToHex(Uint8Array.from([...stringToBytes(CONFIG_DOMAIN), levels, reserveStep, lots, minLots]))
}

/** The slot of the step `l` in the copy `g` of the price lanes. */
export function priceSlot(copy: number, level: number): number {
  if (!Number.isInteger(copy) || copy < 0 || copy >= COPIES) throw new Error(`A copy is in [0, ${COPIES}), got ${copy}`)
  assertBid(level)
  return copy * LEVELS + level
}

/** The slot of the gate lane of the copy `k`. */
export function gateSlot(copy: number): number {
  if (!Number.isInteger(copy) || copy < 0 || copy >= GATE_COPIES) throw new Error(`A copy is in [0, ${GATE_COPIES}), got ${copy}`)
  return GATE_BASE + copy
}

/** The slot of the bidder `bidderIndex`. */
export function bidderSlot(bidderIndex: number): number {
  assertBidderIndex(bidderIndex)
  return VERSION_BASE + bidderIndex
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

/**
 * The SIMD slot values of the bid ciphertext (role 0): `COPIES` thermometers of `level`, the gate bit
 * `level >= reserveStep` in the gate slots, and `version` in the slot of `bidderIndex`.
 */
export function bidSlots(level: number, reserveStep: number, bidderIndex: number, version: number): BigUint64Array {
  assertBid(level)
  assertBid(reserveStep)
  assertVersion(version)
  const slots = new BigUint64Array(DEGREE)
  for (let g = 0; g < COPIES; g++) for (let l = 0; l <= level; l++) slots[g * LEVELS + l] = 1n
  if (level >= reserveStep) for (let k = 0; k < GATE_COPIES; k++) slots[GATE_BASE + k] = 1n
  slots[bidderSlot(bidderIndex)] = BigInt(version)
  return slots
}

/**
 * The SIMD slot values of the mask ciphertext (role 1): 128 independent uniform values below `t`.
 * One honest bidder with an unseen mask makes the sum of the masks uniform, and that hides every
 * count. `random` fills the byte buffer; the default is `crypto.getRandomValues`.
 */
export function maskSlots(random: (bytes: Uint8Array) => void = (bytes) => crypto.getRandomValues(bytes)): BigUint64Array {
  const slots = new BigUint64Array(DEGREE)
  const buffer = new Uint8Array(64)
  let used = buffer.length
  for (let i = 0; i < DEGREE; i++) {
    // Rejection sampling: 256 values of a byte are not a multiple of 257, so use 16 bits (65535 = 255 * 257).
    for (;;) {
      if (used + 2 > buffer.length) {
        random(buffer)
        used = 0
      }
      const sample = buffer[used] | (buffer[used + 1] << 8)
      used += 2
      if (sample < 65535) {
        slots[i] = BigInt(sample % PLAINTEXT_MODULUS)
        break
      }
    }
  }
  return slots
}

/**
 * Whether the zero set of the lane test with the threshold `theta` is the complement side
 * `{theta, ..., n}`, for `n` counted bidders. The other side is `{0, ..., theta - 1}`. The program
 * takes the side with fewer zeros, and the direct side if both are as big. The decoder needs the same
 * rule to know what a zero lane means: with the complement side a zero lane means `c >= theta`; with
 * the direct side a zero lane means `c < theta`.
 */
export function usesComplementSide(theta: number, n: number): boolean {
  return zeroSetSize(theta, n, true) < zeroSetSize(theta, n, false)
}

/** The number of zeros of the lane polynomial: `n + 1 - theta` (at least 0) for the complement side, `theta` for the direct side. */
export function zeroSetSize(theta: number, n: number, complement: boolean): number {
  return complement ? Math.max(0, n + 1 - theta) : theta
}

/** The factors of the lane polynomial, the larger of the two lane kinds: at most 7 for 13 bidders. */
export function laneFactors(params: Pick<RoundParams, 'lots' | 'minLots'>, n: number): number {
  const side = (theta: number) => zeroSetSize(theta, n, usesComplementSide(theta, n))
  return Math.max(side(params.lots), side(params.minLots))
}

/** What the decrypted output means. */
export interface RoundOutput {
  /** The number of counted bidders. */
  counted: number
  /** `versions[i]` is the counted version (1 to 3) of the bidder `i`, or 0 if the bidder was dropped or never bid. */
  versions: number[]
  outcome: Outcome
  /** The clearing step: `l*` when `SoldOut`, the reserve step when `Undersubscribed`, `null` otherwise. */
  step: number | null
  /** Why the output is `Aborted`; `null` otherwise. */
  reason: string | null
}

/**
 * Reads the 128 output slots.
 *
 * `n` is the number of nonzero version slots. A lane slot is zero or uniform. A lane (a step, or the
 * gate) is *zero* when all its copies are zero. With the complement side a zero lane means the test
 * `c >= theta` holds; with the direct side a zero lane means it fails. The price lane of step `l`
 * tests `c_l >= lots`, the gate tests `c_rho >= minLots`. The rules, which the contract applies too:
 *
 * - The price slots of the steps below `reserveStep` or from `levels`, the unused slots, and the
 *   slots of a bidder above `n` must be zero.
 * - The price lane tests must not increase with the step.
 * - The sell-out at the reserve step needs the gate.
 *
 * An output that breaks a rule is `Aborted`. This happens by chance with the probability
 * `257^-6` for each lane, or when no bidder is honest and the masks are known.
 * `bidCounts[i]` (optional) is the bids of the bidder `i`: a counted version above it is invalid.
 */
export function decodeRound(slots: readonly bigint[], params: RoundParams, bidCounts?: readonly number[]): RoundOutput {
  assertRoundParams(params)
  if (slots.length !== DEGREE) throw new Error(`The output has ${DEGREE} slots, got ${slots.length}`)
  const versions: number[] = []
  let invalid: string | null = null
  for (let i = 0; i < MAX_BIDDERS; i++) {
    const slot = slots[VERSION_BASE + i]
    if (slot > BigInt(MAX_BIDS_PER_BIDDER) || (bidCounts !== undefined && slot > BigInt(bidCounts[i] ?? 0))) {
      invalid ??= `the counted version of bidder ${i} is ${slot}`
      versions.push(0)
    } else {
      versions.push(Number(slot))
    }
  }
  const n = versions.filter((v) => v > 0).length
  const aborted = (reason: string): RoundOutput => ({ counted: n, versions, outcome: Outcome.Aborted, step: null, reason })
  if (invalid !== null) return aborted(invalid)
  if (n === 0) return aborted('no bidder counted')

  const { levels, reserveStep, lots, minLots } = params
  // The slots that may hold a lane value: the price steps from the reserve to the last, and the gate.
  const active = new Set<number>()
  for (let g = 0; g < COPIES; g++) for (let l = reserveStep; l < levels; l++) active.add(g * LEVELS + l)
  for (let k = 0; k < GATE_COPIES; k++) active.add(GATE_BASE + k)
  for (let s = 0; s < VERSION_BASE; s++) {
    if (!active.has(s) && slots[s] !== 0n) return aborted(`slot ${s} is not a lane and not zero`)
  }

  const zero = (lane: number[]) => lane.every((s) => slots[s] === 0n)
  const priceComplement = usesComplementSide(lots, n)
  const gateComplement = usesComplementSide(minLots, n)
  const holds: boolean[] = [] // holds[l - reserveStep] is [c_l >= lots]
  for (let l = reserveStep; l < levels; l++) {
    holds.push(zero(Array.from({ length: COPIES }, (_, g) => g * LEVELS + l)) === priceComplement)
  }
  const gate = zero(Array.from({ length: GATE_COPIES }, (_, k) => GATE_BASE + k)) === gateComplement
  for (let j = 1; j < holds.length; j++) {
    if (holds[j] && !holds[j - 1]) return aborted(`the demand test rises at step ${reserveStep + j}`)
  }
  if (holds[0] && !gate) return aborted('the sale sells out but the reserve is not met')

  if (!gate) return { counted: n, versions, outcome: Outcome.NotMet, step: null, reason: null }
  if (!holds[0]) return { counted: n, versions, outcome: Outcome.Undersubscribed, step: reserveStep, reason: null }
  let last = 0
  holds.forEach((h, j) => {
    if (h) last = j
  })
  return { counted: n, versions, outcome: Outcome.SoldOut, step: reserveStep + last, reason: null }
}

/**
 * Decodes the plaintext output the committee published (hex of 128 u64-LE polynomial coefficients)
 * into the output slots.
 */
export async function decodeOutputSlots(plaintextOutput: string): Promise<bigint[]> {
  const hex = plaintextOutput.startsWith('0x') ? plaintextOutput.slice(2) : plaintextOutput
  return decodePlaintextSlots(`0x${hex}`, PRESET)
}

/** `decodeOutputSlots`, then `decodeRound`. */
export async function decodeOutput(plaintextOutput: string, params: RoundParams, bidCounts?: readonly number[]): Promise<RoundOutput> {
  return decodeRound(await decodeOutputSlots(plaintextOutput), params, bidCounts)
}

/**
 * Output slots that decode to the given `outcome`, for the tests of the contract and of the program.
 * `versions[i]` are the counted versions. Each nonzero lane copy gets `nonzero(slot)`, a value in
 * `[1, 256]`; the default is a fixed pattern. A zero lane is 0 in every copy.
 */
export function outputSlotsFor(
  params: RoundParams,
  versions: readonly number[],
  outcome: Outcome.NotMet | Outcome.Undersubscribed | Outcome.SoldOut,
  step?: number,
  nonzero: (slot: number) => bigint = (slot) => BigInt((slot * 37) % 256) + 1n,
): bigint[] {
  assertRoundParams(params)
  if (versions.length !== MAX_BIDDERS) throw new Error(`There are ${MAX_BIDDERS} versions`)
  const { levels, reserveStep, lots, minLots } = params
  const n = versions.filter((v) => v > 0).length
  const slots = new Array<bigint>(DEGREE).fill(0n)
  versions.forEach((v, i) => (slots[VERSION_BASE + i] = BigInt(v)))
  const holdsAt = (l: number) => outcome === Outcome.SoldOut && l <= (step ?? -1)
  const gate = outcome !== Outcome.NotMet
  const priceComplement = usesComplementSide(lots, n)
  const gateComplement = usesComplementSide(minLots, n)
  const put = (lane: number[], holds: boolean, complement: boolean) => {
    // A zero lane means `holds` with the complement side, and `!holds` with the direct side.
    const isZero = holds === complement
    lane.forEach((s) => (slots[s] = isZero ? 0n : nonzero(s)))
  }
  for (let l = reserveStep; l < levels; l++) {
    put(
      Array.from({ length: COPIES }, (_, g) => g * LEVELS + l),
      holdsAt(l),
      priceComplement,
    )
  }
  put(
    Array.from({ length: GATE_COPIES }, (_, k) => GATE_BASE + k),
    gate,
    gateComplement,
  )
  return slots
}

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
 * The price list of a round from the contract's `levels` and its zero-padded `uint256[16]` prices
 * (the getter value and the event `prices`): the first `levels` prices.
 */
export function readPriceList(levels: number | bigint, prices: readonly bigint[]): bigint[] {
  const count = Number(levels)
  if (!Number.isInteger(count) || count < MIN_LEVELS || count > LEVELS) {
    throw new Error(`levels must be an integer in [${MIN_LEVELS}, ${LEVELS}], got ${levels}`)
  }
  return prices.slice(0, count)
}

/** The round a creator opens. */
export interface SaleParams {
  prices: PriceList
  saleToken: Address
  /** The sale-token base units of one lot: what each bidder buys. */
  lot: bigint
  /** The lots for sale. The creator deposits `lot * lots` sale-token base units. */
  lots: number
  /** The reserve price step: the round needs `minLots` bidders at this step or above. */
  reserveStep: number
  /** The fewest bidders at the reserve step or above for the round to go ahead, 1 to `lots`. */
  minLots: number
  paymentToken: Address
  title: string
  gate?: Address
  gateConfig?: Hex
}

/** The part of `SaleParams` that the program and the circuit read. */
export function roundParamsOf(params: Pick<SaleParams, 'prices' | 'reserveStep' | 'lots' | 'minLots'>): RoundParams {
  return { levels: params.prices.length, reserveStep: params.reserveStep, lots: params.lots, minLots: params.minLots }
}

/**
 * The request's `customParams`: `abi.encode(uint8 levels, uint256[16] prices, address saleToken,
 * uint256 lot, uint8 lots, uint8 reserveStep, uint8 minLots, address paymentToken, string title,
 * address gate, bytes gateConfig)`. `levels` is `prices.length`; the contract wants the unused prices
 * to be zero, so they are padded. With the zero `gate` anyone may bid, and `gateConfig` must be empty.
 */
export function encodeSaleParams(params: SaleParams): Hex {
  const error = priceListError(params.prices)
  if (error) throw new Error(error)
  assertRoundParams(roundParamsOf(params))
  if (params.lot <= 0n) throw new Error('The lot must be positive')
  const padded = [...params.prices, ...Array.from({ length: LEVELS - params.prices.length }, () => 0n)]
  const abi: readonly AbiParameter[] = parseAbiParameters(
    'uint8, uint256[16], address, uint256, uint8, uint8, uint8, address, string, address, bytes',
  )
  return encodeAbiParameters(abi, [
    params.prices.length,
    padded,
    params.saleToken,
    params.lot,
    params.lots,
    params.reserveStep,
    params.minLots,
    params.paymentToken,
    params.title,
    params.gate ?? zeroAddress,
    params.gateConfig ?? '0x',
  ])
}

/** What a bid publishes: `PrivateRoundProgram.publishInput` decodes it. */
export interface BidInput {
  bidder: Address
  /** The bid ciphertext and the mask ciphertext (the l-BFV ciphertext bytes), in role order. */
  ciphertexts: readonly [Hex, Hex]
  /** The SAFE commitments of the two ciphertexts (`bytes32`), in role order. */
  ctCommitments: readonly [Hex, Hex]
  /** The commitment of the bid (`bytes32`): `poseidon2(BID_DOMAIN, b, salt, bidder, e3Id)`. */
  bidCommitment: Hex
  /** The bid proof. */
  proof: Hex
  /** What the sale's gate asks for; `0x` when the sale has no gate. */
  gateProof: Hex
  /** The bidder's EIP-712 signature (`bidTypedData`) for a relayed bid; `0x` for a direct bid. */
  signature: Hex
}

/**
 * The `data` of `PrivateRoundProgram.publishInput`: `abi.encode(address bidder, bytes[] ciphertexts,
 * bytes32[] ctCommitments, bytes32 bidCommitment, bytes proof, bytes gateProof, bytes signature)`.
 */
export function encodeBidInput(input: BidInput): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('address, bytes[], bytes32[], bytes32, bytes, bytes, bytes')
  return encodeAbiParameters(abi, [
    input.bidder,
    [...input.ciphertexts],
    [...input.ctCommitments],
    input.bidCommitment,
    input.proof,
    input.gateProof,
    input.signature,
  ])
}

/**
 * `keccak256(abi.encode(bytes32[] ctCommitments, bytes32 bidCommitment, bytes32[] ciphertextHashes))`.
 * A relayed bid signs it, so a relayer cannot swap the bytes or the commitments.
 */
export function bidInputsHash(ctCommitments: readonly [Hex, Hex], bidCommitment: Hex, ciphertexts: readonly [Hex, Hex]): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('bytes32[], bytes32, bytes32[]')
  return keccak256(encodeAbiParameters(abi, [[...ctCommitments], bidCommitment, ciphertexts.map((ciphertext) => keccak256(ciphertext))]))
}

/**
 * The EIP-712 message the bidder signs to let a relayer send a bid: `PrivateRoundProgram.bidDigest`.
 * `version` is the version the bid will get, `bidCount + 1`. Pass the result to `signTypedData`.
 */
export function bidTypedData(chainId: number, program: Address, e3Id: bigint, bidder: Address, version: number, inputsHash: Hex) {
  return {
    domain: { name: 'PrivateRoundProgram', version: '1', chainId, verifyingContract: program },
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

/** `abi.encode(uint8 cmp, bytes proof)`: the `data` of `PrivateRoundProgram.claim`. */
export function encodeClaimData(cmp: 0 | 1 | 2, proof: Hex): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('uint8, bytes')
  return encodeAbiParameters(abi, [cmp, proof])
}
