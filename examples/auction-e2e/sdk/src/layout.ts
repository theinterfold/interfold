// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoding the bidders, the bid circuits (`auction_bid3`, `auction_bid4`), the FHE program
 * (`program/src/lib.rs`) and the result decoder share.
 *
 * All ciphertexts are SIMD-encoded over the 128 slots of the ring. Slot `i` has level `i % LEVELS`,
 * and a bid `b` is in `[0, LEVELS)`. Each bidder sends 3 ciphertexts (4 for the second-price ratio
 * auction) that depend on neither the bidder's position nor the number of bidders:
 *
 *   role 0 (ge)        slot i  [b >= i % LEVELS]
 *   role 1 (gt)        slot i  [b >  i % LEVELS]
 *   role 2 (mask)      slot i  uniform in [0, PLAINTEXT_MODULUS)
 *   role 3 (pairMask)  slots (2c) * LEVELS + l and (2c + 1) * LEVELS + l hold one uniform value, for
 *                      c in 0..4 and l in 0..LEVELS (ratio second-price only)
 *
 * The slots form `GROUPS` groups of `LEVELS` slots. The auction type selects what the result shows.
 *
 * Region auctions (`FirstPrice`, `SecondPrice`). With `n` bidders the program uses
 * `copies = floor(GROUPS / n)` copies of `n` regions: region `r` of copy `c` is group `c * n + r`.
 * The groups beyond `copies * n` are zeroed. Region `k` belongs to the bidder with tie priority `k`.
 * With `h` the highest bid and `s` the second-highest bid:
 *
 *   first-price   the region of the winner is ZERO at `h`, every other slot is non-zero
 *
 *   second-price  level p < s   every region is non-zero
 *                 level p = s   the region of the winner is ZERO, every other region is non-zero
 *                 level p > s   every region is zero
 *
 * A slot of a region holds a uniformly random value where it is non-zero, so a region reads as set
 * at a level if any copy is non-zero there. A set slot reads as zero by error with probability
 * `1 / PLAINTEXT_MODULUS` for each copy.
 *
 * Ratio-lane auctions (`RatioFirstPrice`, `RatioSecondPrice`). Bidder position `k` has the weight
 * `2^k`, so at most 8 bidders fit below the plaintext modulus. A lane holds the weights of the
 * bidders in the tie set, which is the set of bidders whose bid equals the published price:
 *
 *   ratio first-price   group 0, level p at slot p. Level p > h: ZERO. Level p = h: the sum of the
 *                       weights of the bidders with bid h. Level p < h: uniform.
 *
 *   ratio second-price  3 copies c in 0..3: the y lanes are group 2c and the z lanes are group 2c + 1.
 *                       Level p > s: both ZERO. Level p = s: `y = R * c`, `z = y * weights`, with
 *                       `weights` the winner set (the unique top bidder, or the tie set when the top
 *                       bids tie and `s = h`). Level p < s: uniform pair.
 *
 * Both ratio types put the sum of the masks into one random slot (slot 16 and slot 96): its value
 * is fixed by the encrypted masks and is uniform if one bidder is honest. The winner is the member
 * of the sorted tie set at the index `random % tieSet.length`. Every other slot is zero.
 *
 * Leaf 0 of every auction is a configuration input, not a ciphertext: `auctionConfigInput(type)`.
 * `AuctionProgram.validate` inserts its leaf, and the program reads the type from it. Every bid,
 * and every update of it, adds one run of `rolesFor(type).length` consecutive leaves in role order.
 * A leaf binds the ciphertext bytes, the commitment the bid proof checked, the bidder and the bid
 * version. The program picks the latest version of each bidder whose bytes open their commitments
 * (`selection.ts`); the bidder position in this file is the order of the picked runs.
 */
import {
  type AbiParameter,
  type Address,
  bytesToHex,
  concatBytes,
  encodeAbiParameters,
  type Hex,
  hexToBytes,
  keccak256,
  maxUint256,
  parseAbiParameters,
  zeroAddress,
} from 'viem'
import { decodePlaintextSlots } from '@interfold/sdk'

/** Polynomial degree, and so the slot count, of the insecure SIMD preset (param set 5). */
export const DEGREE = 128
/** Plaintext modulus of the same preset: prime, 1 mod 2 * DEGREE, so it supports SIMD. */
export const PLAINTEXT_MODULUS = 257
/** The preset name the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const
/** The number of levels, which is the period of a thermometer. A bid is in `[0, LEVELS)`. */
export const LEVELS = 16
/** The fewest price steps an auction can have. */
export const MIN_LEVELS = 2
/** The groups of `LEVELS` slots in the ring. */
export const GROUPS = DEGREE / LEVELS
export const MIN_BIDDERS = 2
/** The most bids of one bidder: the first bid and two updates. `AuctionProgram.MAX_BIDS_PER_BIDDER`. */
export const MAX_BIDS_PER_BIDDER = 3
/** Coefficients the committee publishes after decryption for this preset. */
export const OUTPUT_COEFFS = 128

/** What the auction reveals. The values are the `uint8` the contract and the program use. */
export enum AuctionType {
  /** The highest bid wins and pays its own bid. The result shows the winner and the highest bid. */
  FirstPrice = 0,
  /** The highest bid wins and pays the second-highest bid. The result shows the winner and that price. */
  SecondPrice = 1,
  /** As `FirstPrice`, with ratio lanes. The result shows the price, the tie set and a random value. */
  RatioFirstPrice = 2,
  /** As `SecondPrice`, with ratio lanes. The result shows the price, the tie set and a random value. */
  RatioSecondPrice = 3,
}

export const AUCTION_TYPES = [
  AuctionType.FirstPrice,
  AuctionType.SecondPrice,
  AuctionType.RatioFirstPrice,
  AuctionType.RatioSecondPrice,
] as const

export const AUCTION_TYPE_LABELS: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]: 'First-price',
  [AuctionType.SecondPrice]: 'Second-price (Vickrey)',
  [AuctionType.RatioFirstPrice]: 'Ratio first-price',
  [AuctionType.RatioSecondPrice]: 'Ratio second-price',
}

export const AUCTION_TYPE_DESCRIPTIONS: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]: 'The highest bid wins and pays its own bid. Only the winner and the winning bid are revealed.',
  [AuctionType.SecondPrice]:
    'The highest bid wins and pays the second-highest bid. Only the winner and that price are revealed; the winning bid stays secret.',
  [AuctionType.RatioFirstPrice]:
    'The highest bid wins and pays its own bid. The price and the set of bidders that tied at the top are revealed; a random value in the result picks the winner from that set.',
  [AuctionType.RatioSecondPrice]:
    'The highest bid wins and pays the second-highest bid. The price and the winner set are revealed (more than one bidder only if the top bids tie); a random value in the result picks the winner from that set.',
}

/** The most bidders of one auction, by type. The ratio types are limited by the weights `2^k` that must stay below the plaintext modulus. */
export const MAX_BIDDERS_BY_TYPE: Record<AuctionType, number> = {
  [AuctionType.FirstPrice]: 4,
  [AuctionType.SecondPrice]: 4,
  [AuctionType.RatioFirstPrice]: 8,
  [AuctionType.RatioSecondPrice]: 8,
}

/** The copies of the `y` and `z` lanes of the ratio second-price auction. */
export const RATIO_COPIES = 3

/** The slot of the random lane: group 1 for ratio first-price, group `2 * RATIO_COPIES` for ratio second-price. */
const RANDOM_SLOT: Record<RatioType, number> = {
  [AuctionType.RatioFirstPrice]: LEVELS,
  [AuctionType.RatioSecondPrice]: 2 * RATIO_COPIES * LEVELS,
}

export function isAuctionType(value: number): value is AuctionType {
  return (AUCTION_TYPES as readonly number[]).includes(value)
}

/** The ratio-lane types: their result is a price, a tie set and a random value. */
export type RatioType = AuctionType.RatioFirstPrice | AuctionType.RatioSecondPrice

export function isRatioType(type: AuctionType): type is RatioType {
  return type === AuctionType.RatioFirstPrice || type === AuctionType.RatioSecondPrice
}

/** The domain prefix of the configuration input. `AuctionProgram.CONFIG_DOMAIN` and the program use the same bytes. */
export const AUCTION_CONFIG_DOMAIN = 'interfold-auction-config-v1'

/**
 * The configuration input of an auction, leaf 0 of its tree: the domain bytes followed by the type
 * byte. The leaf is `keccak256(input) mod BN254`, which `AuctionProgram.validate` inserts.
 */
export function auctionConfigInput(type: AuctionType): `0x${string}` {
  return bytesToHex(concatBytes([new TextEncoder().encode(AUCTION_CONFIG_DOMAIN), new Uint8Array([type])]))
}

/**
 * The price of each step: 2 to `LEVELS` strictly increasing whole numbers. Step `b` costs `prices[b]`. The
 * creator picks the length, `levels`; the bid circuit rejects a bid `b >= levels`.
 */
export type PriceList = readonly bigint[]

/** Why `prices` is not a valid price list, or `null` when it is one. The contract applies the same rules to `uint256` values. */
export function priceListError(prices: PriceList): string | null {
  if (prices.length < MIN_LEVELS || prices.length > LEVELS) {
    return `A price list has ${MIN_LEVELS} to ${LEVELS} prices, got ${prices.length}`
  }
  if (prices.some((price) => price < 0n || price > maxUint256)) return 'A price is a whole number from 0 to 2^256 - 1'
  const flat = prices.findIndex((price, level) => level > 0 && price <= prices[level - 1])
  if (flat > 0) return `Prices must increase: step ${flat} (${prices[flat]}) is not above step ${flat - 1} (${prices[flat - 1]})`
  return null
}

/** Evenly spaced prices: step `b` costs `start + b * step`, for `count` steps. */
export function evenPrices(start: bigint, step: bigint, count: number): bigint[] {
  return Array.from({ length: count }, (_, level) => start + BigInt(level) * step)
}

/**
 * The request's `customParams`: `abi.encode(uint8 auctionType, uint8 levels, uint256[16] prices,
 * string title, address gate, bytes gateConfig)`. `levels` is `prices.length`; the contract wants the
 * unused prices to be zero, so they are padded. With the zero `gate` anyone may bid, and `gateConfig`
 * must be empty. Otherwise the contract calls `gate.configure(e3Id, gateConfig)`.
 */
export function encodeAuctionParams(
  type: AuctionType,
  prices: PriceList,
  title: string,
  gate: Address = zeroAddress,
  gateConfig: Hex = '0x',
): Hex {
  const error = priceListError(prices)
  if (error) throw new Error(error)
  const padded = [...prices, ...Array.from({ length: LEVELS - prices.length }, () => 0n)]
  const abi: readonly AbiParameter[] = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes')
  return encodeAbiParameters(abi, [type, prices.length, padded, title, gate, gateConfig])
}

/**
 * The price list of an auction from the contract's `levels` and its zero-padded `uint256[16]` prices
 * (the last getter value and the event `prices` of `AuctionProgram`): the first `levels` prices.
 */
export function readPriceList(levels: number | bigint, prices: readonly bigint[]): bigint[] {
  const count = Number(levels)
  if (!Number.isInteger(count) || count < MIN_LEVELS || count > LEVELS) {
    throw new Error(`levels must be an integer in [${MIN_LEVELS}, ${LEVELS}], got ${levels}`)
  }
  return prices.slice(0, count)
}

/** What a bid publishes: `AuctionProgram.publishInput` decodes it. */
export interface BidInput {
  bidder: Address
  /** One per role, in role order. */
  ciphertexts: readonly Hex[]
  /** One `bytes32` SAFE commitment per ciphertext, in role order. */
  commitments: readonly Hex[]
  /** The bid proof. */
  proof: Hex
  /** What the auction's gate asks for; `0x` when the auction has no gate. */
  gateProof: Hex
  /** The bidder's EIP-712 signature (`bidTypedData`) for a relayed bid; `0x` for a direct bid. */
  signature: Hex
}

/**
 * The `data` of `AuctionProgram.publishInput`:
 * `abi.encode(address bidder, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes gateProof, bytes signature)`.
 */
export function encodeBidInput(input: BidInput): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('address, bytes[], bytes32[], bytes, bytes, bytes')
  return encodeAbiParameters(abi, [input.bidder, input.ciphertexts, input.commitments, input.proof, input.gateProof, input.signature])
}

/**
 * `keccak256(abi.encode(commitments, ciphertextHashes))` with `ciphertextHashes[r] = keccak256(ciphertexts[r])`.
 * A relayed bid signs it, so a relayer cannot swap the bytes.
 */
export function bidInputsHash(commitments: readonly Hex[], ciphertexts: readonly Hex[]): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('bytes32[], bytes32[]')
  return keccak256(encodeAbiParameters(abi, [commitments, ciphertexts.map((ciphertext) => keccak256(ciphertext))]))
}

/**
 * The EIP-712 message the bidder signs to let a relayer send a bid: `AuctionProgram.bidDigest`.
 * `version` is the version the bid will get, `bidCount + 1`. Pass the result to `signTypedData`.
 */
export function bidTypedData(chainId: number, program: Address, e3Id: bigint, bidder: Address, version: number, inputsHash: Hex) {
  return {
    domain: { name: 'AuctionProgram', version: '1', chainId, verifyingContract: program },
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

export enum Role {
  Ge = 0,
  Gt = 1,
  Mask = 2,
  /** The structured mask of the ratio second-price auction: one value in the `y` and the `z` slot of a lane pair. */
  PairMask = 3,
}

const ROLES_BY_TYPE: Record<AuctionType, readonly Role[]> = {
  [AuctionType.FirstPrice]: [Role.Ge, Role.Gt, Role.Mask],
  [AuctionType.SecondPrice]: [Role.Ge, Role.Gt, Role.Mask],
  [AuctionType.RatioFirstPrice]: [Role.Ge, Role.Gt, Role.Mask],
  [AuctionType.RatioSecondPrice]: [Role.Ge, Role.Gt, Role.Mask, Role.PairMask],
}

/** The roles, in leaf order, of the ciphertexts one bidder submits to an auction of `type`. */
export function rolesFor(type: AuctionType): readonly Role[] {
  return ROLES_BY_TYPE[type]
}

export const ROLE_LABELS: Record<Role, string> = {
  [Role.Ge]: 'Bid thermometer (at least)',
  [Role.Gt]: 'Bid thermometer (above)',
  [Role.Mask]: 'Random mask',
  [Role.PairMask]: 'Random mask (paired lanes)',
}

export function assertBid(bid: number): void {
  if (!Number.isInteger(bid) || bid < 0 || bid >= LEVELS) {
    throw new Error(`A bid must be an integer in [0, ${LEVELS}), got ${bid}`)
  }
}

/** A uniform value in `[0, PLAINTEXT_MODULUS)` from the platform's secure randomness. */
function randomSlot(): bigint {
  // Rejection sampling: 65536 is not a multiple of the modulus, so a plain `%` would be biased.
  const limit = 0x10000 - (0x10000 % PLAINTEXT_MODULUS)
  const word = new Uint16Array(1)
  for (;;) {
    crypto.getRandomValues(word)
    if (word[0] < limit) return BigInt(word[0] % PLAINTEXT_MODULUS)
  }
}

/**
 * The SIMD slot values of one ciphertext of a bid. The masks ignore `bid`. The pair mask repeats
 * one uniform value in the slot `l` of group `2c` and of group `2c + 1`, for each copy `c` of the
 * ratio second-price lanes, so `R` is the same in the `y` and the `z` lane of a level.
 */
export function bidSlots(role: Role, bid: number): BigUint64Array {
  const slots = new BigUint64Array(DEGREE)
  if (role === Role.Mask) {
    for (let i = 0; i < DEGREE; i++) slots[i] = randomSlot()
    return slots
  }
  if (role === Role.PairMask) {
    for (let pair = 0; pair < GROUPS; pair += 2) {
      for (let level = 0; level < LEVELS; level++) {
        const value = randomSlot()
        slots[pair * LEVELS + level] = value
        slots[(pair + 1) * LEVELS + level] = value
      }
    }
    return slots
  }
  assertBid(bid)
  for (let i = 0; i < DEGREE; i++) {
    const level = i % LEVELS
    slots[i] = BigInt(role === Role.Ge ? bid >= level : bid > level)
  }
  return slots
}

/** The slot of `level` in `region` of `copy`, for `n` bidders. */
export function slotIndex(n: number, copy: number, region: number, level: number): number {
  return (copy * n + region) * LEVELS + level
}

/** The copies of the `n` regions that fit the ring. */
export function copiesFor(n: number): number {
  return Math.floor(GROUPS / n)
}

/**
 * The tie priority of each bidder position, as the program derives it: `priority[j]` is the region
 * of bidder position `j`.
 *
 * `seed = keccak256(ge_0 || ge_1 || ...)` over the published ge ciphertexts in leaf order. The
 * priority of position `j` is its rank when the positions are sorted ascending by
 * `keccak256(seed || u32_be(j))`, so the position with the highest hash has priority `n - 1`. All
 * ciphertexts are fixed when the window closes, so no bidder knows the priority beforehand.
 */
export function tiePriority(geCiphertexts: readonly `0x${string}`[]): number[] {
  const seed = hexToBytes(keccak256(concatBytes(geCiphertexts.map((ciphertext) => hexToBytes(ciphertext)))))
  const hashes = geCiphertexts.map((_, position) => {
    const index = new Uint8Array(4)
    new DataView(index.buffer).setUint32(0, position, false)
    return BigInt(keccak256(concatBytes([seed, index])))
  })
  const order = hashes.map((_, position) => position).sort((a, b) => (hashes[a] < hashes[b] ? -1 : hashes[a] > hashes[b] ? 1 : a - b))
  const priority = new Array<number>(order.length).fill(0)
  order.forEach((position, rank) => {
    priority[position] = rank
  })
  return priority
}

function assertBidderCount(type: AuctionType, bidders: number): void {
  const max = MAX_BIDDERS_BY_TYPE[type]
  if (bidders < MIN_BIDDERS || bidders > max) {
    throw new Error(`An auction of this type has ${MIN_BIDDERS} to ${max} bidders, got ${bidders}`)
  }
}

/**
 * The winner and the price on the plaintext bids. The highest bid wins, and a tie goes to the higher
 * priority. The price is the highest bid (first-price) or the second-highest bid (second-price).
 *
 * A ratio type has no tie priority: its winner is a random member of the tie set. Here the winner is
 * the lowest position of the tie set, which is the winner only if the top bid is unique. Use
 * `expectedTieSet` for a round with a tie.
 */
export function expectedAuction(
  type: AuctionType,
  bids: readonly number[],
  priority: readonly number[],
): { winner: number; price: number } {
  assertBidderCount(type, bids.length)
  if (isRatioType(type)) {
    const { price, tieSet } = expectedTieSet(type, bids)
    return { winner: tieSet[0], price }
  }
  const order = bids.map((_, position) => position).sort((a, b) => bids[b] - bids[a] || priority[b] - priority[a])
  return { winner: order[0], price: bids[order[type === AuctionType.FirstPrice ? 0 : 1]] }
}

/**
 * The price and the tie set of a ratio auction on the plaintext bids. The tie set is the bidder
 * positions, ascending, whose bid equals the price. With `RatioSecondPrice` and a unique top bid,
 * the tie set is that one bidder and the price is the second-highest bid.
 */
export function expectedTieSet(type: AuctionType, bids: readonly number[]): { price: number; tieSet: number[] } {
  if (!isRatioType(type)) throw new Error('Only the ratio types have a tie set')
  assertBidderCount(type, bids.length)
  const top = Math.max(...bids)
  const tieSet = bids.flatMap((bid, position) => (bid === top ? [position] : []))
  if (type === AuctionType.RatioSecondPrice && tieSet.length === 1) {
    return { price: Math.max(...bids.filter((_, position) => position !== tieSet[0])), tieSet }
  }
  return { price: top, tieSet }
}

/** What the published result of a region auction shows. */
export interface RegionResult {
  kind: 'region'
  /** Number of bidders in the round. */
  bidders: number
  /** Copies of the regions in the ring. */
  copies: number
  /** `priority[j]` is the region of bidder position `j`. */
  priority: number[]
  /** The price the winner pays (see `expectedAuction`), or `null` if the result is unreadable. */
  price: number | null
  /** The winning bidder position, or `null` if the result does not show one winner. */
  winner: number | null
  /**
   * `set[j][level]`: whether the region of bidder position `j` is non-zero at `level` in one or more
   * copies. The winner's row is the only one that is clear at `price`.
   */
  set: boolean[][]
  /** Whether the groups beyond the last copy are zero, as the program makes them. */
  unusedGroupsZero: boolean
}

/** What the published result of a ratio-lane auction shows. */
export interface LaneResult {
  kind: 'lane'
  /** Number of bidders in the round. */
  bidders: number
  /** Copies of the lanes: 1 for `RatioFirstPrice`, `RATIO_COPIES` for `RatioSecondPrice`. */
  copies: number
  /** The price level, or `null` if every lane is zero. */
  price: number | null
  /** The winning bidder position: `tieSet[random % tieSet.length]`, or `null` if there is no readable tie set. */
  winner: number | null
  /**
   * The winner set at the price level, ascending: the bidders with the top bid. Without a tie it has
   * one member (for `RatioSecondPrice` that bidder bid above the price). Empty if the lane value is no valid set.
   */
  tieSet: number[]
  /** The value of the random lane, or `null` if the price is unreadable. */
  random: number | null
  /** Per level: `'result'` at the price level, `'zero'` above it and `'random'` below it. */
  lanes: Array<'zero' | 'random' | 'result'>
  /** Whether every copy shows the same winner set at the price level, and no copy is non-zero there without its `y` lane. */
  copiesAgree: boolean
}

export type AuctionResult = RegionResult | LaneResult

/**
 * Decode the published plaintext of an auction.
 *
 * @param type The auction type, as `AuctionProgram.auctions` stores it.
 * @param plaintextHex The plaintext output: `OUTPUT_COEFFS` little-endian u64 coefficients.
 * @param geCiphertexts The role-0 ciphertext of each bidder in leaf order, as published. They fix
 * the tie priority of a region auction. A ratio auction only uses their count.
 */
export async function decodeAuction(
  type: AuctionType,
  plaintextHex: string,
  geCiphertexts: readonly `0x${string}`[],
): Promise<AuctionResult> {
  assertBidderCount(type, geCiphertexts.length)
  const hex = plaintextHex.startsWith('0x') ? plaintextHex.slice(2) : plaintextHex
  if (hex.length < OUTPUT_COEFFS * 16) {
    throw new Error(`Plaintext output has ${hex.length / 2} bytes, expected ${OUTPUT_COEFFS * 8}`)
  }
  const slots = await decodePlaintextSlots(`0x${hex}`, PRESET)
  if (slots.length < DEGREE) throw new Error(`Decoded ${slots.length} slots, expected ${DEGREE}`)
  return isRatioType(type) ? decodeLanes(type, slots, geCiphertexts.length) : decodeRegions(type, slots, geCiphertexts)
}

function decodeRegions(type: AuctionType, slots: readonly bigint[], geCiphertexts: readonly `0x${string}`[]): RegionResult {
  const n = geCiphertexts.length
  const copies = copiesFor(n)
  const priority = tiePriority(geCiphertexts)
  const isSet = (region: number, level: number) => {
    for (let copy = 0; copy < copies; copy++) if (slots[slotIndex(n, copy, region, level)] !== 0n) return true
    return false
  }
  const regionSet = Array.from({ length: n }, (_, region) => Array.from({ length: LEVELS }, (_, level) => isSet(region, level)))

  let price: number | null = null
  let winner: number | null = null
  if (type === AuctionType.FirstPrice) {
    // Exactly one slot is clear: the winner's region at the highest bid.
    const clear = regionSet.flatMap((row, region) => row.flatMap((set, level) => (set ? [] : [{ region, level }])))
    if (clear.length === 1) {
      price = clear[0].level
      winner = priority.indexOf(clear[0].region)
    }
  } else {
    // `last(region)` is the highest level at which the region is non-zero. The price is the highest
    // of them: every region is non-zero up to the price, except the winner's at the price itself.
    const lasts = regionSet.map((row) => row.lastIndexOf(true)).filter((level) => level >= 0)
    if (lasts.length > 0) {
      const level = Math.max(...lasts)
      price = level
      const winners = regionSet.map((row, region) => (row[level] ? -1 : region)).filter((region) => region >= 0)
      if (winners.length === 1) winner = priority.indexOf(winners[0])
    }
  }

  let unusedGroupsZero = true
  for (let slot = copies * n * LEVELS; slot < DEGREE; slot++) if (slots[slot] !== 0n) unusedGroupsZero = false

  return {
    kind: 'region',
    bidders: n,
    copies,
    priority,
    price,
    winner,
    set: priority.map((region) => regionSet[region]),
    unusedGroupsZero,
  }
}

/** `value^-1 mod PLAINTEXT_MODULUS`, by Fermat: the modulus is prime. */
function modInverse(value: bigint): bigint {
  const modulus = BigInt(PLAINTEXT_MODULUS)
  let result = 1n
  let base = value % modulus
  for (let exponent = modulus - 2n; exponent > 0n; exponent >>= 1n) {
    if (exponent & 1n) result = (result * base) % modulus
    base = (base * base) % modulus
  }
  return result
}

/** The bidder positions whose bit is set in `weights`, ascending. Empty if `weights` is 0 or has a bit at or above `bidders`. */
function positionsOf(weights: bigint, bidders: number): number[] {
  if (weights === 0n || weights >> BigInt(bidders) !== 0n) return []
  return Array.from({ length: bidders }, (_, position) => position).filter((position) => (weights >> BigInt(position)) & 1n)
}

/**
 * Read a ratio auction. The price is the highest level with a non-zero `y` lane in any copy. The
 * weights of the winner set are the value of that lane (first-price) or the ratio `z / y` (second-price)
 * of every copy that shows it; a copy whose `y` lane is zero there lost it to `R = 0` and must show
 * `z = 0` too.
 */
function decodeLanes(type: RatioType, slots: readonly bigint[], bidders: number): LaneResult {
  const modulus = BigInt(PLAINTEXT_MODULUS)
  const copies = type === AuctionType.RatioFirstPrice ? 1 : RATIO_COPIES
  // First-price has the `y` lanes only, in group 0. Second-price has `y` in group `2c`, `z` in group `2c + 1`.
  const lane = (copy: number, level: number, isZ: boolean) =>
    slots[(type === AuctionType.RatioFirstPrice ? 0 : 2 * copy + Number(isZ)) * LEVELS + level]
  const highest = Array.from({ length: copies }, (_, copy) => {
    for (let level = LEVELS - 1; level >= 0; level--) if (lane(copy, level, false) !== 0n) return level
    return -1
  })
  const price = Math.max(...highest)
  if (price < 0) {
    return {
      kind: 'lane',
      bidders,
      copies,
      price: null,
      winner: null,
      tieSet: [],
      random: null,
      lanes: Array(LEVELS).fill('zero'),
      copiesAgree: true,
    }
  }

  const weights: bigint[] = []
  let copiesAgree = true
  for (let copy = 0; copy < copies; copy++) {
    const y = lane(copy, price, false)
    if (type === AuctionType.RatioFirstPrice) weights.push(y)
    else if (y !== 0n) weights.push((lane(copy, price, true) * modInverse(y)) % modulus)
    else if (lane(copy, price, true) !== 0n) copiesAgree = false
  }
  copiesAgree &&= weights.every((weight) => weight === weights[0])

  const tieSet = positionsOf(weights[0], bidders)
  const random = Number(slots[RANDOM_SLOT[type]])
  return {
    kind: 'lane',
    bidders,
    copies,
    price,
    // Copies that disagree show no single winner set; `decode_ratio` in the program returns none too.
    winner: copiesAgree && tieSet.length > 0 ? tieSet[random % tieSet.length] : null,
    tieSet,
    random,
    lanes: Array.from({ length: LEVELS }, (_, level) => (level > price ? 'zero' : level === price ? 'result' : 'random')),
    copiesAgree,
  }
}

export { bytesToHex }
