// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoding the bidders, the bid circuits (`auction_bid2`, `auction_bid3`, `auction_bid4`), the mask
 * circuit (`auction_mask`), the FHE program (`program/src/lib.rs`) and the result decoder share.
 *
 * All ciphertexts are SIMD-encoded over the 128 slots of the ring. Slot `i` has level `i % LEVELS`,
 * and a bid `b` is in `[0, LEVELS)`.
 * Each bidder sends 3 ciphertexts (4 for the no-provider auction, 2 for the provider-mask auction)
 * that depend on neither the bidder's position nor the number of bidders:
 *
 *   role 0 (ge)     slot i  [b >= i % LEVELS]
 *   role 1 (gt)     slot i  [b >  i % LEVELS]
 *   role 2 (mask)   slot i  uniform in [0, PLAINTEXT_MODULUS) (`FirstPrice` only)
 *   role 3 (share)  slot i  uniform in [0, PLAINTEXT_MODULUS), as a mask (`QnrSecondPrice` only)
 *
 * Every type has ONE copy of the regions, for 2 to 8 bidders: region `k` belongs to the bidder at
 * position `k` and is the slots `16 k .. 16 k + 15`. The slots from `16 n` on are ZERO. `h` is the
 * highest bid and `s` the second-highest bid.
 *
 * First-price (`FirstPrice`, priority-expanded first price). The output is `ge + m * (G + E)` per
 * region, with `m` the sum of the bidder masks, `G` the number of bids above the level and `E` the
 * number of earlier bidders that bid exactly the level:
 *
 *   level p > h   every region is ZERO
 *   level p = h   the region of the winner is exactly 1 and every region before it is exactly 0.
 *                 The regions after the winner hold any value.
 *   level p < h   masked: the slots hold any value
 *
 * The decoder reads the price as the highest level where some region is non-zero, and the winner as
 * the first region that is non-zero there. That region must hold exactly 1. The mask only touches
 * the slots where `G + E >= 1`, which the decoder never needs, so the result is read whatever the
 * masks hold. If one bidder is honest, the masked slots are uniform, so the output shows only the
 * winner and the price.
 *
 * Provider-mask auction (`ProviderSecondPrice`). A bid is 2 ciphertexts `[ge, gt]`, with no mask.
 * The creator names 1 to `MAX_PROVIDERS` mask providers; each sends one mask ciphertext whose 128
 * slots are all non-zero. The result has the second-price pattern:
 *
 *   level p < s   every region is non-zero
 *   level p = s   the region of the winner is ZERO, every other region is non-zero
 *   level p > s   every region is zero
 *
 * The output is `tests * r`, with `r` the product of the masks: every test is below the plaintext
 * modulus, so a non-zero slot is NEVER read as zero. If one provider is honest, each non-zero slot is
 * uniform. The decoder is strict and reads no result from any other pattern.
 *
 * No-provider auction (`QnrSecondPrice`). The result and the layout of the provider-mask auction
 * (the same strict decoder), with no mask providers. A bid is 4 ciphertexts
 * `[ge, gt, share, share]`. The program adds the shares of the counted bids, `S1` and `S2`, and
 * multiplies the tests by `(S1^2 - 3) * (S2^2 - 3)`. 3 is not a square modulo the plaintext modulus,
 * so no factor is ever zero and a non-zero slot is NEVER read as zero, whatever the bidders send. The
 * factor is not exactly uniform, so the non-zero slots show a small statistical hint about the counts
 * of the tests.
 *
 * Leaf 0 of every auction is a configuration input, not a ciphertext: `auctionConfigInput(type,
 * providers)`. `AuctionProgram.validate` inserts its leaf, and the program reads the type and the
 * providers from it. In a provider auction the leaves 1 to k are the masks, one per provider in the order
 * of submission, with the version `MASK_VERSION`; the bids follow. Every bid, and every update of it,
 * adds one run of `rolesFor(type).length` consecutive leaves in role order.
 * A leaf binds the ciphertext bytes, the commitment the bid proof checked, the bidder and the bid
 * version. The program picks the latest version of each bidder whose bytes open their commitments
 * (`selection.ts`); the bidder position in this file is the order of the picked runs. A bidder that
 * updates gets the position of its update, so an update loses the place of the earlier bid. A tie
 * at the top goes to the tied bidder with the lowest position: the one whose counted bid was
 * published first.
 */
import {
  type AbiParameter,
  type Address,
  bytesToHex,
  concatBytes,
  encodeAbiParameters,
  type Hex,
  hexToBytes,
  isAddress,
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
  /** The highest bid wins and pays the second-highest bid, with masks from 1 to `MAX_PROVIDERS` mask providers and up to 8 bidders. The result always decodes. */
  ProviderSecondPrice = 1,
  /** The highest bid wins and pays the second-highest bid, with up to 8 bidders and no mask providers: the bidders send random shares. The result always decodes. */
  QnrSecondPrice = 2,
}

export const AUCTION_TYPES = [AuctionType.FirstPrice, AuctionType.ProviderSecondPrice, AuctionType.QnrSecondPrice] as const

export const AUCTION_TYPE_LABELS: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]: 'First-price',
  [AuctionType.ProviderSecondPrice]: 'Second-price, mask providers',
  [AuctionType.QnrSecondPrice]: 'Second-price, no providers',
}

export const AUCTION_TYPE_DESCRIPTIONS: Record<AuctionType, string> = {
  [AuctionType.FirstPrice]:
    'The highest bid wins and pays its own bid, for up to 8 bidders. Only the winner and the winning bid are revealed. Each bidder has its own lane of the result, and the bidder masks hide every slot the result does not need, so the result can never fail to show the winner. If the top bids tie, the tied bidder who bid first wins; the tie is not revealed.',
  [AuctionType.ProviderSecondPrice]:
    'The highest bid wins and pays the second-highest bid, for up to 8 bidders. Only the winner and that price are revealed. The auction names 1 to 4 mask providers. Each one sends a random mask before bidding opens. If one provider is honest, the result shows nothing else, and it can never fail to show the winner. If the top bids tie, the tied bidder who bid first wins; the tie is not revealed.',
  [AuctionType.QnrSecondPrice]:
    'The highest bid wins and pays the second-highest bid, for up to 8 bidders. Only the winner and that price are revealed. There are no mask providers and no trusted party: each bid carries two random shares, and the program mixes the shares of all bids into a random factor. The result can never fail to show the winner. The trade-off is a small statistical hint about the losing bids, larger on the demo parameters than on secure ones. If the top bids tie, the tied bidder who bid first wins; the tie is not revealed.',
}

/** The most bidders of one auction, by type. Every type has one copy of the regions, so the limit is the 8 groups of the ring. */
export const MAX_BIDDERS_BY_TYPE: Record<AuctionType, number> = {
  [AuctionType.FirstPrice]: 8,
  [AuctionType.ProviderSecondPrice]: 8,
  [AuctionType.QnrSecondPrice]: 8,
}

export function isAuctionType(value: number): value is AuctionType {
  return (AUCTION_TYPES as readonly number[]).includes(value)
}

/** The most mask providers of an auction. `AuctionProgram.MAX_PROVIDERS`. */
export const MAX_PROVIDERS = 4

/**
 * The bid version of a mask in the 25-byte metadata of its leaf (`provider || uint40(version)`):
 * `uint32` max. A bid has the versions 1 to `MAX_BIDS_PER_BIDDER`. `AuctionProgram.MASK_VERSION`.
 */
export const MASK_VERSION = 0xffffffff

/** The type that has mask providers: one mask ciphertext each and bidders that send `[ge, gt]` only. */
export function isProviderType(type: AuctionType): type is AuctionType.ProviderSecondPrice {
  return type === AuctionType.ProviderSecondPrice
}

/** The domain prefix of the configuration input. `AuctionProgram.CONFIG_DOMAIN` and the program use the same bytes. */
export const AUCTION_CONFIG_DOMAIN = 'interfold-auction-config-v1'

/**
 * The configuration input of an auction, leaf 0 of its tree: the domain bytes, the type byte and the
 * mask providers as 20 raw bytes each (`AuctionProgram.configInput`: not the 32-byte words of
 * `abi.encodePacked(address[])`). The leaf is `keccak256(input) mod BN254`, which
 * `AuctionProgram.validate` inserts. Types other than `ProviderSecondPrice` have no providers, so their
 * input is the domain and the type byte only.
 */
export function auctionConfigInput(type: AuctionType, providers: readonly Address[] = []): `0x${string}` {
  const error = providersError(type, providers)
  if (error) throw new Error(error)
  return bytesToHex(
    concatBytes([
      new TextEncoder().encode(AUCTION_CONFIG_DOMAIN),
      new Uint8Array([type]),
      ...providers.map((provider) => hexToBytes(provider)),
    ]),
  )
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
 * Why `providers` is not a valid list of mask providers for an auction of `type`, or `null` when it
 * is one. `AuctionProgram` applies the same rules: a `ProviderSecondPrice` auction has 1 to
 * `MAX_PROVIDERS` providers, each a non-zero address, with no address twice (case does not matter).
 * Every other type has none.
 */
export function providersError(type: AuctionType, providers: readonly Address[]): string | null {
  if (!isProviderType(type)) return providers.length === 0 ? null : 'Only an auction with mask providers has providers'
  if (providers.length < 1 || providers.length > MAX_PROVIDERS) {
    return `An auction has 1 to ${MAX_PROVIDERS} mask providers, got ${providers.length}`
  }
  const seen = new Set<string>()
  for (const provider of providers) {
    if (!isAddress(provider, { strict: false })) return `${provider} is not an address`
    const key = provider.toLowerCase()
    if (key === zeroAddress) return 'A mask provider cannot be the zero address'
    if (seen.has(key)) return `${provider} is listed twice`
    seen.add(key)
  }
  return null
}

/**
 * The request's `customParams`: `abi.encode(uint8 auctionType, uint8 levels, uint256[16] prices,
 * string title, address gate, bytes gateConfig, address[] providers)`. `levels` is `prices.length`;
 * the contract wants the unused prices to be zero, so they are padded. With the zero `gate` anyone
 * may bid, and `gateConfig` must be empty. Otherwise the contract calls
 * `gate.configure(e3Id, gateConfig)`. `providers` are the mask providers (see `providersError`).
 */
export function encodeAuctionParams(
  type: AuctionType,
  prices: PriceList,
  title: string,
  gate: Address = zeroAddress,
  gateConfig: Hex = '0x',
  providers: readonly Address[] = [],
): Hex {
  const error = priceListError(prices) ?? providersError(type, providers)
  if (error) throw new Error(error)
  const padded = [...prices, ...Array.from({ length: LEVELS - prices.length }, () => 0n)]
  const abi: readonly AbiParameter[] = parseAbiParameters('uint8, uint8, uint256[16], string, address, bytes, address[]')
  return encodeAbiParameters(abi, [type, prices.length, padded, title, gate, gateConfig, providers])
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
 * The `data` of `AuctionProgram.publishInput` for the mask of a provider of a `ProviderSecondPrice`
 * auction: the encoding of `encodeBidInput` with the provider as `bidder`, one ciphertext and one
 * commitment, and an empty `gateProof` and `signature`.
 */
export function encodeMaskInput(input: { provider: Address; ciphertext: Hex; commitment: Hex; proof: Hex }): Hex {
  return encodeBidInput({
    bidder: input.provider,
    ciphertexts: [input.ciphertext],
    commitments: [input.commitment],
    proof: input.proof,
    gateProof: '0x',
    signature: '0x',
  })
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
  /** A share of the no-provider auction: uniform in every slot, as a mask. The program adds the shares of all bids. */
  Share = 3,
}

const ROLES_BY_TYPE: Record<AuctionType, readonly Role[]> = {
  [AuctionType.FirstPrice]: [Role.Ge, Role.Gt, Role.Mask],
  [AuctionType.ProviderSecondPrice]: [Role.Ge, Role.Gt],
  [AuctionType.QnrSecondPrice]: [Role.Ge, Role.Gt, Role.Share, Role.Share],
}

/** The roles, in leaf order, of the ciphertexts one bidder submits to an auction of `type`. */
export function rolesFor(type: AuctionType): readonly Role[] {
  return ROLES_BY_TYPE[type]
}

export const ROLE_LABELS: Record<Role, string> = {
  [Role.Ge]: 'Bid thermometer (at least)',
  [Role.Gt]: 'Bid thermometer (above)',
  [Role.Mask]: 'Random mask',
  [Role.Share]: 'Random share',
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

/** The SIMD slot values of one ciphertext of a bid. The masks and the shares ignore `bid`. */
export function bidSlots(role: Role, bid: number): BigUint64Array {
  const slots = new BigUint64Array(DEGREE)
  if (role === Role.Mask || role === Role.Share) {
    for (let i = 0; i < DEGREE; i++) slots[i] = randomSlot()
    return slots
  }
  assertBid(bid)
  for (let i = 0; i < DEGREE; i++) {
    const level = i % LEVELS
    slots[i] = BigInt(role === Role.Ge ? bid >= level : bid > level)
  }
  return slots
}

/** The slot of `level` in the region of bidder position `region`. */
export function slotIndex(region: number, level: number): number {
  return region * LEVELS + level
}

function assertBidderCount(type: AuctionType, bidders: number): void {
  const max = MAX_BIDDERS_BY_TYPE[type]
  if (bidders < MIN_BIDDERS || bidders > max) {
    throw new Error(`An auction of this type has ${MIN_BIDDERS} to ${max} bidders, got ${bidders}`)
  }
}

/**
 * The winner and the price on the plaintext bids. The highest bid wins, and a tie goes to the
 * lowest position. The price is the highest bid (first-price) or the second-highest bid
 * (`ProviderSecondPrice` and `QnrSecondPrice`).
 */
export function expectedAuction(type: AuctionType, bids: readonly number[]): { winner: number; price: number } {
  assertBidderCount(type, bids.length)
  const order = bids.map((_, position) => position).sort((a, b) => bids[b] - bids[a] || a - b)
  return { winner: order[0], price: bids[order[type === AuctionType.FirstPrice ? 0 : 1]] }
}

/** What the published result of an auction shows. Region `k` is the region of bidder position `k`. */
export interface RegionResult {
  /** Number of bidders in the round. */
  bidders: number
  /** The price the winner pays (see `expectedAuction`), or `null` if the result is unreadable. */
  price: number | null
  /** The winning bidder position, or `null` if the result does not show one winner. */
  winner: number | null
  /** `set[j][level]`: whether the region of bidder position `j` is non-zero at `level`. */
  set: boolean[][]
  /** Whether the slots from `16 n` on are zero, as the program makes them. */
  unusedGroupsZero: boolean
}

/**
 * Decode the published plaintext of an auction.
 *
 * @param type The auction type, as `AuctionProgram.auctions` stores it.
 * @param plaintextHex The plaintext output: `OUTPUT_COEFFS` little-endian u64 coefficients.
 * @param bidders The number of counted bids. Bidder position `j` is the place of the `j`-th counted
 * bid in leaf order.
 */
export async function decodeAuction(type: AuctionType, plaintextHex: string, bidders: number): Promise<RegionResult> {
  assertBidderCount(type, bidders)
  const hex = plaintextHex.startsWith('0x') ? plaintextHex.slice(2) : plaintextHex
  if (hex.length < OUTPUT_COEFFS * 16) {
    throw new Error(`Plaintext output has ${hex.length / 2} bytes, expected ${OUTPUT_COEFFS * 8}`)
  }
  const slots = await decodePlaintextSlots(`0x${hex}`, PRESET)
  if (slots.length < DEGREE) throw new Error(`Decoded ${slots.length} slots, expected ${DEGREE}`)
  return type === AuctionType.FirstPrice ? decodeFirstPrice(slots, bidders) : decodeSecondPrice(slots, bidders)
}

/** The non-zero pattern of the `n` regions (region `k` at slots `16 k .. 16 k + 15`), and whether the slots beyond them are zero. */
function readRegions(slots: readonly bigint[], n: number): { set: boolean[][]; unusedGroupsZero: boolean } {
  const set = Array.from({ length: n }, (_, region) => Array.from({ length: LEVELS }, (_, level) => slots[slotIndex(region, level)] !== 0n))
  let unusedGroupsZero = true
  for (let slot = n * LEVELS; slot < DEGREE; slot++) if (slots[slot] !== 0n) unusedGroupsZero = false
  return { set, unusedGroupsZero }
}

/**
 * Read a first-price auction. The price is the highest level where some region is non-zero, and the
 * winner is the first region that is non-zero there. It must hold exactly 1, and the regions before it
 * are zero by the choice of the winner. The result is read only if the slots beyond the `n` regions are
 * zero. Any other pattern gives no price and no winner.
 *
 * The program makes every slot above the price zero, the regions before the winner zero at the
 * price, and the winner's slot at the price exactly 1 (the mask only touches slots where `G + E >= 1`),
 * so a valid output always matches this rule, whatever the masks hold.
 */
function decodeFirstPrice(slots: readonly bigint[], n: number): RegionResult {
  const { set, unusedGroupsZero } = readRegions(slots, n)
  let price: number | null = null
  let winner: number | null = null
  const lasts = set.map((row) => row.lastIndexOf(true)).filter((level) => level >= 0)
  if (unusedGroupsZero && lasts.length > 0) {
    const level = Math.max(...lasts)
    const first = set.findIndex((row) => row[level])
    if (slots[slotIndex(first, level)] === 1n) {
      price = level
      winner = first
    }
  }
  return { bidders: n, price, winner, set, unusedGroupsZero }
}

/**
 * Read a second-price auction (`ProviderSecondPrice`, `QnrSecondPrice`): region `k` at slots `16 k .. 16 k + 15`.
 * The pattern is strict. The result is read only if the slots beyond the `n` regions are zero, no
 * slot above the price is non-zero, exactly one region is zero at the price, and every slot below
 * the price is non-zero. Any other pattern gives no price and no winner.
 *
 * The masks are proven non-zero (the shares always give a non-zero factor) and every test is below
 * the plaintext modulus, so no non-zero slot is ever read as zero: a valid output always matches the
 * pattern.
 */
function decodeSecondPrice(slots: readonly bigint[], n: number): RegionResult {
  const { set, unusedGroupsZero } = readRegions(slots, n)
  let price: number | null = null
  let winner: number | null = null
  // The price is the highest level at which some region is non-zero.
  const lasts = set.map((row) => row.lastIndexOf(true)).filter((level) => level >= 0)
  if (unusedGroupsZero && lasts.length > 0) {
    const level = Math.max(...lasts)
    const winners = set.flatMap((row, region) => (row[level] ? [] : [region]))
    const belowSet = set.every((row) => row.slice(0, level).every(Boolean))
    if (winners.length === 1 && belowSet) {
      price = level
      winner = winners[0]
    }
  }
  return { bidders: n, price, winner, set, unusedGroupsZero }
}

export { bytesToHex }
