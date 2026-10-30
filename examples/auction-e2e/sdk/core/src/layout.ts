// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The slot encoding that the bidders, the bid circuits, the FHE program (`program/src/lib.rs`) and
 * the result decoders share.
 *
 * All ciphertexts are SIMD-encoded over the 128 slots of the ring. Slot `i` has level `i % LEVELS`,
 * and a bid `b` is in `[0, LEVELS)`. A bidder sends 2 to 4 ciphertexts, one for each role of the
 * auction type (see {@link rolesFor}). The ciphertexts depend on neither the position of the bidder
 * nor the number of bidders:
 *
 *   role 0 (ge)     slot i  [b >= i % LEVELS]
 *   role 1 (gt)     slot i  [b >  i % LEVELS]
 *   role 2 (mask)   slot i  uniform in [0, PLAINTEXT_MODULUS) (first price only)
 *   role 3 (share)  slot i  uniform in [0, PLAINTEXT_MODULUS), as a mask (no-provider second price only)
 *
 * Every type has ONE copy of the regions, for 2 to 8 bidders: region `k` belongs to the bidder at
 * position `k` and is the slots `16 k .. 16 k + 15`. The slots from `16 n` on are ZERO.
 *
 * Leaf 0 of every auction is a configuration input, not a ciphertext: see {@link auctionConfigInput}.
 * In a provider auction the leaves 1 to k are the masks, one per provider in the order of
 * submission, with the version {@link MASK_VERSION}; the bids follow. Every bid, and every update of
 * it, adds one run of `rolesFor(type).length` consecutive leaves in role order. A leaf binds the
 * ciphertext bytes, the commitment the bid proof checked, the bidder and the bid version.
 */

/** Polynomial degree, and so the slot count, of the insecure SIMD preset (param set 5). */
export const DEGREE = 128
/** Plaintext modulus of the same preset: prime, 1 mod 2 * DEGREE, so it supports SIMD. */
export const PLAINTEXT_MODULUS = 257
/** The preset name the SDK and the program use. */
export const PRESET = 'INSECURE_THRESHOLD_SIMD' as const
/** The l-BFV parameter set of the preset: param set 5. */
export const PARAM_SET = 5
/** The number of levels, which is the period of a thermometer. A bid is in `[0, LEVELS)`. */
export const LEVELS = 16
/** The fewest price steps an auction can have. */
export const MIN_LEVELS = 2
/** The groups of `LEVELS` slots in the ring. One group is the region of one bidder. */
export const GROUPS = DEGREE / LEVELS
/** The fewest bidders an auction needs to produce a result. */
export const MIN_BIDDERS = 2
/** The most bidders of one auction: the {@link GROUPS} of the ring. The limit is the same for every type. */
export const MAX_BIDDERS = GROUPS
/** The most bids of one bidder: the first bid and two updates. `AuctionProgram.MAX_BIDS_PER_BIDDER`. */
export const MAX_BIDS_PER_BIDDER = 3
/** Coefficients the committee publishes after decryption for this preset. */
export const OUTPUT_COEFFS = 128

/** What the auction reveals. The values are the `uint8` that the contract and the program use. */
export enum AuctionType {
  /** The highest bid wins and pays its own bid. One lane for each bidder. */
  FirstPrice = 0,
  /** The highest bid wins and pays the second-highest bid. Mask providers send the masks. */
  ProviderSecondPrice = 1,
  /** The highest bid wins and pays the second-highest bid. No mask providers: the bidders send random shares. */
  QnrSecondPrice = 2,
}

/** Every {@link AuctionType}, in order of the type id. */
export const AUCTION_TYPES = [AuctionType.FirstPrice, AuctionType.ProviderSecondPrice, AuctionType.QnrSecondPrice] as const

/** Whether `value` is the id of a known {@link AuctionType}. */
export function isAuctionType(value: number): value is AuctionType {
  return (AUCTION_TYPES as readonly number[]).includes(value)
}

/** The role of one ciphertext of a bid. The role sets the slot values of the ciphertext. */
export enum Role {
  /** The thermometer `[b >= level]`. */
  Ge = 0,
  /** The thermometer `[b > level]`. */
  Gt = 1,
  /** A random mask of the first-price auction: uniform in every slot. */
  Mask = 2,
  /** A share of the no-provider auction: uniform in every slot, as a mask. The program adds the shares of all bids. */
  Share = 3,
}

const ROLES_BY_TYPE: Record<AuctionType, readonly Role[]> = {
  [AuctionType.FirstPrice]: [Role.Ge, Role.Gt, Role.Mask],
  [AuctionType.ProviderSecondPrice]: [Role.Ge, Role.Gt],
  [AuctionType.QnrSecondPrice]: [Role.Ge, Role.Gt, Role.Share, Role.Share],
}

/**
 * The roles, in leaf order, of the ciphertexts that one bidder submits to an auction of `type`.
 * The number of roles is the number of ciphertexts of a bid.
 */
export function rolesFor(type: AuctionType): readonly Role[] {
  return ROLES_BY_TYPE[type]
}

/** A short English name of each {@link Role}, for display. */
export const ROLE_LABELS: Record<Role, string> = {
  [Role.Ge]: 'Bid thermometer (at least)',
  [Role.Gt]: 'Bid thermometer (above)',
  [Role.Mask]: 'Random mask',
  [Role.Share]: 'Random share',
}

/**
 * Check that `bid` is a valid bid step.
 *
 * @param bid The bid step.
 * @throws When `bid` is not an integer in `[0, LEVELS)`.
 */
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
 * The SIMD slot values of one ciphertext of a bid.
 *
 * @param role The role of the ciphertext. The roles {@link Role.Mask} and {@link Role.Share} give uniform random slots and ignore `bid`.
 * @param bid The bid step, in `[0, LEVELS)`. The step is not read for the random roles.
 * @returns `DEGREE` slot values, each in `[0, PLAINTEXT_MODULUS)`.
 * @throws When `role` is a thermometer and `bid` is not an integer in `[0, LEVELS)`.
 */
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

/**
 * The slot of `level` in the region of a bidder position.
 *
 * @param region The bidder position, from 0.
 * @param level The price step, in `[0, LEVELS)`.
 * @returns The slot index, `region * LEVELS + level`.
 */
export function slotIndex(region: number, level: number): number {
  return region * LEVELS + level
}

/** The description of one auction design, as the design packages export it. */
export interface AuctionDesign {
  /** The on-chain type id. */
  type: AuctionType
  /** The short identifier of the design, for example `first-price`. */
  name: string
  /** The display name of the design. */
  label: string
  /** A short description of the rules, for display. */
  description: string
  /** The roles of the ciphertexts of one bid, in leaf order. */
  roles: readonly Role[]
  /** The number of ciphertexts of one bid. */
  ciphertextsPerBid: number
  /** Whether the auction names mask providers: `'required'` (1 to 4 providers) or `'none'`. */
  providers: 'none' | 'required'
  /** What the published result reveals. */
  reveals: string
  /** What the participants trust. */
  trust: string
}
