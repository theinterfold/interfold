// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The on-chain encoding of an auction: the request parameters, the configuration input (leaf 0 of
 * the tree), the `publishInput` data of a bid, and the EIP-712 message of a relayed bid. Every
 * function here has a counterpart in `contracts/AuctionProgram.sol` or `program/src/lib.rs`.
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
import { AuctionType, LEVELS, MIN_LEVELS } from './layout'

/** The most mask providers of an auction. `AuctionProgram.MAX_PROVIDERS`. */
export const MAX_PROVIDERS = 4

/**
 * The bid version of a mask in the 25-byte metadata of its leaf (`provider || uint40(version)`):
 * `uint32` max. A bid has the versions 1 to `MAX_BIDS_PER_BIDDER`. `AuctionProgram.MASK_VERSION`.
 */
export const MASK_VERSION = 0xffffffff

/** The domain prefix of the configuration input. `AuctionProgram.CONFIG_DOMAIN` and the program use the same bytes. */
export const AUCTION_CONFIG_DOMAIN = 'interfold-auction-config-v1'

/**
 * Find out why `providers` is not a valid list of mask providers for an auction of `type`.
 * `AuctionProgram` applies the same rules: a `ProviderSecondPrice` auction has 1 to
 * {@link MAX_PROVIDERS} providers, each a non-zero address, with no address twice (case does not
 * matter). Every other type has none.
 *
 * @param type The auction type.
 * @param providers The mask provider addresses.
 * @returns The reason as a sentence, or `null` when the list is valid.
 */
export function providersError(type: AuctionType, providers: readonly Address[]): string | null {
  if (type !== AuctionType.ProviderSecondPrice) {
    return providers.length === 0 ? null : 'Only an auction with mask providers has providers'
  }
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
 * The configuration input of an auction, leaf 0 of its tree: the domain bytes, the type byte and the
 * mask providers as 20 raw bytes each (`AuctionProgram.configInput`: not the 32-byte words of
 * `abi.encodePacked(address[])`). The leaf is `keccak256(input) mod BN254`, which
 * `AuctionProgram.validate` inserts. Types other than `ProviderSecondPrice` have no providers, so
 * their input is the domain and the type byte only.
 *
 * @param type The auction type.
 * @param providers The mask providers, in the order of the request. Empty for every type except `ProviderSecondPrice`.
 * @returns The input bytes as hex.
 * @throws When {@link providersError} finds a problem with `providers`.
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
 * The price of each step: 2 to `LEVELS` strictly increasing whole numbers. Step `b` costs `prices[b]`.
 * The creator picks the length, `levels`. The bid circuit rejects a bid `b >= levels`.
 */
export type PriceList = readonly bigint[]

/**
 * Find out why `prices` is not a valid price list. The contract applies the same rules to `uint256` values.
 *
 * @param prices The price of each step, in the smallest unit of the fee token.
 * @returns The reason as a sentence, or `null` when the list is valid.
 */
export function priceListError(prices: PriceList): string | null {
  if (prices.length < MIN_LEVELS || prices.length > LEVELS) {
    return `A price list has ${MIN_LEVELS} to ${LEVELS} prices, got ${prices.length}`
  }
  if (prices.some((price) => price < 0n || price > maxUint256)) return 'A price is a whole number from 0 to 2^256 - 1'
  const flat = prices.findIndex((price, level) => level > 0 && price <= prices[level - 1])
  if (flat > 0) return `Prices must increase: step ${flat} (${prices[flat]}) is not above step ${flat - 1} (${prices[flat - 1]})`
  return null
}

/**
 * Build an evenly spaced price list: step `b` costs `start + b * step`.
 *
 * @param start The price of step 0.
 * @param step The difference between two steps.
 * @param count The number of steps.
 */
export function evenPrices(start: bigint, step: bigint, count: number): bigint[] {
  return Array.from({ length: count }, (_, level) => start + BigInt(level) * step)
}

/**
 * Encode the `customParams` of an E3 request: `abi.encode(uint8 auctionType, uint8 levels,
 * uint256[16] prices, string title, address gate, bytes gateConfig, address[] providers)`.
 * `levels` is `prices.length`. The contract wants the unused prices to be zero, so they are padded.
 * With the zero `gate` anyone may bid, and `gateConfig` must be empty. Otherwise the contract calls
 * `gate.configure(e3Id, gateConfig)`.
 *
 * @param type The auction type.
 * @param prices The price list (see {@link priceListError}).
 * @param title The title of the auction.
 * @param gate The bidder gate contract. The zero address means no gate.
 * @param gateConfig The configuration that the gate receives.
 * @param providers The mask providers (see {@link providersError}).
 * @returns The ABI-encoded parameters.
 * @throws When the price list or the provider list is invalid.
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
 * Read the price list of an auction from the contract's `levels` and its zero-padded `uint256[16]`
 * prices (the last getter value and the event `prices` of `AuctionProgram`).
 *
 * @param levels The number of price steps.
 * @param prices The zero-padded prices.
 * @returns The first `levels` prices.
 * @throws When `levels` is not an integer in `[MIN_LEVELS, LEVELS]`.
 */
export function readPriceList(levels: number | bigint, prices: readonly bigint[]): bigint[] {
  const count = Number(levels)
  if (!Number.isInteger(count) || count < MIN_LEVELS || count > LEVELS) {
    throw new Error(`levels must be an integer in [${MIN_LEVELS}, ${LEVELS}], got ${levels}`)
  }
  return prices.slice(0, count)
}

/** What a bid publishes. `AuctionProgram.publishInput` decodes it. */
export interface BidInput {
  /** The address that is the bidder of the bid. */
  bidder: Address
  /** One ciphertext for each role, in role order. */
  ciphertexts: readonly Hex[]
  /** One `bytes32` SAFE commitment for each ciphertext, in role order. */
  commitments: readonly Hex[]
  /** The bid proof. */
  proof: Hex
  /** What the gate of the auction asks for. `0x` when the auction has no gate. */
  gateProof: Hex
  /** The EIP-712 signature of the bidder ({@link bidTypedData}) for a relayed bid. `0x` for a direct bid. */
  signature: Hex
}

/**
 * Encode the `data` of `AuctionProgram.publishInput`:
 * `abi.encode(address bidder, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes gateProof, bytes signature)`.
 *
 * @param input The fields of the bid.
 */
export function encodeBidInput(input: BidInput): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('address, bytes[], bytes32[], bytes, bytes, bytes')
  return encodeAbiParameters(abi, [input.bidder, input.ciphertexts, input.commitments, input.proof, input.gateProof, input.signature])
}

/**
 * Compute `keccak256(abi.encode(commitments, ciphertextHashes))` with
 * `ciphertextHashes[r] = keccak256(ciphertexts[r])`. A relayed bid signs the result, so a relayer
 * cannot swap the bytes.
 *
 * @param commitments The commitment of each ciphertext, in role order.
 * @param ciphertexts The ciphertext bytes, in role order.
 */
export function bidInputsHash(commitments: readonly Hex[], ciphertexts: readonly Hex[]): Hex {
  const abi: readonly AbiParameter[] = parseAbiParameters('bytes32[], bytes32[]')
  return keccak256(encodeAbiParameters(abi, [commitments, ciphertexts.map((ciphertext) => keccak256(ciphertext))]))
}

/**
 * Build the EIP-712 message that the bidder signs to let a relayer send a bid
 * (`AuctionProgram.bidDigest`). Pass the result to `signTypedData`.
 *
 * @param chainId The chain id.
 * @param program The address of `AuctionProgram`.
 * @param e3Id The id of the E3.
 * @param bidder The bidder address.
 * @param version The version that the bid will get: `bidCount + 1`.
 * @param inputsHash The result of {@link bidInputsHash}.
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
