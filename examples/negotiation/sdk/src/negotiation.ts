// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The encoders of the `NegotiationProgram` contract (`contracts/NegotiationProgram.sol`): the parameters of a
 * negotiation, the data of `publishInput`, the EIP-712 message of a relayed offer, the leaves of the input tree,
 * and the ABI fragments that the client and the server read. `README.md` ("Contracts") describes the interface.
 */
import { type Address, type Hex, encodeAbiParameters, keccak256, parseAbi, parseAbiParameters, sha256, toHex } from 'viem'

/** The ciphertexts of one offer: lanes 0 to 7, lanes 8 to 15 and the mask. */
export const OFFER_CIPHERTEXT_COUNT = 3

/** The prefix of the configuration input (input 0 of the program). `NegotiationProgram.CONFIG_DOMAIN` is the same bytes. */
export const CONFIG_DOMAIN = 'interfold-negotiation-config-v1'

/** The field of the input leaves: the BN254 scalar field. */
export const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** The EIP-712 domain name and version of the contract. */
export const OFFER_DOMAIN_NAME = 'NegotiationProgram'
export const OFFER_DOMAIN_VERSION = '1'

/** The EIP-712 type of a relayed offer. */
export const OFFER_TYPES = {
  Offer: [
    { name: 'e3Id', type: 'uint256' },
    { name: 'party', type: 'address' },
    { name: 'inputsHash', type: 'bytes32' },
  ],
} as const

/** The ABI that the client and the server need: the events, the views, `publishInput`, `settle` and the errors. */
export const negotiationProgramAbi = parseAbi([
  'event NegotiationCreated(uint256 indexed e3Id, address indexed creator, address indexed seller, address buyer, uint8 levels, uint256 minPrice, uint256 stepPrice, string title)',
  'event OfferSubmitted(uint256 indexed e3Id, address indexed party, uint8 role, uint256 firstLeaf, bytes[] ciphertexts, bytes32[] commitments)',
  'event BuyerJoined(uint256 indexed e3Id, address indexed buyer)',
  'event Settled(uint256 indexed e3Id, bool matched, uint8 step, uint256 price)',
  'function negotiation(uint256 e3Id) view returns (address creator, address seller, address buyer, uint8 levels, uint256 minPrice, uint256 stepPrice, string title)',
  'function offerSubmitted(uint256 e3Id, uint8 role) view returns (bool)',
  'function outcome(uint256 e3Id) view returns (bool settled, bool matched, uint8 step, uint256 price)',
  'function offerDigest(uint256 e3Id, address party, bytes32 inputsHash) view returns (bytes32)',
  'function configLeaf() pure returns (uint256)',
  'function inputLeaf(bytes32 ciphertextHash, bytes32 commitment, address party, uint8 role, uint8 index) pure returns (uint256)',
  'function publishInput(uint256 e3Id, bytes data)',
  'function settle(uint256 e3Id)',
  'error AlreadySettled()',
  'error AlreadySubmitted(address party, uint8 role)',
  'error CoefficientOutOfRange(uint256 index)',
  'error E3DoesNotExist()',
  'error EmptyInputData()',
  'error InputDeadlineReached()',
  'error InvalidLevels(uint8 levels)',
  'error InvalidOfferProof()',
  'error InvalidOfferShape()',
  'error InvalidOutput()',
  'error InvalidParties()',
  'error InvalidPlaintextLength(uint256 length)',
  'error InvalidPrices()',
  'error InvalidSignature(address party)',
  'error NotAParty(address party)',
  'error OutputNotPublished()',
  'error SenderNotParty(address sender, address party)',
])

/** The public terms of a negotiation: the `customParams` of the E3 request. */
export interface NegotiationParams {
  seller: Address
  /** The zero address leaves the buyer seat open: the first valid buyer offer of a wallet other than the seller takes it. */
  buyer: Address
  /** The price levels, 2 to 16. */
  levels: number
  /** The price of level 0. */
  minPrice: bigint
  /** The price difference between two levels. */
  stepPrice: bigint
  title: string
}

/** `abi.encode(address seller, address buyer, uint8 levels, uint256 minPrice, uint256 stepPrice, string title)`. */
export function encodeNegotiationParams(params: NegotiationParams): Hex {
  return encodeAbiParameters(
    parseAbiParameters('address seller, address buyer, uint8 levels, uint256 minPrice, uint256 stepPrice, string title'),
    [params.seller, params.buyer, params.levels, params.minPrice, params.stepPrice, params.title],
  )
}

/** What a party sends with `publishInput`. */
export interface OfferInput {
  party: Address
  /** The three ciphertexts, in the order of `DESIGN.md`. */
  ciphertexts: readonly Hex[]
  /** The ciphertext commitment of each ciphertext. */
  commitments: readonly Hex[]
  /** The Honk proof of `negotiation_offer`. */
  proof: Hex
  /** The EIP-712 signature of `party` for a relayed offer, `0x` for a direct one. */
  signature?: Hex
}

function assertShape(ciphertexts: readonly Hex[], commitments: readonly Hex[]): void {
  if (ciphertexts.length !== OFFER_CIPHERTEXT_COUNT || commitments.length !== OFFER_CIPHERTEXT_COUNT) {
    throw new Error(
      `an offer has ${OFFER_CIPHERTEXT_COUNT} ciphertexts and ${OFFER_CIPHERTEXT_COUNT} commitments, got ${ciphertexts.length} and ${commitments.length}`,
    )
  }
}

/** The data of `publishInput`: `abi.encode(address party, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes signature)`. */
export function encodeOfferInput(input: OfferInput): Hex {
  assertShape(input.ciphertexts, input.commitments)
  return encodeAbiParameters(
    parseAbiParameters('address party, bytes[] ciphertexts, bytes32[] commitments, bytes proof, bytes signature'),
    [input.party, [...input.ciphertexts], [...input.commitments], input.proof, input.signature ?? '0x'],
  )
}

/**
 * What a relayed offer signs: `keccak256(abi.encode(commitments, keccak256(ciphertexts[0]), keccak256(ciphertexts[1]),
 * keccak256(ciphertexts[2])))`. A relayer cannot swap a commitment or a ciphertext.
 */
export function offerInputsHash(commitments: readonly Hex[], ciphertexts: readonly Hex[]): Hex {
  assertShape(ciphertexts, commitments)
  const [h0, h1, h2] = ciphertexts.map((ciphertext) => keccak256(ciphertext))
  return keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32[] commitments, bytes32 hash0, bytes32 hash1, bytes32 hash2'), [
      [...commitments],
      h0,
      h1,
      h2,
    ]),
  )
}

/** The EIP-712 typed data that `party` signs (`signTypedData`) to let a relayer send its offer. */
export function offerTypedData(chainId: number | bigint, program: Address, e3Id: bigint, party: Address, inputsHash: Hex) {
  return {
    domain: { name: OFFER_DOMAIN_NAME, version: OFFER_DOMAIN_VERSION, chainId: BigInt(chainId), verifyingContract: program },
    types: OFFER_TYPES,
    primaryType: 'Offer' as const,
    message: { e3Id, party, inputsHash },
  }
}

/** Leaf 0 of the input tree: `keccak256(CONFIG_DOMAIN) mod BN254`. */
export function configLeaf(): bigint {
  return BigInt(keccak256(toHex(CONFIG_DOMAIN))) % SNARK_SCALAR_FIELD
}

/**
 * The leaf of ciphertext `index` (0 to 2) of an offer: `sha256(keccak256(ciphertext) || commitment || party ||
 * uint40(role * 256 + index)) mod BN254`. The 25 bytes `party || uint40` are the metadata of the leaf.
 */
export function inputLeaf(input: { ciphertext: Hex; commitment: Hex; party: Address; role: number; index: number }): bigint {
  const { ciphertext, commitment, party, role, index } = input
  if (!Number.isInteger(role) || role < 0 || role > 1) throw new Error(`the role must be 0 or 1, got ${role}`)
  if (!Number.isInteger(index) || index < 0 || index >= OFFER_CIPHERTEXT_COUNT) throw new Error(`the index must be 0 to 2, got ${index}`)
  const metadata = BigInt(role) * 256n + BigInt(index)
  const packed =
    `0x${keccak256(ciphertext).slice(2)}${commitment.slice(2)}${party.slice(2)}${metadata.toString(16).padStart(10, '0')}` as Hex
  return BigInt(sha256(packed)) % SNARK_SCALAR_FIELD
}
