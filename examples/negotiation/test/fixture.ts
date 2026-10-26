// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import hre from 'hardhat'
import type { Hex } from 'viem'
import type { HardhatEthers, HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/types'
import type { Wallet } from 'ethers'
import { MockInterfold__factory, MockOfferVerifier__factory } from '../types/factories/contracts/mocks'
import { NegotiationProgram__factory } from '../types/factories/contracts'
import type { NegotiationProgram } from '../types/contracts'
import type { MockInterfold, MockOfferVerifier } from '../types/contracts/mocks'
import { encodeNegotiationParams, encodeOfferInput, offerInputsHash, offerTypedData } from '../sdk/src/negotiation'
import { bytes32, filled } from './helpers'

export const E3_ID = 7n
/** The committee key commitment of the mock E3. */
export const KEY = filled(0xab)
export const VK_ANCHOR = filled(0xcd)
export const LEVELS = 8
export const MIN_PRICE = 1_000n
export const STEP_PRICE = 50n
export const TITLE = 'Unit test negotiation'
export const SELLER_ROLE = 0
export const BUYER_ROLE = 1

/** What a test needs: the contracts, the actors and the helpers to run a negotiation. */
export interface Fixture {
  ethers: HardhatEthers
  creator: HardhatEthersSigner
  seller: HardhatEthersSigner
  buyer: HardhatEthersSigner
  relayer: HardhatEthersSigner
  stranger: HardhatEthersSigner
  program: NegotiationProgram
  programAddress: Hex
  interfold: MockInterfold
  offerVerifier: MockOfferVerifier
  chainId: number
}

/** Deploys the program with a mock verifier and a mock Interfold, and no negotiation. */
export async function deployFixture(): Promise<Fixture> {
  const { ethers } = await hre.network.connect()
  const [creator, seller, buyer, relayer, stranger] = await ethers.getSigners()
  const interfold = await ethers.deployContract('MockInterfold')
  const receiptVerifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
  const availability = await ethers.deployContract('MockDataAvailabilityVerifier')
  const offerVerifier = await ethers.deployContract('MockOfferVerifier')
  const poseidon = await ethers.deployContract('PoseidonT3')
  const factory = await ethers.getContractFactory(
    NegotiationProgram__factory.abi,
    NegotiationProgram__factory.linkBytecode({
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': await poseidon.getAddress(),
    }),
    creator,
  )
  const deployed = await factory.deploy(
    await interfold.getAddress(),
    await receiptVerifier.getAddress(),
    await receiptVerifier.imageId(),
    await offerVerifier.getAddress(),
    VK_ANCHOR,
    await availability.getAddress(),
  )
  const programAddress = (await deployed.getAddress()) as Hex
  return {
    ethers,
    creator,
    seller,
    buyer,
    relayer,
    stranger,
    program: NegotiationProgram__factory.connect(programAddress, creator),
    programAddress,
    interfold: MockInterfold__factory.connect(await interfold.getAddress(), creator),
    offerVerifier: MockOfferVerifier__factory.connect(await offerVerifier.getAddress(), creator),
    chainId: Number((await ethers.provider.getNetwork()).chainId),
  }
}

export interface RequestOptions {
  e3Id?: bigint
  seller?: string
  buyer?: string
  levels?: number
  minPrice?: bigint
  stepPrice?: bigint
  title?: string
  inputDeadline?: bigint
}

/** The `customParams` of a negotiation between the fixture's seller and buyer. */
export function negotiationParams(fixture: Fixture, options: RequestOptions = {}): Hex {
  return encodeNegotiationParams({
    seller: (options.seller ?? fixture.seller.address) as Hex,
    buyer: (options.buyer ?? fixture.buyer.address) as Hex,
    levels: options.levels ?? LEVELS,
    minPrice: options.minPrice ?? MIN_PRICE,
    stepPrice: options.stepPrice ?? STEP_PRICE,
    title: options.title ?? TITLE,
  })
}

/** Sets the mock E3 up and returns the request: `tx()` makes Interfold call `validate`. */
export async function requestNegotiation(fixture: Fixture, options: RequestOptions = {}) {
  const e3Id = options.e3Id ?? E3_ID
  await (await fixture.interfold.setE3(e3Id, options.inputDeadline ?? 2n ** 40n, KEY, fixture.creator.address)).wait()
  const params = negotiationParams(fixture, options)
  return { e3Id, params, tx: () => fixture.interfold.request(e3Id, fixture.programAddress, params) }
}

/** Requests a negotiation and waits for it. */
export async function createNegotiation(fixture: Fixture, options: RequestOptions = {}): Promise<bigint> {
  const { e3Id, tx } = await requestNegotiation(fixture, options)
  await (await tx()).wait()
  return e3Id
}

/** An offer of one party: bytes that stand for three ciphertexts, their commitments and a proof. */
export interface Offer {
  party: Hex
  ciphertexts: Hex[]
  commitments: Hex[]
  proof: Hex
}

/** The offer of `party`. The seed makes the bytes differ between offers. */
export function makeOffer(party: string, seed: number): Offer {
  const byte = (n: number) => (n % 256).toString(16).padStart(2, '0')
  return {
    party: party as Hex,
    ciphertexts: [0, 1, 2].map((r) => `0x${byte(seed * 3 + r).repeat(16 + r)}` as Hex),
    commitments: [0, 1, 2].map((r) => filled((seed * 3 + r + 1) % 256)),
    proof: '0x01',
  }
}

/** The public inputs of the offer proof, in the order of `circuits/PUBLIC_INPUTS.md`. */
export function offerPublicInputs(offer: Offer, role: number, levels = LEVELS): Hex[] {
  return [...offer.commitments, bytes32(BigInt(offer.party)), bytes32(role), bytes32(levels), KEY, VK_ANCHOR]
}

/** The EIP-712 signature of a relayed offer. */
export async function signOffer(fixture: Fixture, signer: Wallet | HardhatEthersSigner, e3Id: bigint, offer: Offer): Promise<Hex> {
  const typed = offerTypedData(
    fixture.chainId,
    fixture.programAddress,
    e3Id,
    offer.party,
    offerInputsHash(offer.commitments, offer.ciphertexts),
  )
  return (await signer.signTypedData(typed.domain, { Offer: [...typed.types.Offer] }, typed.message)) as Hex
}

/** The data of `publishInput` for `offer`, with an optional signature. */
export const offerData = (offer: Offer, signature?: Hex): Hex => encodeOfferInput({ ...offer, signature })

/** The seller or the buyer sends its offer directly. */
export async function submit(fixture: Fixture, signer: HardhatEthersSigner, offer: Offer, e3Id = E3_ID) {
  return (await fixture.program.connect(signer).publishInput(e3Id, offerData(offer))).wait()
}
