// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import hre from 'hardhat'
import { type Hex, zeroAddress } from 'viem'
import type { HardhatEthers, HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/types'
import type { Wallet } from 'ethers'
import { MockInterfold__factory, MockSaleToken__factory, MockPaymentToken__factory } from '../types/factories/contracts/mocks'
import { SealedCcaProgram__factory } from '../types/factories/contracts'
import { type SaleParams, encodeSaleParams, filled } from './helpers'

export const E3_ID = 7n
export const KEY = filled(0xab)
export const VK_ANCHOR = filled(0xcd)
export const U18 = 10n ** 18n
/** Prices in USDC base units per whole sale token: 1.00, 2.00, 3.00 and 4.00 USDC. */
export const PRICES = [1_000_000n, 2_000_000n, 3_000_000n, 4_000_000n]
export const SUPPLY = 100n * U18
export const ESCROW = 50_000_000n

/** What a test needs: the contracts, the actors and the helpers to run a sale. */
export interface Fixture {
  ethers: HardhatEthers
  creator: HardhatEthersSigner
  actors: HardhatEthersSigner[]
  relayer: HardhatEthersSigner
  program: ReturnType<typeof SealedCcaProgram__factory.connect>
  programAddress: Hex
  interfold: ReturnType<typeof MockInterfold__factory.connect>
  saleToken: ReturnType<typeof MockSaleToken__factory.connect>
  usdc: ReturnType<typeof MockPaymentToken__factory.connect>
  bidVerifier: Awaited<ReturnType<typeof deployMockVerifier>>
  claimVerifier: Awaited<ReturnType<typeof deployMockVerifier>>
  chainId: number
}

async function deployMockVerifier(ethers: HardhatEthers) {
  return ethers.deployContract('MockBidVerifier')
}

/** Deploys the program with mock verifiers and a mock Interfold, and no sale. */
export async function deployFixture(): Promise<Fixture> {
  const { ethers } = await hre.network.connect()
  const [creator, relayer, ...actors] = await ethers.getSigners()
  const interfold = await ethers.deployContract('MockInterfold')
  const receiptVerifier = await ethers.deployContract('MockOpenVmReceiptVerifier')
  const availability = await ethers.deployContract('MockDataAvailabilityVerifier')
  const bidVerifier = await deployMockVerifier(ethers)
  const claimVerifier = await deployMockVerifier(ethers)
  const poseidon = await ethers.deployContract('PoseidonT3')
  const clearing = await ethers.deployContract('SaleClearing')
  const output = await ethers.deployContract('SaleOutput')
  const config = await ethers.deployContract('SaleConfig')
  const factory = await ethers.getContractFactory(
    SealedCcaProgram__factory.abi,
    SealedCcaProgram__factory.linkBytecode({
      'npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3': await poseidon.getAddress(),
      'project/contracts/libraries/SaleClearing.sol:SaleClearing': await clearing.getAddress(),
      'project/contracts/libraries/SaleOutput.sol:SaleOutput': await output.getAddress(),
      'project/contracts/libraries/SaleConfig.sol:SaleConfig': await config.getAddress(),
    }),
    creator,
  )
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
    creator,
    relayer,
    actors,
    program: SealedCcaProgram__factory.connect(programAddress, creator),
    programAddress,
    interfold: MockInterfold__factory.connect(await interfold.getAddress(), creator),
    saleToken,
    usdc,
    bidVerifier,
    claimVerifier,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
  }
}

export interface RequestOptions {
  e3Id?: bigint
  prices?: bigint[]
  supply?: bigint
  escrow?: bigint
  gate?: Hex
  gateConfig?: Hex
  revealMode?: number
  /** Skip the approval of the supply. */
  noApproval?: boolean
  inputDeadline?: bigint
}

/** The `customParams` of a sale of the fixture's tokens. */
export function saleParams(fixture: Fixture, saleToken: Hex, paymentToken: Hex, options: RequestOptions = {}): SaleParams {
  return {
    revealMode: options.revealMode,
    prices: options.prices ?? PRICES,
    saleToken,
    supply: options.supply ?? SUPPLY,
    paymentToken,
    escrow: options.escrow ?? ESCROW,
    gate: options.gate ?? zeroAddress,
    gateConfig: options.gateConfig,
  }
}

/** The creator gets the supply, approves it, and Interfold requests the sale: `validate` runs. */
export async function requestSale(fixture: Fixture, options: RequestOptions = {}) {
  const e3Id = options.e3Id ?? E3_ID
  const supply = options.supply ?? SUPPLY
  await (await fixture.interfold.setE3(e3Id, options.inputDeadline ?? 2n ** 40n, KEY, fixture.creator.address)).wait()
  await (await fixture.saleToken.mint(fixture.creator.address, supply)).wait()
  if (!options.noApproval) await (await fixture.saleToken.approve(fixture.programAddress, supply)).wait()
  const params = encodeSaleParams(
    saleParams(fixture, (await fixture.saleToken.getAddress()) as Hex, (await fixture.usdc.getAddress()) as Hex, options),
  )
  return { e3Id, params, tx: () => fixture.interfold.request(e3Id, fixture.programAddress, params) }
}

/** Requests a sale and waits for it. */
export async function createSale(fixture: Fixture, options: RequestOptions = {}): Promise<bigint> {
  const { e3Id, tx } = await requestSale(fixture, options)
  await (await tx()).wait()
  return e3Id
}

/** Gives `holder` payment tokens, and approves the program. */
export async function fund(fixture: Fixture, holder: HardhatEthersSigner, amount = ESCROW) {
  await (await fixture.usdc.mint(holder.address, amount)).wait()
  await (await fixture.usdc.connect(holder).approve(fixture.programAddress, amount)).wait()
}

/** An EIP-2612 permit of `owner` for the program, split into `v`, `r` and `s`. */
export async function signPermit(fixture: Fixture, owner: Wallet | HardhatEthersSigner, value: bigint, deadline: bigint) {
  const token = (await fixture.usdc.getAddress()) as Hex
  const nonce = await fixture.usdc.nonces(owner.address)
  const signature = await owner.signTypedData(
    { name: 'Mock USDC', version: '1', chainId: fixture.chainId, verifyingContract: token },
    {
      Permit: [
        { name: 'owner', type: 'address' },
        { name: 'spender', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    { owner: owner.address, spender: fixture.programAddress, value, nonce, deadline },
  )
  const { v, r, s } = fixture.ethers.Signature.from(signature)
  return { v, r, s }
}

/** The EIP-712 signature of a relayed bid. */
export async function signBid(
  fixture: Fixture,
  bidder: Wallet | HardhatEthersSigner,
  e3Id: bigint,
  version: number,
  inputsHash: Hex,
): Promise<Hex> {
  return (await bidder.signTypedData(
    { name: 'SealedCcaProgram', version: '1', chainId: fixture.chainId, verifyingContract: fixture.programAddress },
    {
      Bid: [
        { name: 'e3Id', type: 'uint256' },
        { name: 'bidder', type: 'address' },
        { name: 'version', type: 'uint32' },
        { name: 'inputsHash', type: 'bytes32' },
      ],
    },
    { e3Id, bidder: bidder.address, version, inputsHash },
  )) as Hex
}
