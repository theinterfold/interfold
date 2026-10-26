// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import {
  BaseError,
  ContractFunctionRevertedError,
  isAddress,
  isHex,
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
} from 'viem'
import { PrivateRoundProgram__factory } from '../types/factories/contracts'

/** A body that `POST /relay` cannot use. The message is safe to return to the caller. */
export class RelayRequestError extends Error {}

/** A relayed bid that the program refuses, or whose transaction reverted. The message is the reason. */
export class RelayRevertError extends Error {}

/** `{ e3Id, data }` of a relay request: `data` is the `data` argument of `publishInput`. */
export function parseRelayRequest(body: unknown): { e3Id: bigint; data: Hex } {
  const { e3Id, data } = (body ?? {}) as { e3Id?: unknown; data?: unknown }
  if (typeof e3Id !== 'string' || !/^\d+$/.test(e3Id)) throw new RelayRequestError('e3Id must be a decimal string')
  if (typeof data !== 'string' || !isHex(data) || data.length % 2 !== 0 || data.length === 2) {
    throw new RelayRequestError('data must be non-empty hex bytes with a 0x prefix')
  }
  return { e3Id: BigInt(e3Id), data }
}

/** The name and arguments of the custom error that a call reverted with, or else the shortest message. */
export function revertReason(error: unknown): string {
  if (!(error instanceof BaseError)) return error instanceof Error ? error.message : String(error)
  const revert = error.walk((cause) => cause instanceof ContractFunctionRevertedError)
  if (revert instanceof ContractFunctionRevertedError) {
    if (revert.data) return `${revert.data.errorName}(${(revert.data.args ?? []).join(', ')})`
    return revert.reason ?? revert.shortMessage
  }
  return error.shortMessage
}

/** The arguments of `depositFor`, which the relayer sends for a bidder who signed an EIP-2612 permit. */
export interface RelayDepositRequest {
  e3Id: bigint
  bidder: Address
  /** The proof that the gate needs, or `0x` when the sale has no gate. */
  gateProof: Hex
  deadline: bigint
  v: number
  r: Hex
  s: Hex
}

/** `{ e3Id, bidder, gateProof?, deadline, v, r, s }` of a relayed deposit. `e3Id` and `deadline` are decimal strings, `v` is a number. */
export function parseRelayDepositRequest(body: unknown): RelayDepositRequest {
  const { e3Id, bidder, gateProof = '0x', deadline, v, r, s } = (body ?? {}) as Record<string, unknown>
  if (typeof e3Id !== 'string' || !/^\d+$/.test(e3Id)) throw new RelayRequestError('e3Id must be a decimal string')
  if (typeof bidder !== 'string' || !isAddress(bidder, { strict: false })) throw new RelayRequestError('bidder must be an address')
  if (typeof gateProof !== 'string' || !isHex(gateProof) || gateProof.length % 2 !== 0)
    throw new RelayRequestError('gateProof must be hex bytes with a 0x prefix')
  if (typeof deadline !== 'string' || !/^\d+$/.test(deadline)) throw new RelayRequestError('deadline must be a decimal string')
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 255) throw new RelayRequestError('v must be a byte')
  for (const [name, value] of [
    ['r', r],
    ['s', s],
  ] as const) {
    if (typeof value !== 'string' || !/^0x[a-fA-F0-9]{64}$/.test(value)) throw new RelayRequestError(`${name} must be 32 bytes of hex`)
  }
  return { e3Id: BigInt(e3Id), bidder, gateProof, deadline: BigInt(deadline), v, r: r as Hex, s: s as Hex }
}

/** Simulates a call of the program, sends it from the relayer account and waits for the receipt. */
async function relayCall(
  publicClient: PublicClient,
  walletClient: WalletClient,
  program: Address,
  call: { functionName: 'publishInput'; args: readonly [bigint, Hex] } | { functionName: 'depositFor'; args: DepositForArgs },
): Promise<Hex> {
  try {
    const { request } = await publicClient.simulateContract({
      address: program,
      abi: PrivateRoundProgram__factory.abi,
      account: walletClient.account,
      ...call,
    } as never)
    const hash = await walletClient.writeContract(request as never)
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    if (receipt.status !== 'success') throw new Error(`the transaction ${hash} reverted`)
    return hash
  } catch (error) {
    throw new RelayRevertError(revertReason(error))
  }
}

type DepositForArgs = readonly [bigint, Address, Hex, bigint, number, Hex, Hex]

/**
 * Sends `publishInput(e3Id, data)` of the sale program from the relayer account and returns the
 * hash of the mined transaction. It simulates first, so a bid that the program refuses costs no gas.
 * The relayer makes no other check: the program verifies the signature, the gate and the proof.
 *
 * @throws RelayRevertError with the revert reason.
 */
export function relayBid(publicClient: PublicClient, walletClient: WalletClient, program: Address, e3Id: bigint, data: Hex): Promise<Hex> {
  return relayCall(publicClient, walletClient, program, { functionName: 'publishInput', args: [e3Id, data] })
}

/**
 * Sends `depositFor(e3Id, bidder, gateProof, deadline, v, r, s)` from the relayer account: the bidder signed an
 * EIP-2612 permit for the escrow, so the bidder needs no gas. Same simulation and error rules as `relayBid`.
 *
 * @throws RelayRevertError with the revert reason.
 */
export function relayDeposit(
  publicClient: PublicClient,
  walletClient: WalletClient,
  program: Address,
  request: RelayDepositRequest,
): Promise<Hex> {
  const { e3Id, bidder, gateProof, deadline, v, r, s } = request
  return relayCall(publicClient, walletClient, program, { functionName: 'depositFor', args: [e3Id, bidder, gateProof, deadline, v, r, s] })
}
