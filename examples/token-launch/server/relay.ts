// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { BaseError, ContractFunctionRevertedError, isHex, type Address, type Hex, type PublicClient, type WalletClient } from 'viem'
import { TokenLaunchProgram__factory } from '../types/factories/contracts'
import type { KeeperCall } from './keeper'

/** A body that a relay route cannot use. The message is safe to return to the caller. */
export class RelayRequestError extends Error {}

/** A relayed call that the program refuses, or whose transaction reverted. The message is the reason. */
export class RelayRevertError extends Error {}

/** The `data` field of a relay body: non-empty hex bytes. */
function relayData(data: unknown): Hex {
  if (typeof data !== 'string' || !isHex(data) || data.length % 2 !== 0 || data.length === 2) {
    throw new RelayRequestError('data must be non-empty hex bytes with a 0x prefix')
  }
  return data
}

/** A decimal id field of a relay body. */
function relayId(name: string, value: unknown): bigint {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) throw new RelayRequestError(`${name} must be a decimal string`)
  return BigInt(value)
}

/** `{ e3Id, data }` of a bid: `e3Id` is the sale id and `data` is the `data` argument of `publishInput`. */
export function parseRelayRequest(body: unknown): { e3Id: bigint; data: Hex } {
  const { e3Id, data } = (body ?? {}) as { e3Id?: unknown; data?: unknown }
  return { e3Id: relayId('e3Id', e3Id), data: relayData(data) }
}

/** `{ saleId, data }` of a claim: `data` is the `data` argument of `claim`. */
export function parseRelayClaimRequest(body: unknown): { saleId: bigint; data: Hex } {
  const { saleId, data } = (body ?? {}) as { saleId?: unknown; data?: unknown }
  return { saleId: relayId('saleId', saleId), data: relayData(data) }
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

/** A call of the sale program that the relayer account sends. */
export type RelayCall =
  | { functionName: 'publishInput'; args: readonly [bigint, Hex] }
  | { functionName: 'claim'; args: readonly [bigint, Hex] }
  | KeeperCall

// One account sends every call, and two transactions that are built at the same time would take the
// same nonce. The calls of this process run one after the other.
let sending: Promise<unknown> = Promise.resolve()

/**
 * Simulates a call of the program, sends it from the relayer account and waits for the receipt. The
 * simulation runs first, so a call that the program refuses costs no gas.
 *
 * @throws RelayRevertError with the revert reason.
 */
export function sendFromRelayer(publicClient: PublicClient, walletClient: WalletClient, program: Address, call: RelayCall): Promise<Hex> {
  const run = async (): Promise<Hex> => {
    try {
      const { request } = await publicClient.simulateContract({
        address: program,
        abi: TokenLaunchProgram__factory.abi,
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
  const result = sending.then(run)
  sending = result.catch(() => undefined)
  return result
}

/**
 * Sends `publishInput(saleId, data)` from the relayer account and returns the hash of the mined
 * transaction. The relayer makes no other check: the program verifies the signature and the proof.
 */
export function relayBid(publicClient: PublicClient, walletClient: WalletClient, program: Address, saleId: bigint, data: Hex): Promise<Hex> {
  return sendFromRelayer(publicClient, walletClient, program, { functionName: 'publishInput', args: [saleId, data] })
}

/**
 * Sends `claim(saleId, data)` from the relayer account. The claim names its recipient inside `data`
 * and the proof binds it, so a fresh address that holds no gas can claim and the relayer cannot
 * redirect the payout.
 */
export function relayClaim(publicClient: PublicClient, walletClient: WalletClient, program: Address, saleId: bigint, data: Hex): Promise<Hex> {
  return sendFromRelayer(publicClient, walletClient, program, { functionName: 'claim', args: [saleId, data] })
}
