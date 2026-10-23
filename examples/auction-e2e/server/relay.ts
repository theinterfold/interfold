// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { BaseError, ContractFunctionRevertedError, isHex, type Address, type Hex, type PublicClient, type WalletClient } from 'viem'
import { AuctionProgram__factory } from '../types/factories/contracts'

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

/**
 * Sends `publishInput(e3Id, data)` of the auction program from the relayer account and returns the
 * hash of the mined transaction. It simulates first, so a bid that the program refuses costs no gas.
 * The relayer makes no other check: the program verifies the signature, the gate and the proof.
 *
 * @throws RelayRevertError with the revert reason.
 */
export async function relayBid(
  publicClient: PublicClient,
  walletClient: WalletClient,
  program: Address,
  e3Id: bigint,
  data: Hex,
): Promise<Hex> {
  try {
    const { request } = await publicClient.simulateContract({
      address: program,
      abi: AuctionProgram__factory.abi,
      functionName: 'publishInput',
      args: [e3Id, data],
      account: walletClient.account,
    })
    const hash = await walletClient.writeContract(request)
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    if (receipt.status !== 'success') throw new Error(`the transaction ${hash} reverted`)
    return hash
  } catch (error) {
    throw new RelayRevertError(revertReason(error))
  }
}
