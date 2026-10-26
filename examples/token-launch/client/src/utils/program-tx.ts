// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { WalletClient } from 'viem'
import { TokenLaunchProgram__factory } from '@contract-types/factories/contracts/TokenLaunchProgram__factory'
import { publicClient } from './chain'
import { getContractAddresses } from './env-config'

/** The program actions that take only the sale id. Anyone may send the first two; the others are for the creator. */
export type SaleAction = 'publishProbes' | 'clear' | 'withdrawProceeds' | 'withdrawUnsold' | 'sweep' | 'refundSupply' | 'withdrawForfeited'

/** The program actions that take a sale id and a bid index. Anyone may send them: the funds go to the bidder or to the registered recipient. */
export type IndexAction = 'refundDropped' | 'refundEscrow' | 'payMarginal'

async function finish(walletClient: WalletClient, request: Parameters<WalletClient['writeContract']>[0], label: string) {
  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`The ${label} transaction reverted`)
  return hash
}

/** Simulate, send and wait for `action(saleId)`. Resolves to the transaction hash. */
export async function sendSaleAction(walletClient: WalletClient, action: SaleAction, saleId: bigint): Promise<`0x${string}`> {
  const [account] = await walletClient.getAddresses()
  const { request } = await publicClient.simulateContract({
    address: getContractAddresses().e3Program,
    abi: TokenLaunchProgram__factory.abi,
    functionName: action,
    args: [saleId],
    account,
  })
  return finish(walletClient, request as Parameters<WalletClient['writeContract']>[0], action)
}

/** Simulate, send and wait for `action(saleId, index)`. Resolves to the transaction hash. */
export async function sendIndexAction(
  walletClient: WalletClient,
  action: IndexAction,
  saleId: bigint,
  index: number,
): Promise<`0x${string}`> {
  const [account] = await walletClient.getAddresses()
  const { request } = await publicClient.simulateContract({
    address: getContractAddresses().e3Program,
    abi: TokenLaunchProgram__factory.abi,
    functionName: action,
    args: [saleId, BigInt(index)],
    account,
  })
  return finish(walletClient, request as Parameters<WalletClient['writeContract']>[0], action)
}
