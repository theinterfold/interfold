// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Account, WalletClient } from 'viem'
import { AuctionProgram__factory } from '../types/factories/contracts'
import { type BidInput, encodeBidInput } from '@interfold/auction'

/**
 * Publish a bid to the program from the wallet's account.
 * @param walletClient - The sender's wallet client. For a direct bid it is the bidder.
 * @param e3Id - The E3 ID
 * @param bid - What `publishInput` takes: the bidder, the bytes, the proof, the gate proof and the signature
 * @param programAddress - The program contract address
 */
export const publishBidInput = async (
  walletClient: WalletClient & { account: Account },
  e3Id: bigint,
  bid: BidInput,
  programAddress: `0x${string}`,
): Promise<`0x${string}`> => {
  return walletClient.writeContract({
    address: programAddress,
    abi: AuctionProgram__factory.abi,
    functionName: 'publishInput',
    args: [e3Id, encodeBidInput(bid)],
    chain: walletClient.chain,
    account: walletClient.account,
  })
}
