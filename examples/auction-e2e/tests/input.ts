// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Account, WalletClient } from 'viem'
import { AuctionProgram__factory } from '../types/factories/contracts'
import { encodeBidInput, type PreparedInput } from '../shared/prover'

/**
 * Publish one ciphertext of a bid to the program.
 * @param walletClient - The bidder's wallet client; the sender is the bidder
 * @param e3Id - The E3 ID
 * @param record - The encrypted, proven ciphertext
 * @param programAddress - The program contract address
 */
export const publishBidInput = async (
  walletClient: WalletClient & { account: Account },
  e3Id: bigint,
  record: PreparedInput,
  programAddress: `0x${string}`,
): Promise<`0x${string}`> => {
  return walletClient.writeContract({
    address: programAddress,
    abi: AuctionProgram__factory.abi,
    functionName: 'publishInput',
    args: [e3Id, encodeBidInput(record)],
    chain: walletClient.chain,
    account: walletClient.account,
  })
}
