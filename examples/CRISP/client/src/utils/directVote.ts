// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { parseAbi } from 'viem'
import type { Address, Hex, PublicClient, WalletClient } from 'viem'

const PUBLISH_INPUT_ABI = parseAbi(['function publishInput(uint256 e3Id, bytes data)'])

/**
 * Commit an encoded input proof straight from the voter's wallet.
 *
 * `publishInput` is permissionless. The payload carries the proof, slot, ciphertext commitment,
 * content hash, parent, and signed 10-minute expiry. It does not carry the ciphertext or wait for
 * VectorX. The durable availability service publishes those bytes and finalizes the input later.
 *
 * @param walletClient The voter's wallet.
 * @param publicClient The public client, for simulation and the receipt.
 * @param crispProgram The CRISP program address.
 * @param e3Id The round.
 * @param encodedProof The compact proof-commitment payload returned by the availability service.
 * @returns The transaction hash, after one confirmation.
 */
export const submitInputCommitmentDirectly = async (
  walletClient: WalletClient,
  publicClient: PublicClient,
  crispProgram: Address,
  e3Id: bigint,
  encodedProof: Hex,
): Promise<Hex> => {
  const account = walletClient.account
  if (!account) throw new Error('Wallet has no account to submit from')

  const { request } = await publicClient.simulateContract({
    account,
    address: crispProgram,
    abi: PUBLISH_INPUT_ABI,
    functionName: 'publishInput',
    args: [e3Id, encodedProof],
  })

  const hash = await walletClient.writeContract(request)
  const receipt = await publicClient.waitForTransactionReceipt({ hash })

  // `waitForTransactionReceipt` resolves for a reverted transaction too. Without this check the
  // caller would mark a vote as cast when the chain refused it.
  if (receipt.status !== 'success') {
    throw new Error(`Vote transaction reverted: ${hash}`)
  }

  return hash
}
