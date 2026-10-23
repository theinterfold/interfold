// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address } from 'viem'
import type { SubmittedBid } from '@interfold/auction'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { MerkleAllowlistGate__factory } from '@contract-types/factories/contracts/gates/MerkleAllowlistGate__factory'
import { getContractAddresses } from './env-config'
import { scanLogs } from './logs'
import { publicClient } from './chain'

/** Every bid of an E3 (all versions of all bidders) in leaf order, from the `BidSubmitted` events. */
export async function readSubmittedBids(e3Id: bigint): Promise<SubmittedBid[]> {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: e3Program,
      abi: AuctionProgram__factory.abi,
      eventName: 'BidSubmitted',
      args: { e3Id },
      strict: true,
      ...range,
    }),
  )
  return logs
    .map(({ args }) => ({
      bidder: args.bidder,
      version: args.version,
      firstIndex: Number(args.firstIndex),
      ciphertexts: [...args.ciphertexts],
      commitments: [...args.commitments],
    }))
    .sort((a, b) => a.firstIndex - b.firstIndex)
}

/** The members the creator set in the allowlist gate of an auction, from its `AllowlistSet` event. `null` if there is none. */
export async function readAllowlist(gate: Address, e3Id: bigint): Promise<Address[] | null> {
  const { e3Program } = getContractAddresses()
  const { logs } = await scanLogs((range) =>
    publicClient.getContractEvents({
      address: gate,
      abi: MerkleAllowlistGate__factory.abi,
      eventName: 'AllowlistSet',
      args: { program: e3Program, e3Id },
      strict: true,
      ...range,
    }),
  )
  const last = logs.at(-1)
  return last ? [...last.args.members] : null
}
