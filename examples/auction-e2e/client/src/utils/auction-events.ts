// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Role } from '@shared/layout'
import { AuctionProgram__factory } from '@contract-types/factories/contracts/AuctionProgram__factory'
import { getContractAddresses } from './env-config'
import { scanLogs } from './logs'
import { publicClient } from './chain'

/** A bidder whose ciphertexts (3, or 4 for ratio-lane second price) are all in the input tree. */
export interface LinkedBidder {
  address: `0x${string}`
  /** The leaf of the bidder's first ciphertext. The program reads bidders in this order. */
  firstIndex: number
  /** The role-0 ciphertext as published: it fixes the tie priority. */
  geCiphertext: `0x${string}`
}

/** The linked bidders of an E3 in leaf order, which is the order the FHE program sees them. */
export async function readLinkedBidders(e3Id: bigint): Promise<LinkedBidder[]> {
  const { e3Program } = getContractAddresses()
  const query = { address: e3Program, abi: AuctionProgram__factory.abi, args: { e3Id }, strict: true } as const
  const [{ logs: submitted }, { logs: linked }] = await Promise.all([
    scanLogs((range) => publicClient.getContractEvents({ ...query, ...range, eventName: 'BidSubmitted' })),
    scanLogs((range) => publicClient.getContractEvents({ ...query, ...range, eventName: 'BidLinked' })),
  ])
  const ge = new Map<string, `0x${string}`>()
  for (const { args } of submitted) {
    if (args.role === Role.Ge) ge.set(args.bidder.toLowerCase(), args.ciphertext)
  }
  return linked
    .map(({ args }) => {
      const geCiphertext = ge.get(args.bidder.toLowerCase())
      if (geCiphertext === undefined) throw new Error(`No role-0 ciphertext for linked bidder ${args.bidder}`)
      return { address: args.bidder, firstIndex: Number(args.firstIndex), geCiphertext }
    })
    .sort((a, b) => a.firstIndex - b.firstIndex)
}
