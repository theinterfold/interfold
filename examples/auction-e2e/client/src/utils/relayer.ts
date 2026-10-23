// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { SERVER_URL } from './env-config'

/**
 * Ask the server to send `publishInput(e3Id, data)` from its relayer account. The bid in `data` is
 * signed by the bidder, so the relayer can pay the gas but cannot change the bid. Resolves to the
 * transaction hash; throws with the revert reason when the server's simulation fails.
 */
export async function relayBid(e3Id: bigint, data: `0x${string}`): Promise<`0x${string}`> {
  let response: Response
  try {
    response = await fetch(`${SERVER_URL}/relay`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ e3Id: e3Id.toString(), data }),
    })
  } catch {
    throw new Error(`Could not reach the relayer at ${SERVER_URL}. Is the server running?`)
  }
  // The server answers `{ txHash }` or `{ error }`.
  const body = (await response.json().catch(() => ({}))) as { txHash?: string; error?: string }
  if (!response.ok || typeof body.txHash !== 'string') throw new Error(body.error ?? `The relayer answered ${response.status}`)
  return body.txHash as `0x${string}`
}
