// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { SERVER_URL } from './env-config'

/** The server answers `{ txHash }` or `{ error }`. */
async function post(path: string, body: Record<string, unknown>): Promise<`0x${string}`> {
  let response: Response
  try {
    response = await fetch(`${SERVER_URL}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
  } catch {
    throw new Error(`Could not reach the relayer at ${SERVER_URL}. Is the server running?`)
  }
  const answer = (await response.json().catch(() => ({}))) as { txHash?: string; error?: string }
  if (!response.ok || typeof answer.txHash !== 'string') throw new Error(answer.error ?? `The relayer answered ${response.status}`)
  return answer.txHash as `0x${string}`
}

/**
 * Ask the server to send `publishInput(e3Id, data)` from its relayer account. The offer in `data` is
 * signed by the party, so the relayer can pay the gas but cannot change the offer. Resolves to the
 * transaction hash; throws with the revert reason when the server's simulation fails.
 */
export const relayOffer = (e3Id: bigint, data: `0x${string}`) => post('/relay', { e3Id: e3Id.toString(), data })
