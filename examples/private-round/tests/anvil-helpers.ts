// SPDX-License-Identifier: LGPL-3.0-only

import type { PublicClient } from 'viem'

/** Advance Anvil time, then mine one block at the new timestamp. */
export async function advanceAnvilTime(publicClient: PublicClient, seconds: number): Promise<void> {
  // viem types only the standard JSON-RPC methods; the `evm_*` methods are Anvil's.
  const request = publicClient.request as (args: { method: string; params: unknown[] }) => Promise<unknown>
  await request({ method: 'evm_increaseTime', params: [seconds] })
  await request({ method: 'evm_mine', params: [] })
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
