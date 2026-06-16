// SPDX-License-Identifier: LGPL-3.0-only

import type { PublicClient } from 'viem'

/** Advance anvil time and mine (closes sortition submission window on-chain). */
export async function advanceAnvilTime(publicClient: PublicClient, seconds: number): Promise<void> {
  await publicClient.request({
    method: 'evm_increaseTime',
    params: [seconds],
  })
  await publicClient.request({
    method: 'evm_mine',
    params: [],
  })
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
