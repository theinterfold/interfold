// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { PublicClient, WalletClient } from 'viem'
import { describe, expect, it, vi } from 'vitest'

import { submitInputCommitmentDirectly } from '../../../client/src/utils/directVote'

describe('client submitInputCommitmentDirectly', () => {
  it('opens no wallet prompt when the page closes during the simulation', async () => {
    const simulation = Promise.withResolvers<{ request: object }>()
    const writeContract = vi.fn()
    let pageClosed = false

    const submission = submitInputCommitmentDirectly(
      { account: {}, writeContract } as unknown as WalletClient,
      { simulateContract: () => simulation.promise } as unknown as PublicClient,
      '0x0000000000000000000000000000000000000001',
      1n,
      '0x',
      () => pageClosed,
    )
    pageClosed = true
    simulation.resolve({ request: {} })

    await expect(submission).rejects.toThrow()
    expect(writeContract).not.toHaveBeenCalled()
  })
})
