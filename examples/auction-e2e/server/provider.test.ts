// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { describe, expect, it, vi } from 'vitest'
import { AuctionType } from '@interfold/auction-core'
import { E3Stage } from '@interfold/sdk/contracts'
import { MaskProvider, MaskRejectedError, NOT_LISTED, decideMask, type ProviderAuction, type ProvedMask } from './provider'

const me = '0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa'
const other = '0x2222222222222222222222222222222222222222'

const auction = (overrides: Partial<ProviderAuction> = {}): ProviderAuction => ({
  type: AuctionType.ProviderSecondPrice,
  providers: [other, me],
  submitted: false,
  stage: E3Stage.KeyPublished,
  inputWindow: [100n, 200n],
  now: 150n,
  ...overrides,
})

describe('decideMask', () => {
  it('submits inside the input window when the creator named the provider and its mask is not on chain', () => {
    expect(decideMask(me, auction())).toEqual({ kind: 'submit' })
    // The address check ignores the case of the checksum.
    expect(decideMask(me.toLowerCase() as `0x${string}`, auction())).toEqual({ kind: 'submit' })
    expect(decideMask(me, auction({ now: 100n }))).toEqual({ kind: 'submit' })
    expect(decideMask(me, auction({ now: 200n }))).toEqual({ kind: 'submit' })
  })

  it('waits for the start of the input window', () => {
    expect(decideMask(me, auction({ now: 99n }))).toEqual({ kind: 'wait', until: 100n })
  })

  it('skips an auction that does not name the provider, or has no providers at all', () => {
    expect(decideMask(me, auction({ providers: [other] }))).toEqual({ kind: 'skip', reason: NOT_LISTED })
    expect(decideMask(me, auction({ type: AuctionType.FirstPrice, providers: [] })).kind).toBe('skip')
  })

  it('skips once the mask is on chain, once the window is closed and when the auction left the key-published stage', () => {
    expect(decideMask(me, auction({ submitted: true })).kind).toBe('skip')
    expect(decideMask(me, auction({ now: 201n })).kind).toBe('skip')
    expect(decideMask(me, auction({ stage: E3Stage.Failed })).kind).toBe('skip')
    expect(decideMask(me, auction({ stage: E3Stage.Requested })).kind).toBe('skip')
  })
})

const proved: ProvedMask = { ciphertext: '0xaa', commitment: '0xbb', proof: '0xcc' }
const key = new Uint8Array([1, 2, 3])
const noSleep = () => Promise.resolve()

/** Wait until the provider is done with `e3Id`. */
async function settled(provider: MaskProvider, e3Id: bigint): Promise<void> {
  await vi.waitFor(() => expect(provider.isRunning(e3Id)).toBe(false))
}

describe('MaskProvider', () => {
  it('proves with the committee key and sends once', async () => {
    const prove = vi.fn(async () => proved)
    const send = vi.fn(async () => '0x01' as const)
    const provider = new MaskProvider({
      address: me,
      readAuction: async () => auction(),
      prove,
      send,
      waitForChainTime: async () => {},
      sleep: noSleep,
    })
    provider.start(7n, key)
    provider.start(7n, key) // A second start while the first runs changes nothing.
    await settled(provider, 7n)
    expect(prove).toHaveBeenCalledTimes(1)
    expect(prove).toHaveBeenCalledWith(key)
    expect(send).toHaveBeenCalledTimes(1)
    expect(send).toHaveBeenCalledWith(7n, proved)
  })

  it('does nothing for an auction that is no mask-provider auction of the program or that does not name it', async () => {
    const prove = vi.fn(async () => proved)
    const provider = new MaskProvider({
      address: me,
      readAuction: async (e3Id) => (e3Id === 1n ? null : auction({ providers: [other] })),
      prove,
      send: vi.fn(),
      waitForChainTime: async () => {},
      sleep: noSleep,
    })
    provider.start(1n, key)
    provider.start(2n, key)
    await settled(provider, 1n)
    await settled(provider, 2n)
    expect(prove).not.toHaveBeenCalled()
  })

  it('sends no second mask after a restart: it reads the flag on chain first', async () => {
    const prove = vi.fn(async () => proved)
    const provider = new MaskProvider({
      address: me,
      readAuction: async () => auction({ submitted: true }),
      prove,
      send: vi.fn(),
      waitForChainTime: async () => {},
      sleep: noSleep,
    })
    provider.start(3n, key)
    await settled(provider, 3n)
    expect(prove).not.toHaveBeenCalled()
  })

  it('waits for the window to open, then sends', async () => {
    let now = 50n
    const waited: bigint[] = []
    const send = vi.fn(async () => '0x01' as const)
    const provider = new MaskProvider({
      address: me,
      readAuction: async () => auction({ now }),
      prove: async () => proved,
      send,
      waitForChainTime: async (target) => {
        waited.push(target)
        now = target
      },
      sleep: noSleep,
    })
    provider.start(4n, key)
    await settled(provider, 4n)
    expect(waited).toEqual([100n])
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('retries a failed send with the same proof, and proves again after the contract rejected the proof', async () => {
    const prove = vi.fn(async () => proved)
    const sends = [new Error('network down'), new MaskRejectedError('InvalidMaskProof()'), '0x01']
    const send = vi.fn(async () => {
      const next = sends.shift()
      if (next instanceof Error) throw next
      return next as `0x${string}`
    })
    const delays: number[] = []
    const provider = new MaskProvider({
      address: me,
      readAuction: async () => auction(),
      prove,
      send,
      waitForChainTime: async () => {},
      sleep: async (ms) => {
        delays.push(ms)
      },
      retryBaseMs: 10,
      retryMaxMs: 15,
    })
    provider.start(5n, key)
    await settled(provider, 5n)
    // Proof 1 serves the first and the second send; the rejection drops it, so the third send has proof 2.
    expect(prove).toHaveBeenCalledTimes(2)
    expect(send).toHaveBeenCalledTimes(3)
    expect(delays).toEqual([10, 15])
  })

  it('stops retrying once the mask is on chain, sent by another run', async () => {
    let calls = 0
    const provider = new MaskProvider({
      address: me,
      // The first read lets the run prove; by the second read another run has sent the mask.
      readAuction: async () => auction({ submitted: ++calls > 2 }),
      prove: async () => proved,
      send: async () => {
        throw new MaskRejectedError('MaskAlreadySubmitted()')
      },
      waitForChainTime: async () => {},
      sleep: noSleep,
    })
    provider.start(6n, key)
    await settled(provider, 6n)
    expect(calls).toBe(3)
  })
})
