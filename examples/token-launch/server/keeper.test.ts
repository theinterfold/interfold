// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { SaleKeeper, type KeeperCall, type KeeperDeps } from './keeper'

const hash = `0x${'ab'.repeat(32)}` as const
type Step = KeeperCall | 'wait' | 'done'

const publishProbes = (saleId: bigint): KeeperCall => ({ functionName: 'publishProbes', args: [saleId] })
const clear = (saleId: bigint): KeeperCall => ({ functionName: 'clear', args: [saleId] })
const payMarginal = (saleId: bigint, index: bigint): KeeperCall => ({ functionName: 'payMarginal', args: [saleId, index] })

describe('SaleKeeper', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined)
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  /**
   * A keeper over a chain that this test steers: `state` is what `next` answers for each sale, and a
   * call that is sent moves its sale to `after` (the chain has moved on once the call is mined).
   */
  const keeper = (state: Map<bigint, Step>, overrides: Partial<KeeperDeps> = {}, after: Step = 'wait') => {
    const discover = vi.fn().mockResolvedValueOnce([...state.keys()]).mockResolvedValue([])
    const send = vi.fn().mockImplementation(async (call: KeeperCall) => {
      state.set(call.args[0], after)
      return hash
    })
    const instance = new SaleKeeper({
      discover,
      next: async (saleId) => state.get(saleId) ?? 'done',
      send,
      ...overrides,
    })
    return { instance, send, discover }
  }

  it('publishes the probes of a sale in the probing phase and clears a sale that is clearable', async () => {
    const state = new Map<bigint, Step>([
      [4n, publishProbes(4n)],
      [9n, clear(9n)],
      [12n, 'wait'],
    ])
    const { instance, send } = keeper(state)
    await instance.tick()
    expect(send.mock.calls).toEqual([[publishProbes(4n)], [clear(9n)]])
    expect(instance.watched).toEqual([4n, 9n, 12n])
  })

  it('sends again only when the chain still allows the call, and stops watching a sale that is done', async () => {
    const state = new Map<bigint, Step>([[4n, publishProbes(4n)]])
    const { instance, send } = keeper(state)
    await instance.tick()
    await instance.tick() // round 2 is running: the chain allows nothing
    state.set(4n, clear(4n))
    await instance.tick()
    state.set(4n, 'done')
    await instance.tick()
    await instance.tick()
    expect(send.mock.calls).toEqual([[publishProbes(4n)], [clear(4n)]])
    expect(instance.watched).toEqual([])
  })

  it('pays every registered marginal claim of a sale in one tick, one call after the other', async () => {
    const pending = [0n, 3n, 7n]
    const order: bigint[] = []
    const send = vi.fn().mockImplementation(async (call: KeeperCall) => {
      order.push(call.args[1] as bigint)
      pending.shift()
      return hash
    })
    const { instance } = keeper(new Map(), {
      discover: vi.fn().mockResolvedValueOnce([6n]).mockResolvedValue([]),
      next: async () => (pending.length === 0 ? 'done' : payMarginal(6n, pending[0])),
      send,
    })
    await instance.tick()
    expect(order).toEqual([0n, 3n, 7n])
    expect(instance.watched).toEqual([])
  })

  it('picks up a sale that appears later, and reads the chain again after a restart', async () => {
    const state = new Map<bigint, Step>([[4n, 'wait']])
    const discover = vi.fn().mockResolvedValueOnce([4n]).mockResolvedValueOnce([5n]).mockResolvedValue([])
    const { instance, send } = keeper(state, { discover })
    await instance.tick()
    state.set(5n, clear(5n))
    await instance.tick()
    expect(send.mock.calls).toEqual([[clear(5n)]])

    // A new process knows no sale. It discovers all of them and sends what the chain allows.
    const restarted = keeper(new Map([[5n, clear(5n)]]))
    await restarted.instance.tick()
    expect(restarted.send.mock.calls).toEqual([[clear(5n)]])
  })

  it('does not run two calls at once, whatever the number of ticks', async () => {
    let release!: () => void
    const send = vi.fn().mockImplementation(() => new Promise<`0x${string}`>((resolve) => (release = () => resolve(hash))))
    const state = new Map<bigint, Step>([[4n, publishProbes(4n)]])
    const { instance } = keeper(state, { send })
    const first = instance.tick()
    await vi.waitFor(() => expect(send).toHaveBeenCalledOnce())
    await instance.tick() // the first tick still runs: this one does nothing
    expect(send).toHaveBeenCalledOnce()
    state.set(4n, 'wait')
    release()
    await first
    expect(send).toHaveBeenCalledOnce()
  })

  it('tries a failed call again at the next tick', async () => {
    const state = new Map<bigint, Step>([[4n, clear(4n)]])
    const { instance, send } = keeper(state)
    send.mockRejectedValueOnce(new Error('rpc down'))
    await instance.tick()
    await instance.tick()
    expect(send).toHaveBeenCalledTimes(2)
  })

  it('survives a chain read that fails', async () => {
    const discover = vi.fn().mockRejectedValueOnce(new Error('rpc down')).mockResolvedValue([4n])
    const { instance, send } = keeper(new Map([[4n, clear(4n)]]), { discover })
    await instance.tick()
    expect(send).not.toHaveBeenCalled()
    await instance.tick()
    expect(send).toHaveBeenCalledOnce()
  })

  it('does not stop sending for one sale because another sale fails to read', async () => {
    const next = vi.fn().mockRejectedValueOnce(new Error('bad read')).mockResolvedValueOnce(clear(4n)).mockResolvedValue('wait')
    const { instance, send } = keeper(new Map(), {
      discover: vi.fn().mockResolvedValueOnce([3n, 4n]).mockResolvedValue([]),
      next,
    })
    await instance.tick()
    expect(send.mock.calls).toEqual([[clear(4n)]])
  })
})
