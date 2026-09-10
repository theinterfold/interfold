// SPDX-License-Identifier: LGPL-3.0-only
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { subscribeEstimatedChainTime } from '../src/utils/estimated-chain-clock'

beforeEach(() => vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] }))
afterEach(() => vi.useRealTimers())

it('shares block reads while display ticks advance locally', async () => {
  const client = { getBlock: vi.fn().mockResolvedValue({ timestamp: 1_000n }) }
  const one = vi.fn()
  const two = vi.fn()
  const stopOne = subscribeEstimatedChainTime(client, one)
  const stopTwo = subscribeEstimatedChainTime(client, two)
  await vi.advanceTimersByTimeAsync(5_000)
  expect(client.getBlock).toHaveBeenCalledTimes(1)
  expect(one).toHaveBeenLastCalledWith(1_005_000)
  expect(two).toHaveBeenLastCalledWith(1_005_000)
  await vi.advanceTimersByTimeAsync(25_000)
  expect(client.getBlock).toHaveBeenCalledTimes(3)
  stopOne()
  stopTwo()
  await vi.advanceTimersByTimeAsync(60_000)
  expect(client.getBlock).toHaveBeenCalledTimes(3)
})

it('does not overlap slow reads, including unsubscribe and resubscribe', async () => {
  let resolve!: (block: { timestamp: bigint }) => void
  const client = {
    getBlock: vi.fn(
      () =>
        new Promise<{ timestamp: bigint }>((done) => {
          resolve = done
        }),
    ),
  }
  const stop = subscribeEstimatedChainTime(client, vi.fn())
  await vi.advanceTimersByTimeAsync(30_000)
  stop()
  const stopAgain = subscribeEstimatedChainTime(client, vi.fn())
  expect(client.getBlock).toHaveBeenCalledTimes(1)
  resolve({ timestamp: 1n })
  await vi.advanceTimersByTimeAsync(15_000)
  expect(client.getBlock).toHaveBeenCalledTimes(2)
  stopAgain()
  resolve({ timestamp: 2n })
  await vi.advanceTimersByTimeAsync(30_000)
  expect(client.getBlock).toHaveBeenCalledTimes(2)
})

it('isolates clients and keeps ticking after RPC failure', async () => {
  const failedClient = { getBlock: vi.fn().mockRejectedValue(new Error('Offline')) }
  const otherClient = { getBlock: vi.fn().mockResolvedValue({ timestamp: 50n }) }
  const failedListener = vi.fn()
  const otherListener = vi.fn()
  const start = Date.now()
  const stopFailed = subscribeEstimatedChainTime(failedClient, failedListener)
  const stopOther = subscribeEstimatedChainTime(otherClient, otherListener)
  await vi.advanceTimersByTimeAsync(5_000)
  expect(failedListener).toHaveBeenLastCalledWith(start + 5_000)
  expect(otherListener).toHaveBeenLastCalledWith(55_000)
  stopFailed()
  stopOther()
})
