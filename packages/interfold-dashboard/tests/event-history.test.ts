// SPDX-License-Identifier: LGPL-3.0-only
import { describe, expect, it, vi } from 'vitest'
import { CanonicalEventHistory, type IndexedLog } from '../src/lib/event-history'

function fixture(scope = 'chain:deployment') {
  const hashes = new Map<bigint, string>()
  const logs: IndexedLog[] = []
  const client = {
    getBlock: vi.fn(async ({ blockNumber }: { blockNumber: bigint }) => ({ hash: hashes.get(blockNumber) ?? `hash:${blockNumber}` })),
    getLogs: vi.fn(async ({ fromBlock, toBlock }: Record<string, unknown>) =>
      logs.filter((log) => log.blockNumber! >= (fromBlock as bigint) && log.blockNumber! <= (toBlock as bigint)),
    ),
  }
  const history = new CanonicalEventHistory(client, scope)
  const read = (head: bigint, from = 1n) => history.read(head, (snapshot) => snapshot.logs({ address: 'contract', event: 'Event' }, from))
  return { client, history, hashes, logs, read }
}
const log = (blockNumber: bigint, logIndex = 0, blockHash = `hash:${blockNumber}`): IndexedLog => ({
  blockNumber,
  logIndex,
  blockHash,
  transactionHash: `tx:${blockNumber}:${logIndex}`,
})

describe('canonical event history', () => {
  it('loads history once, deduplicates replayed logs, and extends only after the cursor', async () => {
    const f = fixture()
    f.logs.push(log(2n), log(2n), log(4n))
    expect(await f.read(10n)).toEqual([log(2n), log(4n)])
    await f.read(10n)
    expect(f.client.getLogs).toHaveBeenCalledTimes(1)
    f.logs.push(log(11n))
    expect(await f.read(12n)).toEqual([log(2n), log(4n), log(11n)])
    expect(f.client.getLogs).toHaveBeenLastCalledWith({ address: 'contract', event: 'Event', fromBlock: 11n, toBlock: 12n })
  })

  it('serializes overlapping refreshes without fetching the same range twice', async () => {
    const f = fixture()
    const [one, two] = await Promise.all([f.read(10n), f.read(12n)])
    expect(one).toEqual([])
    expect(two).toEqual([])
    expect(f.client.getLogs.mock.calls.map(([args]) => [args.fromBlock, args.toBlock])).toEqual([
      [1n, 10n],
      [11n, 12n],
    ])
  })

  it('does not advance a cursor or retain memoized values after a failed chunk', async () => {
    const f = fixture()
    f.client.getLogs.mockResolvedValueOnce([log(2n)]).mockRejectedValueOnce(new Error('Unavailable'))
    await expect(
      f.history.read(20_000n, async (snapshot) => {
        snapshot.set('complete', true)
        return snapshot.logs({ address: 'contract', event: 'Event' }, 1n)
      }),
    ).rejects.toThrow('Unavailable')
    expect(
      await f.history.read(20_000n, async (snapshot) => {
        expect(snapshot.get('complete')).toBeUndefined()
        return snapshot.logs({ address: 'contract', event: 'Event' }, 1n)
      }),
    ).toEqual([])
    expect(f.client.getLogs.mock.calls.map(([args]) => [args.fromBlock, args.toBlock])).toEqual([
      [1n, 9_501n],
      [9_502n, 19_002n],
      [1n, 9_501n],
      [9_502n, 19_002n],
      [19_003n, 20_000n],
    ])
  })

  it('rebuilds after a reorg deeper than the polling window and invalidates terminal values', async () => {
    const f = fixture()
    f.logs.push(log(2n))
    await f.history.read(10_000n, async (snapshot) => {
      snapshot.set('complete', true)
      return snapshot.logs({ address: 'contract', event: 'Event' }, 1n)
    })
    f.hashes.set(10_000n, 'replacement ancestor')
    f.logs.splice(0, 1, log(2n, 0, 'replacement block'))
    expect(
      await f.history.read(10_010n, async (snapshot) => {
        expect(snapshot.get('complete')).toBeUndefined()
        return snapshot.logs({ address: 'contract', event: 'Event' }, 1n)
      }),
    ).toEqual([log(2n, 0, 'replacement block')])
    expect(f.client.getLogs.mock.calls[2][0].fromBlock).toBe(1n)
  })

  it('detects a replacement at the same height and a chain that moves during a read', async () => {
    const f = fixture()
    await f.read(10n)
    f.hashes.set(10n, 'replacement')
    await f.read(10n)
    expect(f.client.getLogs).toHaveBeenCalledTimes(2)
    f.client.getLogs.mockImplementationOnce(async () => {
      f.hashes.set(12n, 'changed mid-read')
      return []
    })
    await expect(f.read(12n)).rejects.toThrow('chain changed')
    await f.read(12n)
    expect(f.client.getLogs.mock.calls.slice(-2).map(([args]) => args.fromBlock)).toEqual([11n, 11n])
  })

  it('prepends missing history and supports a moving recent-events window', async () => {
    const f = fixture()
    f.logs.push(log(3n), log(8n), log(11n))
    expect(await f.read(10n, 7n)).toEqual([log(8n)])
    expect(await f.read(12n, 8n)).toEqual([log(8n), log(11n)])
    expect(await f.read(12n, 1n)).toEqual([log(3n), log(8n), log(11n)])
    expect(f.client.getLogs.mock.calls.map(([args]) => [args.fromBlock, args.toBlock])).toEqual([
      [7n, 10n],
      [11n, 12n],
      [1n, 6n],
    ])
  })

  it('keeps chains, deployments, event arguments, and historical views separate', async () => {
    const one = fixture('one')
    const two = fixture('two')
    one.logs.push(log(8n))
    two.logs.push(log(9n))
    expect(await one.read(10n)).toEqual([log(8n)])
    expect(await two.read(10n)).toEqual([log(9n)])
    await one.history.read(10n, (snapshot) => snapshot.logs({ address: 'another', event: 'Event', args: { id: 5n } }, 1n))
    expect(one.client.getLogs).toHaveBeenCalledTimes(2)
    expect(await one.read(5n)).toEqual([])
    expect(one.client.getLogs).toHaveBeenCalledTimes(3)
  })

  it('discards work interrupted by abort or reset and permits a later retry', async () => {
    const f = fixture()
    const abort = new AbortController()
    await expect(
      f.history.read(
        10n,
        async (snapshot) => {
          await snapshot.logs({ address: 'contract', event: 'Event' }, 1n)
          abort.abort()
        },
        abort.signal,
      ),
    ).rejects.toThrow('cancelled')
    await f.read(10n)
    expect(f.client.getLogs).toHaveBeenCalledTimes(2)
    await expect(
      f.history.read(12n, async () => {
        f.history.reset()
      }),
    ).rejects.toThrow('cancelled')
    await f.read(12n)
    expect(f.client.getLogs).toHaveBeenLastCalledWith({ address: 'contract', event: 'Event', fromBlock: 1n, toBlock: 12n })
  })

  it('rejects unconfirmed and removed events', async () => {
    const f = fixture()
    f.client.getLogs.mockResolvedValueOnce([{ ...log(2n), blockHash: null }])
    await expect(f.read(10n)).rejects.toThrow('unconfirmed')
    f.client.getLogs.mockResolvedValueOnce([{ ...log(2n), removed: true }])
    await expect(f.read(10n)).rejects.toThrow('unconfirmed')
    await f.read(10n)
    expect(f.client.getLogs.mock.calls.every(([args]) => args.fromBlock === 1n)).toBe(true)
  })
})
