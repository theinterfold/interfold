// SPDX-License-Identifier: LGPL-3.0-only

export type IndexedLog = {
  blockNumber: bigint | null
  blockHash: string | null
  transactionHash: string | null
  logIndex: number | null
  removed?: boolean
}

type HistoryClient = {
  getBlock: (args: { blockNumber: bigint }) => Promise<{ hash: string | null }>
  getLogs: (args: Record<string, unknown>) => Promise<IndexedLog[]>
}
type Stream = { from: bigint; to: bigint; logs: IndexedLog[] }
const LOG_CHUNK = 9_500n

function queryKey(value: unknown): string {
  return JSON.stringify(value, (_, item) => {
    if (typeof item === 'bigint') return { bigint: item.toString() }
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return Object.fromEntries(
        Object.keys(item)
          .sort()
          .map((key) => [key, item[key]]),
      )
    }
    return item
  })
}

export class HistorySnapshot {
  constructor(
    readonly head: bigint,
    private client: HistoryClient,
    private streams: Map<string, Stream>,
    private values: Map<string, unknown>,
    private checkCancelled: () => void,
  ) {}

  get<T>(key: string): T | undefined {
    return this.values.get(key) as T | undefined
  }
  set<T>(key: string, value: T) {
    this.values.set(key, value)
  }

  async logs<T extends IndexedLog>(args: Record<string, unknown>, from: bigint): Promise<T[]> {
    this.checkCancelled()
    if (from > this.head) return []
    const key = queryKey(args)
    const cached = this.streams.get(key)
    let logs = cached?.logs ?? []
    const ranges: Array<[bigint, bigint]> = cached
      ? [
          ...(from < cached.from ? [[from, cached.from - 1n] as [bigint, bigint]] : []),
          ...(this.head > cached.to ? [[cached.to + 1n, this.head] as [bigint, bigint]] : []),
        ]
      : [[from, this.head]]
    for (const [start, end] of ranges) {
      const additions: IndexedLog[] = []
      for (let block = start; block <= end; block += LOG_CHUNK + 1n) {
        this.checkCancelled()
        const toBlock = block + LOG_CHUNK < end ? block + LOG_CHUNK : end
        const result = await this.client.getLogs({ ...args, fromBlock: block, toBlock })
        for (const log of result) {
          if (log.removed || log.blockNumber === null || !log.blockHash || !log.transactionHash || log.logIndex === null) {
            throw new Error('The RPC returned an unconfirmed log. Retry the refresh.')
          }
          if (log.blockNumber >= block && log.blockNumber <= toBlock) additions.push(log)
        }
      }
      logs = logs.concat(additions)
    }
    if (ranges.length) {
      const unique = new Map(logs.map((log) => [`${log.blockHash}:${log.transactionHash}:${log.logIndex}`, log]))
      logs = [...unique.values()].sort((a, b) => {
        if (a.blockNumber !== b.blockNumber) return a.blockNumber! < b.blockNumber! ? -1 : 1
        return a.logIndex! - b.logIndex!
      })
      this.streams.set(key, { from: cached && cached.from < from ? cached.from : from, to: this.head, logs })
    }
    return logs.filter((log) => log.blockNumber! >= from && log.blockNumber! <= this.head) as T[]
  }
}

// One instance belongs to one client and deployment. Failed reads commit no cursors or values.
export class CanonicalEventHistory {
  private streams = new Map<string, Stream>()
  private values = new Map<string, unknown>()
  private anchor?: { number: bigint; hash: string }
  private queue: Promise<unknown> = Promise.resolve()
  private epoch = 0

  constructor(
    private client: HistoryClient,
    readonly scope: string,
  ) {}

  reset() {
    this.epoch += 1
    this.streams.clear()
    this.values.clear()
    this.anchor = undefined
  }

  read<T>(head: bigint, work: (snapshot: HistorySnapshot) => Promise<T>, signal?: AbortSignal): Promise<T> {
    const epoch = this.epoch
    const run = async () => {
      const checkCancelled = () => {
        if (signal?.aborted || epoch !== this.epoch) throw new Error('The history refresh was cancelled.')
      }
      checkCancelled()
      const block = await this.client.getBlock({ blockNumber: head })
      if (!block.hash) throw new Error('The requested block has no hash.')
      let reset = this.anchor !== undefined && head < this.anchor.number
      if (this.anchor && !reset) {
        const oldHash = head === this.anchor.number ? block.hash : (await this.client.getBlock({ blockNumber: this.anchor.number })).hash
        reset = oldHash !== this.anchor.hash
      }
      const streams = reset ? new Map<string, Stream>() : new Map(this.streams)
      const values = reset ? new Map<string, unknown>() : new Map(this.values)
      const snapshot = new HistorySnapshot(head, this.client, streams, values, checkCancelled)
      const result = await work(snapshot)
      checkCancelled()
      const after = await this.client.getBlock({ blockNumber: head })
      if (after.hash !== block.hash) throw new Error('The chain changed during the refresh. Retry the refresh.')
      checkCancelled()
      this.streams = streams
      this.values = values
      this.anchor = { number: head, hash: block.hash }
      return result
    }
    const result = this.queue.then(run, run)
    this.queue = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }
}
