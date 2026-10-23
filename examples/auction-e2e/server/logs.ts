// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export interface BlockRange {
  fromBlock: bigint
  toBlock: bigint
}

/** Split `[from, to]` into consecutive ranges of at most `size` blocks. */
export function blockRanges(from: bigint, to: bigint, size: bigint): BlockRange[] {
  if (size <= 0n) throw new Error('The log chunk size must be positive')
  const ranges: BlockRange[] = []
  for (let cursor = from; cursor <= to; cursor += size) {
    const end = cursor + size - 1n
    ranges.push({ fromBlock: cursor, toBlock: end < to ? end : to })
  }
  return ranges
}

/**
 * Collect the logs of `[from, to]` one chunk at a time. Public RPC endpoints cap the block range of
 * one `eth_getLogs` request, so a single query from the deployment block fails there.
 */
export async function getLogsChunked<T>(
  fetchRange: (range: BlockRange) => Promise<T[]>,
  from: bigint,
  to: bigint,
  size: bigint,
): Promise<T[]> {
  const logs: T[] = []
  for (const range of blockRanges(from, to, size)) {
    logs.push(...(await fetchRange(range)))
  }
  return logs
}
