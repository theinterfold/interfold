// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { DEPLOY_BLOCK, LOG_CHUNK_SIZE } from './env-config'
import { publicClient } from './chain'

export interface BlockRange {
  fromBlock: bigint
  toBlock: bigint
}

/** The inclusive block ranges of at most `LOG_CHUNK_SIZE` blocks that cover `from` to the chain head. */
export async function blockRanges(from: bigint = DEPLOY_BLOCK): Promise<{ ranges: BlockRange[]; head: bigint }> {
  const head = await publicClient.getBlockNumber()
  const ranges: BlockRange[] = []
  for (let start = from; start <= head; start += LOG_CHUNK_SIZE) {
    const end = start + LOG_CHUNK_SIZE - 1n
    ranges.push({ fromBlock: start, toBlock: end < head ? end : head })
  }
  return { ranges, head }
}

const CONCURRENT_RANGES = 4

/**
 * Run a log query over every block range from `from` to the head and concatenate the results in
 * block order. Public RPCs cap the range of one `eth_getLogs`, so a scan is a series of bounded
 * requests; a few run at a time to stay within rate limits.
 */
export async function scanLogs<T>(
  read: (range: BlockRange) => Promise<T[]>,
  from: bigint = DEPLOY_BLOCK,
): Promise<{ logs: T[]; head: bigint }> {
  const { ranges, head } = await blockRanges(from)
  const batches: T[][] = []
  for (let i = 0; i < ranges.length; i += CONCURRENT_RANGES) {
    batches.push(...(await Promise.all(ranges.slice(i, i + CONCURRENT_RANGES).map(read))))
  }
  return { logs: batches.flat(), head }
}
