// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { randomBytes, timingSafeEqual } from 'node:crypto'

import { closedReason, computeWindowOpen, type E3Window } from './window'

export interface SchedulerDeps {
  getWindow: (e3Id: bigint) => Promise<E3Window & { inputDeadline: bigint }>
  waitForChainTime: (target: bigint) => Promise<void>
  /** Send the run to the program runner. `skipped` means the E3 has nothing to compute. */
  submit: (e3Id: bigint, committeeKey: Uint8Array, callbackToken: string) => Promise<'submitted' | 'skipped'>
  sleep?: (ms: number) => Promise<void>
  retryBaseMs?: number
  retryMaxMs?: number
  /** How often to check the chain while a run waits for the runner's callback. */
  outcomePollMs?: number
}

interface Entry {
  committeeKey: Uint8Array
  /** The token of the run in progress. Only the runner that got it can call back. */
  token?: string
  settle?: (outcome: 'completed' | 'failed') => void
}

/**
 * Drives the compute of each E3: it waits for the input window to close, sends the run to the
 * runner and, when the run fails, tries again with backoff. It stops when the E3 leaves the
 * `KeyPublished` stage or chain time passes the compute deadline. Each run gets a random token
 * that the runner returns in its callback URL, so only the runner can report a result. The state is
 * in memory: after a restart, recovery schedules the E3 again and issues a new token.
 */
export class ComputeScheduler {
  private readonly active = new Map<string, Entry>()

  constructor(private readonly deps: SchedulerDeps) {}

  /** Start the compute of an E3. Does nothing when it is already scheduled. */
  schedule(e3Id: bigint, committeeKey: Uint8Array): void {
    const id = e3Id.toString()
    if (this.active.has(id)) return
    const entry: Entry = { committeeKey }
    this.active.set(id, entry)
    void this.drive(e3Id, id, entry)
  }

  isScheduled(e3Id: bigint): boolean {
    return this.active.has(e3Id.toString())
  }

  /** Whether `token` is the token of the run in progress. The comparison takes constant time. */
  authorize(e3Id: bigint, token: string): boolean {
    const expected = this.active.get(e3Id.toString())?.token
    if (!expected) return false
    const provided = Buffer.from(token)
    const wanted = Buffer.from(expected)
    return provided.length === wanted.length && timingSafeEqual(provided, wanted)
  }

  /** The runner's result is in and accepted: stop driving the E3. */
  completed(e3Id: bigint): void {
    this.active.get(e3Id.toString())?.settle?.('completed')
  }

  /** The runner reported a failure: the callback token is spent and the run is tried again. */
  failed(e3Id: bigint, error: string): void {
    const entry = this.active.get(e3Id.toString())
    if (!entry) return
    console.warn(`⚠️  The runner failed E3 ${e3Id}: ${error}`)
    entry.token = undefined
    entry.settle?.('failed')
  }

  private async drive(e3Id: bigint, id: string, entry: Entry): Promise<void> {
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)))
    const base = this.deps.retryBaseMs ?? 5_000
    const max = this.deps.retryMaxMs ?? 300_000
    let failures = 0
    try {
      for (;;) {
        try {
          const window = await this.deps.getWindow(e3Id)
          if (!computeWindowOpen(window)) {
            console.log(`⏭️  E3 ${e3Id} needs no compute: ${closedReason(window)}`)
            return
          }
          if (window.now < window.inputDeadline) {
            console.log(`⏰ Waiting for the input window of E3 ${e3Id} to close on-chain...`)
            await this.deps.waitForChainTime(window.inputDeadline)
            continue
          }
          entry.token = randomBytes(32).toString('hex')
          const outcome = new Promise<'completed' | 'failed'>((resolve) => {
            entry.settle = resolve
          })
          if ((await this.deps.submit(e3Id, entry.committeeKey, entry.token)) === 'skipped') return
          if ((await this.awaitOutcome(e3Id, outcome, sleep)) !== 'failed') return
        } catch (error) {
          console.error(`❌ Error processing E3 ${e3Id}:`, error)
        }
        entry.token = undefined
        failures++
        const delay = Math.min(base * 2 ** (failures - 1), max)
        console.log(`🔁 Trying E3 ${e3Id} again in ${Math.round(delay / 1000)} s`)
        await sleep(delay)
      }
    } finally {
      this.active.delete(id)
    }
  }

  /** Wait for the runner's callback; give up when the compute window closes. */
  private async awaitOutcome(
    e3Id: bigint,
    outcome: Promise<'completed' | 'failed'>,
    sleep: (ms: number) => Promise<void>,
  ): Promise<'completed' | 'failed' | 'closed'> {
    const poll = this.deps.outcomePollMs ?? 60_000
    for (;;) {
      const result = await Promise.race([outcome, sleep(poll).then(() => 'poll' as const)])
      if (result !== 'poll') return result
      if (!computeWindowOpen(await this.deps.getWindow(e3Id))) return 'closed'
    }
  }
}
