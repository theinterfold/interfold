// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { setTimeout as sleep } from 'node:timers/promises'
import type { Hex } from 'viem'

/** A call that anyone may send for a sale, and that the keeper sends when the chain allows it. */
export type KeeperCall =
  | { functionName: 'publishProbes'; args: readonly [saleId: bigint] }
  | { functionName: 'clear'; args: readonly [saleId: bigint] }
  | { functionName: 'payMarginal'; args: readonly [saleId: bigint, index: bigint] }

// A sale has at most MAX_BIDDERS registered marginal claims; a tick that stops here goes on at the next one.
const MAX_CALLS_PER_TICK = 100

export interface KeeperDeps {
  /** The sales that exist and that the keeper does not know yet. The first call returns all of them. */
  discover: () => Promise<bigint[]>
  /** The next call that the chain allows for the sale, `wait` while the chain allows none, `done` when the sale needs no more calls. */
  next: (saleId: bigint) => Promise<KeeperCall | 'wait' | 'done'>
  /** Send the call and wait until it is mined. Throws unless it succeeded. */
  send: (call: KeeperCall) => Promise<Hex>
}

/**
 * Moves a sale through the steps that anyone may call: `publishProbes` once the plaintext of round 1
 * is out, `clear` once the plaintext of round 2 is out, and, after the marginal window of a capped
 * sale, `payMarginal` for each registered marginal claim. The chain is the only state: each tick reads
 * what the sale allows and sends that call, so a restart loses nothing and a call that another
 * account already sent is not sent again. One call is in flight at a time.
 */
export class SaleKeeper {
  private readonly sales = new Set<bigint>()
  // One tick at a time, and a tick sends its calls one after the other: no sale gets two calls at once.
  private ticking = false
  private running = false

  constructor(private readonly deps: KeeperDeps) {}

  /** The sales that the keeper still watches. */
  get watched(): bigint[] {
    return [...this.sales]
  }

  /** Check every watched sale once. A tick that starts while the previous one runs does nothing. */
  async tick(): Promise<void> {
    if (this.ticking) return
    this.ticking = true
    try {
      for (const saleId of await this.deps.discover()) this.sales.add(saleId)
      for (const saleId of [...this.sales]) await this.step(saleId)
    } catch (error) {
      console.error('⚠️  The keeper could not read the chain:', error instanceof Error ? error.message : error)
    } finally {
      this.ticking = false
    }
  }

  private async step(saleId: bigint): Promise<void> {
    try {
      // A sale can have many calls to make at once (one `payMarginal` per registered claim): send them
      // one after the other until the chain allows no more, up to a bound per tick.
      for (let sent = 0; sent < MAX_CALLS_PER_TICK; sent++) {
        const call = await this.deps.next(saleId)
        if (call === 'wait') return
        if (call === 'done') {
          this.sales.delete(saleId)
          return
        }
        console.log(`🔧 Sale ${saleId}: sending ${call.functionName}(${call.args.join(', ')})`)
        const hash = await this.deps.send(call)
        console.log(`✅ Sale ${saleId}: ${call.functionName} mined in ${hash}`)
      }
    } catch (error) {
      // The next tick reads the chain again and tries again, if the call is still allowed.
      console.warn(`⚠️  Sale ${saleId}: the keeper call failed:`, error instanceof Error ? error.message : error)
    }
  }

  /** Tick now, then `intervalMs` after each tick ends, until `stop`. */
  start(intervalMs: number): void {
    if (this.running) return
    this.running = true
    void (async () => {
      while (this.running) {
        await this.tick()
        await sleep(intervalMs)
      }
    })()
  }

  stop(): void {
    this.running = false
  }
}
