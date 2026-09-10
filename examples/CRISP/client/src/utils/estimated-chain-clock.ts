// SPDX-License-Identifier: LGPL-3.0-only

export interface BlockClockClient {
  getBlock: () => Promise<{ timestamp: bigint }>
}

type Listener = (estimatedTimeMs: number) => void

// This clock is for display only. Contracts still enforce the input deadline.
class EstimatedChainClock {
  private listeners = new Set<Listener>()
  private observedMs = Date.now()
  private observedAt = performance.now()
  private tick?: ReturnType<typeof setInterval>
  private refresh?: ReturnType<typeof setTimeout>
  private inFlight = false

  constructor(private client?: BlockClockClient) {}

  private now = () => this.observedMs + (performance.now() - this.observedAt)
  private emit = () => this.listeners.forEach((listener) => listener(this.now()))

  private synchronize = async () => {
    if (!this.client || this.inFlight || !this.listeners.size) return
    this.inFlight = true
    try {
      const block = await this.client.getBlock()
      if (this.listeners.size) {
        this.observedMs = Number(block.timestamp) * 1000
        this.observedAt = performance.now()
        this.emit()
      }
    } catch {
      // Keep the last estimate when the RPC is unavailable.
    } finally {
      this.inFlight = false
      if (this.listeners.size) this.refresh = setTimeout(this.synchronize, 15_000)
    }
  }

  subscribe(listener: Listener) {
    const first = this.listeners.size === 0
    this.listeners.add(listener)
    listener(this.now())
    if (first) {
      this.tick = setInterval(this.emit, 1_000)
      void this.synchronize()
    }
    return () => {
      this.listeners.delete(listener)
      if (!this.listeners.size) {
        clearInterval(this.tick)
        clearTimeout(this.refresh)
      }
    }
  }
}

const clocks = new WeakMap<BlockClockClient, EstimatedChainClock>()
const localClock = new EstimatedChainClock()

export function subscribeEstimatedChainTime(client: BlockClockClient | undefined, listener: Listener) {
  if (!client) return localClock.subscribe(listener)
  let clock = clocks.get(client)
  if (!clock) {
    clock = new EstimatedChainClock(client)
    clocks.set(client, clock)
  }
  return clock.subscribe(listener)
}
