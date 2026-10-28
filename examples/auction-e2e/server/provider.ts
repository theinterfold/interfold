// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { Address, Hex } from 'viem'
import { type AuctionType, isProviderType } from '@interfold/auction'
import { E3Stage } from '@interfold/sdk/contracts'

/** What a mask provider needs to know about a type-4 auction to decide what to do. */
export interface ProviderAuction {
  type: AuctionType
  /** The providers the creator named. */
  providers: readonly Address[]
  /** Whether this provider has sent its mask. */
  submitted: boolean
  stage: E3Stage
  /** Unix seconds: the contract takes inputs from `inputWindow[0]` to `inputWindow[1]`. */
  inputWindow: readonly [bigint, bigint]
  /** Chain time, unix seconds. */
  now: bigint
}

export type MaskDecision =
  /** Prove the mask and send it now. */
  | { kind: 'submit' }
  /** The input window is not open yet: wait for chain time `until`. */
  | { kind: 'wait'; until: bigint }
  /** There is nothing to do, for the stated reason. */
  | { kind: 'skip'; reason: string }

/** The reason of the skip for an auction that does not name this provider. The server stays quiet about it. */
export const NOT_LISTED = 'this address is not a mask provider of the auction'

/**
 * What the provider at `address` does with an auction. It sends one mask, once: after the committee
 * key is published, from the start of the input window to its end, and only if the creator named it.
 */
export function decideMask(address: Address, auction: ProviderAuction): MaskDecision {
  if (!isProviderType(auction.type)) return { kind: 'skip', reason: 'the auction type has no mask providers' }
  if (!auction.providers.some((provider) => provider.toLowerCase() === address.toLowerCase())) {
    return { kind: 'skip', reason: NOT_LISTED }
  }
  if (auction.submitted) return { kind: 'skip', reason: 'the mask is already on chain' }
  if (auction.stage !== E3Stage.KeyPublished) return { kind: 'skip', reason: 'the auction is not in the stage that takes inputs' }
  if (auction.now > auction.inputWindow[1]) return { kind: 'skip', reason: 'the input window is closed' }
  if (auction.now < auction.inputWindow[0]) return { kind: 'wait', until: auction.inputWindow[0] }
  return { kind: 'submit' }
}

/** A mask ready to send. `ciphertext`, `commitment` and `proof` go into `encodeMaskInput`. */
export interface ProvedMask {
  ciphertext: Hex
  commitment: Hex
  proof: Hex
}

/** The contract rejected the transaction when it was simulated. The same proof would fail again. */
export class MaskRejectedError extends Error {}

export interface MaskProviderDeps {
  /** The address of the provider key. */
  address: Address
  /** The state of the auction, or `null` when it is no type-4 auction of this program. */
  readAuction: (e3Id: bigint) => Promise<ProviderAuction | null>
  /** Encrypt a random mask to the committee key and prove it, in this process. */
  prove: (committeeKey: Uint8Array) => Promise<ProvedMask>
  /** Send `publishInput` with the mask and wait until it is mined. Throws {@link MaskRejectedError} when the contract rejects it. */
  send: (e3Id: bigint, mask: ProvedMask) => Promise<Hex>
  waitForChainTime: (target: bigint) => Promise<void>
  sleep?: (ms: number) => Promise<void>
  retryBaseMs?: number
  retryMaxMs?: number
}

/**
 * Sends the mask of one provider key to each auction that names it. The state is in memory: after a
 * restart, recovery calls {@link start} again for each auction, and the on-chain `maskSubmitted`
 * flag stops a second mask. Proofs run one at a time, because each one takes much memory.
 */
export class MaskProvider {
  private readonly active = new Set<string>()
  private proving: Promise<unknown> = Promise.resolve()

  constructor(private readonly deps: MaskProviderDeps) {}

  get address(): Address {
    return this.deps.address
  }

  /** Start the mask of an auction. Does nothing while a run for it is in progress. */
  start(e3Id: bigint, committeeKey: Uint8Array): void {
    const id = e3Id.toString()
    if (this.active.has(id)) return
    this.active.add(id)
    void this.drive(e3Id, committeeKey).finally(() => this.active.delete(id))
  }

  isRunning(e3Id: bigint): boolean {
    return this.active.has(e3Id.toString())
  }

  private async drive(e3Id: bigint, committeeKey: Uint8Array): Promise<void> {
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)))
    const base = this.deps.retryBaseMs ?? 5_000
    const max = this.deps.retryMaxMs ?? 60_000
    let failures = 0
    // A proof that was made but not sent is kept for the next try, unless the contract rejected it.
    let proved: ProvedMask | undefined
    for (;;) {
      try {
        const auction = await this.deps.readAuction(e3Id)
        if (!auction) return
        const decision = decideMask(this.deps.address, auction)
        if (decision.kind === 'skip') {
          if (decision.reason !== NOT_LISTED) console.log(`⏭️  No mask of ${this.deps.address} for E3 ${e3Id}: ${decision.reason}`)
          return
        }
        if (decision.kind === 'wait') {
          console.log(`⏰ Waiting for the input window of E3 ${e3Id} to open before sending the mask...`)
          await this.deps.waitForChainTime(decision.until)
          continue
        }
        if (!proved) {
          console.log(`🎭 Proving the mask of ${this.deps.address} for E3 ${e3Id}...`)
          proved = await this.prove(committeeKey)
          // The proof takes minutes: the window may have closed, or another run may have sent the mask.
          continue
        }
        const hash = await this.deps.send(e3Id, proved)
        console.log(`✅ Sent the mask of ${this.deps.address} for E3 ${e3Id}: ${hash}`)
        return
      } catch (error) {
        if (error instanceof MaskRejectedError) proved = undefined
        console.error(`❌ Mask of ${this.deps.address} for E3 ${e3Id} failed:`, error instanceof Error ? error.message : error)
      }
      failures++
      const delay = Math.min(base * 2 ** (failures - 1), max)
      console.log(`🔁 Trying the mask of E3 ${e3Id} again in ${Math.round(delay / 1000)} s`)
      await sleep(delay)
    }
  }

  private prove(committeeKey: Uint8Array): Promise<ProvedMask> {
    const run = this.proving.then(() => this.deps.prove(committeeKey))
    this.proving = run.catch(() => undefined)
    return run
  }
}
