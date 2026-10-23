// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import type { CiphertextOutputReference } from '@interfold/sdk'
import type { Hex } from 'viem'

import type { AvailabilityStore, AvailHelper, PendingPublication } from './availability'
import { closedReason, computeWindowOpen, type E3Window } from './window'

export interface PublicationDeps {
  store: AvailabilityStore
  helper: Pick<AvailHelper, 'submit' | 'proof'>
  getWindow: (e3Id: bigint) => Promise<E3Window>
  /** Send `publishCiphertextOutput`, wait for the receipt and throw unless it succeeded. */
  publish: (e3Id: bigint, reference: CiphertextOutputReference) => Promise<Hex>
  pollIntervalMs: number
  sleep?: (ms: number) => Promise<void>
}

export type PublicationOutcome = 'published' | 'abandoned' | 'missing'

/**
 * Takes the output of an E3 through Avail to Ethereum: it publishes the ciphertext to Avail, waits
 * for the VectorX proof, then calls `publishCiphertextOutput`. The VectorX proof can take hours.
 * Every step writes its result to the output record first, so `resume` continues after a restart.
 * The run stops for good when the compute window closes: Interfold takes no output after that.
 */
export class AvailPublicationRunner {
  private readonly running = new Set<string>()
  // One Avail account signs every submission, and parallel `auction-da` processes would pick the
  // same account nonce. This chain runs the submissions one after the other.
  private submitQueue: Promise<unknown> = Promise.resolve()

  constructor(private readonly deps: PublicationDeps) {}

  private submitSerialized(file: string): Promise<PendingPublication> {
    const result = this.submitQueue.then(() => this.deps.helper.submit(file))
    this.submitQueue = result.catch(() => undefined)
    return result
  }

  /** Run the publication in the background. Does nothing when this E3 is already running. */
  start(e3Id: bigint): void {
    const key = e3Id.toString()
    if (this.running.has(key)) return
    this.running.add(key)
    void this.run(e3Id)
      .then((outcome) => console.log(`📦 Publication of E3 ${e3Id} ended: ${outcome}`))
      .catch((error) => console.error(`❌ Publication of E3 ${e3Id} stopped:`, error))
      .finally(() => this.running.delete(key))
  }

  /** Start every output that the previous run left unfinished. */
  async resume(): Promise<void> {
    for (const record of await this.deps.store.listRecords()) {
      if (record.published || record.abandoned) continue
      console.log(`🔁 Resuming the Avail publication of E3 ${record.e3Id}`)
      this.start(BigInt(record.e3Id))
    }
  }

  async run(e3Id: bigint): Promise<PublicationOutcome> {
    const { store, helper, getWindow, publish, pollIntervalMs } = this.deps
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)))

    for (;;) {
      try {
        const record = await store.readRecord(e3Id)
        if (!record) return 'missing'
        if (record.published) return 'published'
        if (record.abandoned) return 'abandoned'

        // Interfold accepts one output per E3, only in the KeyPublished stage and before the
        // compute deadline. Another publisher, a timeout or a failure ends this one. Never send a
        // second output.
        const window = await getWindow(e3Id)
        if (!computeWindowOpen(window)) {
          const reason = closedReason(window)
          console.log(`⏭️  The output of E3 ${e3Id} is not published: ${reason}`)
          await store.writeRecord({ ...record, abandoned: reason })
          return 'abandoned'
        }

        if (!record.pending) {
          console.log(`📤 Publishing the output of E3 ${e3Id} to Avail...`)
          const pending = await this.submitSerialized(store.ciphertextPath(e3Id))
          // Read the record again: a verified callback can replace the output before it has a
          // publication, and Avail then holds the bytes of the replacement.
          const current = await store.readRecord(e3Id)
          if (!current || current.contentHash.toLowerCase() !== pending.contentHash.toLowerCase()) {
            throw new Error(`Avail published content hash ${pending.contentHash}, which is not the output of E3 ${e3Id}`)
          }
          await store.writeRecord({ ...current, pending })
          console.log(`✅ Avail finalized the output of E3 ${e3Id} in block ${pending.blockNumber}`)
          continue
        }

        if (!record.proof) {
          const result = await helper.proof(record.pending)
          if (result.status === 'pending') {
            console.log(`⏳ The VectorX proof of E3 ${e3Id} is not ready`)
            await sleep(pollIntervalMs)
            continue
          }
          if (result.contentHash.toLowerCase() !== record.contentHash.toLowerCase()) {
            throw new Error(`VectorX proof is for content hash ${result.contentHash}, expected ${record.contentHash}`)
          }
          const { status: _status, ...proof } = result
          await store.writeRecord({ ...record, proof })
          console.log(`✅ The VectorX proof of E3 ${e3Id} is ready`)
          continue
        }

        const published = await publish(e3Id, {
          contentHash: record.contentHash,
          ciphertextCommitment: record.ciphertextCommitment,
          computeProof: record.computeProof,
          availabilityProof: record.proof.abiProof,
        })
        await store.writeRecord({ ...record, published })
        console.log(`✅ Published the output of E3 ${e3Id} in ${published}`)
        return 'published'
      } catch (error) {
        console.error(`⚠️  Publication step of E3 ${e3Id} failed, retrying:`, error instanceof Error ? error.message : error)
        await sleep(pollIntervalMs)
      }
    }
  }
}
