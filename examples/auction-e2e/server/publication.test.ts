// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { E3Stage } from '@interfold/sdk/contracts'

import { AvailabilityStore, parseProofOutput, parseSubmitOutput, type OutputRecord, type PendingPublication } from './availability'
import { AvailPublicationRunner } from './publication'
import type { E3Window } from './window'

const contentHash = `0x${'ab'.repeat(32)}` as const
const pending: PendingPublication = { contentHash, blockHash: '0x01', blockNumber: 9, extrinsicIndex: 1 }
const ready = { status: 'ready', contentHash, blockNumber: 9, leafIndex: '4', abiProof: '0xbeef' } as const
const record: OutputRecord = { e3Id: '3', contentHash, ciphertextCommitment: `0x${'cd'.repeat(32)}`, computeProof: '0x01' }
const open: E3Window = { stage: E3Stage.KeyPublished, now: 100n, computeDeadline: 200n }

describe('AvailPublicationRunner', () => {
  let directory: string
  let store: AvailabilityStore

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'auction-publication-'))
    store = new AvailabilityStore(directory)
    await store.createRecord(record, Buffer.from('ciphertext'))
    vi.spyOn(console, 'log').mockImplementation(() => undefined)
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await rm(directory, { recursive: true, force: true })
  })

  const runner = (overrides: Partial<ConstructorParameters<typeof AvailPublicationRunner>[0]> = {}) => {
    const helper = {
      submit: vi.fn().mockResolvedValue(pending),
      proof: vi.fn().mockResolvedValueOnce({ status: 'pending' }).mockResolvedValue(ready),
    }
    const publish = vi.fn().mockResolvedValue('0xfeed')
    const instance = new AvailPublicationRunner({
      store,
      helper,
      getWindow: async () => open,
      publish,
      pollIntervalMs: 1,
      sleep: async () => undefined,
      ...overrides,
    })
    return { instance, helper, publish }
  }

  it('submits, waits for the proof and publishes once with the ABI proof', async () => {
    const { instance, helper, publish } = runner()
    expect(await instance.run(3n)).toBe('published')
    expect(helper.submit).toHaveBeenCalledOnce()
    expect(helper.proof).toHaveBeenCalledTimes(2)
    expect(publish).toHaveBeenCalledOnce()
    expect(publish).toHaveBeenCalledWith(3n, {
      contentHash,
      ciphertextCommitment: record.ciphertextCommitment,
      computeProof: '0x01',
      availabilityProof: '0xbeef',
    })
    expect((await store.readRecord(3n))?.published).toBe('0xfeed')
    // A repeated run never publishes again.
    expect(await instance.run(3n)).toBe('published')
    expect(publish).toHaveBeenCalledOnce()
  })

  it('resumes after a restart without submitting to Avail again', async () => {
    await store.writeRecord({ ...record, pending })
    const { instance, helper, publish } = runner()
    expect(await instance.run(3n)).toBe('published')
    expect(helper.submit).not.toHaveBeenCalled()
    expect(publish).toHaveBeenCalledOnce()
  })

  it('does not publish when the E3 left the KeyPublished stage', async () => {
    const { instance, helper, publish } = runner({ getWindow: async () => ({ ...open, stage: E3Stage.CiphertextReady }) })
    expect(await instance.run(3n)).toBe('abandoned')
    expect(helper.submit).not.toHaveBeenCalled()
    expect(publish).not.toHaveBeenCalled()
  })

  it('abandons the record when chain time passes the compute deadline, and resume skips it', async () => {
    await store.writeRecord({ ...record, pending })
    const { instance, helper, publish } = runner({ getWindow: async () => ({ ...open, now: 201n }) })
    expect(await instance.run(3n)).toBe('abandoned')
    expect((await store.readRecord(3n))?.abandoned).toContain('deadline')
    expect(helper.proof).not.toHaveBeenCalled()
    expect(publish).not.toHaveBeenCalled()

    const start = vi.spyOn(instance, 'start')
    await instance.resume()
    expect(start).not.toHaveBeenCalled()
  })

  it('stops retrying a failing publication when the deadline passes', async () => {
    let now = 100n
    const publish = vi.fn().mockImplementation(async () => {
      now = 201n
      throw new Error('reverted')
    })
    const { instance } = runner({ getWindow: async () => ({ ...open, now }), publish })
    expect(await instance.run(3n)).toBe('abandoned')
    expect(publish).toHaveBeenCalledOnce()
  })

  it('retries a failed step', async () => {
    const submit = vi.fn().mockRejectedValueOnce(new Error('Avail is down')).mockResolvedValue(pending)
    const { instance, publish } = runner({
      helper: { submit, proof: vi.fn().mockResolvedValue(ready) },
    })
    expect(await instance.run(3n)).toBe('published')
    expect(submit).toHaveBeenCalledTimes(2)
    expect(publish).toHaveBeenCalledOnce()
  })

  it('retries after a proof for other content', async () => {
    const wrong = { ...ready, contentHash: `0x${'11'.repeat(32)}` as const }
    const { instance, publish } = runner({
      helper: { submit: vi.fn().mockResolvedValue(pending), proof: vi.fn().mockResolvedValueOnce(wrong).mockResolvedValue(ready) },
    })
    expect(await instance.run(3n)).toBe('published')
    expect(publish).toHaveBeenCalledOnce()
  })

  it('runs the Avail submissions of two E3s one at a time', async () => {
    await store.createRecord({ ...record, e3Id: '4' }, Buffer.from('other'))
    let active = 0
    let overlap = false
    const submit = vi.fn().mockImplementation(async () => {
      active++
      overlap ||= active > 1
      await new Promise((resolve) => setTimeout(resolve, 5))
      active--
      return pending
    })
    const { instance } = runner({ helper: { submit, proof: vi.fn().mockResolvedValue(ready) } })
    await store.writeRecord({ ...record, e3Id: '4' })
    await Promise.all([instance.run(3n), instance.run(4n)])
    expect(submit).toHaveBeenCalledTimes(2)
    expect(overlap).toBe(false)
  })
})

describe('AvailabilityStore.createRecord', () => {
  it('replaces an output that has no Avail publication, and keeps one that has', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'auction-store-'))
    try {
      const store = new AvailabilityStore(directory)
      await store.createRecord(record, Buffer.from('first'))
      const replacement = { ...record, contentHash: `0x${'22'.repeat(32)}` as const }
      expect((await store.createRecord(replacement, Buffer.from('second'))).created).toBe(true)
      expect((await store.readRecord(3n))?.contentHash).toBe(replacement.contentHash)

      await store.writeRecord({ ...replacement, pending: { ...pending, contentHash: replacement.contentHash } })
      const third = await store.createRecord(record, Buffer.from('third'))
      expect(third.created).toBe(false)
      expect(third.record.contentHash).toBe(replacement.contentHash)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})

describe('helper output', () => {
  it('parses the documents of auction-da', () => {
    expect(parseSubmitOutput(JSON.stringify(pending))).toEqual(pending)
    expect(parseProofOutput('{"status":"pending"}')).toEqual({ status: 'pending' })
    expect(parseProofOutput(JSON.stringify(ready))).toEqual(ready)
    expect(() => parseSubmitOutput('{}')).toThrow()
    expect(() => parseProofOutput('{"status":"ready"}')).toThrow()
  })
})
