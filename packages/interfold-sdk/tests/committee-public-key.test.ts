// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { bytesToHex, keccak256 } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  CommitteePublicKeyAssembler,
  MAX_COMMITTEE_PUBLIC_KEY_BYTES,
  MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES,
} from '../src/committee-public-key'
import type { CommitteePublicKeyChunkPublishedData } from '../src/events/types'

const publisher = '0x0000000000000000000000000000000000000001'
const nodes = [publisher, '0x0000000000000000000000000000000000000002']
const pkCommitment = `0x${'11'.repeat(32)}`

function lbfvEnvelope(relinearizationKey: Uint8Array, schemaVersion = 3): Uint8Array {
  const encoded = new Uint8Array(18 + relinearizationKey.length)
  encoded.set(new TextEncoder().encode('IFLBFVKE'))
  const view = new DataView(encoded.buffer)
  view.setUint16(8, schemaVersion, false)
  view.setUint32(10, 0, false)
  view.setUint32(14, relinearizationKey.length, false)
  encoded.set(relinearizationKey, 18)
  return encoded
}

function eventsFor(
  bytes: Uint8Array,
  candidateHash = keccak256(bytes),
  e3Id = 7n,
  publisherAddress = publisher,
): CommitteePublicKeyChunkPublishedData[] {
  const chunkCount = Math.ceil(bytes.length / MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
  return Array.from({ length: chunkCount }, (_, chunkIndex) => ({
    e3Id,
    publisher: publisherAddress,
    candidateHash,
    nodes,
    pkCommitment,
    chunkIndex,
    chunkCount,
    totalLength: bytes.length,
    chunk: bytesToHex(
      bytes.slice(chunkIndex * MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES, (chunkIndex + 1) * MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES),
    ),
  }))
}

describe('CommitteePublicKeyAssembler', () => {
  it('assembles a valid l-BFV key envelope', () => {
    const encoded = lbfvEnvelope(new Uint8Array([3, 4, 5]))
    const [event] = eventsFor(encoded)

    expect(new CommitteePublicKeyAssembler().add(event)?.publicKey).toEqual(encoded)
  })

  it('rejects a pre-cutover l-BFV key envelope', () => {
    const [event] = eventsFor(lbfvEnvelope(new Uint8Array([3, 4, 5]), 2))

    expect(new CommitteePublicKeyAssembler().add(event)).toBeUndefined()
  })

  it('rejects a malformed l-BFV key envelope', () => {
    const encoded = lbfvEnvelope(new Uint8Array([3, 4, 5]))
    new DataView(encoded.buffer).setUint32(14, 4, false)
    const [event] = eventsFor(encoded)

    expect(new CommitteePublicKeyAssembler().add(event)).toBeUndefined()
  })

  it('assembles deterministic chunks in any event order', () => {
    const bytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES + 17).map((_, index) => index % 251)
    const [first, second] = eventsFor(bytes)
    const assembler = new CommitteePublicKeyAssembler()

    expect(assembler.add(second)).toBeUndefined()
    const result = assembler.add(first)

    expect(result?.e3Id).toBe(7n)
    expect(result?.nodes).toEqual(nodes)
    expect(result?.pkCommitment).toBe(pkCommitment)
    expect(result?.publicKey).toEqual(bytes)
  })

  it('assembles the secure-16384 key envelope in 86 chunks', () => {
    const relinearizationKey = new Uint8Array(7_833_888).fill(9)
    const bytes = lbfvEnvelope(relinearizationKey)
    const events = eventsFor(bytes).reverse()
    const assembler = new CommitteePublicKeyAssembler()

    expect(events).toHaveLength(86)
    let result
    for (const event of events) result = assembler.add(event) ?? result

    // toEqual on a multi-megabyte Uint8Array compares Object.entries of both sides and exhausts the heap.
    expect(result?.publicKey.length).toBe(bytes.length)
    expect(keccak256(result!.publicKey)).toBe(keccak256(bytes))
  })

  it('accepts 16 MiB and rejects one additional byte', () => {
    const bytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_BYTES).fill(3)
    const events = eventsFor(bytes)
    const assembler = new CommitteePublicKeyAssembler()

    expect(events).toHaveLength(183)
    let result
    for (const event of events) result = assembler.add(event) ?? result
    expect(result?.publicKey.length).toBe(bytes.length)
    expect(result?.publicKey[0]).toBe(3)
    expect(result?.publicKey.at(-1)).toBe(3)

    expect(() =>
      new CommitteePublicKeyAssembler().add({
        ...events[0],
        totalLength: MAX_COMMITTEE_PUBLIC_KEY_BYTES + 1,
      }),
    ).toThrow('Committee public-key total length is outside the supported range')
  })

  it('accepts an identical replay but rejects a conflicting duplicate', () => {
    const bytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES + 1).fill(7)
    const [first, second] = eventsFor(bytes)
    const assembler = new CommitteePublicKeyAssembler()

    expect(assembler.add(first)).toBeUndefined()
    expect(assembler.bufferedByteLength).toBe(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
    expect(assembler.add(first)).toBeUndefined()
    expect(
      assembler.add({
        ...first,
        chunk: bytesToHex(new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES).fill(8)),
      }),
    ).toBeUndefined()
    expect(assembler.bufferedByteLength).toBe(0)
    expect(assembler.add(second)).toBeUndefined()
  })

  it('limits candidate assemblies for one E3', () => {
    const bytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES + 1).fill(7)
    const [firstA, secondA] = eventsFor(bytes)
    const [firstB, secondB] = eventsFor(bytes, keccak256(bytes), 7n, '0x2222222222222222222222222222222222222222')
    const assembler = new CommitteePublicKeyAssembler(128, 64 * 1024 * 1024, 1)

    expect(assembler.add(firstA)).toBeUndefined()
    expect(assembler.add(firstB)).toBeUndefined()
    expect(assembler.add(secondA)?.publicKey).toEqual(bytes)
    expect(assembler.add(secondB)).toBeUndefined()
    expect(assembler.bufferedByteLength).toBe(0)
  })

  it('bounds partial assembly bytes and releases them on clear', () => {
    const totalLength = MAX_COMMITTEE_PUBLIC_KEY_BYTES
    const chunkCount = Math.ceil(totalLength / MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
    const assembler = new CommitteePublicKeyAssembler(128, MAX_COMMITTEE_PUBLIC_KEY_BYTES, 3)
    const event = (chunkIndex: number, publisherAddress: string): CommitteePublicKeyChunkPublishedData => {
      const remaining = totalLength - chunkIndex * MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES
      const chunkLength = Math.min(remaining, MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
      return {
        e3Id: 7n,
        publisher: publisherAddress,
        candidateHash: `0x${'22'.repeat(32)}`,
        nodes,
        pkCommitment,
        chunkIndex,
        chunkCount,
        totalLength,
        chunk: bytesToHex(new Uint8Array(chunkLength).fill(3)),
      }
    }

    for (let index = 0; index < chunkCount - 1; index += 1) {
      expect(assembler.add(event(index, publisher))).toBeUndefined()
    }
    const bufferedBeforeRejection = (chunkCount - 1) * MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES
    expect(assembler.bufferedByteLength).toBe(bufferedBeforeRejection)

    expect(assembler.add(event(0, '0x2222222222222222222222222222222222222222'))).toBeUndefined()
    expect(assembler.bufferedByteLength).toBe(bufferedBeforeRejection)

    assembler.clear(7n)
    expect(assembler.bufferedByteLength).toBe(0)

    const recoveryBytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES).fill(4)
    const [recovery] = eventsFor(recoveryBytes, keccak256(recoveryBytes), 8n)
    expect(assembler.add(recovery)?.publicKey).toEqual(recoveryBytes)
    expect(assembler.bufferedByteLength).toBe(0)
  })

  it('does not poison a candidate when the buffer is full, and evicts older E3s to make room', () => {
    const partial = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_BYTES).fill(6)
    const assembler = new CommitteePublicKeyAssembler(128, MAX_COMMITTEE_PUBLIC_KEY_BYTES, 3)

    // Fill the buffer to within one chunk of the cap with an old E3's partial candidate.
    for (const event of eventsFor(partial, keccak256(partial), 7n).slice(0, -1)) assembler.add(event)
    expect(assembler.bufferedByteLength).toBe(MAX_COMMITTEE_PUBLIC_KEY_BYTES - 4096)

    // A newer E3 needs room: the old E3's partial chunks are evicted instead of the new candidate being rejected.
    const bytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES + 1).fill(5)
    const [first, second] = eventsFor(bytes, keccak256(bytes), 8n)
    expect(assembler.add(first)).toBeUndefined()
    expect(assembler.bufferedByteLength).toBe(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
    expect(assembler.add(second)?.publicKey).toEqual(bytes)
  })

  it('keeps a candidate usable after dropping a chunk for a full buffer', () => {
    // One candidate is at most the cap, so another publisher's partial candidate on the same E3 (which is never
    // evicted for its own E3) fills the rest. Results are compared by length and hash: a failed toEqual or
    // toBeUndefined on a 16 MiB key renders the whole array and exhausts the heap.
    const otherPublisher = '0x2222222222222222222222222222222222222222'
    const otherBytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES + 1).fill(5)
    const [otherFirst] = eventsFor(otherBytes, keccak256(otherBytes), 7n, otherPublisher)
    const partial = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_BYTES).fill(6)
    const assembler = new CommitteePublicKeyAssembler(128, MAX_COMMITTEE_PUBLIC_KEY_BYTES, 3)
    const events = eventsFor(partial, keccak256(partial), 7n)

    expect(assembler.add(otherFirst) === undefined).toBe(true)
    for (const event of events.slice(1)) expect(assembler.add(event) === undefined).toBe(true)
    expect(assembler.bufferedByteLength).toBe(MAX_COMMITTEE_PUBLIC_KEY_BYTES)

    // Nothing can be evicted: the first chunk is dropped, but the candidate is not marked invalid.
    expect(assembler.add(events[0]) === undefined).toBe(true)
    expect(assembler.bufferedByteLength).toBe(MAX_COMMITTEE_PUBLIC_KEY_BYTES)

    // A conflicting duplicate discards the other candidate and frees its chunk.
    const conflicting = bytesToHex(new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES).fill(8))
    expect(assembler.add({ ...otherFirst, chunk: conflicting }) === undefined).toBe(true)
    expect(assembler.bufferedByteLength).toBe(MAX_COMMITTEE_PUBLIC_KEY_BYTES - MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)

    // The redelivered first chunk now fits and completes the candidate.
    const result = assembler.add(events[0])
    expect(result?.publicKey.length).toBe(MAX_COMMITTEE_PUBLIC_KEY_BYTES)
    expect(keccak256(result!.publicKey)).toBe(keccak256(partial))
    expect(assembler.bufferedByteLength).toBe(0)
  })

  it('ignores late chunks of a cleared E3 instead of buffering them', () => {
    const bytes = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES * 3).map((_, index) => index % 251)
    const otherPublisher = '0x2222222222222222222222222222222222222222'
    const [firstA, secondA, thirdA] = eventsFor(bytes)
    const [, secondB, thirdB] = eventsFor(bytes, keccak256(bytes), 7n, otherPublisher)
    const assembler = new CommitteePublicKeyAssembler()

    assembler.add(firstA)
    assembler.add(secondA)
    expect(assembler.add(thirdA)?.publicKey).toEqual(bytes)
    assembler.clear(7n)

    expect(assembler.add(secondB)).toBeUndefined()
    expect(assembler.add(thirdB)).toBeUndefined()
    expect(assembler.bufferedByteLength).toBe(0)
  })

  it('does not accept bytes that differ from the candidate hash', () => {
    const bytes = new Uint8Array([1, 2, 3])
    const [event] = eventsFor(bytes, `0x${'22'.repeat(32)}`)

    expect(new CommitteePublicKeyAssembler().add(event)).toBeUndefined()
  })

  it('allows another publisher after a candidate fails semantic validation', () => {
    const wrongBytes = new Uint8Array([1, 2, 3])
    const validBytes = new Uint8Array([4, 5, 6])
    const [wrong] = eventsFor(wrongBytes, keccak256(wrongBytes), 13n)
    const [valid] = eventsFor(validBytes, keccak256(validBytes), 13n)
    const assembler = new CommitteePublicKeyAssembler()

    expect(assembler.add(wrong)?.publicKey).toEqual(wrongBytes)
    expect(
      assembler.add({
        ...valid,
        publisher: '0x2222222222222222222222222222222222222222',
      })?.publicKey,
    ).toEqual(validBytes)
  })

  it('evicts old partial and completed E3 state at the configured bound', () => {
    const large = new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES + 1).fill(3)
    const [oldFirst, oldSecond] = eventsFor(large, keccak256(large), 7n)
    const currentBytes = new Uint8Array([4])
    const [current] = eventsFor(currentBytes, keccak256(currentBytes), 8n)
    const assembler = new CommitteePublicKeyAssembler(1)

    expect(assembler.add(oldFirst)).toBeUndefined()
    expect(assembler.add(current)?.e3Id).toBe(8n)
    expect(assembler.add(oldSecond)).toBeUndefined()
    expect(assembler.add(current)?.e3Id).toBe(8n)
  })
})
