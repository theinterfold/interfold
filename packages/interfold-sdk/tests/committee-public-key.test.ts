// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { bytesToHex, keccak256 } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  CommitteePublicKeyAssembler,
  decodeLbfvKeyEnvelope,
  MAX_COMMITTEE_PUBLIC_KEY_BYTES,
  MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES,
} from '../src/committee-public-key'
import type { CommitteePublicKeyChunkPublishedData } from '../src/events/types'

const publisher = '0x0000000000000000000000000000000000000001'
const nodes = [publisher, '0x0000000000000000000000000000000000000002']
const pkCommitment = `0x${'11'.repeat(32)}`

function lbfvEnvelope(publicKey: Uint8Array, relinearizationKey: Uint8Array): Uint8Array {
  const encoded = new Uint8Array(18 + publicKey.length + relinearizationKey.length)
  encoded.set(new TextEncoder().encode('IFLBFVKE'))
  const view = new DataView(encoded.buffer)
  view.setUint16(8, 1, false)
  view.setUint32(10, publicKey.length, false)
  view.setUint32(14, relinearizationKey.length, false)
  encoded.set(publicKey, 18)
  encoded.set(relinearizationKey, 18 + publicKey.length)
  return encoded
}

function eventsFor(bytes: Uint8Array, candidateHash = keccak256(bytes), e3Id = 7n): CommitteePublicKeyChunkPublishedData[] {
  const chunkCount = Math.ceil(bytes.length / MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
  return Array.from({ length: chunkCount }, (_, chunkIndex) => ({
    e3Id,
    publisher,
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
  it('decodes the versioned l-BFV key envelope', () => {
    const encoded = lbfvEnvelope(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]))
    const decoded = decodeLbfvKeyEnvelope(encoded)

    expect(decoded.schemaVersion).toBe(1)
    expect(decoded.publicKey).toEqual(new Uint8Array([1, 2]))
    expect(decoded.relinearizationKey).toEqual(new Uint8Array([3, 4, 5]))
  })

  it('exposes decoded l-BFV key material after assembly', () => {
    const encoded = lbfvEnvelope(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]))
    const [event] = eventsFor(encoded)
    const result = new CommitteePublicKeyAssembler().add(event)

    expect(result?.lbfvKeyEnvelope?.publicKey).toEqual(new Uint8Array([1, 2]))
    expect(result?.lbfvKeyEnvelope?.relinearizationKey).toEqual(new Uint8Array([3, 4, 5]))
  })

  it('rejects a malformed l-BFV key envelope', () => {
    const encoded = lbfvEnvelope(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]))
    new DataView(encoded.buffer).setUint32(14, 4, false)
    const [event] = eventsFor(encoded)

    expect(() => decodeLbfvKeyEnvelope(encoded)).toThrow('length does not match its header')
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

  it('assembles the secure-16384 key envelope in 142 chunks', () => {
    const publicKey = new Uint8Array(5_222_596).fill(7)
    const relinearizationKey = new Uint8Array(7_833_888).fill(9)
    const bytes = lbfvEnvelope(publicKey, relinearizationKey)
    const events = eventsFor(bytes).reverse()
    const assembler = new CommitteePublicKeyAssembler()

    expect(events).toHaveLength(142)
    let result
    for (const event of events) result = assembler.add(event) ?? result

    expect(result?.publicKey.length).toBe(bytes.length)
    expect(result?.lbfvKeyEnvelope?.publicKey.length).toBe(publicKey.length)
    expect(result?.lbfvKeyEnvelope?.publicKey[0]).toBe(7)
    expect(result?.lbfvKeyEnvelope?.relinearizationKey.length).toBe(relinearizationKey.length)
    expect(result?.lbfvKeyEnvelope?.relinearizationKey[0]).toBe(9)
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
    expect(assembler.add(first)).toBeUndefined()
    expect(
      assembler.add({
        ...first,
        chunk: bytesToHex(new Uint8Array(MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES).fill(8)),
      }),
    ).toBeUndefined()
    expect(assembler.add(second)).toBeUndefined()
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
