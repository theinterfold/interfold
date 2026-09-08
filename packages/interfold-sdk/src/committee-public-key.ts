// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { hexToBytes, isHex, keccak256, type Hex } from 'viem'

import type { CommitteePublicKeyChunkPublishedData } from './events/types'

export const MAX_COMMITTEE_PUBLIC_KEY_BYTES = 512 * 1024
export const MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES = 90 * 1024
export const DEFAULT_MAX_TRACKED_COMMITTEE_KEYS = 128

export interface AssembledCommitteePublicKey {
  e3Id: bigint
  nodes: string[]
  pkCommitment: Hex
  publicKey: Uint8Array
}

interface Assembly {
  nodes: string[]
  pkCommitment: Hex
  candidateHash: Hex
  totalLength: number
  chunks: Array<Uint8Array | undefined>
}

/**
 * Reassembles the deterministic public-key chunks emitted by the registry.
 *
 * The first candidate emitted by each publisher is the only candidate accepted
 * from that publisher. This matches ciphernode and indexer recovery behavior.
 */
export class CommitteePublicKeyAssembler {
  private readonly selectedCandidates = new Map<string, Hex>()
  private readonly assemblies = new Map<string, Assembly>()
  private readonly invalidAssemblies = new Set<string>()
  private readonly completedAssemblies = new Set<string>()
  private readonly trackedE3s = new Map<string, true>()

  constructor(private readonly maxTrackedE3s = DEFAULT_MAX_TRACKED_COMMITTEE_KEYS) {
    if (!Number.isInteger(maxTrackedE3s) || maxTrackedE3s < 1) {
      throw new Error('Maximum tracked committee-key count must be a positive integer')
    }
  }

  add(event: CommitteePublicKeyChunkPublishedData): AssembledCommitteePublicKey | undefined {
    const e3Key = event.e3Id.toString()
    this.track(e3Key)
    const metadata = validateEvent(event)
    const publisherKey = `${e3Key}:${event.publisher.toLowerCase()}`
    const selectedCandidate = this.selectedCandidates.get(publisherKey)
    if (selectedCandidate && selectedCandidate.toLowerCase() !== metadata.candidateHash.toLowerCase()) {
      return undefined
    }
    this.selectedCandidates.set(publisherKey, metadata.candidateHash)

    const assemblyKey = `${publisherKey}:${metadata.candidateHash.toLowerCase()}`
    if (this.completedAssemblies.has(assemblyKey)) return undefined
    if (this.invalidAssemblies.has(assemblyKey)) return undefined
    const assembly = this.assemblies.get(assemblyKey) ?? {
      nodes: [...event.nodes],
      pkCommitment: metadata.pkCommitment,
      candidateHash: metadata.candidateHash,
      totalLength: event.totalLength,
      chunks: Array.from<Uint8Array | undefined>({ length: event.chunkCount }).fill(undefined),
    }

    if (!metadataMatches(assembly, event, metadata.pkCommitment)) {
      this.assemblies.delete(assemblyKey)
      this.invalidAssemblies.add(assemblyKey)
      return undefined
    }

    const existing = assembly.chunks[event.chunkIndex]
    if (existing && !bytesEqual(existing, metadata.chunk)) {
      this.assemblies.delete(assemblyKey)
      this.invalidAssemblies.add(assemblyKey)
      return undefined
    }
    assembly.chunks[event.chunkIndex] = metadata.chunk
    this.assemblies.set(assemblyKey, assembly)

    if (assembly.chunks.some((chunk) => chunk === undefined)) return undefined

    const publicKey = new Uint8Array(assembly.totalLength)
    let offset = 0
    for (const chunk of assembly.chunks as Uint8Array[]) {
      publicKey.set(chunk, offset)
      offset += chunk.length
    }
    if (offset !== assembly.totalLength || keccak256(publicKey).toLowerCase() !== assembly.candidateHash.toLowerCase()) {
      this.assemblies.delete(assemblyKey)
      this.invalidAssemblies.add(assemblyKey)
      return undefined
    }

    this.completedAssemblies.add(assemblyKey)
    this.assemblies.delete(assemblyKey)
    return {
      e3Id: event.e3Id,
      nodes: assembly.nodes,
      pkCommitment: assembly.pkCommitment,
      publicKey,
    }
  }

  clear(e3Id: bigint): void {
    const e3Key = e3Id.toString()
    this.trackedE3s.delete(e3Key)
    this.dropE3(e3Key)
  }

  private track(e3Key: string): void {
    this.trackedE3s.delete(e3Key)
    this.trackedE3s.set(e3Key, true)
    while (this.trackedE3s.size > this.maxTrackedE3s) {
      const oldest = this.trackedE3s.keys().next().value
      if (oldest === undefined) return
      this.trackedE3s.delete(oldest)
      this.dropE3(oldest)
    }
  }

  private dropE3(e3Key: string): void {
    const prefix = `${e3Key}:`
    for (const key of this.selectedCandidates.keys()) {
      if (key.startsWith(prefix)) this.selectedCandidates.delete(key)
    }
    for (const key of this.assemblies.keys()) {
      if (key.startsWith(prefix)) this.assemblies.delete(key)
    }
    for (const key of this.invalidAssemblies) {
      if (key.startsWith(prefix)) this.invalidAssemblies.delete(key)
    }
    for (const key of this.completedAssemblies) {
      if (key.startsWith(prefix)) this.completedAssemblies.delete(key)
    }
  }
}

function validateEvent(event: CommitteePublicKeyChunkPublishedData): {
  candidateHash: Hex
  pkCommitment: Hex
  chunk: Uint8Array
} {
  if (!isBytes32(event.candidateHash) || !isBytes32(event.pkCommitment)) {
    throw new Error('Committee public-key chunk contains an invalid bytes32 value')
  }
  if (!Number.isInteger(event.totalLength) || event.totalLength <= 0 || event.totalLength > MAX_COMMITTEE_PUBLIC_KEY_BYTES) {
    throw new Error('Committee public-key total length is outside the supported range')
  }
  const expectedChunkCount = Math.ceil(event.totalLength / MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
  if (!Number.isInteger(event.chunkCount) || event.chunkCount !== expectedChunkCount) {
    throw new Error('Committee public-key chunk count does not match the total length')
  }
  if (!Number.isInteger(event.chunkIndex) || event.chunkIndex < 0 || event.chunkIndex >= event.chunkCount) {
    throw new Error('Committee public-key chunk index is outside the candidate range')
  }
  if (!isHex(event.chunk)) {
    throw new Error('Committee public-key chunk is not valid hex')
  }

  const chunk = hexToBytes(event.chunk)
  const remaining = event.totalLength - event.chunkIndex * MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES
  const expectedLength = Math.min(remaining, MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES)
  if (chunk.length !== expectedLength) {
    throw new Error('Committee public-key chunk length does not match its index')
  }

  return {
    candidateHash: event.candidateHash as Hex,
    pkCommitment: event.pkCommitment as Hex,
    chunk,
  }
}

function metadataMatches(assembly: Assembly, event: CommitteePublicKeyChunkPublishedData, pkCommitment: Hex): boolean {
  return (
    assembly.totalLength === event.totalLength &&
    assembly.chunks.length === event.chunkCount &&
    assembly.pkCommitment.toLowerCase() === pkCommitment.toLowerCase() &&
    assembly.nodes.length === event.nodes.length &&
    assembly.nodes.every((node, index) => node.toLowerCase() === event.nodes[index]?.toLowerCase())
  )
}

function isBytes32(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value)
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}
