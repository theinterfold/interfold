// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
import { getBytes, isHexString, keccak256 } from "ethers";

const MAX_PUBLIC_KEY_BYTES = 512 * 1024;
const PUBLIC_KEY_CHUNK_BYTES = 90 * 1024;

export interface CommitteePublicKeyChunk {
  publisher: string;
  candidateHash: string;
  pkCommitment: string;
  chunkIndex: number;
  chunkCount: number;
  totalLength: number;
  chunk: string;
}

interface CandidateAssembly {
  candidateHash: string;
  totalLength: number;
  chunks: Array<Uint8Array | undefined>;
  invalid: boolean;
}

/**
 * Reassemble the only complete transport candidate in an ordered registry log stream.
 *
 * This function checks the transport hash and all chunk metadata. The caller must still
 * validate the returned BFV key against the semantic DKG commitment before production use.
 */
export function assembleUniqueCommitteePublicKey(
  events: CommitteePublicKeyChunk[],
  expectedPkCommitment: string,
): Uint8Array {
  if (!isHexString(expectedPkCommitment, 32)) {
    throw new Error("Expected committee public-key commitment is not bytes32");
  }

  const selectedByPublisher = new Map<string, string>();
  const assemblies = new Map<string, CandidateAssembly>();

  for (const event of events) {
    const chunk = validateChunk(event, expectedPkCommitment);
    if (!chunk) continue;

    const publisher = event.publisher.toLowerCase();
    const candidateHash = event.candidateHash.toLowerCase();
    const selected = selectedByPublisher.get(publisher);
    if (selected && selected !== candidateHash) continue;
    selectedByPublisher.set(publisher, candidateHash);

    const key = `${publisher}:${candidateHash}`;
    const assembly = assemblies.get(key) ?? {
      candidateHash,
      totalLength: event.totalLength,
      chunks: Array.from<Uint8Array | undefined>({
        length: event.chunkCount,
      }).fill(undefined),
      invalid: false,
    };

    if (
      assembly.totalLength !== event.totalLength ||
      assembly.chunks.length !== event.chunkCount
    ) {
      assembly.invalid = true;
    } else {
      const existing = assembly.chunks[event.chunkIndex];
      if (existing && !bytesEqual(existing, chunk)) {
        assembly.invalid = true;
      } else {
        assembly.chunks[event.chunkIndex] = chunk;
      }
    }
    assemblies.set(key, assembly);
  }

  const complete = new Map<string, Uint8Array>();
  for (const assembly of assemblies.values()) {
    if (assembly.invalid || assembly.chunks.some((chunk) => !chunk)) continue;

    const publicKey = new Uint8Array(assembly.totalLength);
    let offset = 0;
    for (const chunk of assembly.chunks as Uint8Array[]) {
      publicKey.set(chunk, offset);
      offset += chunk.length;
    }
    if (
      offset !== assembly.totalLength ||
      keccak256(publicKey).toLowerCase() !== assembly.candidateHash
    ) {
      continue;
    }
    complete.set(assembly.candidateHash, publicKey);
  }

  if (complete.size === 0) {
    throw new Error("No complete committee public-key candidate was published");
  }
  if (complete.size > 1) {
    throw new Error(
      "Multiple complete committee public-key candidates require semantic BFV validation",
    );
  }
  return complete.values().next().value!;
}

function validateChunk(
  event: CommitteePublicKeyChunk,
  expectedPkCommitment: string,
): Uint8Array | undefined {
  if (
    !isHexString(event.candidateHash, 32) ||
    !isHexString(event.pkCommitment, 32) ||
    event.pkCommitment.toLowerCase() !== expectedPkCommitment.toLowerCase() ||
    !isHexString(event.chunk)
  ) {
    return undefined;
  }
  if (
    !Number.isInteger(event.totalLength) ||
    event.totalLength <= 0 ||
    event.totalLength > MAX_PUBLIC_KEY_BYTES
  ) {
    return undefined;
  }
  const expectedChunkCount = Math.ceil(
    event.totalLength / PUBLIC_KEY_CHUNK_BYTES,
  );
  if (
    !Number.isInteger(event.chunkCount) ||
    event.chunkCount !== expectedChunkCount ||
    !Number.isInteger(event.chunkIndex) ||
    event.chunkIndex < 0 ||
    event.chunkIndex >= event.chunkCount
  ) {
    return undefined;
  }

  const chunk = getBytes(event.chunk);
  const remaining =
    event.totalLength - event.chunkIndex * PUBLIC_KEY_CHUNK_BYTES;
  if (chunk.length !== Math.min(remaining, PUBLIC_KEY_CHUNK_BYTES)) {
    return undefined;
  }
  return chunk;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length &&
    left.every((byte, index) => byte === right[index])
  );
}
