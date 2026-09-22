// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { concat, hexlify, keccak256 } from "ethers";

import {
  type CommitteePublicKeyChunk,
  assembleUniqueCommitteePublicKey,
} from "../../tasks/committeePublicKey";

const commitment = `0x${"11".repeat(32)}`;
const publisherA = `0x${"aa".repeat(20)}`;
const publisherB = `0x${"bb".repeat(20)}`;
const publicKeyChunkBytes = 90 * 1024;
const maxPublicKeyBytes = 16 * 1024 * 1024;
const secure16384KeyEnvelopeBytes = 10_445_217;

function allChunksFor(
  publicKey: Uint8Array,
  publisher = publisherA,
): CommitteePublicKeyChunk[] {
  const candidateHash = keccak256(publicKey);
  const chunkCount = Math.ceil(publicKey.length / publicKeyChunkBytes);
  return Array.from({ length: chunkCount }, (_, chunkIndex) => ({
    publisher,
    candidateHash,
    pkCommitment: commitment,
    chunkIndex,
    chunkCount,
    totalLength: publicKey.length,
    chunk: hexlify(
      publicKey.slice(
        chunkIndex * publicKeyChunkBytes,
        (chunkIndex + 1) * publicKeyChunkBytes,
      ),
    ),
  }));
}

function chunksFor(
  first: Uint8Array,
  second: Uint8Array,
  publisher = publisherA,
): CommitteePublicKeyChunk[] {
  const publicKey = concat([first, second]);
  const candidateHash = keccak256(publicKey);
  return [
    {
      publisher,
      candidateHash,
      pkCommitment: commitment,
      chunkIndex: 0,
      chunkCount: 2,
      totalLength: first.length + second.length,
      chunk: hexlify(first),
    },
    {
      publisher,
      candidateHash,
      pkCommitment: commitment,
      chunkIndex: 1,
      chunkCount: 2,
      totalLength: first.length + second.length,
      chunk: hexlify(second),
    },
  ];
}

describe("committee public-key task assembly", function () {
  const first = new Uint8Array(publicKeyChunkBytes).fill(0x11);
  const second = new Uint8Array([0x22, 0x33]);

  it("reassembles complete chunks in any arrival order", function () {
    const chunks = chunksFor(first, second).reverse();
    const result = assembleUniqueCommitteePublicKey(chunks, commitment);

    expect(hexlify(result)).to.equal(concat([first, second]));
  });

  it("reassembles the secure-16384 key envelope in 114 chunks", function () {
    const keyEnvelope = new Uint8Array(secure16384KeyEnvelopeBytes).fill(0x44);
    const chunks = allChunksFor(keyEnvelope).reverse();

    expect(chunks).to.have.length(114);
    const result = assembleUniqueCommitteePublicKey(chunks, commitment);
    expect(result).to.have.length(secure16384KeyEnvelopeBytes);
    expect(result[0]).to.equal(0x44);
    expect(result.at(-1)).to.equal(0x44);
  });

  it("accepts 16 MiB and rejects one additional byte", function () {
    const publicKey = new Uint8Array(maxPublicKeyBytes).fill(0x33);
    const chunks = allChunksFor(publicKey);

    expect(chunks).to.have.length(183);
    const result = assembleUniqueCommitteePublicKey(chunks, commitment);
    expect(result).to.have.length(maxPublicKeyBytes);
    expect(result[0]).to.equal(0x33);
    expect(result.at(-1)).to.equal(0x33);

    const oversized = chunks.map((chunk) => ({
      ...chunk,
      totalLength: maxPublicKeyBytes + 1,
    }));
    expect(() =>
      assembleUniqueCommitteePublicKey(oversized, commitment),
    ).to.throw("No complete committee public-key candidate");
  });

  it("rejects incomplete and corrupted candidates", function () {
    const [firstChunk, secondChunk] = chunksFor(first, second);
    expect(() =>
      assembleUniqueCommitteePublicKey([firstChunk!], commitment),
    ).to.throw("No complete committee public-key candidate");

    const corrupted = { ...secondChunk!, chunk: "0x4455" };
    expect(() =>
      assembleUniqueCommitteePublicKey([firstChunk!, corrupted], commitment),
    ).to.throw("No complete committee public-key candidate");
  });

  it("uses only the first valid candidate from each publisher", function () {
    const firstCandidate = chunksFor(first, second);
    const secondCandidate = chunksFor(first, new Uint8Array([0x44, 0x55]));

    expect(() =>
      assembleUniqueCommitteePublicKey(
        [firstCandidate[0]!, ...secondCandidate],
        commitment,
      ),
    ).to.throw("No complete committee public-key candidate");
  });

  it("rejects different complete candidates without semantic validation", function () {
    const firstCandidate = chunksFor(first, second, publisherA);
    const secondCandidate = chunksFor(
      first,
      new Uint8Array([0x44, 0x55]),
      publisherB,
    );

    expect(() =>
      assembleUniqueCommitteePublicKey(
        [...firstCandidate, ...secondCandidate],
        commitment,
      ),
    ).to.throw("Multiple complete committee public-key candidates");
  });

  it("deduplicates the same complete candidate from two publishers", function () {
    const result = assembleUniqueCommitteePublicKey(
      [
        ...chunksFor(first, second, publisherA),
        ...chunksFor(first, second, publisherB),
      ],
      commitment,
    );

    expect(hexlify(result)).to.equal(concat([first, second]));
  });
});
