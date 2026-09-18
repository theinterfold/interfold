// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { ethers } from "./fixtures/connection";

const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const HASH_A = ethers.keccak256(ethers.toUtf8Bytes("route-a"));
const HASH_B = ethers.keccak256(ethers.toUtf8Bytes("route-b"));
const HASH_C = ethers.keccak256(ethers.toUtf8Bytes("route-c"));
const HASH_D = ethers.keccak256(ethers.toUtf8Bytes("route-d"));

function proofWithAnchors(
  length: number,
  first: string,
  second: string,
): string {
  const inputs = Array.from({ length }, () => ethers.ZeroHash);
  inputs[0] = first;
  inputs[1] = second;
  return abiCoder.encode(["bytes", "bytes32[]"], ["0x1234", inputs]);
}

describe("BFV verifier routers", function () {
  it("routes PK proofs by public-input length and VK anchors", async function () {
    const [, nodeOne, nodeTwo] = await ethers.getSigners();
    const e3Id = 11;
    const committeeRoot = 12;
    const sortedNodes = [
      await nodeOne.getAddress(),
      await nodeTwo.getAddress(),
    ];
    const pkCommitment = ethers.id("pk-commitment");
    const committeeHash = ethers.id("committee");
    const minimum = await ethers.deployContract("MockBfvPkVerifierRoute", [
      2,
      HASH_A,
      HASH_B,
      false,
    ]);
    const sameLength = await ethers.deployContract("MockBfvPkVerifierRoute", [
      10,
      HASH_A,
      HASH_B,
      false,
    ]);
    const small = await ethers.deployContract("MockBfvPkVerifierRoute", [
      10,
      HASH_C,
      HASH_D,
      true,
    ]);
    const router = await ethers.deployContract("BfvPkVerifierRouter", [
      [
        await minimum.getAddress(),
        await sameLength.getAddress(),
        await small.getAddress(),
      ],
      10,
    ]);
    const smallProof = proofWithAnchors(36, HASH_C, HASH_D);
    await small.setExpectedContext(
      e3Id,
      committeeRoot,
      sortedNodes,
      pkCommitment,
      committeeHash,
      smallProof,
    );

    expect(await router.h()).to.equal(10);
    expect(await router.routeCount()).to.equal(3);
    expect(
      await router.verify.staticCall(
        e3Id,
        committeeRoot,
        sortedNodes,
        pkCommitment,
        committeeHash,
        smallProof,
      ),
    ).to.equal(true);
    expect(
      await router.verify.staticCall(
        e3Id,
        committeeRoot,
        sortedNodes,
        pkCommitment,
        committeeHash,
        proofWithAnchors(36, HASH_A, HASH_B),
      ),
    ).to.equal(false);
    expect(
      await router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(12, HASH_A, HASH_B),
      ),
    ).to.equal(false);

    await expect(
      router.verify.staticCall(
        e3Id,
        committeeRoot,
        sortedNodes,
        pkCommitment,
        committeeHash,
        proofWithAnchors(36, HASH_A, HASH_D),
      ),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      router.verify.staticCall(
        e3Id,
        committeeRoot,
        sortedNodes,
        pkCommitment,
        committeeHash,
        proofWithAnchors(36, HASH_C, HASH_A),
      ),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      router.verify.staticCall(
        e3Id + 1,
        committeeRoot,
        sortedNodes,
        pkCommitment,
        committeeHash,
        smallProof,
      ),
    ).to.be.revertedWithCustomError(small, "UnexpectedContext");
    await expect(
      router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(13, HASH_A, HASH_B),
      ),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });

  it("routes decryption proofs by public-input length and VK anchors", async function () {
    const e3Id = 21;
    const decryptionDomain = ethers.id("decryption-domain");
    const plaintextOutputHash = ethers.id("plaintext-output");
    const committeeHash = ethers.id("decryption-committee");
    const ciphertextCommitment = ethers.id("ciphertext-commitment");
    const minimum = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [1, HASH_A, HASH_B, false],
    );
    const sameLength = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [9, HASH_A, HASH_B, false],
    );
    const small = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [9, HASH_C, HASH_D, true],
    );
    const router = await ethers.deployContract("BfvDecryptionVerifierRouter", [
      [
        await minimum.getAddress(),
        await sameLength.getAddress(),
        await small.getAddress(),
      ],
      9,
    ]);
    const smallProof = proofWithAnchors(138, HASH_C, HASH_D);
    await small.setExpectedContext(
      e3Id,
      decryptionDomain,
      plaintextOutputHash,
      committeeHash,
      ciphertextCommitment,
      smallProof,
    );

    expect(await router.threshold()).to.equal(9);
    expect(await router.routeCount()).to.equal(3);
    expect(
      await router.verify.staticCall(
        e3Id,
        decryptionDomain,
        plaintextOutputHash,
        committeeHash,
        ciphertextCommitment,
        smallProof,
      ),
    ).to.equal(true);
    expect(
      await router.verify.staticCall(
        e3Id,
        decryptionDomain,
        plaintextOutputHash,
        committeeHash,
        ciphertextCommitment,
        proofWithAnchors(138, HASH_A, HASH_B),
      ),
    ).to.equal(false);
    expect(
      await router.verify.staticCall(
        1,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(114, HASH_A, HASH_B),
      ),
    ).to.equal(false);

    await expect(
      router.verify.staticCall(
        e3Id,
        decryptionDomain,
        plaintextOutputHash,
        committeeHash,
        ciphertextCommitment,
        proofWithAnchors(138, HASH_A, HASH_D),
      ),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      router.verify.staticCall(
        e3Id,
        decryptionDomain,
        plaintextOutputHash,
        committeeHash,
        ciphertextCommitment,
        proofWithAnchors(138, HASH_C, HASH_A),
      ),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      router.verify.staticCall(
        e3Id,
        decryptionDomain,
        ethers.id("wrong-plaintext-output"),
        committeeHash,
        ciphertextCommitment,
        smallProof,
      ),
    ).to.be.revertedWithCustomError(small, "UnexpectedContext");
    await expect(
      router.verify.staticCall(
        1,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(115, HASH_A, HASH_B),
      ),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });
});
