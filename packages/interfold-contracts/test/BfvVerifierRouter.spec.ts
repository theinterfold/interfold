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
    const sortedNodes = [
      await nodeOne.getAddress(),
      await nodeTwo.getAddress(),
    ];
    const context = [
      11,
      12,
      sortedNodes,
      ethers.id("pk-commitment"),
      ethers.id("committee"),
    ] as const;
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
    // The selected route rejects any call other than this exact forwarding.
    await small.expectCall(
      small.interface.encodeFunctionData("verify", [...context, smallProof]),
    );
    const verify = (proof: string) =>
      router.verify.staticCall(...context, proof);

    expect(await router.h()).to.equal(10);
    expect(await router.routeCount()).to.equal(3);
    expect(await verify(smallProof)).to.equal(true);
    expect(await verify(proofWithAnchors(36, HASH_A, HASH_B))).to.equal(false);
    expect(await verify(proofWithAnchors(12, HASH_A, HASH_B))).to.equal(false);

    await expect(
      verify(proofWithAnchors(36, HASH_A, HASH_D)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(proofWithAnchors(36, HASH_C, HASH_A)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(proofWithAnchors(13, HASH_A, HASH_B)),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });

  it("routes decryption proofs by public-input length and VK anchors", async function () {
    const context = [
      21,
      ethers.id("decryption-domain"),
      ethers.id("plaintext-output"),
      ethers.id("decryption-committee"),
      ethers.id("ciphertext-commitment"),
    ] as const;
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
    await small.expectCall(
      small.interface.encodeFunctionData("verify", [...context, smallProof]),
    );
    const verify = (proof: string) =>
      router.verify.staticCall(...context, proof);

    expect(await router.threshold()).to.equal(9);
    expect(await router.routeCount()).to.equal(3);
    expect(await verify(smallProof)).to.equal(true);
    expect(await verify(proofWithAnchors(138, HASH_A, HASH_B))).to.equal(false);
    expect(await verify(proofWithAnchors(114, HASH_A, HASH_B))).to.equal(false);

    await expect(
      verify(proofWithAnchors(138, HASH_A, HASH_D)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(proofWithAnchors(138, HASH_C, HASH_A)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(proofWithAnchors(115, HASH_A, HASH_B)),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });
});
