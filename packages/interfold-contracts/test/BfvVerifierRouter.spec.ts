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
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [0]);
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.setInterfold(await interfold.getAddress());
    const minimum = await ethers.deployContract("MockBfvPkVerifierRoute", [
      2,
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
      await registry.getAddress(),
      [await minimum.getAddress(), await small.getAddress()],
      [0, 0],
      10,
    ]);

    expect(await router.h()).to.equal(10);
    expect(await router.routeCount()).to.equal(2);
    expect(
      await router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(54, HASH_C, HASH_D),
      ),
    ).to.equal(true);
    expect(
      await router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(30, HASH_A, HASH_B),
      ),
    ).to.equal(false);

    await expect(
      router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(54, HASH_C, HASH_A),
      ),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(31, HASH_A, HASH_B),
      ),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });

  it("rejects a PK route for a different E3 parameter set", async function () {
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [2]);
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.setInterfold(await interfold.getAddress());
    const legacy = await ethers.deployContract("MockBfvPkVerifierRoute", [
      2,
      HASH_A,
      HASH_B,
      true,
    ]);
    const secure16384 = await ethers.deployContract("MockBfvPkVerifierRoute", [
      2,
      HASH_C,
      HASH_D,
      true,
    ]);
    const router = await ethers.deployContract("BfvPkVerifierRouter", [
      await registry.getAddress(),
      [await legacy.getAddress(), await secure16384.getAddress()],
      [0, 2],
      2,
    ]);

    expect((await router.routeAt(1))[4]).to.equal(2);
    expect(
      await router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(30, HASH_C, HASH_D),
      ),
    ).to.equal(true);
    await expect(
      router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(30, HASH_A, HASH_B),
      ),
    )
      .to.be.revertedWithCustomError(router, "ParamSetRouteMismatch")
      .withArgs(2);
  });

  it("routes decryption proofs by public-input length and VK anchors", async function () {
    const minimum = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [1, HASH_A, HASH_B, false],
    );
    const small = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [9, HASH_C, HASH_D, true],
    );
    const router = await ethers.deployContract("BfvDecryptionVerifierRouter", [
      [await minimum.getAddress(), await small.getAddress()],
      9,
    ]);

    expect(await router.threshold()).to.equal(9);
    expect(await router.routeCount()).to.equal(2);
    expect(
      await router.verify.staticCall(
        1,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(138, HASH_C, HASH_D),
      ),
    ).to.equal(true);
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
        1,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        proofWithAnchors(138, HASH_C, HASH_A),
      ),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
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
