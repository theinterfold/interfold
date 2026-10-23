// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { bfvDecExpectedPublicInputsLen } from "../scripts/utils";
import { ethers } from "./fixtures/connection";

/** Decrypted-output cap of the parameter sets these routes model (0-4). */
const MESSAGE_COEFFS_COUNT = 50;
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

function pkProofWithAnchor(length: number, nodesFoldKeyHash: string): string {
  const inputs = Array.from({ length }, () => ethers.ZeroHash);
  inputs[0] = nodesFoldKeyHash;
  return abiCoder.encode(["bytes", "bytes32[]"], ["0x1234", inputs]);
}

describe("BFV verifier routers", function () {
  it("routes PK proofs by public-input length and nodes-fold VK anchor", async function () {
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [0]);
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.setInterfold(await interfold.getAddress());
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
      false,
    ]);
    const sameLength = await ethers.deployContract("MockBfvPkVerifierRoute", [
      10,
      HASH_A,
      false,
    ]);
    const small = await ethers.deployContract("MockBfvPkVerifierRoute", [
      10,
      HASH_C,
      true,
    ]);
    const router = await ethers.deployContract("BfvPkVerifierRouter", [
      await registry.getAddress(),
      [
        await minimum.getAddress(),
        await sameLength.getAddress(),
        await small.getAddress(),
      ],
      [0, 0, 0],
      10,
    ]);
    const smallProof = pkProofWithAnchor(54, HASH_C);
    // The selected route rejects any call other than this exact forwarding.
    await small.expectCall(
      small.interface.encodeFunctionData("verify", [...context, smallProof]),
    );
    const verify = (proof: string) =>
      router.verify.staticCall(...context, proof);

    expect(await router.h()).to.equal(10);
    expect(await router.routeCount()).to.equal(3);
    expect(await verify(smallProof)).to.equal(true);
    expect(await verify(pkProofWithAnchor(54, HASH_A))).to.equal(false);
    expect(await verify(pkProofWithAnchor(30, HASH_A))).to.equal(false);

    await expect(
      verify(pkProofWithAnchor(54, HASH_B)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(pkProofWithAnchor(55, HASH_A)),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });

  it("rejects a PK route for a different E3 parameter set", async function () {
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [2]);
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.setInterfold(await interfold.getAddress());
    const legacy = await ethers.deployContract("MockBfvPkVerifierRoute", [
      2,
      HASH_A,
      true,
    ]);
    const secure16384 = await ethers.deployContract("MockBfvPkVerifierRoute", [
      2,
      HASH_C,
      true,
    ]);
    const router = await ethers.deployContract("BfvPkVerifierRouter", [
      await registry.getAddress(),
      [await legacy.getAddress(), await secure16384.getAddress()],
      [0, 2],
      2,
    ]);

    expect((await router.routeAt(1))[3]).to.equal(2);
    expect(
      await router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        pkProofWithAnchor(30, HASH_C),
      ),
    ).to.equal(true);
    await expect(
      router.verify.staticCall(
        1,
        2,
        [],
        ethers.ZeroHash,
        ethers.ZeroHash,
        pkProofWithAnchor(30, HASH_A),
      ),
    )
      .to.be.revertedWithCustomError(router, "ParamSetRouteMismatch")
      .withArgs(2);
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
      [1, HASH_A, HASH_B, false, 50],
    );
    const sameLength = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [9, HASH_A, HASH_B, false, 50],
    );
    const small = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [9, HASH_C, HASH_D, true, 50],
    );
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [0]);
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.setInterfold(await interfold.getAddress());
    const router = await ethers.deployContract("BfvDecryptionVerifierRouter", [
      await registry.getAddress(),
      [
        await minimum.getAddress(),
        await sameLength.getAddress(),
        await small.getAddress(),
      ],
      [0, 0, 0],
      9,
    ]);
    const smallLen = bfvDecExpectedPublicInputsLen(9, MESSAGE_COEFFS_COUNT);
    const minimumLen = bfvDecExpectedPublicInputsLen(1, MESSAGE_COEFFS_COUNT);
    const smallProof = proofWithAnchors(smallLen, HASH_C, HASH_D);
    await small.expectCall(
      small.interface.encodeFunctionData("verify", [...context, smallProof]),
    );
    const verify = (proof: string) =>
      router.verify.staticCall(...context, proof);

    expect(await router.threshold()).to.equal(9);
    expect(await router.routeCount()).to.equal(3);
    expect(await verify(smallProof)).to.equal(true);
    expect(await verify(proofWithAnchors(smallLen, HASH_A, HASH_B))).to.equal(
      false,
    );
    expect(await verify(proofWithAnchors(minimumLen, HASH_A, HASH_B))).to.equal(
      false,
    );

    await expect(
      verify(proofWithAnchors(smallLen, HASH_A, HASH_D)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(proofWithAnchors(smallLen, HASH_C, HASH_A)),
    ).to.be.revertedWithCustomError(router, "VkHashMismatch");
    await expect(
      verify(proofWithAnchors(minimumLen + 1, HASH_A, HASH_B)),
    ).to.be.revertedWithCustomError(router, "InvalidPublicInputsLength");
  });

  it("rejects a decryption route for a different E3 parameter set", async function () {
    // The E3 runs the l-BFV path (parameter set 4); its proof carries the trBFV route's anchors.
    const interfold = await ethers.deployContract("MockBfvV2Interfold", [4]);
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    await registry.setInterfold(await interfold.getAddress());
    const trbfv = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [1, HASH_A, HASH_B, true, 50],
    );
    const lbfv = await ethers.deployContract("MockBfvDecryptionVerifierRoute", [
      1,
      HASH_A,
      HASH_C,
      true,
      50,
    ]);
    const router = await ethers.deployContract("BfvDecryptionVerifierRouter", [
      await registry.getAddress(),
      [await trbfv.getAddress(), await lbfv.getAddress()],
      [0, 4],
      1,
    ]);
    const context = [
      21,
      ethers.id("decryption-domain"),
      ethers.id("plaintext-output"),
      ethers.id("decryption-committee"),
      ethers.id("ciphertext-commitment"),
    ] as const;

    expect((await router.routeAt(1))[4]).to.equal(4);
    expect(
      await router.verify.staticCall(
        ...context,
        proofWithAnchors(
          bfvDecExpectedPublicInputsLen(1, MESSAGE_COEFFS_COUNT),
          HASH_A,
          HASH_C,
        ),
      ),
    ).to.equal(true);
    await expect(
      router.verify.staticCall(
        ...context,
        proofWithAnchors(
          bfvDecExpectedPublicInputsLen(1, MESSAGE_COEFFS_COUNT),
          HASH_A,
          HASH_B,
        ),
      ),
    )
      .to.be.revertedWithCustomError(router, "ParamSetRouteMismatch")
      .withArgs(4);
  });

  it("routes decryption proofs by the message width of each parameter set", async function () {
    const context = [
      21,
      ethers.id("decryption-domain"),
      ethers.id("plaintext-output"),
      ethers.id("decryption-committee"),
      ethers.id("ciphertext-commitment"),
    ] as const;
    const registry = await ethers.deployContract("MockCiphernodeRegistry");
    const capped = await ethers.deployContract(
      "MockBfvDecryptionVerifierRoute",
      [1, HASH_A, HASH_B, true, 50],
    );
    const simd = await ethers.deployContract("MockBfvDecryptionVerifierRoute", [
      1,
      HASH_A,
      HASH_B,
      true,
      128,
    ]);
    const router = await ethers.deployContract("BfvDecryptionVerifierRouter", [
      await registry.getAddress(),
      [await capped.getAddress(), await simd.getAddress()],
      [4, 5],
      1,
    ]);
    // 7 + 1 + 3 * (T + 1) + message coefficients, with T = 1.
    const cappedLen = bfvDecExpectedPublicInputsLen(1, MESSAGE_COEFFS_COUNT);
    const simdLen = cappedLen - 50 + 128;
    expect((await router.routeAt(0))[1]).to.equal(cappedLen);
    expect((await router.routeAt(1))[1]).to.equal(simdLen);

    const verifyOnParamSet = async (paramSet: number, length: number) => {
      const interfold = await ethers.deployContract("MockBfvV2Interfold", [
        paramSet,
      ]);
      await registry.setInterfold(await interfold.getAddress());
      return router.verify.staticCall(
        ...context,
        proofWithAnchors(length, HASH_A, HASH_B),
      );
    };

    expect(await verifyOnParamSet(4, cappedLen)).to.equal(true);
    expect(await verifyOnParamSet(5, simdLen)).to.equal(true);
    // A proof of the wrong width for the E3's parameter set is refused.
    await expect(verifyOnParamSet(5, cappedLen))
      .to.be.revertedWithCustomError(router, "ParamSetRouteMismatch")
      .withArgs(5);
    await expect(verifyOnParamSet(4, simdLen))
      .to.be.revertedWithCustomError(router, "ParamSetRouteMismatch")
      .withArgs(4);
  });
});
