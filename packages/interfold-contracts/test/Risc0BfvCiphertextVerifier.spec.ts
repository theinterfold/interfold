// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { ethers } from "./fixtures";

describe("Risc0BfvCiphertextVerifier", function () {
  const imageId = `0x${"44".repeat(32)}`;
  const schemeId = ethers.keccak256(ethers.toUtf8Bytes("fhe.rs:BFV"));
  const committeePublicKey = `0x${"33".repeat(32)}`;
  const ciphertextHash = `0x${"55".repeat(32)}`;
  const ciphertextCommitment = `0x${"66".repeat(32)}`;
  const paramsHash = `0x${"77".repeat(32)}`;
  const inputRoot = `0x${"88".repeat(32)}`;

  it("rejects an EOA as the RISC Zero verifier", async function () {
    const [signer] = await ethers.getSigners();
    const factory = await ethers.getContractFactory(
      "Risc0BfvCiphertextVerifier",
    );

    await expect(
      factory.deploy(await signer.getAddress(), imageId),
    ).to.be.revertedWithCustomError(factory, "InvalidVerifier");
  });

  function encodeVec32(value: string) {
    const encoded = [32, 0, 0, 0];
    for (const byte of ethers.getBytes(value)) encoded.push(byte, 0, 0, 0);
    return Uint8Array.from(encoded);
  }

  it("rejects a verifier address without code", async function () {
    const [, verifierAddress] = await ethers.getSigners();
    const factory = await ethers.getContractFactory(
      "Risc0BfvCiphertextVerifier",
    );

    await expect(
      factory.deploy(verifierAddress, imageId),
    ).to.be.revertedWithCustomError(factory, "InvalidVerifier");
  });

  it("verifies the exact E3 domain emitted by the compute guest", async function () {
    const [publisher] = await ethers.getSigners();
    const risc0 = await ethers.deployContract("MockRisc0ComputeVerifier");
    const verifier = await ethers.deployContract("Risc0BfvCiphertextVerifier", [
      await risc0.getAddress(),
      imageId,
    ]);
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const e3Id = 7;
    const journal = ethers.concat(
      [
        ethers.zeroPadValue(ethers.toBeHex(chainId), 32),
        ethers.zeroPadValue(await publisher.getAddress(), 32),
        ethers.zeroPadValue(ethers.toBeHex(e3Id), 32),
        schemeId,
        committeePublicKey,
        ciphertextHash,
        ciphertextCommitment,
        paramsHash,
        inputRoot,
      ].map(encodeVec32),
    );
    await risc0.setExpectedJournalDigest(ethers.sha256(journal));
    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32", "bytes32"],
      ["0x1234", paramsHash, inputRoot],
    );

    expect(
      await verifier.verify.staticCall(
        e3Id,
        schemeId,
        paramsHash,
        committeePublicKey,
        ciphertextHash,
        ciphertextCommitment,
        proof,
      ),
    ).to.equal(true);
    expect(
      await verifier.verify.staticCall(
        e3Id,
        schemeId,
        ethers.ZeroHash,
        committeePublicKey,
        ciphertextHash,
        ciphertextCommitment,
        proof,
      ),
    ).to.equal(false);
    await expect(
      verifier.verify(
        e3Id + 1,
        schemeId,
        paramsHash,
        committeePublicKey,
        ciphertextHash,
        ciphertextCommitment,
        proof,
      ),
    ).to.be.revertedWithCustomError(risc0, "UnexpectedJournalDigest");
  });
});
