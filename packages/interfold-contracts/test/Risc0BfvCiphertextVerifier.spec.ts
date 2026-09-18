// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { ethers, networkHelpers } from "./fixtures";

describe("Risc0BfvCiphertextVerifier", function () {
  const imageId = `0x${"44".repeat(32)}`;
  const schemeId = ethers.keccak256(ethers.toUtf8Bytes("fhe.rs:BFV"));
  const committeePublicKey = `0x${"33".repeat(32)}`;
  const ciphertextHash = `0x${"55".repeat(32)}`;
  const ciphertextCommitment = `0x${"66".repeat(32)}`;
  const paramsHash = `0x${"77".repeat(32)}`;
  const inputRoot = `0x${"88".repeat(32)}`;

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

  it("forwards the exact seal, image ID, and wrapper-encoded E3 domain", async function () {
    const [publisher] = await ethers.getSigners();
    const risc0 = await ethers.deployContract("MockRisc0ComputeVerifier");
    const verifier = await ethers.deployContract("Risc0BfvCiphertextVerifier", [
      await risc0.getAddress(),
      imageId,
    ]);
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const e3Id = 7;
    const seal = "0x1234";
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
    await risc0.setExpectedCall(seal, imageId, ethers.sha256(journal));
    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32", "bytes32"],
      [seal, paramsHash, inputRoot],
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

    const wrongSealProof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32", "bytes32"],
      ["0x1235", paramsHash, inputRoot],
    );
    await expect(
      verifier.verify(
        e3Id,
        schemeId,
        paramsHash,
        committeePublicKey,
        ciphertextHash,
        ciphertextCommitment,
        wrongSealProof,
      ),
    ).to.be.revertedWithCustomError(risc0, "UnexpectedSealHash");

    const wrongImageVerifier = await ethers.deployContract(
      "Risc0BfvCiphertextVerifier",
      [await risc0.getAddress(), `0x${"45".repeat(32)}`],
    );
    await expect(
      wrongImageVerifier.verify(
        e3Id,
        schemeId,
        paramsHash,
        committeePublicKey,
        ciphertextHash,
        ciphertextCommitment,
        proof,
      ),
    ).to.be.revertedWithCustomError(risc0, "UnexpectedImageId");
  });

  it("accepts the pinned Rust compute-journal interoperability vector", async function () {
    const publisherAddress = "0x1111111111111111111111111111111111111111";
    const seal = "0x11223344";
    const vectorSchemeId = `0x${"22".repeat(32)}`;
    const vectorCommitteeKey = `0x${"33".repeat(32)}`;
    const vectorCiphertextHash = ethers.hexlify(
      Uint8Array.from({ length: 32 }, (_, index) => index),
    );
    const vectorCiphertextCommitment = ethers.hexlify(
      Uint8Array.from({ length: 32 }, (_, index) => index + 32),
    );
    const vectorParamsHash =
      "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const vectorInputRoot =
      "0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e";
    const vectorJournalDigest =
      "0x4403934eb9404372d77f23454aeb4bb7f21bbe856c5c51fc3243f5e05cc2c702";

    expect((await ethers.provider.getNetwork()).chainId).to.equal(31_337n);
    await networkHelpers.setBalance(publisherAddress, ethers.parseEther("1"));
    await networkHelpers.impersonateAccount(publisherAddress);
    const publisher = await ethers.getSigner(publisherAddress);
    const risc0 = await ethers.deployContract("MockRisc0ComputeVerifier");
    const verifier = await ethers.deployContract("Risc0BfvCiphertextVerifier", [
      await risc0.getAddress(),
      imageId,
    ]);
    const publisherVerifier = await ethers.getContractAt(
      "Risc0BfvCiphertextVerifier",
      await verifier.getAddress(),
      publisher,
    );
    await risc0.setExpectedCall(seal, imageId, vectorJournalDigest);
    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32", "bytes32"],
      [seal, vectorParamsHash, vectorInputRoot],
    );

    expect(
      await publisherVerifier.verify.staticCall(
        7,
        vectorSchemeId,
        vectorParamsHash,
        vectorCommitteeKey,
        vectorCiphertextHash,
        vectorCiphertextCommitment,
        proof,
      ),
    ).to.equal(true);
  });
});
