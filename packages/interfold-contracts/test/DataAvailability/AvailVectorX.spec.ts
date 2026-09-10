// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";

import { ethers } from "../fixtures";

describe("AvailVectorXDataAvailabilityVerifier", function () {
  const rangeHash = ethers.keccak256(ethers.toUtf8Bytes("avail-range"));
  const object = ethers.toUtf8Bytes("exact encrypted object");
  const contentHash = ethers.keccak256(object);

  async function fixture() {
    const vectorx = await ethers.deployContract("MockVectorX");
    await vectorx.waitForDeployment();
    const bridge = await ethers.deployContract("MockAvailBridge", [
      await vectorx.getAddress(),
    ]);
    await bridge.waitForDeployment();
    const verifier = await ethers.deployContract(
      "AvailVectorXDataAvailabilityVerifier",
      [await bridge.getAddress(), await vectorx.getAddress()],
    );
    await verifier.waitForDeployment();
    await vectorx.setRangeStartBlock(rangeHash, 1_000);
    return { vectorx, bridge, verifier };
  }

  function proof(overrides: Partial<Record<string, unknown>> = {}) {
    const input = {
      dataRootProof: [],
      leafProof: [],
      rangeHash,
      dataRootIndex: 7n,
      blobRoot: ethers.ZeroHash,
      bridgeRoot: ethers.ZeroHash,
      leaf: contentHash,
      leafIndex: 12n,
      ...overrides,
    };
    return ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "tuple(bytes32[] dataRootProof,bytes32[] leafProof,bytes32 rangeHash,uint256 dataRootIndex,bytes32 blobRoot,bytes32 bridgeRoot,bytes32 leaf,uint256 leafIndex)",
      ],
      [input],
    );
  }

  it("returns stable retrieval coordinates for the exact Avail leaf", async function () {
    const { verifier } = await fixture();
    const receipt = await verifier.verifyDataAvailability(contentHash, proof());
    expect(receipt.contentHash).to.equal(contentHash);
    expect(receipt.blockNumber).to.equal(1_008n);
    expect(receipt.leafIndex).to.equal(12n);
  });

  it("rejects a receipt for different bytes", async function () {
    const { verifier } = await fixture();
    await expect(
      verifier.verifyDataAvailability(
        ethers.keccak256(ethers.toUtf8Bytes("substitute")),
        proof(),
      ),
    ).to.be.revertedWithCustomError(verifier, "ContentHashMismatch");
  });

  it("rejects the submitted-data Merkle hash in place of the proof leaf", async function () {
    const { verifier } = await fixture();
    await expect(
      verifier.verifyDataAvailability(
        contentHash,
        proof({ leaf: ethers.keccak256(contentHash) }),
      ),
    ).to.be.revertedWithCustomError(verifier, "ContentHashMismatch");
  });

  it("rejects a leaf that the Avail bridge did not verify", async function () {
    const { bridge, verifier } = await fixture();
    await bridge.setProofValid(false);
    await expect(
      verifier.verifyDataAvailability(contentHash, proof()),
    ).to.be.revertedWithCustomError(verifier, "InvalidAvailabilityProof");
  });

  it("fails closed if the bridge rotates to a different VectorX verifier", async function () {
    const { bridge, verifier } = await fixture();
    const replacement = await ethers.deployContract("MockVectorX");
    await replacement.waitForDeployment();
    await bridge.setVectorX(await replacement.getAddress());
    await expect(
      verifier.verifyDataAvailability(contentHash, proof()),
    ).to.be.revertedWithCustomError(verifier, "InvalidVectorX");
  });

  it("rejects a bridge and VectorX pair that do not match at deployment", async function () {
    const { bridge, verifier } = await fixture();
    const replacement = await ethers.deployContract("MockVectorX");
    await replacement.waitForDeployment();

    await expect(
      ethers.deployContract("AvailVectorXDataAvailabilityVerifier", [
        await bridge.getAddress(),
        await replacement.getAddress(),
      ]),
    ).to.be.revertedWithCustomError(verifier, "InvalidVectorX");
  });

  it("rejects malformed proof encoding", async function () {
    const { verifier } = await fixture();
    await expect(
      verifier.verifyDataAvailability(contentHash, "0xdead"),
    ).to.be.revert(ethers);
  });

  it("rejects retrieval coordinates that do not fit the recorded reference", async function () {
    const { vectorx, verifier } = await fixture();
    await expect(
      verifier.verifyDataAvailability(
        contentHash,
        proof({ dataRootIndex: 1n << 32n }),
      ),
    ).to.be.revertedWithCustomError(verifier, "DataRootIndexTooLarge");
    await expect(
      verifier.verifyDataAvailability(
        contentHash,
        proof({ leafIndex: 1n << 128n }),
      ),
    ).to.be.revertedWithCustomError(verifier, "LeafIndexTooLarge");

    await vectorx.setRangeStartBlock(rangeHash, (1n << 32n) - 1n);
    await expect(
      verifier.verifyDataAvailability(contentHash, proof({ dataRootIndex: 0 })),
    ).to.be.revertedWithCustomError(verifier, "BlockNumberOverflow");
  });
});
