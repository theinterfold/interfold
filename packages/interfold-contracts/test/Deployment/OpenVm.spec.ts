// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { artifacts } from "hardhat";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { deployOpenVmReceiptVerifier } from "../../scripts/openVm";
import { ethers } from "../fixtures/connection";

describe("OpenVM deployment configuration", function () {
  const commitments = {
    OPENVM_APP_EXE_COMMIT: ethers.zeroPadValue("0x01", 32),
    OPENVM_APP_VM_COMMIT: ethers.zeroPadValue("0x02", 32),
  };

  it("requires explicit configuration and rejects noncanonical commitments", async function () {
    await expect(deployOpenVmReceiptVerifier(ethers, {})).to.be.rejectedWith(
      "OPENVM_APP_EXE_COMMIT",
    );
    await expect(
      deployOpenVmReceiptVerifier(ethers, commitments),
    ).to.be.rejectedWith("OPENVM_HALO2_VERIFIER");
    await expect(
      deployOpenVmReceiptVerifier(ethers, {
        ...commitments,
        OPENVM_APP_VM_COMMIT: ethers.ZeroHash,
      }),
    ).to.be.rejectedWith("nonzero canonical");
    await expect(
      deployOpenVmReceiptVerifier(ethers, {
        ...commitments,
        OPENVM_APP_VM_COMMIT: `0x${"ff".repeat(32)}`,
      }),
    ).to.be.rejectedWith("nonzero canonical");
  });

  it("requires deployed code and its exact runtime hash", async function () {
    const [owner] = await ethers.getSigners();
    await expect(
      deployOpenVmReceiptVerifier(ethers, {
        ...commitments,
        OPENVM_HALO2_VERIFIER: owner.address,
        OPENVM_HALO2_RUNTIME_CODE_HASH: ethers.ZeroHash,
      }),
    ).to.be.rejectedWith("runtime code differs");
    // This test checks deployment bindings only. The real-proof suite supplies the Halo2 artifact.
    const target = await ethers.deployContract("MockCiphertextVerifier");
    const address = await target.getAddress();
    const codeHash = ethers.keccak256(await ethers.provider.getCode(address));
    await expect(
      deployOpenVmReceiptVerifier(ethers, {
        ...commitments,
        OPENVM_HALO2_VERIFIER: address,
        OPENVM_HALO2_RUNTIME_CODE_HASH: ethers.ZeroHash,
      }),
    ).to.be.rejectedWith("runtime code differs");
    const { receipt } = await deployOpenVmReceiptVerifier(ethers, {
      ...commitments,
      OPENVM_HALO2_VERIFIER: address,
      OPENVM_HALO2_RUNTIME_CODE_HASH: codeHash,
    });
    expect(await receipt.verifier()).to.equal(address);
    expect(await receipt.appExeCommit()).to.equal(
      commitments.OPENVM_APP_EXE_COMMIT,
    );
  });

  it("checks artifact bytes and refuses conflicting deployment modes", async function () {
    const directory = mkdtempSync(
      path.join(tmpdir(), "interfold-openvm-deploy-"),
    );
    try {
      const artifact = await artifacts.readArtifact("MockCiphertextVerifier");
      const bytes = JSON.stringify({ bytecode: artifact.bytecode });
      const file = path.join(directory, "verifier.json");
      writeFileSync(file, bytes);
      const config = {
        ...commitments,
        OPENVM_VERIFIER_ARTIFACT: file,
        OPENVM_VERIFIER_SHA256: createHash("sha256")
          .update(bytes)
          .digest("hex"),
      };
      await expect(
        deployOpenVmReceiptVerifier(ethers, {
          ...config,
          OPENVM_HALO2_VERIFIER: ethers.ZeroAddress,
        }),
      ).to.be.rejectedWith("not both");
      await expect(
        deployOpenVmReceiptVerifier(ethers, {
          ...config,
          OPENVM_VERIFIER_SHA256: "0".repeat(64),
        }),
      ).to.be.rejectedWith("checksum differs");
      const { receipt, halo2Verifier } = await deployOpenVmReceiptVerifier(
        ethers,
        config,
      );
      expect(await receipt.verifier()).to.equal(halo2Verifier);
      expect(await ethers.provider.getCode(halo2Verifier)).not.to.equal("0x");
    } finally {
      rmSync(directory, { recursive: true });
    }
  });
});
