// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

describe("MockE3Program", function () {
  it("has no mutable control surface", async function () {
    const program = await ethers.deployContract("MockE3Program");
    await program.waitForDeployment();

    const functionNames = program.interface.fragments.flatMap((fragment) =>
      fragment.type === "function" && "name" in fragment ? [fragment.name] : [],
    );

    expect(functionNames).to.have.members([
      "ENCRYPTION_SCHEME_ID",
      "publishInput",
      "validate",
      "verify",
      "verifyDataAvailability",
    ]);
  });

  it("accepts BFV requests and application outputs without mutable state", async function () {
    const [publisher] = await ethers.getSigners();
    const program = await ethers.deployContract("MockE3Program");
    await program.waitForDeployment();
    const scheme = ethers.id("fhe.rs:BFV");

    expect(await program.validate.staticCall(1, 2, "0x", "0x", "0x")).to.equal(
      scheme,
    );
    expect(
      await program.verify.staticCall(
        1,
        ethers.ZeroHash,
        ethers.ZeroHash,
        "0x",
      ),
    ).to.equal(true);
    await expect(program.publishInput(1, "0x1234"))
      .to.emit(program, "InputPublished")
      .withArgs(1, await publisher.getAddress(), "0x1234");

    expect(await program.validate.staticCall(1, 2, "0x", "0x", "0x")).to.equal(
      scheme,
    );

    const object = "0x1234";
    const contentHash = ethers.keccak256(object);
    expect(
      await program.verifyDataAvailability.staticCall(contentHash, object),
    ).to.deep.equal([contentHash, 1n, 1n]);
    await expect(
      program.verifyDataAvailability.staticCall(ethers.ZeroHash, object),
    ).to.be.revertedWithCustomError(program, "InvalidDataAvailabilityProof");
  });
});
