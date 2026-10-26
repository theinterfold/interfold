// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

import {
  type MockPkVerifier,
  MockPkVerifier__factory as MockPkVerifierFactory,
} from "../types";

const { ethers } = await network.connect();
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

const H = 2;
const LBFV_ROWS = 3;
// `DkgAggregatorV2` public inputs: 39 fixed + 3h + 3 per row, key-envelope commitment at 21 + 3h.
const V2_PUBLIC_INPUTS_LEN = 39 + 3 * H + 3 * LBFV_ROWS;
const V2_COMMITMENT_INDEX = 21 + 3 * H;

const encodeProof = (publicInputs: string[]): string =>
  abiCoder.encode(["bytes", "bytes32[]"], ["0x", publicInputs]);

const lbfvPlaceholderInputs = (commitment: string): string[] => {
  const inputs = new Array<string>(V2_PUBLIC_INPUTS_LEN).fill(ethers.ZeroHash);
  inputs[V2_COMMITMENT_INDEX] = commitment;
  return inputs;
};

describe("MockPkVerifier", function () {
  const commitment = ethers.keccak256("0xabcd");
  const other = ethers.keccak256("0xbeef");

  const deploy = async (): Promise<MockPkVerifier> => {
    const [owner] = await ethers.getSigners();
    const deployed = await ethers.deployContract("MockPkVerifier");
    await deployed.waitForDeployment();
    return MockPkVerifierFactory.connect(await deployed.getAddress(), owner);
  };
  const verify = (verifier: MockPkVerifier, proof: string) =>
    verifier.verify.staticCall(1, 0, [], commitment, ethers.ZeroHash, proof);

  it("accepts a legacy proof whose last public input is the commitment", async function () {
    const verifier = await deploy();
    expect(await verify(verifier, encodeProof([other, commitment]))).to.equal(
      true,
    );
  });

  it("rejects a legacy proof whose last public input differs", async function () {
    const verifier = await deploy();
    await expect(
      verify(verifier, encodeProof([commitment, other])),
    ).to.be.revertedWithCustomError(verifier, "PkCommitmentMismatch");
  });

  it("accepts an l-BFV V2 placeholder proof by its key-envelope slot", async function () {
    const verifier = await deploy();
    expect(
      await verify(verifier, encodeProof(lbfvPlaceholderInputs(commitment))),
    ).to.equal(true);
  });

  it("rejects an l-BFV V2 proof carrying the commitment only in the last slot", async function () {
    const verifier = await deploy();
    const inputs = lbfvPlaceholderInputs(other);
    inputs[inputs.length - 1] = commitment;
    await expect(
      verify(verifier, encodeProof(inputs)),
    ).to.be.revertedWithCustomError(verifier, "PkCommitmentMismatch");
  });
});
