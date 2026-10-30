// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import hre, { network } from "hardhat";

import {
  fullyQualifiedName,
  recordDeployments,
  recordedDeployments,
  verifyRecordedDeployments,
} from "../../scripts/sourceVerification";
import { CiphernodeRegistryOwnable__factory as RegistryFactory } from "../../types";

const connection = recordDeployments(await network.connect());
const { ethers } = connection;

describe("Source verification", function () {
  it("records a factory deployment with its libraries and without the overrides", async function () {
    const [owner] = await ethers.getSigners();
    const library = await (
      await ethers.getContractFactory("SlashingEvidenceLib")
    ).deploy();
    const libraries = { SlashingEvidenceLib: await library.getAddress() };
    const factory = await ethers.getContractFactory("SlashingManager", {
      libraries,
    });
    const manager = await factory.deploy(60, owner.address, {
      gasLimit: 30_000_000,
    });

    const record = recordedDeployments().at(-1)!;
    expect(record).to.deep.include({
      network: connection.networkName,
      live: false,
      address: await manager.getAddress(),
      contract: "SlashingManager",
      constructorArgs: [60, owner.address],
      libraries,
    });
    expect(record.transaction.hash).to.equal(
      manager.deploymentTransaction()!.hash,
    );
  });

  it("records deployContract", async function () {
    const token = await ethers.deployContract("MockFeeOnTransferToken", [25]);

    expect(recordedDeployments().at(-1)).to.deep.include({
      address: await token.getAddress(),
      contract: "MockFeeOnTransferToken",
      constructorArgs: [25],
    });
  });

  it("names the contract for a bare name and for an ABI factory", async function () {
    expect(
      await fullyQualifiedName(hre.artifacts, { contract: "SlashingManager" }),
    ).to.equal("contracts/slashing/SlashingManager.sol:SlashingManager");
    expect(
      await fullyQualifiedName(hre.artifacts, { abi: RegistryFactory.abi }),
    ).to.equal(
      "contracts/registry/CiphernodeRegistryOwnable.sol:CiphernodeRegistryOwnable",
    );
  });

  it("submits nothing from a local chain", async function () {
    await ethers.deployContract("MockFeeOnTransferToken", [25]);
    expect(recordedDeployments()).to.not.be.empty;

    // A submission would first wait for confirmations that this chain never mines.
    await verifyRecordedDeployments();
    expect(recordedDeployments()).to.be.empty;
  });
});
