// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

/**
 * ZEN2-04 follow-up: `SlashingManager._committeeFinalized` decides whether a
 * failed E3 waits for its accusation window. Only the registry's explicit
 * `CommitteeNotFinalized()` may open settlement early; every other probe
 * outcome must fail closed, so a registry without the view can only delay a
 * refund, never release it ahead of pending accusations.
 */
describe("SlashingManager committee probe", function () {
  async function deploy() {
    const evidenceLib = await ethers.deployContract("SlashingEvidenceLib");
    const factory = await ethers.getContractFactory(
      "SlashingManagerProbeHarness",
      { libraries: { SlashingEvidenceLib: await evidenceLib.getAddress() } },
    );
    const harness = await factory.deploy();
    const registry = await ethers.deployContract("RevertingCanonicalRegistry");
    return { harness, registry, registryAddress: await registry.getAddress() };
  }

  it("reads an answer as finalized", async function () {
    const { harness, registry, registryAddress } = await deploy();
    await registry.setMode(0);
    expect(await harness.committeeFinalized(registryAddress, 1)).to.equal(true);
  });

  it("reads only CommitteeNotFinalized() as no committee", async function () {
    const { harness, registry, registryAddress } = await deploy();
    await registry.setMode(1);
    expect(await harness.committeeFinalized(registryAddress, 1)).to.equal(
      false,
    );
  });

  for (const [label, mode] of [
    ["a different custom error", 2],
    ["an empty revert", 3],
    ["a string revert", 4],
  ] as const) {
    it(`fails closed on ${label}`, async function () {
      const { harness, registry, registryAddress } = await deploy();
      await registry.setMode(mode);
      expect(await harness.committeeFinalized(registryAddress, 1)).to.equal(
        true,
      );
    });
  }

  it("fails closed on an address with no code", async function () {
    const { harness } = await deploy();
    const eoa = ethers.Wallet.createRandom().address;
    expect(await harness.committeeFinalized(eoa, 1)).to.equal(true);
  });
});
