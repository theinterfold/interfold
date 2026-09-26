// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  deployInterfoldSystem,
  ethers,
  makeRequest,
  networkHelpers,
  publishAvailableCiphertextOutput,
  setupAndPublishCommittee,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("NodeReleaseRegistry", function () {
  async function setup() {
    return deployInterfoldSystem({ setupOperators: 1 });
  }

  it("admits every operator that acknowledges the required release", async function () {
    const { bondingRegistry } = await deployInterfoldSystem({
      setupOperators: 3,
    });
    expect(await bondingRegistry.numActiveOperators()).to.equal(3);
  });

  it("excludes a stale node after a mandatory release", async function () {
    const { interfold, bondingRegistry, nodeReleaseRegistry, operator1 } =
      await loadFixture(setup);
    const operator = await operator1!.getAddress();
    const nextRelease = ethers.id("interfold.node.release:v1:next");

    expect(await bondingRegistry.isActive(operator)).to.equal(true);
    await interfold.setRequestsPaused(true);
    await nodeReleaseRegistry.setRequiredNodeRelease(1, 2);

    expect(await bondingRegistry.isActive(operator)).to.equal(false);
    expect(await bondingRegistry.numActiveOperators()).to.equal(0);
    expect(await nodeReleaseRegistry.isNodeReleaseReady(operator)).to.equal(
      false,
    );

    await nodeReleaseRegistry
      .connect(operator1!)
      .acknowledgeNodeRelease(nextRelease, 1, 2);
    expect(await bondingRegistry.isActive(operator)).to.equal(true);
    expect(await bondingRegistry.numActiveOperators()).to.equal(1);
  });

  it("accepts a compatible patch without a governance transaction", async function () {
    const { bondingRegistry, nodeReleaseRegistry, operator1 } =
      await loadFixture(setup);
    const operator = await operator1!.getAddress();
    const patchRelease = ethers.id("interfold.node.release:v1:patch");

    await nodeReleaseRegistry
      .connect(operator1!)
      .acknowledgeNodeRelease(patchRelease, 1, 1);

    expect(await bondingRegistry.isActive(operator)).to.equal(true);
    expect(await nodeReleaseRegistry.isNodeReleaseReady(operator)).to.equal(
      true,
    );
    expect(
      (await nodeReleaseRegistry.operatorNodeRelease(operator)).releaseId,
    ).to.equal(patchRelease);
  });

  it("does not invalidate eligibility twice during initial setup", async function () {
    const { interfold, bondingRegistry, ciphernodeRegistry, owner } =
      await deployInterfoldSystem({ setupOperators: 0 });
    const replacement = await ethers.deployContract("NodeReleaseRegistry", [
      await owner.getAddress(),
      await bondingRegistry.getAddress(),
      await ciphernodeRegistry.getAddress(),
    ]);

    await interfold.setRequestsPaused(true);
    await interfold.setNodeReleaseRegistry(await replacement.getAddress());
    const versionAfterActivation =
      await bondingRegistry.eligibilityConfigurationVersion();

    await replacement.setRequiredNodeRelease(1, 1);

    expect(await bondingRegistry.eligibilityConfigurationVersion()).to.equal(
      versionAfterActivation,
    );
  });

  it("makes protocol-3 nodes ineligible when protocol 4 activates", async function () {
    const { interfold, bondingRegistry, nodeReleaseRegistry, operator1 } =
      await loadFixture(setup);
    const operator = await operator1!.getAddress();
    const protocol3 = ethers.id("interfold.node.release:v1:protocol-3");
    const protocol4 = ethers.id("interfold.node.release:v1:protocol-4");

    await interfold.setRequestsPaused(true);
    await nodeReleaseRegistry.setRequiredNodeRelease(3, 1);
    await nodeReleaseRegistry
      .connect(operator1!)
      .acknowledgeNodeRelease(protocol3, 3, 1);

    expect(await bondingRegistry.isActive(operator)).to.equal(true);
    await nodeReleaseRegistry.setRequiredNodeRelease(4, 1);
    expect(await bondingRegistry.isActive(operator)).to.equal(false);
    expect(await nodeReleaseRegistry.isNodeReleaseReady(operator)).to.equal(
      false,
    );

    await nodeReleaseRegistry
      .connect(operator1!)
      .acknowledgeNodeRelease(protocol4, 4, 1);
    expect(await bondingRegistry.isActive(operator)).to.equal(true);
  });

  it("requires a paused and drained cutover", async function () {
    const {
      interfold,
      nodeReleaseRegistry,
      ciphernodeRegistry,
      slashingManager,
      usdcToken,
      request,
      operator1,
      operator2,
      operator3,
    } = await deployInterfoldSystem({ setupOperators: 3 });
    await expect(
      nodeReleaseRegistry.setRequiredNodeRelease(2, 2),
    ).to.be.revertedWithCustomError(
      nodeReleaseRegistry,
      "NodeReleasePolicyRequiresPause",
    );

    const e3Id = await interfold.nexte3Id();
    await makeRequest(interfold, usdcToken, request);
    await interfold.setRequestsPaused(true);
    await expect(nodeReleaseRegistry.setRequiredNodeRelease(2, 2))
      .to.be.revertedWithCustomError(
        nodeReleaseRegistry,
        "NodeReleasePolicyInUse",
      )
      .withArgs(1, 1);

    // Completing the E3 drains it, but its committee stays unreleased.
    const proof = "0x1337";
    await setupAndPublishCommittee(ciphernodeRegistry, e3Id, "0xcafe", [
      operator1!,
      operator2!,
      operator3!,
    ]);
    await time.increaseTo(BigInt(request.inputWindow[1]) + 1n);
    await publishAvailableCiphertextOutput(
      interfold,
      e3Id,
      "0xda7a",
      ethers.id("node-release-ciphertext"),
      proof,
    );
    await interfold.publishPlaintextOutput(e3Id, "0xbeef", proof);
    await expect(nodeReleaseRegistry.setRequiredNodeRelease(2, 2))
      .to.be.revertedWithCustomError(
        nodeReleaseRegistry,
        "NodeReleasePolicyInUse",
      )
      .withArgs(0, 1);

    await time.increaseTo(
      (await slashingManager.accusationSubmissionDeadline(e3Id)) + 1n,
    );
    await ciphernodeRegistry.releaseCommittee(e3Id);
    await nodeReleaseRegistry.setRequiredNodeRelease(2, 2);
    expect(await nodeReleaseRegistry.requiredProtocolVersion()).to.equal(2);
    expect(await nodeReleaseRegistry.requiredNodeGeneration()).to.equal(2);
  });

  it("reserves global eligibility invalidation for the release controller", async function () {
    const { bondingRegistry, nodeReleaseRegistry } = await loadFixture(setup);

    await expect(
      bondingRegistry.refreshOperatorStatus(ethers.ZeroAddress),
    ).to.be.revertedWithCustomError(
      nodeReleaseRegistry,
      "OnlyNodeReleaseRegistry",
    );
  });

  it("rejects invalid and regressive compatibility requirements", async function () {
    const { interfold, nodeReleaseRegistry } = await loadFixture(setup);
    await interfold.setRequestsPaused(true);

    await expect(
      nodeReleaseRegistry.setRequiredNodeRelease(0, 1),
    ).to.be.revertedWithCustomError(nodeReleaseRegistry, "InvalidNodeRelease");
    await expect(
      nodeReleaseRegistry.setRequiredNodeRelease(1, 1),
    ).to.be.revertedWithCustomError(
      nodeReleaseRegistry,
      "NodeReleasePolicyRegression",
    );
  });

  it("rejects a dependency replacement that leaves stale release bindings", async function () {
    const { interfold, bondingRegistry, slashingManager, nodeReleaseRegistry } =
      await deployInterfoldSystem({ setupOperators: 0 });
    const replacement = await ethers.deployContract("MockCiphernodeRegistry");
    await replacement.setInterfold(await interfold.getAddress());
    await replacement.setBondingRegistry(await bondingRegistry.getAddress());
    await replacement.setSlashingManager(await slashingManager.getAddress());
    await interfold.setRequestsPaused(true);
    await bondingRegistry.setRegistry(await replacement.getAddress());
    await slashingManager.setCiphernodeRegistry(await replacement.getAddress());
    await interfold.setCiphernodeRegistry(await replacement.getAddress());

    await expect(
      interfold.setRequestsPaused(false),
    ).to.be.revertedWithCustomError(
      interfold,
      "DependencyConfigurationMismatch",
    );
    expect(await nodeReleaseRegistry.ciphernodeRegistry()).to.not.equal(
      await replacement.getAddress(),
    );
  });

  it("rejects a controller bound to another ciphernode registry", async function () {
    const { interfold, bondingRegistry, owner } = await loadFixture(setup);
    const wrongRegistry = await ethers.deployContract("MockCiphernodeRegistry");
    await wrongRegistry.setInterfold(await interfold.getAddress());
    const wrongController = await ethers.deployContract("NodeReleaseRegistry", [
      await owner.getAddress(),
      await bondingRegistry.getAddress(),
      await wrongRegistry.getAddress(),
    ]);

    await interfold.setRequestsPaused(true);
    await expect(
      interfold.setNodeReleaseRegistry(await wrongController.getAddress()),
    ).to.be.revertedWithCustomError(
      wrongController,
      "NodeReleaseBindingMismatch",
    );
  });

  it("cannot renounce release administration", async function () {
    const { nodeReleaseRegistry } = await loadFixture(setup);

    await expect(
      nodeReleaseRegistry.renounceOwnership(),
    ).to.be.revertedWithCustomError(
      nodeReleaseRegistry,
      "RenounceOwnershipDisabled",
    );
  });
});
