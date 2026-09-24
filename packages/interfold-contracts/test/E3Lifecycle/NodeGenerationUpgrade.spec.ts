// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";

import { nodeReleaseUpgradeTransactions } from "../../scripts/upgrade/nodeRelease";
import { NodeReleaseRegistry__factory as NodeReleaseRegistryFactory } from "../../types";
import {
  buildRequestParams,
  deployInterfoldSystem,
  ethers,
  makeRequest,
  networkHelpers,
  signAndEncodeAttestation,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;
const releaseId = (version: string) =>
  ethers.id(`interfold.node.release:v1:${version}`);
const release = {
  version: "0.18.0",
  releaseId: releaseId("0.18.0"),
  protocolVersion: 4,
  nodeGeneration: 2,
};

describe("Node generation upgrades with terminal committees", function () {
  async function activeCommittee() {
    const system = await deployInterfoldSystem({ setupOperators: 4 });
    const {
      interfold,
      nodeReleaseRegistry,
      ciphernodeRegistry: registry,
    } = system;
    const operators = (await ethers.getSigners()).slice(2, 6);
    const addresses = await Promise.all(
      operators.map((operator) => operator.getAddress()),
    );

    await interfold.setRequestsPaused(true);
    await nodeReleaseRegistry.setRequiredNodeRelease(4, 1);
    for (const operator of operators) {
      await nodeReleaseRegistry
        .connect(operator)
        .acknowledgeNodeRelease(releaseId("0.16.0"), 4, 1);
    }
    await interfold.setRequestsPaused(false);

    const request = async () => {
      await time.increase(1);
      const id = await interfold.nexte3Id();
      await makeRequest(
        interfold,
        system.usdcToken,
        await buildRequestParams(
          system.mocks.e3Program,
          system.mocks.decryptionVerifier,
        ),
      );
      await time.increase(1);
      return id;
    };
    const e3Id = await request();
    for (const operator of operators.slice(0, 3)) {
      await registry.connect(operator).submitTicket(e3Id, 1);
    }
    await time.increaseTo((await registry.getCommitteeDeadline(e3Id)) + 1n);
    await registry.finalizeCommittee(e3Id);

    const deployReplacement = async () =>
      new NodeReleaseRegistryFactory(system.owner).deploy(
        await system.owner.getAddress(),
        await system.bondingRegistry.getAddress(),
        await registry.getAddress(),
      );
    const committeeNodes = (id: bigint) =>
      Promise.all(
        [0, 1, 2].map((index) => registry.canonicalCommitteeNodeAt(id, index)),
      );
    return {
      ...system,
      registry,
      e3Id,
      operators,
      addresses,
      request,
      deployReplacement,
      committeeNodes,
    };
  }

  async function failedCommittee() {
    const state = await activeCommittee();
    const deadlines = await state.interfold.getDeadlines(state.e3Id);
    await time.increaseTo(deadlines.dkgDeadline + 1n);
    await state.interfold.markE3Failed(state.e3Id);
    await state.interfold.setRequestsPaused(true);
    const replaceController = async () => {
      const replacement = await state.deployReplacement();
      const transactions = await nodeReleaseUpgradeTransactions(
        state.interfold,
        release,
        replacement,
      );
      for (const { to, data, value } of transactions) {
        await state.owner.sendTransaction({ to, data, value });
      }
      return replacement;
    };
    return { ...state, replaceController };
  }

  it("blocks both generation updates and replacement during active DKG", async function () {
    const { interfold, nodeReleaseRegistry, deployReplacement } =
      await loadFixture(activeCommittee);
    await interfold.setRequestsPaused(true);
    const replacement = await deployReplacement();
    await expect(
      replacement.inheritReleasePolicy(await nodeReleaseRegistry.getAddress()),
    )
      .to.be.revertedWithCustomError(replacement, "NodeReleasePolicyInUse")
      .withArgs(1, 1);
    await expect(nodeReleaseRegistry.setRequiredNodeRelease(4, 2))
      .to.be.revertedWithCustomError(
        nodeReleaseRegistry,
        "NodeReleasePolicyInUse",
      )
      .withArgs(1, 1);
    await expect(
      interfold.setNodeReleaseRegistry(await replacement.getAddress()),
    )
      .to.be.revertedWithCustomError(replacement, "NodeReleasePolicyInUse")
      .withArgs(1, 1);
  });

  it("changes generation without releasing the failed committee or changing its deadlines", async function () {
    const {
      interfold,
      registry,
      slashingManager,
      e3RefundManager,
      bondingRegistry,
      nodeReleaseRegistry,
      e3Id,
      addresses,
      committeeNodes,
    } = await loadFixture(failedCommittee);
    const deadline = await slashingManager.accusationSubmissionDeadline(e3Id);
    const members = await committeeNodes(e3Id);
    const dependencies = await slashingManager.getE3Dependencies(e3Id);

    await nodeReleaseRegistry.setRequiredNodeRelease(4, 2);

    expect(await interfold.activeE3Count()).to.equal(0);
    expect(await registry.unreleasedCommitteeCount()).to.equal(1);
    expect(await committeeNodes(e3Id)).to.deep.equal(members);
    expect(await slashingManager.getE3Dependencies(e3Id)).to.deep.equal(
      dependencies,
    );
    expect(await slashingManager.accusationSubmissionDeadline(e3Id)).to.equal(
      deadline,
    );
    expect(await bondingRegistry.isActive(addresses[0])).to.equal(false);
    expect(await registry.isCommitteeMemberActive(e3Id, addresses[0])).to.equal(
      true,
    );
    await expect(registry.releaseCommittee(e3Id))
      .to.be.revertedWithCustomError(registry, "CommitteeAccusationWindowOpen")
      .withArgs(e3Id, deadline);
    await expect(
      interfold.processE3Failure(e3Id),
    ).to.be.revertedWithCustomError(e3RefundManager, "SettlementBlocked");
  });

  it("keeps protocol-version changes and the full-drain guard blocked", async function () {
    const { nodeReleaseRegistry } = await loadFixture(failedCommittee);
    await expect(nodeReleaseRegistry.assertUpgradeWindow())
      .to.be.revertedWithCustomError(
        nodeReleaseRegistry,
        "NodeReleasePolicyInUse",
      )
      .withArgs(0, 1);
    await expect(nodeReleaseRegistry.setRequiredNodeRelease(5, 2))
      .to.be.revertedWithCustomError(
        nodeReleaseRegistry,
        "NodeReleasePolicyInUse",
      )
      .withArgs(0, 1);
  });

  it("cannot bypass the drain by activating an unconfigured replacement", async function () {
    const { interfold, nodeReleaseRegistry, deployReplacement } =
      await loadFixture(failedCommittee);
    const replacement = await deployReplacement();
    await expect(
      interfold.setNodeReleaseRegistry(await replacement.getAddress()),
    )
      .to.be.revertedWithCustomError(replacement, "NodeReleasePolicyInUse")
      .withArgs(0, 1);
    await expect(replacement.setRequiredNodeRelease(4, 2))
      .to.be.revertedWithCustomError(replacement, "NodeReleasePolicyInUse")
      .withArgs(0, 1);
    expect(await interfold.nodeReleaseRegistry()).to.equal(
      await nodeReleaseRegistry.getAddress(),
    );
  });

  it("keeps pause and monotonic policy checks with terminal committees", async function () {
    const { interfold, nodeReleaseRegistry, deployReplacement } =
      await loadFixture(failedCommittee);
    const replacement = await deployReplacement();
    await interfold.setRequestsPaused(false);
    await expect(
      nodeReleaseRegistry.setRequiredNodeRelease(4, 2),
    ).to.be.revertedWithCustomError(
      nodeReleaseRegistry,
      "NodeReleasePolicyRequiresPause",
    );
    await expect(
      replacement.inheritReleasePolicy(await nodeReleaseRegistry.getAddress()),
    ).to.be.revertedWithCustomError(
      replacement,
      "NodeReleasePolicyRequiresPause",
    );
    await interfold.setRequestsPaused(true);
    await nodeReleaseRegistry.setRequiredNodeRelease(4, 2);
    for (const [protocol, generation] of [
      [4, 1],
      [3, 2],
      [4, 2],
      [5, 1],
    ]) {
      await expect(
        nodeReleaseRegistry.setRequiredNodeRelease(protocol, generation),
      ).to.be.revertedWithCustomError(
        nodeReleaseRegistry,
        "NodeReleasePolicyRegression",
      );
    }
  });

  it("preserves accusations, appeals, collateral locks, and settlement after replacement", async function () {
    const {
      interfold,
      registry,
      bondingRegistry,
      e3RefundManager,
      slashingManager,
      owner,
      e3Id,
      operators,
      addresses,
      replaceController,
    } = await loadFixture(failedCommittee);
    await replaceController();

    // Old members remain accusation voters even though they cannot enter new committees.
    const reason = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));
    await slashingManager.setSlashPolicy(reason, {
      ticketPenalty: ethers.parseUnits("1", 6),
      ciphernodeBondPenalty: 0,
      requiresProof: true,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: 3600,
      enabled: true,
      affectsCommittee: true,
      failureReason: 0,
    });
    const proof = await signAndEncodeAttestation(
      operators.slice(1, 3),
      e3Id,
      addresses[0],
      await slashingManager.getAddress(),
    );
    await slashingManager.proposeSlash(e3Id, addresses[0], proof);
    await slashingManager
      .connect(operators[0])
      .fileAppeal(0, "retained evidence");
    await expect(
      bondingRegistry
        .connect(operators[0])
        .removeTicketBalanceFor(addresses[0], 1),
    ).to.be.revertedWithCustomError(bondingRegistry, "OperatorUnderSlash");
    const deadline = await slashingManager.accusationSubmissionDeadline(e3Id);
    await time.increaseTo(deadline + 1n);
    await expect(
      interfold.processE3Failure(e3Id),
    ).to.be.revertedWithCustomError(e3RefundManager, "SettlementBlocked");
    await slashingManager
      .connect(owner)
      .resolveAppeal(0, true, "evidence accepted");
    await interfold.processE3Failure(e3Id);
    await registry.releaseCommittee(e3Id);
    expect(await registry.unreleasedCommitteeCount()).to.equal(0);
    expect(
      (await e3RefundManager.getRefundDistribution(e3Id)).calculated,
    ).to.equal(true);
  });

  it("forms a new committee from upgraded nodes while the failed committee stays locked", async function () {
    const {
      interfold,
      registry,
      bondingRegistry,
      e3Id,
      operators,
      addresses,
      request,
      replaceController,
      committeeNodes,
    } = await loadFixture(failedCommittee);
    const replacement = await replaceController();
    expect(await bondingRegistry.numActiveOperators()).to.equal(0);

    for (const operator of operators.slice(1)) {
      await replacement
        .connect(operator)
        .acknowledgeNodeRelease(releaseId("0.18.0"), 4, 2);
    }
    await time.increase(1);
    await interfold.setRequestsPaused(false);
    await expect(request())
      .to.be.revertedWithCustomError(registry, "InsufficientBondOwners")
      .withArgs(3, 0);
    await bondingRegistry.refreshOperatorStatus(addresses[0]);
    await time.increase(1);
    const nextE3 = await request();
    await expect(
      registry.connect(operators[0]).submitTicket(nextE3, 1),
    ).to.be.revertedWithCustomError(registry, "NodeNotEligible");
    for (const operator of operators.slice(1)) {
      await registry.connect(operator).submitTicket(nextE3, 1);
    }
    await time.increaseTo((await registry.getCommitteeDeadline(nextE3)) + 1n);
    await registry.finalizeCommittee(nextE3);
    expect(await committeeNodes(nextE3)).to.have.members(addresses.slice(1));
    expect(await registry.isCommitteeMemberActive(e3Id, addresses[0])).to.equal(
      true,
    );
    expect(await registry.unreleasedCommitteeCount()).to.equal(2);
  });

  it("admits both v0.17 and v0.18 declarations at generation two", async function () {
    const { nodeReleaseRegistry, operators } =
      await loadFixture(failedCommittee);
    await nodeReleaseRegistry.setRequiredNodeRelease(4, 2);
    for (const [index, version] of ["0.17.0", "0.18.0"].entries()) {
      await nodeReleaseRegistry
        .connect(operators[index])
        .acknowledgeNodeRelease(releaseId(version), 4, 2);
      expect(
        await nodeReleaseRegistry.isNodeReleaseReady(operators[index]),
      ).to.equal(true);
    }
  });

  it("prepares inheritance, activation, and generation in that order without sending them", async function () {
    const { interfold, nodeReleaseRegistry, deployReplacement } =
      await loadFixture(failedCommittee);
    const replacement = await deployReplacement();
    const transactions = await nodeReleaseUpgradeTransactions(
      interfold,
      release,
      replacement,
    );
    expect(transactions.map(({ to }) => to)).to.deep.equal([
      await replacement.getAddress(),
      await interfold.getAddress(),
      await replacement.getAddress(),
    ]);
    expect(transactions.map(({ data }) => data.slice(0, 10))).to.deep.equal([
      replacement.interface.getFunction("inheritReleasePolicy").selector,
      interfold.interface.getFunction("setNodeReleaseRegistry").selector,
      replacement.interface.getFunction("setRequiredNodeRelease").selector,
    ]);
    expect(await interfold.nodeReleaseRegistry()).to.equal(
      await nodeReleaseRegistry.getAddress(),
    );
    expect(await replacement.requiredNodeGeneration()).to.equal(0);
  });

  it("does not prepare a protocol change or a regressive generation", async function () {
    const { interfold, nodeReleaseRegistry } =
      await loadFixture(failedCommittee);
    await expect(
      nodeReleaseUpgradeTransactions(interfold, {
        ...release,
        protocolVersion: 5,
      }),
    ).to.be.rejectedWith("cannot change protocolVersion");
    await nodeReleaseRegistry.setRequiredNodeRelease(4, 3);
    await expect(
      nodeReleaseUpgradeTransactions(interfold, release),
    ).to.be.rejectedWith("cannot move backwards");
  });

  it("omits a no-op generation call when only the controller changes", async function () {
    const { interfold, deployReplacement } = await loadFixture(failedCommittee);
    const compatible = { ...release, nodeGeneration: 1 };
    expect(
      await nodeReleaseUpgradeTransactions(interfold, compatible),
    ).to.deep.equal([]);
    const transactions = await nodeReleaseUpgradeTransactions(
      interfold,
      compatible,
      await deployReplacement(),
    );
    expect(transactions).to.have.length(2);
  });
});
