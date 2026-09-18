// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";

import {
  buildSlashingManagerMigrationTransactions,
  deploySlashingManagerReplacement,
  slashPolicyReasons,
} from "../../scripts/protocol/serviceMigration";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
} from "../../scripts/protocol/types";
import { deployInterfoldSystem, ethers, networkHelpers } from "../fixtures";

const { loadFixture } = networkHelpers;

describe("Slashing-manager migration", function () {
  async function setup() {
    return deployInterfoldSystem({ setupOperators: 3 });
  }

  it("builds one reusable cutover that preserves registered operators", async function () {
    const system = await loadFixture(setup);
    const owner = await system.owner.getAddress();
    const previousManager = await system.slashingManager.getAddress();
    const reason = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));
    const disabledReason = ethers.keccak256(
      ethers.solidityPacked(["uint256"], [1]),
    );
    const policy = {
      ticketPenalty: 1n,
      ciphernodeBondPenalty: 2n,
      requiresProof: false,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: 3600,
      enabled: true,
      affectsCommittee: false,
      failureReason: 0,
    };
    await system.slashingManager.setSlashPolicy(reason, policy);
    await system.slashingManager.setSlashPolicy(disabledReason, {
      ...policy,
      enabled: false,
    });

    const config = {
      protocolOwner: owner,
      slasher: ethers.ZeroAddress,
      slashing: { initialDelay: "0" },
    } as ProtocolConfigFile;
    const deployment = {
      interfold: await system.interfold.getAddress(),
      ciphernodeRegistry: await system.ciphernodeRegistry.getAddress(),
      bondingRegistryProxy: await system.bondingRegistry.getAddress(),
      e3RefundManager: await system.e3RefundManager.getAddress(),
      slashingManager: previousManager,
    } as ProtocolDeployment;
    const replacement = await deploySlashingManagerReplacement(ethers, config);
    const migration = await buildSlashingManagerMigrationTransactions(
      ethers,
      config,
      deployment,
      replacement,
    );

    expect(migration.migratedSlashPolicyReasons).to.deep.equal([
      reason,
      disabledReason,
    ]);
    expect(migration.transactions).to.have.lengthOf(10);
    const rootBefore = await system.ciphernodeRegistry.root();
    const registeredBefore =
      await system.bondingRegistry.numRegisteredOperators();
    const activeBefore = await system.bondingRegistry.numActiveOperators();
    await system.interfold.setRequestsPaused(true);
    for (const transaction of migration.transactions) {
      await (
        await system.owner.sendTransaction({
          to: transaction.to,
          data: transaction.data,
          value: transaction.value,
        })
      ).wait();
    }

    expect(await system.interfold.slashingManager()).to.equal(
      replacement.manager,
    );
    expect(await system.ciphernodeRegistry.slashingManager()).to.equal(
      replacement.manager,
    );
    expect(await system.bondingRegistry.slashingManager()).to.equal(
      replacement.manager,
    );
    expect(
      await system.bondingRegistry.isAuthorizedSlashingManager(
        replacement.manager,
      ),
    ).to.equal(true);
    expect(
      await system.bondingRegistry.isAuthorizedSlashingManager(previousManager),
    ).to.equal(false);
    expect(await system.ciphernodeRegistry.root()).to.equal(rootBefore);
    expect(await system.bondingRegistry.numRegisteredOperators()).to.equal(
      registeredBefore,
    );
    expect(await system.bondingRegistry.numActiveOperators()).to.equal(
      activeBefore,
    );
    const replacementManager = await ethers.getContractAt(
      "SlashingManager",
      replacement.manager,
    );
    const migratedPolicy = await replacementManager.getSlashPolicy(reason);
    expect(migratedPolicy.ticketPenalty).to.equal(policy.ticketPenalty);
    expect(migratedPolicy.ciphernodeBondPenalty).to.equal(
      policy.ciphernodeBondPenalty,
    );
    expect(migratedPolicy.enabled).to.equal(true);
    const migratedDisabledPolicy =
      await replacementManager.getSlashPolicy(disabledReason);
    expect(migratedDisabledPolicy.ticketPenalty).to.equal(policy.ticketPenalty);
    expect(migratedDisabledPolicy.ciphernodeBondPenalty).to.equal(
      policy.ciphernodeBondPenalty,
    );
    expect(migratedDisabledPolicy.enabled).to.equal(false);
  });

  it("accepts configured policy reasons without deployment addresses", function () {
    const customReason = `0x${"12".repeat(32)}`;
    const reasons = slashPolicyReasons({
      slashing: {
        initialDelay: "0",
        policyReasons: [customReason, customReason],
      },
    } as ProtocolConfigFile);

    expect(reasons).to.have.lengthOf(12);
    expect(reasons.at(-1)).to.equal(customReason);
    expect(() =>
      slashPolicyReasons({
        slashing: { initialDelay: "0", policyReasons: ["0x12"] },
      } as ProtocolConfigFile),
    ).to.throw("Invalid slash-policy reason");
  });
});
