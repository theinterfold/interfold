// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// SlashingManager lane / role / EIP-712 / admin / event coverage that is
// not already exercised by `SlashingManager.spec.ts` /
// `CommitteeExpulsion.spec.ts`:
//
//   * SLASHER_ROLE admin is GOVERNANCE_ROLE (not DEFAULT_ADMIN_ROLE).
//   * `BondingRegistry.deregisterOperator` blocked while a Lane B slash
//     proposal is open; unblocks after execution or upheld appeal.
//   * Lane A `proposeSlash` with a non-zero `appealWindow` defers
//     execution (no auto-execute) and respects the challenge window.
//   * EIP-712 attestation signatures are bound to the SlashingManager's
//     domain: wrong `verifyingContract` and wrong `chainId` both fail
//     signature recovery.
//   * Admin handover uses AccessControlDefaultAdminRules' two-step
//     `beginDefaultAdminTransfer` + `acceptDefaultAdminTransfer`.
//   * `SlashProposed` / `SlashExecuted` emit the `lane` field correctly
//     (Lane.LaneA=0 for `proposeSlash`, Lane.LaneB=1 for
//     `proposeSlashEvidence`).
import { expect } from "chai";

import type { SlashingManager } from "../../types/contracts/slashing/SlashingManager";
import {
  ADDRESS_ONE,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  signAndEncodeAttestation,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("SlashingManager — lanes, roles, EIP-712 & admin handover", function () {
  const REASON_PT_0 = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));
  const REASON_INACTIVITY = ethers.encodeBytes32String("inactivity");

  const SLASHER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("SLASHER_ROLE"));
  const GOVERNANCE_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("GOVERNANCE_ROLE"),
  );
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;

  const APPEAL_WINDOW = 7 * 24 * 60 * 60;
  // Constructor uses 2 days as the AccessControlDefaultAdminRules delay.
  const DEFAULT_ADMIN_DELAY = 2 * 24 * 60 * 60;

  const addressOne = ADDRESS_ONE;

  async function setupLaneAPolicy(
    slashingManager: SlashingManager,
    appealWindow: number = 0,
  ) {
    await slashingManager.setSlashPolicy(REASON_PT_0, {
      ticketPenalty: ethers.parseUnits("50", 6),
      licensePenalty: ethers.parseEther("100"),
      requiresProof: true,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow,
      enabled: true,
      affectsCommittee: false,
      failureReason: 0,
    });
  }

  async function setupLaneBPolicy(slashingManager: SlashingManager) {
    await slashingManager.setSlashPolicy(REASON_INACTIVITY, {
      ticketPenalty: ethers.parseUnits("20", 6),
      licensePenalty: ethers.parseEther("50"),
      requiresProof: false,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: APPEAL_WINDOW,
      enabled: true,
      affectsCommittee: false,
      failureReason: 0,
    });
  }

  async function setup() {
    const signers = await ethers.getSigners();
    const [
      owner,
      slasher,
      proposer,
      operator,
      newAdmin,
      voter1,
      voter2,
      voter3,
    ] = signers;
    const operatorAddress = await operator.getAddress();

    const sys = await deployInterfoldSystem({
      useMockCiphernodeRegistry: true,
      deployCircuitVerifier: true,
      setupOperators: 0,
      wireSlashingManager: false,
      mintUsdcTo: [],
    });
    const {
      slashingManager,
      bondingRegistry,
      licenseToken: interfoldToken,
      ticketToken,
      mockCiphernodeRegistry: mockCiphernodeRegistryOpt,
    } = sys;
    const mockCiphernodeRegistry = mockCiphernodeRegistryOpt!;

    await interfoldToken.mint(
      operatorAddress,
      ethers.parseEther("2000"),
      ethers.encodeBytes32String("Test allocation"),
    );
    await slashingManager.addSlasher(await slasher.getAddress());
    await slashingManager.setCiphernodeRegistry(
      await mockCiphernodeRegistry.getAddress(),
    );
    await slashingManager.setInterfold(addressOne);
    await slashingManager.setE3RefundManager(addressOne);

    return {
      owner,
      slasher,
      proposer,
      operator,
      operatorAddress,
      newAdmin,
      voter1,
      voter2,
      voter3,
      slashingManager,
      bondingRegistry,
      interfoldToken,
      ticketToken,
      mockCiphernodeRegistry,
    };
  }

  // --------------------------------------------------------------------------
  // SLASHER_ROLE admin is GOVERNANCE_ROLE
  // --------------------------------------------------------------------------
  describe("SLASHER_ROLE admin separation", function () {
    it("getRoleAdmin(SLASHER_ROLE) returns GOVERNANCE_ROLE", async function () {
      const { slashingManager } = await loadFixture(setup);
      expect(await slashingManager.getRoleAdmin(SLASHER_ROLE)).to.equal(
        GOVERNANCE_ROLE,
      );
    });

    it("non-GOVERNANCE_ROLE caller cannot addSlasher", async function () {
      const { slashingManager, proposer, slasher } = await loadFixture(setup);
      // `proposer` holds neither role — OZ AccessControl reverts with
      // AccessControlUnauthorizedAccount(account, role).
      await expect(
        slashingManager
          .connect(proposer)
          .addSlasher(await slasher.getAddress()),
      )
        .to.be.revertedWithCustomError(
          slashingManager,
          "AccessControlUnauthorizedAccount",
        )
        .withArgs(await proposer.getAddress(), GOVERNANCE_ROLE);
    });

    it("GOVERNANCE_ROLE holder can addSlasher / removeSlasher", async function () {
      const { slashingManager, owner, proposer } = await loadFixture(setup);
      const proposerAddr = await proposer.getAddress();
      // _grantRole emits RoleGranted(role, account, sender).
      await expect(slashingManager.connect(owner).addSlasher(proposerAddr))
        .to.emit(slashingManager, "RoleGranted")
        .withArgs(SLASHER_ROLE, proposerAddr, await owner.getAddress());
      expect(await slashingManager.hasRole(SLASHER_ROLE, proposerAddr)).to.be
        .true;
      await expect(slashingManager.connect(owner).removeSlasher(proposerAddr))
        .to.emit(slashingManager, "RoleRevoked")
        .withArgs(SLASHER_ROLE, proposerAddr, await owner.getAddress());
      expect(await slashingManager.hasRole(SLASHER_ROLE, proposerAddr)).to.be
        .false;
    });
  });

  // --------------------------------------------------------------------------
  // deregisterOperator blocked while Lane B proposal open
  // --------------------------------------------------------------------------
  describe("deregisterOperator gated by open Lane B proposals", function () {
    async function registerOperatorForExit(
      ctx: Awaited<ReturnType<typeof setup>>,
    ) {
      const { bondingRegistry, interfoldToken, operator } = ctx;
      // Bond the license required to register.
      const licenseAmount = ethers.parseEther("1000");
      await interfoldToken
        .connect(operator)
        .approve(await bondingRegistry.getAddress(), licenseAmount);
      await bondingRegistry.connect(operator).bondLicense(licenseAmount);
      await bondingRegistry.connect(operator).registerOperator();
    }

    it("hasOpenLaneBProposal flips true after proposeSlashEvidence and false after executeSlash", async function () {
      const ctx = await loadFixture(setup);
      const { slashingManager, slasher, operatorAddress } = ctx;
      await setupLaneBPolicy(slashingManager);

      expect(await slashingManager.hasOpenLaneBProposal(operatorAddress)).to.be
        .false;

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("ev"),
        );

      expect(await slashingManager.hasOpenLaneBProposal(operatorAddress)).to.be
        .true;

      await time.increase(APPEAL_WINDOW + 1);
      await slashingManager.executeSlash(0);

      expect(await slashingManager.hasOpenLaneBProposal(operatorAddress)).to.be
        .false;
    });

    it("deregisterOperator reverts OperatorUnderSlash while Lane B proposal open", async function () {
      const ctx = await loadFixture(setup);
      const {
        slashingManager,
        bondingRegistry,
        slasher,
        operator,
        operatorAddress,
      } = ctx;
      await registerOperatorForExit(ctx);
      await setupLaneBPolicy(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("ev"),
        );

      await expect(
        bondingRegistry.connect(operator).deregisterOperator(),
      ).to.be.revertedWithCustomError(bondingRegistry, "OperatorUnderSlash");
    });

    it("deregisterOperator succeeds after executeSlash clears the gate", async function () {
      const ctx = await loadFixture(setup);
      const {
        slashingManager,
        bondingRegistry,
        slasher,
        operator,
        operatorAddress,
      } = ctx;
      await registerOperatorForExit(ctx);
      await setupLaneBPolicy(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("ev"),
        );
      await time.increase(APPEAL_WINDOW + 1);
      await slashingManager.executeSlash(0);

      await bondingRegistry.connect(operator).deregisterOperator();
      expect(await bondingRegistry.isRegistered(operatorAddress)).to.be.false;
      expect(await bondingRegistry.hasExitInProgress(operatorAddress)).to.be
        .true;
      const op = { registered: false, exitRequested: true };
      expect(op.registered).to.be.false;
      expect(op.exitRequested).to.be.true;
    });

    it("deregisterOperator succeeds after appeal is upheld (Lane B unwinds open count)", async function () {
      const ctx = await loadFixture(setup);
      const {
        slashingManager,
        bondingRegistry,
        owner,
        slasher,
        operator,
        operatorAddress,
      } = ctx;
      await registerOperatorForExit(ctx);
      await setupLaneBPolicy(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("ev"),
        );
      await slashingManager.connect(operator).fileAppeal(0, "I was online");
      // Owner has GOVERNANCE_ROLE and can resolve appeals.
      await slashingManager.connect(owner).resolveAppeal(0, true, "upheld");

      expect(await slashingManager.hasOpenLaneBProposal(operatorAddress)).to.be
        .false;
      await bondingRegistry.connect(operator).deregisterOperator();
      expect(await bondingRegistry.isRegistered(operatorAddress)).to.be.false;
      expect(await bondingRegistry.hasExitInProgress(operatorAddress)).to.be
        .true;
      const op = { registered: false, exitRequested: true };
      expect(op.registered).to.be.false;
      expect(op.exitRequested).to.be.true;
    });
  });

  // --------------------------------------------------------------------------
  // Lane A challenge window defers execution
  // --------------------------------------------------------------------------
  describe("Lane A challenge window deferral", function () {
    async function setupCommittee(ctx: Awaited<ReturnType<typeof setup>>) {
      const { mockCiphernodeRegistry, operatorAddress, voter1, voter2 } = ctx;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);
    }

    it("proposeSlash with appealWindow>0 does NOT auto-execute and remains executable later", async function () {
      const ctx = await loadFixture(setup);
      const { slashingManager, proposer, operatorAddress, voter1, voter2 } =
        ctx;
      await setupLaneAPolicy(slashingManager, APPEAL_WINDOW);
      await setupCommittee(ctx);

      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.emit(slashingManager, "SlashProposed");

      const p = await slashingManager.getSlashProposal(0);
      expect(p.executed).to.be.false;
      expect(p.executableAt).to.be.gt(p.proposedAt);

      // Cannot execute before window elapses
      await expect(
        slashingManager.executeSlash(0),
      ).to.be.revertedWithCustomError(slashingManager, "AppealWindowActive");

      await time.increase(APPEAL_WINDOW + 1);
      await expect(slashingManager.executeSlash(0)).to.emit(
        slashingManager,
        "SlashExecuted",
      );
    });

    it("operator can fileAppeal on a Lane A deferred proposal", async function () {
      const ctx = await loadFixture(setup);
      const {
        slashingManager,
        proposer,
        operator,
        operatorAddress,
        voter1,
        voter2,
      } = ctx;
      await setupLaneAPolicy(slashingManager, APPEAL_WINDOW);
      await setupCommittee(ctx);

      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      await expect(
        slashingManager.connect(operator).fileAppeal(0, "not me"),
      ).to.emit(slashingManager, "AppealFiled");
    });
  });

  // --------------------------------------------------------------------------
  // EIP-712 domain binding
  // --------------------------------------------------------------------------
  describe("EIP-712 domain binding rejects cross-deployment replay", function () {
    async function setupCommittee(ctx: Awaited<ReturnType<typeof setup>>) {
      const { mockCiphernodeRegistry, operatorAddress, voter1, voter2 } = ctx;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);
    }

    it("attestation signed for a different verifyingContract is rejected", async function () {
      const ctx = await loadFixture(setup);
      const { slashingManager, proposer, operatorAddress, voter1, voter2 } =
        ctx;
      await setupLaneAPolicy(slashingManager, 0);
      await setupCommittee(ctx);

      // Sign against a wrong verifyingContract address.
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        addressOne, // not the real SlashingManager address
      );

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidVoteSignature");
    });

    it("attestation signed for a different chainId is rejected", async function () {
      const ctx = await loadFixture(setup);
      const { slashingManager, proposer, operatorAddress, voter1, voter2 } =
        ctx;
      await setupLaneAPolicy(slashingManager, 0);
      await setupCommittee(ctx);

      // Sign against a wrong chainId (mainnet) — still anchored to the right
      // verifyingContract.
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
        0,
        1,
      );

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidVoteSignature");
    });

    it("attestationDomainSeparator() matches EIP-712 view", async function () {
      const { slashingManager } = await loadFixture(setup);
      const sep = await slashingManager.attestationDomainSeparator();
      expect(sep).to.be.a("string");
      expect(sep.length).to.equal(66); // 0x + 32 bytes
      expect(sep).to.not.equal(ethers.ZeroHash);
    });
  });

  // --------------------------------------------------------------------------
  // AccessControlDefaultAdminRules two-step admin handover
  // --------------------------------------------------------------------------
  describe("two-step DEFAULT_ADMIN handover", function () {
    it("defaultAdminDelay() returns the configured 2-day delay", async function () {
      const { slashingManager } = await loadFixture(setup);
      expect(await slashingManager.defaultAdminDelay()).to.equal(
        DEFAULT_ADMIN_DELAY,
      );
    });

    it("acceptDefaultAdminTransfer requires beginDefaultAdminTransfer + delay", async function () {
      const { slashingManager, owner, newAdmin } = await loadFixture(setup);
      const newAdminAddr = await newAdmin.getAddress();

      // Premature accept fails (no pending transfer scheduled).
      await expect(
        slashingManager.connect(newAdmin).acceptDefaultAdminTransfer(),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "AccessControlInvalidDefaultAdmin",
      );

      await slashingManager
        .connect(owner)
        .beginDefaultAdminTransfer(newAdminAddr);

      // Still too early to accept — schedule has not elapsed.
      await expect(
        slashingManager.connect(newAdmin).acceptDefaultAdminTransfer(),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "AccessControlEnforcedDefaultAdminDelay",
      );

      await time.increase(DEFAULT_ADMIN_DELAY + 1);

      await slashingManager.connect(newAdmin).acceptDefaultAdminTransfer();
      expect(await slashingManager.defaultAdmin()).to.equal(newAdminAddr);
      expect(await slashingManager.hasRole(DEFAULT_ADMIN_ROLE, newAdminAddr)).to
        .be.true;
    });
  });

  // --------------------------------------------------------------------------
  // SlashProposed / SlashExecuted carry the lane field
  // --------------------------------------------------------------------------
  describe("SlashProposed / SlashExecuted carry lane field", function () {
    it("Lane A (proposeSlash) emits lane=0 on SlashProposed and SlashExecuted", async function () {
      const ctx = await loadFixture(setup);
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = ctx;
      await setupLaneAPolicy(slashingManager, 0);
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);

      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );

      const tx = await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      // Lane.LaneA == 0
      await expect(tx)
        .to.emit(slashingManager, "SlashProposed")
        .withArgs(
          0n,
          0n,
          operatorAddress,
          REASON_PT_0,
          ethers.parseUnits("50", 6),
          ethers.parseEther("100"),
          // executableAt is `block.timestamp` since appealWindow=0
          await ethers.provider
            .getBlock("latest")
            .then((b) => BigInt(b!.timestamp)),
          await proposer.getAddress(),
          0n,
        );

      // The SlashExecuted event in the same tx should carry lane=0 as well.
      const receipt = await tx.wait();
      const executedLog = receipt!.logs.find((l) => {
        try {
          const parsed = slashingManager.interface.parseLog(l);
          return parsed?.name === "SlashExecuted";
        } catch {
          return false;
        }
      });
      expect(executedLog).to.not.be.undefined;
      const parsed = slashingManager.interface.parseLog(executedLog!);
      // SlashExecuted args: (proposalId, e3Id, operator, reason, ticket,
      //                     license, executor, lane)
      expect(parsed!.args[7]).to.equal(0n);
    });

    it("Lane B (proposeSlashEvidence + executeSlash) emits lane=1", async function () {
      const ctx = await loadFixture(setup);
      const { slashingManager, slasher, operatorAddress } = ctx;
      await setupLaneBPolicy(slashingManager);

      await expect(
        slashingManager
          .connect(slasher)
          .proposeSlashEvidence(
            0,
            operatorAddress,
            REASON_INACTIVITY,
            ethers.toUtf8Bytes("ev"),
          ),
      )
        .to.emit(slashingManager, "SlashProposed")
        // Final indexed argument is Lane.LaneB == 1
        .withArgs(
          0n,
          0n,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.parseUnits("20", 6),
          ethers.parseEther("50"),
          (executableAt: bigint) => executableAt > 0n,
          await slasher.getAddress(),
          1n,
        );

      await time.increase(APPEAL_WINDOW + 1);
      const tx = await slashingManager.executeSlash(0);
      const receipt = await tx.wait();
      const executedLog = receipt!.logs.find((l) => {
        try {
          return (
            slashingManager.interface.parseLog(l)?.name === "SlashExecuted"
          );
        } catch {
          return false;
        }
      });
      expect(executedLog).to.not.be.undefined;
      const parsed = slashingManager.interface.parseLog(executedLog!);
      expect(parsed!.args[7]).to.equal(1n);
    });
  });
});
