// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import InterfoldModule from "../../ignition/modules/interfold";
import { localPricingConfig } from "../../scripts/pricingConfig";
import type {
  MockBlacklistUSDC,
  MockFeeOnTransferToken,
  MockUSDC,
} from "../../types";
import {
  Interfold__factory as InterfoldFactory,
  MockFeeOnTransferToken__factory as MockFeeOnTransferTokenFactory,
  MockUSDC__factory as MockUSDCFactory,
} from "../../types";
import {
  ACTIVE_CRYPTO_CONFIG_ID,
  currentPricingConfig,
  deployInterfoldSystem,
  deploySlashingManager,
  encodeMockDkgProof,
  ethers,
  ignition,
  makeRequest,
  networkHelpers,
  publishAvailableCiphertextOutput,
  setPricingConfig,
  signAndEncodeAttestation,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

/**
 * Integration tests for E3 Refund/Timeout Mechanism
 *
 * These tests verify the full integration between:
 * - Interfold.sol (main coordinator with integrated lifecycle management)
 * - E3RefundManager.sol (refund calculation and claiming)
 * - CiphernodeRegistryOwnable.sol (committee management)
 */
describe("E3 Integration - Refund/Timeout Mechanism", function () {
  let firstE3Id: bigint;
  // Time constants
  const ONE_HOUR = 60 * 60;
  const ONE_DAY = 24 * ONE_HOUR;
  const THREE_DAYS = 3 * ONE_DAY;
  const THIRTY_DAYS = 30 * ONE_DAY;
  const SORTITION_SUBMISSION_WINDOW = 60;

  const addressOne = "0x0000000000000000000000000000000000000001";

  const defaultTimeoutConfig = {
    dkgWindow: ONE_DAY,
    computeWindow: THREE_DAYS,
    decryptionWindow: ONE_DAY,
  };

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  // Lane A reason derived on-chain as keccak256(abi.encodePacked(proofType))
  const REASON_PT_0 = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));
  const REASON_PT_1 = ethers.keccak256(ethers.solidityPacked(["uint256"], [1]));

  const setup = async () => {
    // E3Integration historically uses 7 signers in this order:
    //   [owner, requester, treasury, operator1, operator2, computeProvider, operator3]
    const [
      owner,
      requester,
      treasury,
      operator1,
      operator2,
      computeProvider,
      operator3,
    ] = await ethers.getSigners();

    const sys = await deployInterfoldSystem({
      committeeThresholds: [[0, [2, 3]]],
      deployCircuitVerifier: true,
      maxDuration: THIRTY_DAYS,
      mintUsdcTo: [],
      setupOperators: 0,
      slashedFundsTreasury: treasury,
      timeoutConfig: defaultTimeoutConfig,
      treasury,
      useBlacklistFeeToken: true,
      wireSlashingManager: true,
    });

    const {
      interfold,
      e3RefundManager,
      bondingRegistry,
      ciphernodeRegistry: registry,
      slashingManager,
      nodeReleaseRegistry,
      usdcToken,
      ciphernodeBondToken: foldToken,
      mocks: {
        e3Program,
        decryptionVerifier,
        randomnessProvider,
        circuitVerifier: _circuitVerifier,
      },
    } = sys;
    if (!randomnessProvider) throw new Error("randomness provider missing");

    const interfoldAddress = await interfold.getAddress();
    firstE3Id = await interfold.nexte3Id();
    const e3RefundManagerAddress = await e3RefundManager.getAddress();

    // Slash policy for Lane A proof routing E2E tests
    await slashingManager.setSlashPolicy(REASON_PT_0, {
      ticketPenalty: ethers.parseUnits("50", 6),
      ciphernodeBondPenalty: ethers.parseEther("100"),
      requiresProof: true,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: 0,
      enabled: true,
      affectsCommittee: false,
      failureReason: 0,
    });

    // Token mints (skip default end-user mint via mintUsdcTo:[])
    await usdcToken.mint(
      await requester.getAddress(),
      ethers.parseUnits("10000", 6),
    );
    await usdcToken.mint(e3RefundManagerAddress, ethers.parseUnits("10000", 6));

    // ── Helpers ────────────────────────────────────────────────────────────────
    const makeRequest = async (
      signer: Signer = requester,
      committeeSize: number = 0,
      requestToken: MockUSDC | MockFeeOnTransferToken = usdcToken,
    ): Promise<{ e3Id: bigint }> => {
      // Ticket voting power is snapshotted at request timestamp - 1. EDR may
      // mine consecutive setup transactions with the same timestamp, so move
      // the request clock forward before taking that conservative snapshot.
      await time.increase(1);
      const startTime = (await time.latest()) + 100;

      const requestParams = {
        committeeSize,
        inputWindow: [startTime + 100, startTime + ONE_DAY] as [number, number],
        e3Program: await e3Program.getAddress(),
        paramSet: 0,
        computeProviderParams: abiCoder.encode(
          ["address"],
          [await decryptionVerifier.getAddress()],
        ),
        customParams: abiCoder.encode(
          ["address"],
          ["0x1234567890123456789012345678901234567890"],
        ),
        expectedFeeToken: await requestToken.getAddress(),
        expectedCryptoConfigId: ACTIVE_CRYPTO_CONFIG_ID,
        maxFee: ethers.MaxUint256,
      };

      const e3Id = await interfold.nexte3Id();
      const fee = await interfold.getE3Quote(requestParams);
      await requestToken.connect(signer).approve(interfoldAddress, fee);
      await interfold.connect(signer).request(requestParams);
      await time.increase(1);

      return { e3Id };
    };

    const setupOperator = async (operator: Signer) => {
      const operatorAddress = await operator.getAddress();
      const bondOwnerAddress = await computeProvider.getAddress();
      const ticketTokenAddress = await bondingRegistry.ticketToken();
      const ticketAmount = ethers.parseUnits("100", 6);

      await foldToken.mint(
        bondOwnerAddress,
        ethers.parseEther("10000"),
        ethers.encodeBytes32String("Test allocation"),
      );
      await usdcToken.mint(bondOwnerAddress, ethers.parseUnits("100000", 6));

      await bondingRegistry.connect(operator).setBondOwner(bondOwnerAddress);
      await nodeReleaseRegistry
        .connect(operator)
        .acknowledgeNodeRelease(
          ethers.id("interfold.node.release:v1:test"),
          1,
          1,
        );
      await foldToken
        .connect(computeProvider)
        .approve(await bondingRegistry.getAddress(), ethers.parseEther("2000"));
      await bondingRegistry
        .connect(computeProvider)
        .bondCiphernodeFor(operatorAddress, ethers.parseEther("1000"));
      await bondingRegistry
        .connect(computeProvider)
        .registerOperatorFor(operatorAddress);

      await usdcToken
        .connect(computeProvider)
        .approve(ticketTokenAddress, ticketAmount);
      await bondingRegistry
        .connect(computeProvider)
        .addTicketBalanceFor(operatorAddress, ticketAmount);
    };

    const transferBondOwner = async (operator: Signer, nextOwner: Signer) => {
      const operatorAddress = await operator.getAddress();
      const nextOwnerAddress = await nextOwner.getAddress();
      await bondingRegistry
        .connect(computeProvider)
        .proposeBondOwner(operatorAddress, nextOwnerAddress);
      await bondingRegistry.connect(nextOwner).acceptBondOwner(operatorAddress);
    };

    const makeReadyRequest = async () => {
      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await makeRequest();
    };

    const finalizeReadyCommittee = async () => {
      await makeReadyRequest();
      for (const operator of [operator1, operator2, operator3]) {
        await registry.connect(operator).submitTicket(firstE3Id, 1);
      }
      const deadline = await registry.getCommitteeDeadline(firstE3Id);
      await time.setNextBlockTimestamp(deadline + 1n);
      await registry.finalizeCommittee(firstE3Id);
    };

    const finalizeAndPublishCommittee = async () => {
      for (const operator of [operator1, operator2, operator3]) {
        await registry.connect(operator).submitTicket(firstE3Id, 1);
      }
      const deadline = await registry.getCommitteeDeadline(firstE3Id);
      await time.setNextBlockTimestamp(deadline + 1n);
      await registry.finalizeCommittee(firstE3Id);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );
    };

    return {
      interfold,
      e3RefundManager,
      bondingRegistry,
      registry,
      slashingManager,
      _circuitVerifier,
      usdcToken,
      foldToken,
      e3Program,
      decryptionVerifier,
      randomnessProvider,
      owner,
      requester,
      treasury,
      operator1,
      operator2,
      operator3,
      computeProvider,
      makeRequest,
      setupOperator,
      transferBondOwner,
      makeReadyRequest,
      finalizeReadyCommittee,
      finalizeAndPublishCommittee,
    };
  };

  describe("E3 Request with Lifecycle Integration", function () {
    it("rejects requests until the dependency graph is activated", async function () {
      const sys = await deployInterfoldSystem({
        setupOperators: 0,
        wireSlashingManager: false,
      });

      await expect(
        makeRequest(sys.interfold, sys.usdcToken, sys.request),
      ).to.be.revertedWithCustomError(sys.interfold, "RequestsPaused");
    });

    it("initializes E3 lifecycle when request is made", async function () {
      const {
        interfold,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Check that E3 lifecycle was initialized
      const stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(1); // E3Stage.Requested

      // Check requester is tracked
      const storedRequester = await interfold.getRequester(firstE3Id);
      expect(storedRequester).to.equal(await requester.getAddress());
    });

    it("keeps a selected operator's queued collateral slashable until the E3 ends", async function () {
      const {
        interfold,
        bondingRegistry,
        registry,
        slashingManager,
        operator1,
        computeProvider,
        finalizeReadyCommittee,
      } = await loadFixture(setup);

      await finalizeReadyCommittee();
      const operatorAddress = await operator1.getAddress();

      await expect(
        bondingRegistry
          .connect(computeProvider)
          .setCommitteeObligation(firstE3Id, operatorAddress, false),
      ).to.be.revertedWithCustomError(bondingRegistry, "Unauthorized");
      await expect(registry.releaseCommittee(firstE3Id))
        .to.be.revertedWithCustomError(registry, "E3NotTerminal")
        .withArgs(firstE3Id);

      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operatorAddress);
      expect(await registry.isCommitteeMemberActive(firstE3Id, operatorAddress))
        .to.be.true;

      // The E3 fails early (DKG timeout) while the queued exit is still
      // maturing and the accusation window is still open.
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(firstE3Id);

      // ZEN-09: a finalized committee stays held through the accusation
      // window, so a valid accusation submitted after the E3 ends still finds
      // collateral to slash.
      const [, submissionDeadline] =
        await slashingManager.getE3AccusationWindow(firstE3Id);
      expect(
        await slashingManager.accusationSubmissionDeadline(firstE3Id),
      ).to.equal(submissionDeadline);
      expect(submissionDeadline).to.be.greaterThan(await time.latest());
      await expect(registry.releaseCommittee(firstE3Id))
        .to.be.revertedWithCustomError(
          registry,
          "CommitteeAccusationWindowOpen",
        )
        .withArgs(firstE3Id, submissionDeadline);

      // The exit matures, but the committee hold still blocks the claim.
      await time.increase((await bondingRegistry.exitDelay()) + 1n);
      await expect(
        bondingRegistry
          .connect(computeProvider)
          .claimExitsFor(operatorAddress, ethers.MaxUint256, ethers.MaxUint256),
      ).to.be.revertedWithCustomError(
        bondingRegistry,
        "OperatorInActiveCommittee",
      );

      // In this fixture the exit delay outlasts the accusation window, so the
      // window has already closed. The ZEN-09 test below covers the case where
      // the exit matures first.
      expect(await time.latest()).to.be.greaterThan(submissionDeadline);
      await expect(registry.releaseCommittee(firstE3Id))
        .to.emit(registry, "CommitteeActivationChanged")
        .withArgs(firstE3Id, false);

      await bondingRegistry
        .connect(computeProvider)
        .claimExitsFor(operatorAddress, ethers.MaxUint256, ethers.MaxUint256);
      const [pendingTickets, pendingCiphernodeBond] =
        await bondingRegistry.pendingExits(operatorAddress);
      expect(pendingTickets).to.equal(0);
      expect(pendingCiphernodeBond).to.equal(0);
    });

    it("ZEN-09: holds a finalized committee through the last second of the accusation window", async function () {
      const { interfold, registry, slashingManager, finalizeReadyCommittee } =
        await loadFixture(setup);

      await finalizeReadyCommittee();
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(firstE3Id);

      const [, submissionDeadline] =
        await slashingManager.getE3AccusationWindow(firstE3Id);
      await time.setNextBlockTimestamp(submissionDeadline);
      await expect(registry.releaseCommittee(firstE3Id))
        .to.be.revertedWithCustomError(
          registry,
          "CommitteeAccusationWindowOpen",
        )
        .withArgs(firstE3Id, submissionDeadline);

      await time.setNextBlockTimestamp(submissionDeadline + 1n);
      await expect(registry.releaseCommittee(firstE3Id))
        .to.emit(registry, "CommitteeActivationChanged")
        .withArgs(firstE3Id, false);
      expect(await registry.unreleasedCommitteeCount()).to.equal(0);
    });

    it("ZEN-09: releases a finalized committee after governance closes its accusation window", async function () {
      const {
        interfold,
        registry,
        slashingManager,
        owner,
        finalizeReadyCommittee,
      } = await loadFixture(setup);

      await finalizeReadyCommittee();
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(firstE3Id);

      const [, submissionDeadline] =
        await slashingManager.getE3AccusationWindow(firstE3Id);
      await time.increaseTo(submissionDeadline + 1n);
      await slashingManager.connect(owner).closeE3(firstE3Id);
      expect(
        await slashingManager.accusationSubmissionDeadline(firstE3Id),
      ).to.equal(0);

      await expect(registry.releaseCommittee(firstE3Id))
        .to.emit(registry, "CommitteeActivationChanged")
        .withArgs(firstE3Id, false);
    });

    it("ZEN-09: releases an unfinalized committee at terminal stage without an accusation hold", async function () {
      const { interfold, registry, slashingManager, makeReadyRequest } =
        await loadFixture(setup);

      await makeReadyRequest();
      const [, submissionDeadline] =
        await slashingManager.getE3AccusationWindow(firstE3Id);
      expect(submissionDeadline).to.be.greaterThan(await time.latest());

      const committeeDeadline = await registry.getCommitteeDeadline(firstE3Id);
      await time.setNextBlockTimestamp(committeeDeadline + 1n);
      await expect(registry.finalizeCommittee(firstE3Id))
        .to.emit(registry, "CommitteeActivationChanged")
        .withArgs(firstE3Id, false);
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(6); // E3Stage.Failed
      expect(await registry.unreleasedCommitteeCount()).to.equal(0);
    });

    it("ZEN-09: an exit that matures before the accusation window closes cannot be claimed", async function () {
      const {
        interfold,
        bondingRegistry,
        registry,
        slashingManager,
        owner,
        operator1,
        computeProvider,
        finalizeReadyCommittee,
      } = await loadFixture(setup);

      // Shorten the exit delay so it matures well inside the accusation
      // window of the round configured in this fixture.
      await bondingRegistry.connect(owner).setExitDelay(ONE_DAY);
      await finalizeReadyCommittee();
      const operatorAddress = await operator1.getAddress();

      // Day 0.1: the operator queues its entire stake for withdrawal.
      await bondingRegistry
        .connect(operator1)
        .deregisterOperatorFor(operatorAddress);

      // Day 1: the round fails. Its accusation window remains open.
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(firstE3Id);
      const [, submissionDeadline] =
        await slashingManager.getE3AccusationWindow(firstE3Id);

      // The exit delay matures before the accusation deadline.
      await time.increase(ONE_DAY + 1);
      expect(await time.latest()).to.be.lessThan(submissionDeadline);

      // Neither the release nor the claim can proceed.
      await expect(registry.releaseCommittee(firstE3Id))
        .to.be.revertedWithCustomError(
          registry,
          "CommitteeAccusationWindowOpen",
        )
        .withArgs(firstE3Id, submissionDeadline);
      await expect(
        bondingRegistry
          .connect(computeProvider)
          .claimExitsFor(operatorAddress, ethers.MaxUint256, ethers.MaxUint256),
      ).to.be.revertedWithCustomError(
        bondingRegistry,
        "OperatorInActiveCommittee",
      );

      // After the window closes both succeed.
      await time.increaseTo(submissionDeadline + 1n);
      await registry.releaseCommittee(firstE3Id);
      await bondingRegistry
        .connect(computeProvider)
        .claimExitsFor(operatorAddress, ethers.MaxUint256, ethers.MaxUint256);
      const [pendingTickets, pendingCiphernodeBond] =
        await bondingRegistry.pendingExits(operatorAddress);
      expect(pendingTickets).to.equal(0);
      expect(pendingCiphernodeBond).to.equal(0);
    });

    it("classifies every supported failure reason by economic responsibility", async function () {
      const { e3RefundManager } = await loadFixture(setup);

      for (const reason of [5, 6, 7, 8, 9]) {
        expect(await e3RefundManager.getFailurePayer(reason)).to.equal(1);
      }
      for (const reason of [1, 2, 3, 4, 10, 11, 12]) {
        expect(await e3RefundManager.getFailurePayer(reason)).to.equal(2);
      }

      await expect(
        e3RefundManager.getFailurePayer(0),
      ).to.be.revertedWithCustomError(e3RefundManager, "InvalidFailureReason");
      await expect(
        e3RefundManager.getFailurePayer(13),
      ).to.be.revertedWithCustomError(e3RefundManager, "InvalidFailureReason");
    });

    it("allows only the requester to cancel after the randomness timeout", async function () {
      const {
        interfold,
        makeReadyRequest,
        owner,
        requester,
        randomnessProvider,
        registry,
      } = await loadFixture(setup);
      await randomnessProvider.setAutoFulfill(false);
      await makeReadyRequest();

      await expect(interfold.connect(owner).cancelE3(firstE3Id))
        .to.be.revertedWithCustomError(interfold, "NotRequester")
        .withArgs(firstE3Id, await owner.getAddress());

      await expect(interfold.connect(requester).cancelE3(firstE3Id))
        .to.be.revertedWithCustomError(interfold, "E3NotCancellable")
        .withArgs(firstE3Id, 1);

      const deadline = await registry.getCommitteeDeadline(firstE3Id);
      await time.increaseTo(deadline + 1n);
      await expect(interfold.connect(requester).cancelE3(firstE3Id))
        .to.emit(interfold, "E3Failed")
        .withArgs(firstE3Id, 1, 1);
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(1);

      await expect(interfold.connect(requester).cancelE3(firstE3Id))
        .to.be.revertedWithCustomError(interfold, "E3NotCancellable")
        .withArgs(firstE3Id, 6);
    });

    it("refunds service fees after a randomness timeout", async function () {
      const ctx = await loadFixture(setup);
      await ctx.randomnessProvider.setAutoFulfill(false);
      const requesterAddress = await ctx.requester.getAddress();
      const requesterBalanceBefore =
        await ctx.usdcToken.balanceOf(requesterAddress);
      await ctx.makeReadyRequest();
      const serviceFee = await ctx.interfold.e3Payments(firstE3Id);
      const randomnessFee = (await ctx.interfold.getPricingConfig())
        .randomnessFlatFee;
      const requesterBalanceAfterRequest =
        await ctx.usdcToken.balanceOf(requesterAddress);
      expect(requesterBalanceBefore - requesterBalanceAfterRequest).to.equal(
        serviceFee + randomnessFee,
      );

      const pricing = await ctx.interfold.getPricingConfig();
      expect(
        await ctx.interfold.pendingTreasuryClaim(
          pricing.protocolTreasury,
          await ctx.usdcToken.getAddress(),
        ),
      ).to.equal(randomnessFee);

      const deadline = await ctx.registry.getCommitteeDeadline(firstE3Id);
      await time.increaseTo(deadline + 1n);
      await ctx.interfold.connect(ctx.requester).cancelE3(firstE3Id);
      expect(await ctx.registry.unreleasedCommitteeCount()).to.equal(0);
      expect(await ctx.registry.randomnessProvider()).to.equal(
        ethers.ZeroAddress,
      );

      const requestId = await ctx.randomnessProvider.requestIdByE3Id(firstE3Id);
      await ctx.randomnessProvider.fulfill(requestId, 123n);
      expect(await ctx.registry.sortitionSeed(firstE3Id)).to.deep.equal([
        false,
        0n,
      ]);

      await ctx.interfold.processE3Failure(firstE3Id);

      const distribution =
        await ctx.e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.requesterAmount).to.equal(
        distribution.originalPayment,
      );
      expect(distribution.honestNodeAmount).to.equal(0);
      expect(distribution.protocolAmount).to.equal(0);

      await ctx.e3RefundManager
        .connect(ctx.requester)
        .claimRequesterRefund(firstE3Id);
      const requesterBalanceAfterRefund =
        await ctx.usdcToken.balanceOf(requesterAddress);
      expect(
        requesterBalanceAfterRefund - requesterBalanceAfterRequest,
      ).to.equal(serviceFee);
    });

    it("rejects cancellation after the committee randomness is known", async function () {
      const ctx = await loadFixture(setup);
      await ctx.makeReadyRequest();

      await expect(ctx.interfold.connect(ctx.requester).cancelE3(firstE3Id))
        .to.be.revertedWithCustomError(ctx.interfold, "E3NotCancellable")
        .withArgs(firstE3Id, 1);
    });

    it("keeps timely randomness available for replay after failure", async function () {
      const ctx = await loadFixture(setup);
      await ctx.makeReadyRequest();

      const acceptedSeed = await ctx.registry.sortitionSeed(firstE3Id);
      expect(acceptedSeed[0]).to.equal(true);
      const deadline = await ctx.registry.getCommitteeDeadline(firstE3Id);
      await time.increaseTo(deadline + 1n);
      await ctx.interfold.markE3Failed(firstE3Id);

      expect(await ctx.registry.sortitionSeed(firstE3Id)).to.deep.equal(
        acceptedSeed,
      );
      expect(await ctx.registry.randomnessProvider()).to.equal(
        await ctx.randomnessProvider.getAddress(),
      );
    });

    it("does not expose an unresolved seed after the E3 times out", async function () {
      const ctx = await loadFixture(setup);
      await ctx.randomnessProvider.setAutoFulfill(false);
      await ctx.makeReadyRequest();

      const deadline = await ctx.registry.getCommitteeDeadline(firstE3Id);
      await time.increaseTo(deadline + 1n);
      await ctx.interfold.markE3Failed(firstE3Id);

      expect(await ctx.registry.sortitionSeed(firstE3Id)).to.deep.equal([
        false,
        0n,
      ]);
      expect(await ctx.registry.randomnessProvider()).to.equal(
        ethers.ZeroAddress,
      );
    });

    it("rejects invalid failure reasons from an authorized dependency", async function () {
      const { interfold, registry, makeReadyRequest } =
        await loadFixture(setup);
      await makeReadyRequest();

      const registryAddress = await registry.getAddress();
      await networkHelpers.impersonateAccount(registryAddress);
      await networkHelpers.setBalance(registryAddress, ethers.parseEther("1"));
      const registrySigner = await ethers.getSigner(registryAddress);

      for (const reason of [0, 9, 13, 255]) {
        await expect(
          interfold.connect(registrySigner).onE3Failed(firstE3Id, reason),
        )
          .to.be.revertedWithCustomError(interfold, "InvalidFailureReason")
          .withArgs(reason);
      }

      await networkHelpers.stopImpersonatingAccount(registryAddress);
    });

    it("routes zero-value node shares to the treasury", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        usdcToken,
        treasury,
        finalizeReadyCommittee,
      } = await loadFixture(setup);

      await setPricingConfig(interfold, {
        keyGenFixedPerNode: 0,
        keyGenPerEncryptionProof: 0,
        coordinationPerPair: 0,
        availabilityPerNodePerSec: 0,
        decryptionPerNode: 0,
        publicationBase: 5,
        verificationPerProof: 0,
        protocolTreasury: await treasury.getAddress(),
        marginBps: 0,
        protocolShareBps: 0,
        dkgUtilizationBps: 0,
        computeUtilizationBps: 0,
        decryptUtilizationBps: 0,
        minCommitteeSize: 0,
        minThreshold: 0,
        randomnessFlatFee: 1,
      });

      await finalizeReadyCommittee();

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      const deadlines = await interfold.getDeadlines(firstE3Id);
      await time.increaseTo(deadlines.computeDeadline + 1n);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      expect(
        await e3RefundManager.pendingTreasuryClaim(
          await treasury.getAddress(),
          await usdcToken.getAddress(),
        ),
      ).to.equal(3);
    });

    it("AUD-M07: snapshots failure allocation and treasury at request time", async function () {
      const {
        interfold,
        e3RefundManager,
        bondingRegistry,
        registry,
        usdcToken,
        makeRequest,
        owner,
        treasury,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await makeRequest();

      const originalTreasury = await treasury.getAddress();
      const rotatedTreasury = await computeProvider.getAddress();
      const snapshot = await e3RefundManager.getE3PolicySnapshot(firstE3Id);
      expect(snapshot.initialized).to.equal(true);
      expect(snapshot.version).to.equal(1);
      expect(snapshot.treasury).to.equal(originalTreasury);
      expect(snapshot.registry).to.equal(await registry.getAddress());
      expect(snapshot.bondingRegistry).to.equal(
        await bondingRegistry.getAddress(),
      );
      expect(snapshot.allocation.committeeFormationBps).to.equal(1000n);
      expect(snapshot.allocation.dkgBps).to.equal(4000n);
      expect(snapshot.allocation.decryptionBps).to.equal(4500n);
      expect(snapshot.allocation.protocolBps).to.equal(500n);
      expect(snapshot.allocation.successSlashedNodeBps).to.equal(5000n);

      await e3RefundManager.connect(owner).setWorkAllocation({
        committeeFormationBps: 2000,
        dkgBps: 3000,
        decryptionBps: 4500,
        protocolBps: 500,
        successSlashedNodeBps: 1000,
      });
      await e3RefundManager.connect(owner).setTreasury(rotatedTreasury);

      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );
      const deadlines = await interfold.getDeadlines(firstE3Id);
      await time.increaseTo(deadlines.computeDeadline + 1n);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.honestNodeAmount).to.equal(
        (distribution.originalPayment * 5000n) / 10000n,
      );
      expect(
        await e3RefundManager.pendingTreasuryClaim(
          originalTreasury,
          await usdcToken.getAddress(),
        ),
      ).to.equal(distribution.protocolAmount);
      expect(
        await e3RefundManager.pendingTreasuryClaim(
          rotatedTreasury,
          await usdcToken.getAddress(),
        ),
      ).to.equal(0);

      const unchanged = await e3RefundManager.getE3PolicySnapshot(firstE3Id);
      expect(unchanged.version).to.equal(1);
      expect(unchanged.treasury).to.equal(originalTreasury);
      expect(unchanged.allocation.committeeFormationBps).to.equal(1000n);
    });

    it("blocks dependency rotation until the active generation is drained", async function () {
      const {
        interfold,
        registry,
        makeRequest,
        owner,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await makeRequest();
      const rotatedRegistry = await (
        await ethers.deployContract("MockCiphernodeRegistry")
      ).getAddress();
      await interfold.connect(owner).setRequestsPaused(true);
      await expect(
        interfold.connect(owner).setCiphernodeRegistry(rotatedRegistry),
      ).to.be.revertedWithCustomError(
        interfold,
        "DependencyGenerationNotDrained",
      );
      expect(await interfold.activeE3Count()).to.equal(1);
      expect(await registry.unreleasedCommitteeCount()).to.equal(1);
    });
  });

  describe("Committee Formed Integration", function () {
    it("transitions to CommitteeFormed when publishCommittee is called", async function () {
      const {
        interfold,
        registry,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // Make a request first
      await makeRequest();

      // Verify stage is Requested
      let stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(1); // E3Stage.Requested

      // Submit tickets for sortition
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);

      // Fast forward past submission window
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);

      // Finalize committee
      await registry.finalizeCommittee(firstE3Id);

      // Publish committee (this triggers onCommitteePublished -> onCommitteeFormed)
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);

      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      // Verify stage transitioned to KeyPublished (after publishCommittee which calls onKeyPublished)
      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(3); // E3Stage.KeyPublished

      // Verify deadlines were set
      const deadlines = await interfold.getDeadlines(firstE3Id);
      expect(deadlines.dkgDeadline).to.be.gt(0);
    });

    it("emits CommitteeFormed event when committee is published", async function () {
      const {
        interfold,
        registry,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // Make a request
      await makeRequest();

      // Complete sortition process
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      // Publish committee and expect CommitteeFormed event
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);

      await expect(
        registry.publishCommittee(
          firstE3Id,
          pkCommitment,
          encodeMockDkgProof(pkCommitment),
          "0x01",
        ),
      )
        .to.emit(interfold, "CommitteeFormed")
        .withArgs(firstE3Id);
    });

    it("rejects committee publication after the DKG deadline", async function () {
      const { interfold, registry, finalizeReadyCommittee } =
        await loadFixture(setup);
      await finalizeReadyCommittee();

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      const { dkgDeadline } = await interfold.getDeadlines(firstE3Id);
      await time.increaseTo(dkgDeadline + 1n);

      await expect(
        registry.publishCommittee(
          firstE3Id,
          pkCommitment,
          encodeMockDkgProof(pkCommitment),
          "0x01",
        ),
      ).to.be.revertedWithCustomError(interfold, "DKGDeadlinePassed");
    });
  });

  describe("processE3Failure()", function () {
    it("reverts if lifecycle is not a valid contract", async function () {
      const {
        interfold,
        owner,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
        e3Program,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      const emptyRegistry = await ethers.deployContract(
        "MockCiphernodeRegistry",
      );

      // Create a new Interfold with addressOne as the refund manager placeholder.
      const newInterfoldContract = await ignition.deploy(InterfoldModule, {
        parameters: {
          Interfold: {
            owner: await owner.getAddress(),
            maxDuration: THIRTY_DAYS,
            registry: await emptyRegistry.getAddress(),
            bondingRegistry: await interfold.bondingRegistry(),
            e3RefundManager: addressOne,
            feeToken: await interfold.feeToken(),
            pricingConfig: localPricingConfig(await owner.getAddress()),
            initialE3Program: await e3Program.getAddress(),
          },
        },
      });
      const newInterfold = InterfoldFactory.connect(
        await newInterfoldContract.interfold.getAddress(),
        owner,
      );

      // Calling processE3Failure with a placeholder lifecycle should revert
      // (it will try to call getE3Stage on an EOA which will fail)
      await expect(newInterfold.processE3Failure(firstE3Id)).to.be.revert(
        ethers,
      );
    });

    it("reverts if E3 not in failed state", async function () {
      const {
        interfold,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // E3 is in Requested state, not Failed
      await expect(
        interfold.processE3Failure(firstE3Id),
      ).to.be.revertedWithCustomError(interfold, "E3NotFailed");
    });

    it("processes failure and calculates refund for committee formation timeout", async function () {
      const {
        interfold,
        e3RefundManager,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Fast forward past committee formation deadline
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);

      // Mark E3 as failed
      await interfold.markE3Failed(firstE3Id);

      const stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(6); // E3Stage.Failed

      // Process the failure
      await expect(interfold.processE3Failure(firstE3Id)).to.emit(
        interfold,
        "E3FailureProcessed",
      );

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.calculated).to.be.true;
      expect(distribution.requesterAmount).to.equal(
        distribution.originalPayment,
      );
      expect(distribution.honestNodeAmount).to.equal(0);
      expect(distribution.protocolAmount).to.equal(0);
    });

    it("processes failure after an incomplete provisional committee", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        operator1,
        makeReadyRequest,
      } = await loadFixture(setup);

      await makeReadyRequest();
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);

      await registry.finalizeCommittee(firstE3Id);

      await interfold.processE3Failure(firstE3Id);
      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.honestNodeAmount).to.equal(0);
    });

    it("rolls back failure processing when the registry lookup reverts", async function () {
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: true,
      });
      const registry = sys.mockCiphernodeRegistry!;
      const e3Id = await sys.interfold.nexte3Id();
      await makeRequest(sys.interfold, sys.usdcToken, sys.request);
      const payment = await sys.interfold.e3Payments(e3Id);
      const registryAddress = await registry.getAddress();

      await networkHelpers.setBalance(registryAddress, ethers.parseEther("1"));
      await networkHelpers.impersonateAccount(registryAddress);
      await sys.interfold
        .connect(await ethers.getSigner(registryAddress))
        .onE3Failed(e3Id, 8);
      await networkHelpers.stopImpersonatingAccount(registryAddress);
      await registry.setRevertActiveCommitteeNodes(true);

      await expect(
        sys.interfold.processE3Failure(e3Id),
      ).to.be.revertedWithCustomError(registry, "ActiveCommitteeLookupFailed");
      expect(await sys.interfold.e3Payments(e3Id)).to.equal(payment);
      const distribution =
        await sys.e3RefundManager.getRefundDistribution(e3Id);
      expect(distribution.calculated).to.equal(false);
    });

    it("allows requester to claim refund after failure processing", async function () {
      const {
        interfold,
        e3RefundManager,
        makeRequest,
        requester,
        usdcToken,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Get initial balance
      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      // Fast forward and fail E3
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      // Claim refund
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);

      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(balanceAfter).to.be.gt(balanceBefore);
    });

    it("rejects sender fees from fee escrow and refund custody", async function () {
      const {
        interfold,
        e3RefundManager,
        makeRequest,
        owner,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      const token = await new MockFeeOnTransferTokenFactory(owner).deploy(0);
      const tokenAddress = await token.getAddress();
      await token.setFeeIsChargedOnTop(true);
      await token.mint(requester, ethers.parseEther("10000"));
      await interfold.setFeeAssetConfig({
        token: tokenAddress,
        expectedDecimals: 18,
        pricing: {
          ...(await currentPricingConfig(interfold)),
          randomnessFlatFee: ethers.parseEther("1"),
        },
      });

      await makeRequest(requester, 0, token);
      await makeRequest(requester, 0, token);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 2);
      await interfold.markE3Failed(firstE3Id);
      await interfold.markE3Failed(firstE3Id + 1n);

      const firstPayment = await interfold.e3Payments(firstE3Id);
      const senderFee = firstPayment / 100n;
      await token.setFeeBps(100);
      await expect(interfold.processE3Failure(firstE3Id))
        .to.be.revertedWithCustomError(interfold, "AssetTransferMismatch")
        .withArgs(tokenAddress, firstPayment, firstPayment + senderFee);
      expect(await interfold.e3Payments(firstE3Id)).to.equal(firstPayment);

      await token.setFeeBps(0);
      await interfold.processE3Failure(firstE3Id);
      await interfold.processE3Failure(firstE3Id + 1n);

      const firstDistribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      const managerAddress = await e3RefundManager.getAddress();
      const managerBalance = await token.balanceOf(managerAddress);
      const refundFee = firstDistribution.requesterAmount / 100n;
      await token.setFeeBps(100);
      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id),
      )
        .to.be.revertedWithCustomError(e3RefundManager, "AssetTransferMismatch")
        .withArgs(
          tokenAddress,
          firstDistribution.requesterAmount,
          firstDistribution.requesterAmount + refundFee,
        );
      expect(await token.balanceOf(managerAddress)).to.equal(managerBalance);

      await token.setFeeBps(0);
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
    });

    it("reverts if trying to process failure twice", async function () {
      const {
        interfold,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      // Second call should fail - payment already cleared
      await expect(
        interfold.processE3Failure(firstE3Id),
      ).to.be.revertedWithCustomError(interfold, "NoPaymentToRefund");
    });

    it("reverts if requester tries to claim refund twice", async function () {
      const {
        interfold,
        e3RefundManager,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      // First claim succeeds
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);

      // Second claim should fail
      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id),
      ).to.be.revertedWithCustomError(e3RefundManager, "AlreadyClaimed");
    });

    it("reverts if refund not yet calculated", async function () {
      const {
        e3RefundManager,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Try to claim before failure is processed
      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id),
      ).to.be.revertedWithCustomError(e3RefundManager, "RefundNotCalculated");
    });
  });

  describe("Slashed Funds Escrow", function () {
    it("E2E: slash via SlashingManager pays honest nodes without reducing the requester refund", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        slashingManager,
        bondingRegistry,
        usdcToken,
        makeRequest,
        owner,
        requester,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });
      // 1. Request E3, form committee, publish key
      await makeRequest(requester, 0);
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      // 2. Wait past compute deadline → mark as failed
      const e3 = await interfold.getE3(firstE3Id);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(firstE3Id);

      // 3. Process failure → distribution calculated, funds transferred to refund manager
      await interfold.processE3Failure(firstE3Id);
      const distributionBefore =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distributionBefore.calculated).to.be.true;

      // Record refund manager USDC balance before slash routing
      const refundManagerBalanceBefore = await usdcToken.balanceOf(
        await e3RefundManager.getAddress(),
      );

      // Record BondingRegistry's slashedTicketBalance before slash
      const slashedBalanceBefore = await bondingRegistry.slashedTicketBalance();

      // 4. Slash operator1 via proposeSlash (Lane A) — real on-chain flow.
      //    The manager reserves the slash, then atomically routes the reserved
      //    underlying through Interfold into E3RefundManager escrow.
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );

      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );

      // 5. Verify actual USDC moved to the refund manager
      const refundManagerBalanceAfter = await usdcToken.balanceOf(
        await e3RefundManager.getAddress(),
      );
      const actualSlashedAmount =
        refundManagerBalanceAfter - refundManagerBalanceBefore;
      expect(actualSlashedAmount).to.be.gt(0);

      // Verify BondingRegistry's slashedTicketBalance was decremented
      const slashedBalanceAfter = await bondingRegistry.slashedTicketBalance();
      expect(slashedBalanceAfter).to.equal(
        slashedBalanceBefore, // slash added then redirect removed the same amount
      );

      // 6. Base refunds stay denominated in the E3 fee token; the slash is a
      //    separate claim in its actual underlying token.
      const distributionAfter =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distributionAfter.requesterAmount).to.equal(
        distributionBefore.requesterAmount,
      );
      expect(distributionAfter.honestNodeAmount).to.equal(
        distributionBefore.honestNodeAmount,
      );
      const usdcAddress = await usdcToken.getAddress();
      const requesterSlashClaim = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        usdcAddress,
        await requester.getAddress(),
      );
      expect(requesterSlashClaim).to.equal(0);
      expect(distributionAfter.totalSlashed).to.equal(actualSlashedAmount);

      const honestSlashClaims = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        usdcAddress,
        await computeProvider.getAddress(),
      );
      expect(honestSlashClaims).to.equal(actualSlashedAmount);
      for (const node of [operator1, operator2, operator3]) {
        expect(
          await e3RefundManager.pendingSlashedClaim(
            firstE3Id,
            usdcAddress,
            await node.getAddress(),
          ),
        ).to.equal(0);
      }

      // 7. The requester pulls only the fault-attributed base refund.
      const requesterBalanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
      expect(
        await usdcToken.balanceOf(await e3RefundManager.getAddress()),
      ).to.be.gte(await e3RefundManager.tokenLiability(usdcAddress));
      const requesterBalanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(requesterBalanceAfter - requesterBalanceBefore).to.equal(
        distributionAfter.requesterAmount,
      );
    });

    it("AUD-M05: reserves a failed slash route and retries it permissionlessly", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        slashingManager,
        bondingRegistry,
        usdcToken,
        makeRequest,
        owner,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest(requester, 0);
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      await registry.publishCommittee(
        firstE3Id,
        ethers.keccak256(publicKey),
        encodeMockDkgProof(ethers.keccak256(publicKey)),
        "0x01",
      );

      const e3 = await interfold.getE3(firstE3Id);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const blacklistToken = usdcToken as unknown as MockBlacklistUSDC;
      const refundManagerAddress = await e3RefundManager.getAddress();
      await blacklistToken.blacklist(refundManagerAddress);

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await expect(
        slashingManager.proposeSlash(
          firstE3Id,
          await operator1.getAddress(),
          proof,
        ),
      ).to.emit(slashingManager, "SlashRoutePending");

      const pending = await slashingManager.getPendingSlashRoute(0);
      expect(pending.pending).to.equal(true);
      expect(pending.e3Id).to.equal(firstE3Id);
      expect(pending.token).to.equal(await usdcToken.getAddress());
      expect(pending.amount).to.be.gt(0);
      expect(await bondingRegistry.reservedSlashedTicketBalance()).to.equal(
        pending.amount,
      );
      expect(await bondingRegistry.slashedTicketBalance()).to.equal(
        pending.amount,
      );
      const oldManagerAddress = await slashingManager.getAddress();
      const reservation = await bondingRegistry.getSlashedTicketReservation(
        oldManagerAddress,
        0,
      );
      expect(reservation.e3Id).to.equal(firstE3Id);
      expect(reservation.refundManager).to.equal(refundManagerAddress);
      expect(reservation.amount).to.equal(pending.amount);

      const newManager = await deploySlashingManager(
        0,
        await owner.getAddress(),
      );
      await newManager.setBondingRegistry(await bondingRegistry.getAddress());
      const newManagerAddress = await newManager.getAddress();
      await bondingRegistry
        .connect(owner)
        .setSlashingManager(newManagerAddress);

      await expect(
        bondingRegistry.connect(owner).revokeSlashingManager(oldManagerAddress),
      )
        .to.be.revertedWithCustomError(
          bondingRegistry,
          "ManagerHasPendingSlashRoutes",
        )
        .withArgs(oldManagerAddress, 1);

      await networkHelpers.setBalance(
        newManagerAddress,
        ethers.parseEther("1"),
      );
      await networkHelpers.impersonateAccount(newManagerAddress);
      await expect(
        bondingRegistry
          .connect(await ethers.getSigner(newManagerAddress))
          .redirectReservedSlashedTicketFunds(0),
      )
        .to.be.revertedWithCustomError(
          bondingRegistry,
          "SlashReservationNotFound",
        )
        .withArgs(newManagerAddress, 0);
      await networkHelpers.stopImpersonatingAccount(newManagerAddress);

      await expect(
        bondingRegistry.connect(owner).withdrawSlashedFunds(pending.amount, 0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ReservedSlashedFunds");

      await blacklistToken.unblacklist(refundManagerAddress);
      const refundBalanceBefore =
        await usdcToken.balanceOf(refundManagerAddress);
      await expect(slashingManager.connect(requester).retrySlashRoute(0))
        .to.emit(slashingManager, "SlashRouteCompleted")
        .withArgs(0, firstE3Id, await usdcToken.getAddress(), pending.amount)
        .and.to.emit(interfold, "SlashedFundsEscrowed")
        .withArgs(firstE3Id, await usdcToken.getAddress(), pending.amount);

      expect(
        (await usdcToken.balanceOf(refundManagerAddress)) - refundBalanceBefore,
      ).to.equal(pending.amount);
      expect((await slashingManager.getPendingSlashRoute(0)).pending).to.equal(
        false,
      );
      expect(await bondingRegistry.reservedSlashedTicketBalance()).to.equal(0);
      expect(await bondingRegistry.slashedTicketBalance()).to.equal(0);
      expect(
        await bondingRegistry.pendingSlashRouteCount(oldManagerAddress),
      ).to.equal(0);
      const [, submissionDeadline] =
        await slashingManager.getE3AccusationWindow(firstE3Id);
      await expect(slashingManager.connect(owner).closeE3(firstE3Id))
        .to.be.revertedWithCustomError(slashingManager, "AccusationWindowOpen")
        .withArgs(firstE3Id, submissionDeadline);
      await time.increaseTo(submissionDeadline + 1n);
      await slashingManager.connect(owner).closeE3(firstE3Id);
      await bondingRegistry
        .connect(owner)
        .revokeSlashingManager(oldManagerAddress);
      expect(
        await slashingManager.connect(requester).retrySlashRoute.staticCall(0),
      ).to.equal(false);
    });

    it("AUD-H01: preserves a slash token distinct from the E3 fee token", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        slashingManager,
        usdcToken: ticketUnderlying,
        makeRequest,
        owner,
        requester,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      const feeToken = await new MockUSDCFactory(owner).deploy(0);
      await feeToken.waitForDeployment();
      await feeToken.mint(
        await requester.getAddress(),
        ethers.parseUnits("10000", 6),
      );
      await interfold.connect(owner).setFeeAssetConfig({
        token: await feeToken.getAddress(),
        expectedDecimals: 6,
        pricing: {
          ...(await currentPricingConfig(interfold)),
          randomnessFlatFee: 1_000_000,
        },
      });

      await makeRequest(requester, 0, feeToken);
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      await registry.publishCommittee(
        firstE3Id,
        ethers.keccak256(publicKey),
        encodeMockDkgProof(ethers.keccak256(publicKey)),
        "0x01",
      );

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );

      const underlyingAddress = await ticketUnderlying.getAddress();
      const feeTokenAddress = await feeToken.getAddress();
      const actualSlash = ethers.parseUnits("50", 6);
      expect(
        await e3RefundManager.pendingSlashedFunds(firstE3Id, underlyingAddress),
      ).to.equal(actualSlash);

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      // Fee settlement cannot consume or relabel the ticket underlying.
      // Anyone can settle its recorded proposal explicitly.
      expect(
        await e3RefundManager.pendingSlashedFunds(firstE3Id, underlyingAddress),
      ).to.equal(actualSlash);
      await e3RefundManager.connect(operator3).settleSlashedFunds(firstE3Id, 0);

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.feeToken).to.equal(feeTokenAddress);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          feeTokenAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);

      const bondOwnerAddress = await computeProvider.getAddress();
      const totalSlashCredits = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        underlyingAddress,
        bondOwnerAddress,
      );
      expect(totalSlashCredits).to.equal(actualSlash);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          underlyingAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          underlyingAddress,
          await operator1.getAddress(),
        ),
      ).to.equal(0);
      expect(totalSlashCredits).to.be.gt(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          underlyingAddress,
          await operator2.getAddress(),
        ),
      ).to.equal(0);
      expect(await e3RefundManager.tokenLiability(underlyingAddress)).to.equal(
        totalSlashCredits,
      );

      const requesterAddress = await requester.getAddress();
      const feeBefore = await feeToken.balanceOf(requesterAddress);
      const underlyingBefore =
        await ticketUnderlying.balanceOf(bondOwnerAddress);
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
      await e3RefundManager
        .connect(computeProvider)
        .claimSlashedFunds(firstE3Id, underlyingAddress);

      expect((await feeToken.balanceOf(requesterAddress)) - feeBefore).to.equal(
        distribution.requesterAmount,
      );
      expect(
        (await ticketUnderlying.balanceOf(bondOwnerAddress)) - underlyingBefore,
      ).to.equal(totalSlashCredits);
      expect(await e3RefundManager.tokenLiability(underlyingAddress)).to.equal(
        0,
      );
    });

    it("E2E: honest nodes can claim their share after slashed funds are escrowed", async function () {
      const {
        interfold,
        e3RefundManager,
        bondingRegistry,
        registry,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      // 1. Request E3, form committee, publish key
      await makeRequest(undefined, 0);
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      const operator2Address = await operator2.getAddress();
      await bondingRegistry
        .connect(computeProvider)
        .proposeBondOwner(operator2Address, await owner.getAddress());
      await bondingRegistry.connect(owner).acceptBondOwner(operator2Address);
      expect(
        await e3RefundManager.rewardRecipient(firstE3Id, operator2Address),
      ).to.equal(await computeProvider.getAddress());

      // 2. Fail via compute timeout
      const e3 = await interfold.getE3(firstE3Id);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      // 3. Record the base distribution before slash.
      const distributionBefore =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      const honestNodeAmountBefore = distributionBefore.honestNodeAmount;

      // 4. Slash operator1 — this routes funds into the refund pool
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.honestNodeCount).to.be.gt(0);
      expect(distribution.honestNodeAmount).to.equal(honestNodeAmountBefore);
      const usdcAddress = await usdcToken.getAddress();
      const bondOwnerAddress = await computeProvider.getAddress();
      const ownerSlashClaim = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        usdcAddress,
        bondOwnerAddress,
      );
      expect(ownerSlashClaim).to.be.gt(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          await operator1.getAddress(),
        ),
      ).to.equal(0);
      // 5. The bond owner claims operator2's base reward and the aggregated
      // slashed-fund rewards for the honest operators.
      const ownerBalanceBefore = await usdcToken.balanceOf(bondOwnerAddress);
      await expect(
        e3RefundManager
          .connect(operator2)
          .claimHonestNodeReward(firstE3Id, await operator2.getAddress()),
      ).to.be.revertedWithCustomError(e3RefundManager, "Unauthorized");
      await e3RefundManager
        .connect(computeProvider)
        .claimHonestNodeReward(firstE3Id, await operator2.getAddress());
      await e3RefundManager
        .connect(computeProvider)
        .claimSlashedFunds(firstE3Id, usdcAddress);
      const ownerBalanceAfter = await usdcToken.balanceOf(bondOwnerAddress);

      const perNodeAmount =
        distribution.honestNodeAmount / BigInt(distribution.honestNodeCount);
      const baseTopUp =
        ownerBalanceAfter -
        ownerBalanceBefore -
        perNodeAmount -
        ownerSlashClaim;
      expect(
        baseTopUp == perNodeAmount / 2n ||
          baseTopUp == perNodeAmount - perNodeAmount / 2n,
      ).to.equal(true);
    });

    it("does not return a penalty to its target through a later expulsion", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        requester,
        treasury,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      // Give every operator its own recipient, so a per-recipient balance
      // identifies exactly one operator.
      await transferBondOwner(operator1, requester);
      await transferBondOwner(operator2, treasury);
      await transferBondOwner(operator3, computeProvider);

      // A non-expelling penalty on operator1, then an expelling one on
      // operator2. Redistributing operator2's held share must not hand any of
      // operator1's own penalty back to operator1.
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_1, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: 0n,
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      });
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      // Settle the round: a slash route is only distributed once the refund
      // distribution exists.
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const operator1Address = await operator1.getAddress();
      const operator2Address = await operator2.getAddress();
      const usdcAddress = await usdcToken.getAddress();
      const operator1Recipient = await requester.getAddress();
      const operator2Recipient = await treasury.getAddress();

      // Penalize operator1 without expelling it. Its penalty is shared out.
      const penaltyProof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        operator1Address,
        await slashingManager.getAddress(),
        1,
      );
      const penaltyProposalId = await slashingManager.totalProposals();
      await slashingManager.proposeSlash(
        firstE3Id,
        operator1Address,
        penaltyProof,
      );
      await slashingManager.retrySlashRoute(penaltyProposalId);

      // operator1 is the target, so it receives none of its own penalty.
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          operator1Recipient,
        ),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          operator2Recipient,
        ),
      ).to.be.gt(0);

      // Now expel operator2, which redistributes the share it was holding.
      const expulsionProof = await signAndEncodeAttestation(
        [operator1, operator3],
        firstE3Id,
        operator2Address,
        await slashingManager.getAddress(),
      );
      const expulsionProposalId = await slashingManager.totalProposals();
      await slashingManager.proposeSlash(
        firstE3Id,
        operator2Address,
        expulsionProof,
      );
      await time.increase(ONE_DAY + 1);
      const operator3Recipient = await computeProvider.getAddress();
      const operator1Before = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        usdcAddress,
        operator1Recipient,
      );
      const operator3Before = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        usdcAddress,
        operator3Recipient,
      );
      expect(operator1Before).to.equal(0);
      await slashingManager.executeSlash(expulsionProposalId);

      // Two things move here. (1) operator2's held 25 came entirely from
      // operator1's penalty, so re-sharing it must skip operator1 and go to
      // operator3 alone. (2) operator2's own 50 penalty is a new penalty, split
      // between operator1 and operator3, 25 each; operator1 is entitled to
      // that share. So operator1 gains exactly 25 and operator3 gains 50:
      // nothing of operator1's own penalty came back to operator1.
      const penalty = ethers.parseUnits("50", 6);
      expect(
        (await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          operator1Recipient,
        )) - operator1Before,
      ).to.equal(penalty / 2n);
      expect(
        (await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          operator3Recipient,
        )) - operator3Before,
      ).to.equal(penalty);
      // Custody still covers what the contract says it owes.
      expect(
        await usdcToken.balanceOf(await e3RefundManager.getAddress()),
      ).to.be.gte(await e3RefundManager.tokenLiability(usdcAddress));
    });

    for (const [label, order] of [
      ["A then B", [0, 1]],
      ["B then A", [1, 0]],
    ] as const) {
      it(`shares each non-expelling penalty with every other member (${label})`, async function () {
        const {
          interfold,
          e3RefundManager,
          slashingManager,
          usdcToken,
          makeRequest,
          owner,
          requester,
          treasury,
          computeProvider,
          operator1,
          operator2,
          operator3,
          setupOperator,
          transferBondOwner,
          finalizeAndPublishCommittee,
        } = await loadFixture(setup);

        for (const operator of [operator1, operator2, operator3]) {
          await setupOperator(operator);
        }
        await transferBondOwner(operator1, requester);
        await transferBondOwner(operator2, treasury);
        await transferBondOwner(operator3, computeProvider);

        await slashingManager.connect(owner).setSlashPolicy(REASON_PT_1, {
          ticketPenalty: ethers.parseUnits("50", 6),
          ciphernodeBondPenalty: 0n,
          requiresProof: true,
          proofVerifier: ethers.ZeroAddress,
          banNode: false,
          appealWindow: 0,
          enabled: true,
          affectsCommittee: false,
          failureReason: 0,
        });

        await makeRequest();
        await finalizeAndPublishCommittee();

        const e3 = await interfold.getE3(firstE3Id);
        await time.increaseTo(
          Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
        );
        await interfold.markE3Failed(firstE3Id);
        await interfold.processE3Failure(firstE3Id);

        const usdcAddress = await usdcToken.getAddress();
        const members = [operator1, operator2, operator3];
        const recipients = [requester, treasury, computeProvider];
        const penalty = ethers.parseUnits("50", 6);

        // Two non-expelling penalties, on A then B or B then A. A target is
        // excluded only from its own penalty, so each penalty is split
        // between the other two members and the outcome does not depend on
        // the order the proposals execute in.
        for (const targetIndex of order) {
          const voters = members.filter((_, i) => i !== targetIndex);
          const proof = await signAndEncodeAttestation(
            voters,
            firstE3Id,
            await members[targetIndex].getAddress(),
            await slashingManager.getAddress(),
            1,
          );
          const proposalId = await slashingManager.totalProposals();
          await slashingManager.proposeSlash(
            firstE3Id,
            await members[targetIndex].getAddress(),
            proof,
          );
          await slashingManager.retrySlashRoute(proposalId);
        }

        const claim = async (i: number) =>
          e3RefundManager.pendingSlashedClaim(
            firstE3Id,
            usdcAddress,
            await recipients[i].getAddress(),
          );
        // A gets half of B's penalty, B gets half of A's, C gets half of both.
        expect(await claim(0)).to.equal(penalty / 2n);
        expect(await claim(1)).to.equal(penalty / 2n);
        expect(await claim(2)).to.equal(penalty);
        expect(
          await usdcToken.balanceOf(await e3RefundManager.getAddress()),
        ).to.be.gte(await e3RefundManager.tokenLiability(usdcAddress));
      });
    }

    it("clears a bucket whose penalty target was expelled earlier", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        requester,
        treasury,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await transferBondOwner(operator1, requester);
      await transferBondOwner(operator2, treasury);
      await transferBondOwner(operator3, computeProvider);

      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_1, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: 0n,
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      });
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: 0n,
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const usdcAddress = await usdcToken.getAddress();
      const slashingAddress = await slashingManager.getAddress();
      const op1 = await operator1.getAddress();
      const op2 = await operator2.getAddress();
      const penalty = ethers.parseUnits("50", 6);

      // 1. Non-expelling penalty on A: B and C hold 25 each, tagged target=A.
      const penaltyId = await slashingManager.totalProposals();
      await slashingManager.proposeSlash(
        firstE3Id,
        op1,
        await signAndEncodeAttestation(
          [operator2, operator3],
          firstE3Id,
          op1,
          slashingAddress,
          1,
        ),
      );
      await slashingManager.retrySlashRoute(penaltyId);

      // 2. Expel A. A leaves the active roster, but B's bucket is still
      //    keyed by A. Provenance bookkeeping must find it without the
      //    roster, or it is left describing funds that have already moved.
      const expelAId = await slashingManager.totalProposals();
      await slashingManager.proposeSlash(
        firstE3Id,
        op1,
        await signAndEncodeAttestation(
          [operator2, operator3],
          firstE3Id,
          op1,
          slashingAddress,
        ),
      );
      await time.increase(ONE_DAY + 1);
      await slashingManager.executeSlash(expelAId);

      // A's bucket exists on B and C even though A is no longer active.
      expect(await e3RefundManager.heldSlashFrom(firstE3Id, op2, op1)).to.equal(
        penalty / 2n,
      );

      // 3. B claims its 25. The claim zeroes heldSlash and must also drop
      //    the target=A bucket that backs it. Walking the active roster for
      //    bucket keys would miss A and leave the bucket describing funds
      //    that have already left.
      await e3RefundManager.claimOperatorSlashedFunds(firstE3Id, op2);
      const [, bHeld] = await e3RefundManager.operatorHeldRewards(
        firstE3Id,
        op2,
      );
      expect(bHeld).to.equal(0);
      expect(await e3RefundManager.heldSlashFrom(firstE3Id, op2, op1)).to.equal(
        0,
      );
      expect(
        await usdcToken.balanceOf(await e3RefundManager.getAddress()),
      ).to.be.gte(await e3RefundManager.tokenLiability(usdcAddress));
    });

    it("does not return a non-expelling ticket penalty to its target", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        requester,
        treasury,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await transferBondOwner(operator1, requester);
      await transferBondOwner(operator2, treasury);
      await makeRequest();
      await finalizeAndPublishCommittee();

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      const proposalId = await slashingManager.totalProposals();
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );
      await slashingManager.retrySlashRoute(proposalId);

      const token = await usdcToken.getAddress();
      const targetRecipient = await requester.getAddress();
      const operator2Recipient = await treasury.getAddress();
      const operator3Recipient = await computeProvider.getAddress();
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          token,
          targetRecipient,
        ),
      ).to.equal(0);
      const recipientClaims =
        (await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          token,
          operator2Recipient,
        )) +
        (await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          token,
          operator3Recipient,
        ));
      expect(recipientClaims).to.equal(ethers.parseUnits("50", 6));

      await e3RefundManager
        .connect(requester)
        .claimHonestNodeReward(firstE3Id, await operator1.getAddress());
    });

    it("holds an accused member's base reward and reallocates it after expulsion", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        requester,
        treasury,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await transferBondOwner(operator1, requester);
      await transferBondOwner(operator2, treasury);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_1, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const unrelatedProof = await signAndEncodeAttestation(
        [operator1, operator3],
        firstE3Id,
        await operator2.getAddress(),
        await slashingManager.getAddress(),
        1,
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator2.getAddress(),
        unrelatedProof,
      );

      await expect(
        e3RefundManager
          .connect(requester)
          .claimHonestNodeReward(firstE3Id, await operator1.getAddress()),
      ).to.be.revertedWithCustomError(
        e3RefundManager,
        "RewardPendingExpulsion",
      );

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      const perNode = distribution.perNodeAmount;
      await e3RefundManager
        .connect(treasury)
        .claimHonestNodeReward(firstE3Id, await operator2.getAddress());
      const treasuryBefore = await usdcToken.balanceOf(
        await treasury.getAddress(),
      );

      await slashingManager.executeSlash(0);

      await expect(
        e3RefundManager
          .connect(requester)
          .claimHonestNodeReward(firstE3Id, await operator1.getAddress()),
      ).to.be.revertedWithCustomError(e3RefundManager, "AlreadyClaimed");
      await e3RefundManager
        .connect(treasury)
        .claimHonestNodeReward(firstE3Id, await operator2.getAddress());
      const treasuryTopUp =
        (await usdcToken.balanceOf(await treasury.getAddress())) -
        treasuryBefore;
      expect(
        treasuryTopUp == perNode / 2n ||
          treasuryTopUp == perNode - perNode / 2n,
      ).to.equal(true);

      const token = await usdcToken.getAddress();
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          token,
          await requester.getAddress(),
        ),
      ).to.equal(0);
      const honestSlashClaims =
        (await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          token,
          await treasury.getAddress(),
        )) +
        (await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          token,
          await computeProvider.getAddress(),
        ));
      expect(honestSlashClaims).to.equal(ethers.parseUnits("100", 6));
    });

    it("reallocates an unclaimed base reward after a late expulsion", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        operator1,
        operator2,
        operator3,
        computeProvider,
        makeReadyRequest,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      await makeReadyRequest();
      await finalizeAndPublishCommittee();

      const deadlines = await interfold.getDeadlines(firstE3Id);
      await time.increaseTo(deadlines.computeDeadline + 1n);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const managerAddress = await slashingManager.getAddress();
      await networkHelpers.impersonateAccount(managerAddress);
      await networkHelpers.setBalance(managerAddress, ethers.parseEther("1"));
      const manager = await ethers.getSigner(managerAddress);
      await e3RefundManager
        .connect(manager)
        .openExpulsionProposal(firstE3Id, 99, await operator1.getAddress());
      await e3RefundManager
        .connect(manager)
        .resolveExpulsionProposal(firstE3Id, 99, true);
      await networkHelpers.stopImpersonatingAccount(managerAddress);

      await expect(
        e3RefundManager
          .connect(computeProvider)
          .claimHonestNodeReward(firstE3Id, await operator1.getAddress()),
      ).to.be.revertedWithCustomError(e3RefundManager, "AlreadyClaimed");

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      const balanceBefore = await usdcToken.balanceOf(computeProvider);
      await e3RefundManager
        .connect(computeProvider)
        .claimHonestNodeReward(firstE3Id, await operator2.getAddress());
      await e3RefundManager
        .connect(computeProvider)
        .claimHonestNodeReward(firstE3Id, await operator3.getAddress());
      expect(
        (await usdcToken.balanceOf(computeProvider)) - balanceBefore,
      ).to.equal(distribution.perNodeAmount * 3n);
    });

    it("releases a successful E3 reward when an expelling proposal is cleared", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await transferBondOwner(operator1, requester);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );
      await slashingManager.connect(operator1).fileAppeal(0, "not responsible");

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));
      const ciphertext = "0x" + "ab".repeat(100);
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertext,
        ethers.keccak256(ciphertext),
        "0x1337",
      );
      await interfold.publishPlaintextOutput(
        firstE3Id,
        "0x" + "cd".repeat(100),
        "0x1337",
      );

      const targetRecipient = await requester.getAddress();
      expect(
        await interfold.pendingReward(firstE3Id, targetRecipient),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingHeldSuccessReward(
          firstE3Id,
          targetRecipient,
        ),
      ).to.equal(0);

      await slashingManager.connect(owner).resolveAppeal(0, true, "cleared");
      const released = await e3RefundManager.pendingHeldSuccessReward(
        firstE3Id,
        targetRecipient,
      );
      expect(released).to.be.gt(0);
      const balanceBefore = await usdcToken.balanceOf(targetRecipient);
      await e3RefundManager
        .connect(requester)
        .claimHeldSuccessReward(firstE3Id);
      expect(
        (await usdcToken.balanceOf(targetRecipient)) - balanceBefore,
      ).to.equal(released);
    });

    it("ZEN2-04: an expulsion leaves a supplier-paid reason alone", async function () {
      const {
        interfold,
        registry,
        slashingManager,
        makeRequest,
        owner,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const proof1 = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof1,
      );
      const proof2 = await signAndEncodeAttestation(
        [operator1, operator3],
        firstE3Id,
        await operator2.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator2.getAddress(),
        proof2,
      );

      // The round fails for a reason the committee already pays for. The
      // expulsion that breaks viability must not rewrite it: only a
      // requester-paid reason may move onto the committee, and DKGTimeout
      // already charges the committee.
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(firstE3Id);
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        3 /* DKGTimeout */,
      );

      await time.increase(ONE_DAY + 1);
      await slashingManager.executeSlash(0);
      await expect(slashingManager.executeSlash(1)).to.not.emit(
        interfold,
        "E3FailureReclassified",
      );
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        3 /* DKGTimeout */,
      );
    });

    it("ZEN2-04: an expulsion corrects a front-run requester-paid reason", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        makeRequest,
        owner,
        operator1,
        operator2,
        operator3,
        setupOperator,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      // Two committee members face expulsions. Executing both drops the
      // active roster below the viability threshold M.
      const proof1 = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof1,
      );
      const proof2 = await signAndEncodeAttestation(
        [operator1, operator3],
        firstE3Id,
        await operator2.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator2.getAddress(),
        proof2,
      );

      // The member front-runs the slash and locks in the requester-paid
      // reason during the grace period.
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.connect(operator1).markE3Failed(firstE3Id);
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        6 /* ComputeTimeout */,
      );

      // Executing the expulsions corrects the payer before settlement. The
      // first keeps the committee viable; the second breaks viability.
      await time.increase(ONE_DAY + 1);
      await slashingManager.executeSlash(0);
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        6 /* ComputeTimeout */,
      );
      await expect(slashingManager.executeSlash(1))
        .to.emit(interfold, "E3FailureReclassified")
        .withArgs(
          firstE3Id,
          6 /* ComputeTimeout */,
          2 /* InsufficientCommitteeMembers */,
        );
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        2 /* InsufficientCommitteeMembers */,
      );
      // The stage stays terminal; only the payer moved.
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(6);

      // Settlement now refunds the requester in full instead of 45%.
      await interfold.processE3Failure(firstE3Id);
      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.requesterAmount).to.equal(
        distribution.originalPayment,
      );
      expect(distribution.honestNodeAmount).to.equal(0);
      expect(distribution.protocolAmount).to.equal(0);
    });

    it("ZEN2-04: settlement makes the recorded reason final", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        makeRequest,
        owner,
        operator1,
        operator2,
        operator3,
        setupOperator,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      const proof1 = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof1,
      );
      const proof2 = await signAndEncodeAttestation(
        [operator1, operator3],
        firstE3Id,
        await operator2.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator2.getAddress(),
        proof2,
      );

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.connect(operator1).markE3Failed(firstE3Id);
      // Settlement runs before the expulsions execute.
      await interfold.processE3Failure(firstE3Id);
      const settled = await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(settled.calculated).to.be.true;

      // The correction no longer applies, and the expulsion still executes so
      // the collateral penalty is not lost.
      await time.increase(ONE_DAY + 1);
      await slashingManager.executeSlash(0);
      await slashingManager.executeSlash(1);
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        6 /* ComputeTimeout */,
      );
      const after = await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(after.requesterAmount).to.equal(settled.requesterAmount);
      expect(after.honestNodeAmount).to.equal(settled.honestNodeAmount);
    });

    it("ZEN2-04: only the E3's slashing manager corrects a reason", async function () {
      const {
        interfold,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await makeRequest();
      await finalizeAndPublishCommittee();

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);

      // A failed E3 does not let an arbitrary caller move the payer.
      await expect(
        interfold
          .connect(requester)
          .onE3Failed(firstE3Id, 2 /* InsufficientCommitteeMembers */),
      ).to.be.revertedWithCustomError(
        interfold,
        "OnlyCiphernodeRegistryOrSlashingManager",
      );
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(
        6 /* ComputeTimeout */,
      );
    });

    it("ZEN2-20: a proposal opened after settlement holds a credited reward", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await transferBondOwner(operator1, requester);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      // The E3 completes with no proposal open, so the reward is credited.
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));
      const ciphertext = "0x" + "ab".repeat(100);
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertext,
        ethers.keccak256(ciphertext),
        "0x1337",
      );
      await interfold.publishPlaintextOutput(
        firstE3Id,
        "0x" + "cd".repeat(100),
        "0x1337",
      );

      const operator1Address = await operator1.getAddress();
      const targetRecipient = await requester.getAddress();
      const credited = await e3RefundManager.pendingHeldSuccessReward(
        firstE3Id,
        targetRecipient,
      );
      expect(credited).to.be.gt(0);

      // A valid expelling proposal opens AFTER completion.
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        operator1Address,
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(firstE3Id, operator1Address, proof);

      // The credited reward is now held: it reports zero and cannot be pulled
      // through any claim path.
      expect(
        await e3RefundManager.pendingHeldSuccessReward(
          firstE3Id,
          targetRecipient,
        ),
      ).to.equal(0);
      expect(
        await interfold.pendingReward(firstE3Id, targetRecipient),
      ).to.equal(0);
      const [, pending, excluded] = await e3RefundManager.rewardStatus(
        firstE3Id,
        operator1Address,
      );
      expect(pending).to.be.true;
      expect(excluded).to.be.false;

      await expect(
        e3RefundManager.connect(requester).claimHeldSuccessReward(firstE3Id),
      ).to.be.revertedWithCustomError(e3RefundManager, "NothingToClaim");
      await expect(
        interfold.connect(requester).claimReward(firstE3Id),
      ).to.be.revertedWithCustomError(interfold, "NothingToClaim");
      await expect(
        e3RefundManager.claimOperatorHeldSuccessReward(
          firstE3Id,
          operator1Address,
        ),
      )
        .to.be.revertedWithCustomError(
          e3RefundManager,
          "RewardPendingExpulsion",
        )
        .withArgs(firstE3Id, operator1Address);

      // Clearing the proposal releases exactly the original allocation.
      await slashingManager.connect(operator1).fileAppeal(0, "not responsible");
      await slashingManager.connect(owner).resolveAppeal(0, true, "cleared");
      expect(
        await e3RefundManager.pendingHeldSuccessReward(
          firstE3Id,
          targetRecipient,
        ),
      ).to.equal(credited);
      const balanceBefore = await usdcToken.balanceOf(targetRecipient);
      await e3RefundManager
        .connect(requester)
        .claimHeldSuccessReward(firstE3Id);
      expect(
        (await usdcToken.balanceOf(targetRecipient)) - balanceBefore,
      ).to.equal(credited);
    });

    it("ZEN2-20: an executed expulsion forfeits a credited reward", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        requester,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
        transferBondOwner,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await transferBondOwner(operator1, requester);
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));
      const ciphertext = "0x" + "ab".repeat(100);
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertext,
        ethers.keccak256(ciphertext),
        "0x1337",
      );
      await interfold.publishPlaintextOutput(
        firstE3Id,
        "0x" + "cd".repeat(100),
        "0x1337",
      );

      const operator1Address = await operator1.getAddress();
      const targetRecipient = await requester.getAddress();
      // The other two operators keep the fixture's shared bond owner.
      const operator2Recipient = await computeProvider.getAddress();
      const credited = await e3RefundManager.pendingHeldSuccessReward(
        firstE3Id,
        targetRecipient,
      );
      expect(credited).to.be.gt(0);
      const peersBefore = await e3RefundManager.pendingHeldSuccessReward(
        firstE3Id,
        operator2Recipient,
      );

      // Open and execute the expulsion after completion.
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        operator1Address,
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(firstE3Id, operator1Address, proof);
      await time.increase(ONE_DAY + 1);
      await slashingManager.executeSlash(0);

      const [, , excluded] = await e3RefundManager.rewardStatus(
        firstE3Id,
        operator1Address,
      );
      expect(excluded).to.be.true;

      // The forfeited allocation is unreachable and was reallocated to the
      // remaining eligible members, not left with the accused recipient.
      expect(
        await e3RefundManager.pendingHeldSuccessReward(
          firstE3Id,
          targetRecipient,
        ),
      ).to.equal(0);
      await expect(
        e3RefundManager.connect(requester).claimHeldSuccessReward(firstE3Id),
      ).to.be.revertedWithCustomError(e3RefundManager, "NothingToClaim");
      await expect(
        e3RefundManager.claimOperatorHeldSuccessReward(
          firstE3Id,
          operator1Address,
        ),
      ).to.be.revertedWithCustomError(
        e3RefundManager,
        "RewardPendingExpulsion",
      );
      expect(
        await e3RefundManager.pendingHeldSuccessReward(
          firstE3Id,
          operator2Recipient,
        ),
      ).to.be.gt(peersBefore);

      // Custody still covers what the contract says it owes.
      expect(
        await usdcToken.balanceOf(await e3RefundManager.getAddress()),
      ).to.be.gte(
        await e3RefundManager.tokenLiability(await usdcToken.getAddress()),
      );
    });

    it("ZEN2-20: a shared recipient keeps independent per-operator allocations", async function () {
      const {
        interfold,
        e3RefundManager,
        slashingManager,
        usdcToken,
        makeRequest,
        owner,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
        finalizeAndPublishCommittee,
      } = await loadFixture(setup);

      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await slashingManager.connect(owner).setSlashPolicy(REASON_PT_0, {
        ticketPenalty: ethers.parseUnits("50", 6),
        ciphernodeBondPenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: ONE_DAY,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest();
      await finalizeAndPublishCommittee();

      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));
      const ciphertext = "0x" + "ab".repeat(100);
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertext,
        ethers.keccak256(ciphertext),
        "0x1337",
      );
      await interfold.publishPlaintextOutput(
        firstE3Id,
        "0x" + "cd".repeat(100),
        "0x1337",
      );

      // All three operators share one bond owner in this fixture.
      const sharedRecipient = await computeProvider.getAddress();
      const operator1Address = await operator1.getAddress();
      for (const operator of [operator1, operator2, operator3]) {
        expect(
          await e3RefundManager.rewardRecipient(
            firstE3Id,
            await operator.getAddress(),
          ),
        ).to.equal(sharedRecipient);
      }
      const total = await e3RefundManager.pendingHeldSuccessReward(
        firstE3Id,
        sharedRecipient,
      );
      const [accusedShare] = await e3RefundManager.operatorHeldRewards(
        firstE3Id,
        operator1Address,
      );
      expect(accusedShare).to.be.gt(0);
      expect(total).to.be.gt(accusedShare);

      // A proposal against one operator must hold only that operator's share.
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        operator1Address,
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(firstE3Id, operator1Address, proof);

      expect(
        await e3RefundManager.pendingHeldSuccessReward(
          firstE3Id,
          sharedRecipient,
        ),
      ).to.equal(total - accusedShare);

      const balanceBefore = await usdcToken.balanceOf(sharedRecipient);
      await e3RefundManager
        .connect(computeProvider)
        .claimHeldSuccessReward(firstE3Id);
      expect(
        (await usdcToken.balanceOf(sharedRecipient)) - balanceBefore,
      ).to.equal(total - accusedShare);
      // The accused operator's share stays held, not paid with its peers.
      const [stillHeld] = await e3RefundManager.operatorHeldRewards(
        firstE3Id,
        operator1Address,
      );
      expect(stillHeld).to.equal(accusedShare);
    });

    it("routes failed-E3 slashes to treasury when no honest nodes exist", async function () {
      const {
        interfold,
        e3RefundManager,
        usdcToken,
        makeRequest,
        requester,
        treasury,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Fail at committee formation (no honest nodes, requester gets all escrow).
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const distributionBefore =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      const slashedAmount = ethers.parseUnits("100", 6);
      await usdcToken.mint(await e3RefundManager.getAddress(), slashedAmount);

      // Call from the Interfold frozen in the E3 policy snapshot. Rotating the
      // manager's live pointer must not grant settlement authority for old E3s.
      const originalInterfold = await e3RefundManager.interfold();
      await ethers.provider.send("hardhat_impersonateAccount", [
        originalInterfold,
      ]);
      await ethers.provider.send("hardhat_setBalance", [
        originalInterfold,
        "0x1000000000000000000",
      ]);
      await e3RefundManager
        .connect(await ethers.getSigner(originalInterfold))
        .escrowSlashedFunds(
          firstE3Id,
          100,
          await operator1.getAddress(),
          await usdcToken.getAddress(),
          slashedAmount,
        );
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [
        originalInterfold,
      ]);

      const distributionAfter =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      const tokenAddress = await usdcToken.getAddress();

      expect(distributionAfter.requesterAmount).to.equal(
        distributionBefore.originalPayment,
      );
      expect(distributionAfter.honestNodeAmount).to.equal(0);
      expect(distributionAfter.protocolAmount).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          tokenAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingTreasuryClaim(
          await treasury.getAddress(),
          tokenAddress,
        ),
      ).to.equal(slashedAmount);
      expect(await e3RefundManager.tokenLiability(tokenAddress)).to.equal(
        slashedAmount,
      );
    });

    it("credits every failed-E3 slash to honest nodes without requester compensation", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        usdcToken,
        makeRequest,
        requester,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest(requester);
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.requesterAmount).to.equal(
        distribution.originalPayment,
      );
      expect(distribution.honestNodeAmount).to.equal(0);
      const firstSlash = ethers.parseUnits("25", 6);
      const secondSlash = ethers.parseUnits("50", 6);
      const totalSlash = firstSlash + secondSlash;
      const refundManagerAddress = await e3RefundManager.getAddress();
      await usdcToken.mint(refundManagerAddress, totalSlash);

      const originalInterfold = await e3RefundManager.interfold();
      await ethers.provider.send("hardhat_impersonateAccount", [
        originalInterfold,
      ]);
      await ethers.provider.send("hardhat_setBalance", [
        originalInterfold,
        "0x1000000000000000000",
      ]);
      const interfoldSigner = await ethers.getSigner(originalInterfold);
      const usdcAddress = await usdcToken.getAddress();

      await e3RefundManager
        .connect(interfoldSigner)
        .escrowSlashedFunds(
          firstE3Id,
          100,
          await operator1.getAddress(),
          usdcAddress,
          firstSlash,
        );
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);

      await e3RefundManager
        .connect(interfoldSigner)
        .escrowSlashedFunds(
          firstE3Id,
          101,
          await operator2.getAddress(),
          usdcAddress,
          secondSlash,
        );
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [
        originalInterfold,
      ]);

      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);

      const honestSlashClaims = await e3RefundManager.pendingSlashedClaim(
        firstE3Id,
        usdcAddress,
        await computeProvider.getAddress(),
      );
      expect(honestSlashClaims).to.equal(totalSlash);
      expect(
        (await e3RefundManager.getRefundDistribution(firstE3Id)).totalSlashed,
      ).to.equal(totalSlash);
    });

    it("queues slashed funds arriving before processE3Failure and applies on calculate", async function () {
      const {
        interfold,
        e3RefundManager,
        usdcToken,
        makeRequest,
        requester,
        treasury,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Fail E3 but DON'T call processE3Failure yet
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);

      const slashedAmount = ethers.parseUnits("50", 6);
      await usdcToken.mint(await e3RefundManager.getAddress(), slashedAmount);

      // Escrow slashed funds BEFORE processE3Failure — should be queued
      const originalInterfold = await e3RefundManager.interfold();
      await ethers.provider.send("hardhat_impersonateAccount", [
        originalInterfold,
      ]);
      await ethers.provider.send("hardhat_setBalance", [
        originalInterfold,
        "0x1000000000000000000",
      ]);
      await e3RefundManager
        .connect(await ethers.getSigner(originalInterfold))
        .escrowSlashedFunds(
          firstE3Id,
          100,
          await operator1.getAddress(),
          await usdcToken.getAddress(),
          slashedAmount,
        );
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [
        originalInterfold,
      ]);

      // Distribution should not exist yet
      const distBefore = await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distBefore.calculated).to.be.false;

      // Process the failure, then settle the proposal-scoped route.
      await interfold.processE3Failure(firstE3Id);
      await e3RefundManager.settleSlashedFunds(firstE3Id, 100);

      const distAfter = await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distAfter.calculated).to.be.true;
      const usdcAddress = await usdcToken.getAddress();
      expect(
        await e3RefundManager.pendingSlashedFunds(firstE3Id, usdcAddress),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          firstE3Id,
          usdcAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingTreasuryClaim(
          await treasury.getAddress(),
          usdcAddress,
        ),
      ).to.equal(slashedAmount);
    });
  });

  describe("Failure Claim Roles and DKG Timeout", function () {
    it("AUD-M02: a requester who is also a node can claim both requester-fault allocations", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        usdcToken,
        makeRequest,
        computeProvider,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      await usdcToken.mint(
        await operator1.getAddress(),
        ethers.parseUnits("10000", 6),
      );
      await makeRequest(operator1);

      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(firstE3Id);
      await interfold.processE3Failure(firstE3Id);

      await e3RefundManager.connect(operator1).claimRequesterRefund(firstE3Id);
      expect(
        await e3RefundManager.hasRequesterClaimed(
          firstE3Id,
          await operator1.getAddress(),
        ),
      ).to.equal(true);
      expect(
        await e3RefundManager.hasHonestNodeClaimed(
          firstE3Id,
          await operator1.getAddress(),
        ),
      ).to.equal(false);

      await e3RefundManager
        .connect(computeProvider)
        .claimHonestNodeReward(firstE3Id, await operator1.getAddress());
      expect(
        await e3RefundManager.hasHonestNodeClaimed(
          firstE3Id,
          await operator1.getAddress(),
        ),
      ).to.equal(true);
    });

    it("complete flow: request -> committee formed -> DKG timeout -> fail -> process -> claim", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        usdcToken,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Make request
      await makeRequest();
      let stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(1); // Requested

      // 2. Complete sortition (committee finalized, DKG starts)
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(2); // CommitteeFinalized

      // 3. Fast forward past DKG deadline (key never published - simulating DKG failure)
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);

      // 4. Check failure condition and mark as failed
      const [canFail, reason] =
        await interfold.checkFailureCondition(firstE3Id);
      expect(canFail).to.be.true;
      expect(reason).to.equal(3); // DKGTimeout

      await interfold.markE3Failed(firstE3Id);
      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(6); // Failed

      const failureReason = await interfold.getFailureReason(firstE3Id);
      expect(failureReason).to.equal(3); // DKGTimeout

      // 5. Process failure and claim refund
      await interfold.processE3Failure(firstE3Id);

      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.requesterAmount).to.equal(
        distribution.originalPayment,
      );
      expect(distribution.honestNodeAmount).to.equal(0);
      expect(distribution.protocolAmount).to.equal(0);
      expect(balanceAfter - balanceBefore).to.equal(
        distribution.requesterAmount,
      );
    });
  });

  describe("Full Failure Flow - Compute Timeout", function () {
    it("complete flow: request -> activated -> compute timeout -> fail -> process -> claim", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        usdcToken,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Make request
      await makeRequest();
      let stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(1); // Requested

      // 2. Complete sortition and DKG
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(3); // KeyPublished

      // 3. Wait past compute deadline (ciphertext never published)
      const e3 = await interfold.getE3(firstE3Id);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);

      // 4. Check failure condition and mark as failed
      const [canFail, reason] =
        await interfold.checkFailureCondition(firstE3Id);
      expect(canFail).to.be.true;
      expect(reason).to.equal(6); // ComputeTimeout

      await interfold.markE3Failed(firstE3Id);
      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(6); // Failed

      const failureReason = await interfold.getFailureReason(firstE3Id);
      expect(failureReason).to.equal(6); // ComputeTimeout

      // 5. Process and claim
      await interfold.processE3Failure(firstE3Id);

      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.requesterAmount).to.equal(
        (distribution.originalPayment * 4500n) / 10000n,
      );
      expect(distribution.honestNodeAmount).to.equal(
        (distribution.originalPayment * 5000n) / 10000n,
      );
      expect(distribution.protocolAmount).to.equal(
        distribution.originalPayment -
          distribution.requesterAmount -
          distribution.honestNodeAmount,
      );
      expect(balanceAfter - balanceBefore).to.equal(
        distribution.requesterAmount,
      );
    });
  });

  describe("Full Failure Flow - Decryption Timeout", function () {
    it("complete flow: request -> ciphertext published -> decryption timeout -> fail -> process -> claim", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        usdcToken,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Make request
      await makeRequest();
      let stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(1); // Requested

      // 2. Complete sortition and DKG
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(3); // KeyPublished

      // 3. Publish ciphertext output
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proof,
      );
      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(4); // CiphertextReady

      // 4. Wait past decryption deadline (plaintext never published)
      await time.increase(defaultTimeoutConfig.decryptionWindow + 1);

      // 5. Check failure condition and mark as failed
      const [canFail, reason] =
        await interfold.checkFailureCondition(firstE3Id);
      expect(canFail).to.be.true;
      expect(reason).to.equal(10); // DecryptionTimeout

      await interfold.markE3Failed(firstE3Id);
      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(6); // Failed

      const failureReason = await interfold.getFailureReason(firstE3Id);
      expect(failureReason).to.equal(10); // DecryptionTimeout

      // 6. Process failure and claim refund
      await interfold.processE3Failure(firstE3Id);

      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      const distribution =
        await e3RefundManager.getRefundDistribution(firstE3Id);
      expect(distribution.requesterAmount).to.equal(
        distribution.originalPayment,
      );
      expect(distribution.honestNodeAmount).to.equal(0);
      expect(distribution.protocolAmount).to.equal(0);
      expect(balanceAfter - balanceBefore).to.equal(
        distribution.requesterAmount,
      );
    });
  });

  describe("Multiple E3 Requests Isolation", function () {
    it("tracks multiple E3s independently", async function () {
      const {
        interfold,
        usdcToken,
        requester,
        e3Program,
        decryptionVerifier,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      const interfoldAddress = await interfold.getAddress();

      // Helper to make requests
      const makeRequestN = async (n: number) => {
        const startTime = (await time.latest()) + 100;
        const requestParams = {
          committeeSize: 0,
          inputWindow: [startTime, startTime + ONE_DAY] as [number, number],
          e3Program: await e3Program.getAddress(),
          paramSet: 0,
          computeProviderParams: abiCoder.encode(
            ["address"],
            [await decryptionVerifier.getAddress()],
          ),
          customParams: abiCoder.encode(
            ["address"],
            ["0x1234567890123456789012345678901234567890"],
          ),
          expectedFeeToken: await usdcToken.getAddress(),
          expectedCryptoConfigId: ACTIVE_CRYPTO_CONFIG_ID,
          maxFee: ethers.MaxUint256,
        };
        const fee = await interfold.getE3Quote(requestParams);
        await usdcToken.connect(requester).approve(interfoldAddress, fee);
        await interfold.connect(requester).request(requestParams);
        return n;
      };

      // Make 3 requests
      await makeRequestN(0);
      await makeRequestN(1);
      await makeRequestN(2);

      // Verify all are in Requested stage
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(1);
      expect(await interfold.getE3Stage(firstE3Id + 1n)).to.equal(1);
      expect(await interfold.getE3Stage(firstE3Id + 2n)).to.equal(1);

      // Fail E3 #0 by waiting past its deadline
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);

      // E3 #0 is failed, but E3 #1 and #2 are still active
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(6); // Failed
      expect(await interfold.getE3Stage(firstE3Id + 1n)).to.equal(1); // Still Requested
      expect(await interfold.getE3Stage(firstE3Id + 2n)).to.equal(1); // Still Requested

      // E3 #1 and #2 also can be failed now (their deadlines have also passed)
      const [canFail1] = await interfold.checkFailureCondition(firstE3Id + 1n);
      const [canFail2] = await interfold.checkFailureCondition(firstE3Id + 2n);
      expect(canFail1).to.be.true;
      expect(canFail2).to.be.true;

      // But they haven't auto-failed - must be explicitly marked
      expect(await interfold.getE3Stage(firstE3Id + 1n)).to.equal(1);
      expect(await interfold.getE3Stage(firstE3Id + 2n)).to.equal(1);

      // Now mark E3 #2 as failed (but not #1)
      await interfold.markE3Failed(firstE3Id + 2n);
      expect(await interfold.getE3Stage(firstE3Id + 2n)).to.equal(6); // Now Failed
      expect(await interfold.getE3Stage(firstE3Id + 1n)).to.equal(1); // Still Requested

      // Verify each E3 has independent failure reasons
      expect(await interfold.getFailureReason(firstE3Id)).to.equal(1); // CommitteeFormationTimeout
      expect(await interfold.getFailureReason(firstE3Id + 2n)).to.equal(1); // CommitteeFormationTimeout
    });

    it("allows claiming refunds for each failed E3 independently", async function () {
      const {
        interfold,
        e3RefundManager,
        usdcToken,
        requester,
        e3Program,
        decryptionVerifier,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      const interfoldAddress = await interfold.getAddress();

      // Make 2 requests
      for (let i = 0; i < 2; i++) {
        const startTime = (await time.latest()) + 100;
        const requestParams = {
          committeeSize: 0,
          inputWindow: [startTime, startTime + ONE_DAY] as [number, number],
          e3Program: await e3Program.getAddress(),
          paramSet: 0,
          computeProviderParams: abiCoder.encode(
            ["address"],
            [await decryptionVerifier.getAddress()],
          ),
          customParams: abiCoder.encode(
            ["address"],
            ["0x1234567890123456789012345678901234567890"],
          ),
          expectedFeeToken: await usdcToken.getAddress(),
          expectedCryptoConfigId: ACTIVE_CRYPTO_CONFIG_ID,
          maxFee: ethers.MaxUint256,
        };
        const fee = await interfold.getE3Quote(requestParams);
        await usdcToken.connect(requester).approve(interfoldAddress, fee);
        await interfold.connect(requester).request(requestParams);
      }

      // Fail both
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(firstE3Id);
      await interfold.markE3Failed(firstE3Id + 1n);

      // Process both
      await interfold.processE3Failure(firstE3Id);
      await interfold.processE3Failure(firstE3Id + 1n);

      // Claim both refunds independently
      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      await e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id);
      const balanceAfterFirst = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(balanceAfterFirst).to.be.gt(balanceBefore);

      await e3RefundManager
        .connect(requester)
        .claimRequesterRefund(firstE3Id + 1n);
      const balanceAfterSecond = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(balanceAfterSecond).to.be.gt(balanceAfterFirst);

      // Verify can't claim twice
      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id),
      ).to.be.revertedWithCustomError(e3RefundManager, "AlreadyClaimed");
    });
  });

  describe("Success Path (Complete E3)", function () {
    it("distributes escrowed slashed funds to nodes and treasury on successful completion", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        slashingManager,
        usdcToken,
        makeRequest,
        operator1,
        operator2,
        operator3,
        treasury,
        computeProvider,
        owner,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Request E3, form committee, publish key
      await makeRequest(undefined, 0);
      // Governance changes after request must not alter this E3's success
      // allocation or redirect its treasury share.
      await e3RefundManager.connect(owner).setWorkAllocation({
        committeeFormationBps: 1000,
        dkgBps: 3000,
        decryptionBps: 5500,
        protocolBps: 500,
        successSlashedNodeBps: 1000,
      });
      await e3RefundManager
        .connect(owner)
        .setTreasury(await computeProvider.getAddress());
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      expect(await interfold.getE3Stage(firstE3Id)).to.equal(3); // KeyPublished

      // 2. Slash operator1 during active E3 (before completion)
      //    With the stage-check removed, this should escrow funds in E3RefundManager
      const refundManagerAddress = await e3RefundManager.getAddress();
      const refundBalanceBefore =
        await usdcToken.balanceOf(refundManagerAddress);

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );

      // Verify USDC moved to refund manager (escrowed)
      const refundBalanceAfter =
        await usdcToken.balanceOf(refundManagerAddress);
      const actualSlashedAmount = refundBalanceAfter - refundBalanceBefore;
      expect(actualSlashedAmount).to.be.gt(0);

      // 3. Complete the E3 successfully: publish ciphertext → publish plaintext
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proofBytes = "0x1337";
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proofBytes,
      );
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(4); // CiphertextReady

      // Record the E3 payment (normal rewards) before completion zeroes it
      const e3Payment = await interfold.e3Payments(firstE3Id);

      // Record balances before plaintext publish (which triggers pull credits).
      const treasuryAddress = await treasury.getAddress();
      const treasuryBalanceBefore = await usdcToken.balanceOf(treasuryAddress);
      const bondOwnerAddress = await computeProvider.getAddress();
      const bondOwnerBalanceBefore =
        await usdcToken.balanceOf(bondOwnerAddress);

      const plaintextOutput = "0x" + "cd".repeat(100);
      await interfold.publishPlaintextOutput(
        firstE3Id,
        plaintextOutput,
        proofBytes,
      );
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(5); // Complete
      await e3RefundManager.settleSlashedFunds(firstE3Id, 0);

      // 4. Verify escrowed slashed funds were distributed
      //    50% to honest nodes (split equally), 50% to treasury
      const expectedSlashedToNodes =
        (actualSlashedAmount * BigInt(5000)) / BigInt(10000);
      const expectedSlashedToTreasury =
        actualSlashedAmount - expectedSlashedToNodes;

      const treasuryBalanceAfter = await usdcToken.balanceOf(treasuryAddress);

      // Treasury & honest-node slashed-share are pull-payments (M-02 / H-01):
      // the dispatch only credits internal pull-pools; nobody received tokens
      // synchronously at `publishPlaintextOutput` for the slashed portion.
      expect(treasuryBalanceAfter - treasuryBalanceBefore).to.equal(0);

      // Treasury claims its slashed-funds protocol share.
      const usdcAddress = await usdcToken.getAddress();
      const pendingTreasury = await e3RefundManager.pendingTreasuryClaim(
        treasuryAddress,
        usdcAddress,
      );
      expect(pendingTreasury).to.equal(expectedSlashedToTreasury);
      await e3RefundManager.connect(treasury).treasuryClaim(usdcAddress);
      const treasuryBalanceClaimed = await usdcToken.balanceOf(treasuryAddress);
      expect(treasuryBalanceClaimed - treasuryBalanceBefore).to.equal(
        expectedSlashedToTreasury,
      );

      // Normal rewards and slashed-fund rewards are both owner-routed pull
      // payments. This test claims only the slashed-fund share.
      void e3Payment;

      await e3RefundManager
        .connect(computeProvider)
        .claimSlashedFunds(firstE3Id, usdcAddress);
      const slashedClaimedTotal =
        (await usdcToken.balanceOf(bondOwnerAddress)) - bondOwnerBalanceBefore;
      expect(slashedClaimedTotal).to.equal(expectedSlashedToNodes);

      // Verify refund manager escrowed balance was drained
      const refundBalanceFinal =
        await usdcToken.balanceOf(refundManagerAddress);
      expect(refundBalanceFinal).to.be.lt(refundBalanceAfter);
    });

    it("transitions through all stages to completion", async function () {
      const {
        interfold,
        registry,
        makeRequest,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Make request
      await makeRequest();
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(1); // Requested

      // 2. Complete sortition and publish committee (CommitteeFinalized -> KeyPublished)
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      expect(await interfold.getE3Stage(firstE3Id)).to.equal(2); // CommitteeFinalized

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      expect(await interfold.getE3Stage(firstE3Id)).to.equal(3); // KeyPublished

      // 3. Publish ciphertext output (after input deadline)
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proof,
      );
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(4); // CiphertextReady

      // 4. Publish plaintext output
      const plaintextOutput = "0x" + "cd".repeat(100);
      await interfold.publishPlaintextOutput(firstE3Id, plaintextOutput, proof);
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(5); // Complete

      // Cannot mark completed E3 as failed
      await expect(
        interfold.markE3Failed(firstE3Id),
      ).to.be.revertedWithCustomError(interfold, "E3AlreadyComplete");
    });

    it("prevents refund claims for completed E3", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        makeRequest,
        requester,
        operator1,
        operator2,
        operator3,
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // Complete full E3 flow
      await makeRequest();

      // Complete sortition
      await registry.connect(operator1).submitTicket(firstE3Id, 1);
      await registry.connect(operator2).submitTicket(firstE3Id, 1);
      await registry.connect(operator3).submitTicket(firstE3Id, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(firstE3Id);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        firstE3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      // Publish outputs
      const e3 = await interfold.getE3(firstE3Id);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proof,
      );

      const plaintextOutput = "0x" + "cd".repeat(100);
      await interfold.publishPlaintextOutput(firstE3Id, plaintextOutput, proof);

      // Verify E3 is complete
      expect(await interfold.getE3Stage(firstE3Id)).to.equal(5); // Complete

      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(firstE3Id),
      ).to.be.revertedWithCustomError(e3RefundManager, "RefundNotCalculated");
    });
  });
});
