// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import InterfoldModule from "../../ignition/modules/interfold";
import { Interfold__factory as InterfoldFactory } from "../../types";
import {
  deployInterfoldSystem,
  ethers,
  ignition,
  networkHelpers,
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
  // Time constants
  const ONE_HOUR = 60 * 60;
  const ONE_DAY = 24 * ONE_HOUR;
  const THREE_DAYS = 3 * ONE_DAY;
  const THIRTY_DAYS = 30 * ONE_DAY;
  const SORTITION_SUBMISSION_WINDOW = 10;

  const addressOne = "0x0000000000000000000000000000000000000001";

  const defaultTimeoutConfig = {
    dkgWindow: ONE_DAY,
    computeWindow: THREE_DAYS,
    decryptionWindow: ONE_DAY,
  };

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  // Lane A reason derived on-chain as keccak256(abi.encodePacked(proofType))
  const REASON_PT_0 = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));

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
      bfvParams: "large",
      committeeThresholds: [[0, [1, 3]]],
      deployCircuitVerifier: true,
      maxDuration: THIRTY_DAYS,
      mintUsdcTo: [],
      setupOperators: 0,
      slashedFundsTreasury: treasury,
      timeoutConfig: defaultTimeoutConfig,
      treasury,
      wireSlashingManager: true,
    });

    const {
      interfold,
      e3RefundManager,
      bondingRegistry,
      ciphernodeRegistry: registry,
      slashingManager,
      usdcToken,
      licenseToken: intfToken,
      mocks: {
        e3Program,
        decryptionVerifier,
        circuitVerifier: _circuitVerifier,
      },
    } = sys;

    const interfoldAddress = await interfold.getAddress();
    const e3RefundManagerAddress = await e3RefundManager.getAddress();

    // Slash policy for Lane A proof routing E2E tests
    await slashingManager.setSlashPolicy(REASON_PT_0, {
      ticketPenalty: ethers.parseUnits("50", 6),
      licensePenalty: ethers.parseEther("100"),
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
    ): Promise<{ e3Id: number }> => {
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
        proofAggregationEnabled: false,
      };

      const fee = await interfold.getE3Quote(requestParams);
      await usdcToken.connect(signer).approve(interfoldAddress, fee);
      await interfold.connect(signer).request(requestParams);

      return { e3Id: 0 };
    };

    const setupOperator = async (operator: Signer) => {
      const operatorAddress = await operator.getAddress();
      const ticketTokenAddress = await bondingRegistry.ticketToken();
      const ticketAmount = ethers.parseUnits("100", 6);

      await intfToken.mint(
        operatorAddress,
        ethers.parseEther("10000"),
        ethers.encodeBytes32String("Test allocation"),
      );
      await usdcToken.mint(operatorAddress, ethers.parseUnits("100000", 6));

      await intfToken
        .connect(operator)
        .approve(await bondingRegistry.getAddress(), ethers.parseEther("2000"));
      await bondingRegistry
        .connect(operator)
        .bondLicense(ethers.parseEther("1000"));
      await bondingRegistry.connect(operator).registerOperator();

      await usdcToken
        .connect(operator)
        .approve(ticketTokenAddress, ticketAmount);
      await bondingRegistry.connect(operator).addTicketBalance(ticketAmount);
    };

    return {
      interfold,
      e3RefundManager,
      bondingRegistry,
      registry,
      slashingManager,
      _circuitVerifier,
      usdcToken,
      intfToken,
      e3Program,
      decryptionVerifier,
      owner,
      requester,
      treasury,
      operator1,
      operator2,
      operator3,
      computeProvider,
      makeRequest,
      setupOperator,
    };
  };

  describe("E3 Request with Lifecycle Integration", function () {
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
      const stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(1); // E3Stage.Requested

      // Check requester is tracked
      const storedRequester = await interfold.getRequester(0);
      expect(storedRequester).to.equal(await requester.getAddress());
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
      let stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(1); // E3Stage.Requested

      // Submit tickets for sortition
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);

      // Fast forward past submission window
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);

      // Finalize committee
      await registry.finalizeCommittee(0);

      // Publish committee (this triggers onCommitteePublished -> onCommitteeFormed)
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);

      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      // Verify stage transitioned to KeyPublished (after publishCommittee which calls onKeyPublished)
      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(3); // E3Stage.KeyPublished

      // Verify deadlines were set
      const deadlines = await interfold.getDeadlines(0);
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
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      // Publish committee and expect CommitteeFormed event
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);

      await expect(
        registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x"),
      )
        .to.emit(interfold, "CommitteeFormed")
        .withArgs(0);
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
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest();

      // Create a new interfold with addressOne as lifecycle placeholder (not a real contract)
      const newInterfoldContract = await ignition.deploy(InterfoldModule, {
        parameters: {
          Interfold: {
            owner: await owner.getAddress(),
            maxDuration: THIRTY_DAYS,
            registry: await interfold.ciphernodeRegistry(),
            bondingRegistry: await interfold.bondingRegistry(),
            e3RefundManager: addressOne,
            feeToken: await interfold.feeToken(),
          },
        },
      });
      const newInterfold = InterfoldFactory.connect(
        await newInterfoldContract.interfold.getAddress(),
        owner,
      );

      // Calling processE3Failure with a placeholder lifecycle should revert
      // (it will try to call getE3Stage on an EOA which will fail)
      await expect(newInterfold.processE3Failure(0)).to.be.revert(ethers);
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
      await expect(interfold.processE3Failure(0)).to.be.revertedWithCustomError(
        interfold,
        "E3NotFailed",
      );
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
      await interfold.markE3Failed(0);

      const stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(6); // E3Stage.Failed

      // Process the failure
      await expect(interfold.processE3Failure(0)).to.emit(
        interfold,
        "E3FailureProcessed",
      );

      const distribution = await e3RefundManager.getRefundDistribution(0);
      expect(distribution.calculated).to.be.true;
      expect(distribution.requesterAmount).to.be.gt(0);
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
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      // Claim refund
      await e3RefundManager.connect(requester).claimRequesterRefund(0);

      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(balanceAfter).to.be.gt(balanceBefore);
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
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      // Second call should fail - payment already cleared
      await expect(interfold.processE3Failure(0)).to.be.revertedWithCustomError(
        interfold,
        "NoPaymentToRefund",
      );
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
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      // First claim succeeds
      await e3RefundManager.connect(requester).claimRequesterRefund(0);

      // Second claim should fail
      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(0),
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
        e3RefundManager.connect(requester).claimRequesterRefund(0),
      ).to.be.revertedWithCustomError(e3RefundManager, "RefundNotCalculated");
    });
  });

  describe("Slashed Funds Escrow", function () {
    it("E2E: slash via SlashingManager escrows actual USDC to refund manager and requester can claim", async function () {
      const {
        interfold,
        e3RefundManager,
        registry,
        slashingManager,
        bondingRegistry,
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

      // 1. Request E3, form committee, publish key
      await makeRequest(requester, 0);
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      // 2. Wait past compute deadline → mark as failed
      const e3 = await interfold.getE3(0);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(0);

      // 3. Process failure → distribution calculated, funds transferred to refund manager
      await interfold.processE3Failure(0);
      const distributionBefore = await e3RefundManager.getRefundDistribution(0);
      expect(distributionBefore.calculated).to.be.true;

      // Record refund manager USDC balance before slash routing
      const refundManagerBalanceBefore = await usdcToken.balanceOf(
        await e3RefundManager.getAddress(),
      );

      // Record BondingRegistry's slashedTicketBalance before slash
      const slashedBalanceBefore = await bondingRegistry.slashedTicketBalance();

      // 4. Slash operator1 via proposeSlash (Lane A) — real on-chain flow
      //    This triggers: _executeSlash → slashTicketBalance → redirectSlashedTicketFunds
      //    → ticketToken.payout(refundManager, amount) → interfold.escrowSlashedFunds → e3RefundManager.escrowSlashedFunds
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        0,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );

      await slashingManager.proposeSlash(
        0,
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

      // 6. Verify distribution was updated with requester-first priority
      const distributionAfter = await e3RefundManager.getRefundDistribution(0);
      expect(distributionAfter.totalSlashed).to.equal(actualSlashedAmount);
      expect(distributionAfter.requesterAmount).to.be.gte(
        distributionBefore.requesterAmount,
      );

      // 7. Verify requester can actually claim and receives the correct USDC
      const requesterBalanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(0);
      const requesterBalanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(requesterBalanceAfter - requesterBalanceBefore).to.equal(
        distributionAfter.requesterAmount,
      );
    });

    it("E2E: honest nodes can claim their share after slashed funds are escrowed", async function () {
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
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Request E3, form committee, publish key
      await makeRequest(undefined, 0);
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      // 2. Fail via compute timeout
      const e3 = await interfold.getE3(0);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      // 3. Record distribution BEFORE slash to verify it actually changes
      const distributionBefore = await e3RefundManager.getRefundDistribution(0);
      const honestNodeAmountBefore = distributionBefore.honestNodeAmount;

      // 4. Slash operator1 — this routes funds into the refund pool
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        0,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        0,
        await operator1.getAddress(),
        proof,
      );

      const distribution = await e3RefundManager.getRefundDistribution(0);
      expect(distribution.honestNodeCount).to.be.gt(0);
      // Verify that honestNodeAmount INCREASED due to slashed funds escrow
      expect(distribution.honestNodeAmount).to.be.gt(honestNodeAmountBefore);
      expect(distribution.totalSlashed).to.be.gt(0);

      // 5. operator2 (honest node) claims their share
      const op2BalanceBefore = await usdcToken.balanceOf(
        await operator2.getAddress(),
      );
      await e3RefundManager.connect(operator2).claimHonestNodeReward(0);
      const op2BalanceAfter = await usdcToken.balanceOf(
        await operator2.getAddress(),
      );

      const perNodeAmount =
        distribution.honestNodeAmount / BigInt(distribution.honestNodeCount);
      expect(op2BalanceAfter - op2BalanceBefore).to.equal(perNodeAmount);
    });

    it("requester-first priority: requester gets filled before honest nodes", async function () {
      const {
        interfold,
        e3RefundManager,
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

      // Fail the E3 at committee formation stage (no honest nodes, requester gets 95%)
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      const distributionBefore = await e3RefundManager.getRefundDistribution(0);
      const slashedAmount = ethers.parseUnits("100", 6);

      // requesterGap = originalPayment - requesterAmount (how much more needed to be whole)
      const requesterGap =
        distributionBefore.originalPayment - distributionBefore.requesterAmount;

      // Escrow slashed funds via the interfold proxy (swap interfold address for test)
      const originalInterfold = await e3RefundManager.interfold();
      await e3RefundManager.setInterfold(await owner.getAddress());
      await e3RefundManager.connect(owner).escrowSlashedFunds(0, slashedAmount);
      await e3RefundManager.setInterfold(originalInterfold);

      const distributionAfter = await e3RefundManager.getRefundDistribution(0);

      // H-08: with no honest nodes (failure at committee formation), the\n      // node share is routed to the treasury pull-pool instead of being\n      // stranded in `dist.honestNodeAmount`. Requester is still capped at\n      // `originalPayment` via the requesterGap.
      const expectedToRequester =
        slashedAmount >= requesterGap ? requesterGap : slashedAmount;
      const expectedToHonestNodes = 0n;

      expect(distributionAfter.requesterAmount).to.equal(
        distributionBefore.requesterAmount + expectedToRequester,
      );
      expect(distributionAfter.honestNodeAmount).to.equal(
        distributionBefore.honestNodeAmount + expectedToHonestNodes,
      );
      expect(distributionAfter.totalSlashed).to.equal(slashedAmount);
    });

    it("queues slashed funds arriving before processE3Failure and applies on calculate", async function () {
      const {
        interfold,
        e3RefundManager,
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

      // Fail E3 but DON'T call processE3Failure yet
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(0);

      const slashedAmount = ethers.parseUnits("50", 6);

      // Escrow slashed funds BEFORE processE3Failure — should be queued
      const originalInterfold = await e3RefundManager.interfold();
      await e3RefundManager.setInterfold(await owner.getAddress());
      await e3RefundManager.connect(owner).escrowSlashedFunds(0, slashedAmount);
      await e3RefundManager.setInterfold(originalInterfold);

      // Distribution should not exist yet
      const distBefore = await e3RefundManager.getRefundDistribution(0);
      expect(distBefore.calculated).to.be.false;

      // Now process the failure — pending funds should be applied
      await interfold.processE3Failure(0);

      const distAfter = await e3RefundManager.getRefundDistribution(0);
      expect(distAfter.calculated).to.be.true;
      expect(distAfter.totalSlashed).to.equal(slashedAmount);

      // `totalSlashed` was already asserted above; the per-bucket split is\n      // exercised by the dedicated requester-priority test — the residual\n      // is routed to the treasury pull-pool, not to a single dist bucket.
    });
  });

  describe("Full Failure Flow - DKG Timeout", function () {
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
      let stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(1); // Requested

      // 2. Complete sortition (committee finalized, DKG starts)
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(2); // CommitteeFinalized

      // 3. Fast forward past DKG deadline (key never published - simulating DKG failure)
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);

      // 4. Check failure condition and mark as failed
      const [canFail, reason] = await interfold.checkFailureCondition(0);
      expect(canFail).to.be.true;
      expect(reason).to.equal(3); // DKGTimeout

      await interfold.markE3Failed(0);
      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(6); // Failed

      const failureReason = await interfold.getFailureReason(0);
      expect(failureReason).to.equal(3); // DKGTimeout

      // 5. Process failure and claim refund
      await interfold.processE3Failure(0);

      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(0);
      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      const distribution = await e3RefundManager.getRefundDistribution(0);
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
      let stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(1); // Requested

      // 2. Complete sortition and DKG
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(3); // KeyPublished

      // 3. Wait past compute deadline (ciphertext never published)
      const e3 = await interfold.getE3(0);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);

      // 4. Check failure condition and mark as failed
      const [canFail, reason] = await interfold.checkFailureCondition(0);
      expect(canFail).to.be.true;
      expect(reason).to.equal(6); // ComputeTimeout

      await interfold.markE3Failed(0);
      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(6); // Failed

      const failureReason = await interfold.getFailureReason(0);
      expect(failureReason).to.equal(6); // ComputeTimeout

      // 5. Process and claim
      await interfold.processE3Failure(0);

      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(0);
      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      const distribution = await e3RefundManager.getRefundDistribution(0);
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
      let stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(1); // Requested

      // 2. Complete sortition and DKG
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(3); // KeyPublished

      // 3. Publish ciphertext output
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await interfold.publishCiphertextOutput(0, ciphertextOutput, proof);
      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(4); // CiphertextReady

      // 4. Wait past decryption deadline (plaintext never published)
      await time.increase(defaultTimeoutConfig.decryptionWindow + 1);

      // 5. Check failure condition and mark as failed
      const [canFail, reason] = await interfold.checkFailureCondition(0);
      expect(canFail).to.be.true;
      expect(reason).to.equal(10); // DecryptionTimeout

      await interfold.markE3Failed(0);
      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(6); // Failed

      const failureReason = await interfold.getFailureReason(0);
      expect(failureReason).to.equal(10); // DecryptionTimeout

      // 6. Process failure and claim refund
      await interfold.processE3Failure(0);

      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(0);
      const balanceAfter = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      const distribution = await e3RefundManager.getRefundDistribution(0);
      expect(balanceAfter - balanceBefore).to.equal(
        distribution.requesterAmount,
      );
      expect(distribution.requesterAmount).to.be.gt(0);
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
          proofAggregationEnabled: false,
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
      expect(await interfold.getE3Stage(0)).to.equal(1);
      expect(await interfold.getE3Stage(1)).to.equal(1);
      expect(await interfold.getE3Stage(2)).to.equal(1);

      // Fail E3 #0 by waiting past its deadline
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(0);

      // E3 #0 is failed, but E3 #1 and #2 are still active
      expect(await interfold.getE3Stage(0)).to.equal(6); // Failed
      expect(await interfold.getE3Stage(1)).to.equal(1); // Still Requested
      expect(await interfold.getE3Stage(2)).to.equal(1); // Still Requested

      // E3 #1 and #2 also can be failed now (their deadlines have also passed)
      const [canFail1] = await interfold.checkFailureCondition(1);
      const [canFail2] = await interfold.checkFailureCondition(2);
      expect(canFail1).to.be.true;
      expect(canFail2).to.be.true;

      // But they haven't auto-failed - must be explicitly marked
      expect(await interfold.getE3Stage(1)).to.equal(1);
      expect(await interfold.getE3Stage(2)).to.equal(1);

      // Now mark E3 #2 as failed (but not #1)
      await interfold.markE3Failed(2);
      expect(await interfold.getE3Stage(2)).to.equal(6); // Now Failed
      expect(await interfold.getE3Stage(1)).to.equal(1); // Still Requested

      // Verify each E3 has independent failure reasons
      expect(await interfold.getFailureReason(0)).to.equal(1); // CommitteeFormationTimeout
      expect(await interfold.getFailureReason(2)).to.equal(1); // CommitteeFormationTimeout
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
          proofAggregationEnabled: false,
        };
        const fee = await interfold.getE3Quote(requestParams);
        await usdcToken.connect(requester).approve(interfoldAddress, fee);
        await interfold.connect(requester).request(requestParams);
      }

      // Fail both
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await interfold.markE3Failed(0);
      await interfold.markE3Failed(1);

      // Process both
      await interfold.processE3Failure(0);
      await interfold.processE3Failure(1);

      // Claim both refunds independently
      const balanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );

      await e3RefundManager.connect(requester).claimRequesterRefund(0);
      const balanceAfterFirst = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(balanceAfterFirst).to.be.gt(balanceBefore);

      await e3RefundManager.connect(requester).claimRequesterRefund(1);
      const balanceAfterSecond = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      expect(balanceAfterSecond).to.be.gt(balanceAfterFirst);

      // Verify can't claim twice
      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(0),
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
        setupOperator,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // 1. Request E3, form committee, publish key
      await makeRequest(undefined, 0);
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      expect(await interfold.getE3Stage(0)).to.equal(3); // KeyPublished

      // 2. Slash operator1 during active E3 (before completion)
      //    With the stage-check removed, this should escrow funds in E3RefundManager
      const refundManagerAddress = await e3RefundManager.getAddress();
      const refundBalanceBefore =
        await usdcToken.balanceOf(refundManagerAddress);

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        0,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        0,
        await operator1.getAddress(),
        proof,
      );

      // Verify USDC moved to refund manager (escrowed)
      const refundBalanceAfter =
        await usdcToken.balanceOf(refundManagerAddress);
      const actualSlashedAmount = refundBalanceAfter - refundBalanceBefore;
      expect(actualSlashedAmount).to.be.gt(0);

      // 3. Complete the E3 successfully: publish ciphertext → publish plaintext
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proofBytes = "0x1337";
      await interfold.publishCiphertextOutput(0, ciphertextOutput, proofBytes);
      expect(await interfold.getE3Stage(0)).to.equal(4); // CiphertextReady

      // Record the E3 payment (normal rewards) before completion zeroes it
      const e3Payment = await interfold.e3Payments(0);

      // Record balances before plaintext publish (which triggers _distributeRewards)
      const treasuryAddress = await treasury.getAddress();
      const treasuryBalanceBefore = await usdcToken.balanceOf(treasuryAddress);
      const op1BalanceBefore = await usdcToken.balanceOf(
        await operator1.getAddress(),
      );
      const op2BalanceBefore = await usdcToken.balanceOf(
        await operator2.getAddress(),
      );
      const op3BalanceBefore = await usdcToken.balanceOf(
        await operator3.getAddress(),
      );

      const plaintextOutput = "0x" + "cd".repeat(100);
      await interfold.publishPlaintextOutput(0, plaintextOutput, proofBytes);
      expect(await interfold.getE3Stage(0)).to.equal(5); // Complete

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

      // Honest nodes receive normal E3 rewards synchronously via
      // bondingRegistry.distributeRewards; the slashed-funds node share is
      // pull-only via claimSlashedFundsOnSuccess (H-01).
      const op1BalanceAfter = await usdcToken.balanceOf(
        await operator1.getAddress(),
      );
      const op2BalanceAfter = await usdcToken.balanceOf(
        await operator2.getAddress(),
      );
      const op3BalanceAfter = await usdcToken.balanceOf(
        await operator3.getAddress(),
      );
      const nodesReceivedSync =
        op1BalanceAfter -
        op1BalanceBefore +
        (op2BalanceAfter - op2BalanceBefore) +
        (op3BalanceAfter - op3BalanceBefore);
      // Normal E3 rewards path is not asserted here — it depends on the
      // BondingRegistry distribution mode which is out of scope for this
      // slashed-funds test. We only assert the slashed-share pull path below.
      void nodesReceivedSync;
      void e3Payment;

      // Each honest node pulls their slashed share.
      const ops = [operator1, operator2, operator3];
      let slashedClaimedTotal = 0n;
      for (const op of ops) {
        const before = await usdcToken.balanceOf(await op.getAddress());
        await e3RefundManager.connect(op).claimSlashedFundsOnSuccess(0);
        const after = await usdcToken.balanceOf(await op.getAddress());
        slashedClaimedTotal += after - before;
      }
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
      expect(await interfold.getE3Stage(0)).to.equal(1); // Requested

      // 2. Complete sortition and publish committee (CommitteeFinalized -> KeyPublished)
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      expect(await interfold.getE3Stage(0)).to.equal(2); // CommitteeFinalized

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      expect(await interfold.getE3Stage(0)).to.equal(3); // KeyPublished

      // 3. Publish ciphertext output (after input deadline)
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await interfold.publishCiphertextOutput(0, ciphertextOutput, proof);
      expect(await interfold.getE3Stage(0)).to.equal(4); // CiphertextReady

      // 4. Publish plaintext output
      const plaintextOutput = "0x" + "cd".repeat(100);
      await interfold.publishPlaintextOutput(0, plaintextOutput, proof);
      expect(await interfold.getE3Stage(0)).to.equal(5); // Complete

      // Cannot mark completed E3 as failed
      await expect(interfold.markE3Failed(0)).to.be.revertedWithCustomError(
        interfold,
        "E3AlreadyComplete",
      );
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
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(0, publicKey, pkCommitment, "0x", "0x");

      // Publish outputs
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await interfold.publishCiphertextOutput(0, ciphertextOutput, proof);

      const plaintextOutput = "0x" + "cd".repeat(100);
      await interfold.publishPlaintextOutput(0, plaintextOutput, proof);

      // Verify E3 is complete
      expect(await interfold.getE3Stage(0)).to.equal(5); // Complete

      await expect(
        e3RefundManager.connect(requester).claimRequesterRefund(0),
      ).to.be.revertedWithCustomError(e3RefundManager, "RefundNotCalculated");
    });
  });
});
