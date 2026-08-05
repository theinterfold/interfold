// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import InterfoldModule from "../../ignition/modules/interfold";
import type { MockBlacklistUSDC } from "../../types";
import {
  Interfold__factory as InterfoldFactory,
  MockUSDC__factory as MockUSDCFactory,
} from "../../types";
import {
  deployInterfoldSystem,
  encodeMockDkgProof,
  ethers,
  ignition,
  makeRequest,
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
      useBlacklistFeeToken: true,
      wireSlashingManager: true,
    });

    const {
      interfold,
      e3RefundManager,
      bondingRegistry,
      ciphernodeRegistry: registry,
      slashingManager,
      usdcToken,
      licenseToken: foldToken,
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
      requestToken = usdcToken,
    ): Promise<{ e3Id: number }> => {
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
      };

      const fee = await interfold.getE3Quote(requestParams);
      await requestToken.connect(signer).approve(interfoldAddress, fee);
      await interfold.connect(signer).request(requestParams);

      return { e3Id: 0 };
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
      await foldToken
        .connect(computeProvider)
        .approve(await bondingRegistry.getAddress(), ethers.parseEther("2000"));
      await bondingRegistry
        .connect(computeProvider)
        .bondLicenseFor(operatorAddress, ethers.parseEther("1000"));
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

    const makeReadyRequest = async () => {
      for (const operator of [operator1, operator2, operator3]) {
        await setupOperator(operator);
      }
      await makeRequest();
    };

    const finalizeReadyCommittee = async () => {
      await makeReadyRequest();
      for (const operator of [operator1, operator2, operator3]) {
        await registry.connect(operator).submitTicket(0, 1);
      }
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);
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
      owner,
      requester,
      treasury,
      operator1,
      operator2,
      operator3,
      computeProvider,
      makeRequest,
      setupOperator,
      makeReadyRequest,
      finalizeReadyCommittee,
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

    it("rejects invalid failure reasons from an authorized dependency", async function () {
      const { interfold, registry, makeReadyRequest } =
        await loadFixture(setup);
      await makeReadyRequest();

      const registryAddress = await registry.getAddress();
      await networkHelpers.impersonateAccount(registryAddress);
      await networkHelpers.setBalance(registryAddress, ethers.parseEther("1"));
      const registrySigner = await ethers.getSigner(registryAddress);

      for (const reason of [0, 13, 255]) {
        await expect(interfold.connect(registrySigner).onE3Failed(0, reason))
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

      await interfold.setPricingConfig({
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
      });

      await finalizeReadyCommittee();

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      const deadlines = await interfold.getDeadlines(0);
      await time.increaseTo(deadlines.computeDeadline + 1n);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

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
      const snapshot = await e3RefundManager.getE3PolicySnapshot(0);
      expect(snapshot.initialized).to.equal(true);
      expect(snapshot.version).to.equal(1);
      expect(snapshot.treasury).to.equal(originalTreasury);
      expect(snapshot.registry).to.equal(await registry.getAddress());
      expect(snapshot.bondingRegistry).to.equal(
        await bondingRegistry.getAddress(),
      );
      expect(snapshot.allocation.committeeFormationBps).to.equal(1000);

      await e3RefundManager.connect(owner).setWorkAllocation({
        committeeFormationBps: 2000,
        dkgBps: 3000,
        decryptionBps: 4500,
        protocolBps: 500,
        successSlashedNodeBps: 1000,
      });
      await e3RefundManager.connect(owner).setTreasury(rotatedTreasury);

      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );
      const deadlines = await interfold.getDeadlines(0);
      await time.increaseTo(deadlines.computeDeadline + 1n);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      const distribution = await e3RefundManager.getRefundDistribution(0);
      expect(distribution.honestNodeAmount).to.equal(
        (distribution.originalPayment * 4000n) / 10000n,
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

      const unchanged = await e3RefundManager.getE3PolicySnapshot(0);
      expect(unchanged.version).to.equal(1);
      expect(unchanged.treasury).to.equal(originalTreasury);
      expect(unchanged.allocation.committeeFormationBps).to.equal(1000);
    });

    it("AUD-M04: drains an in-flight E3 through request-time dependencies", async function () {
      const {
        interfold,
        e3RefundManager,
        bondingRegistry,
        registry,
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
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);
      const rotationTestWindow = 100;
      await registry
        .connect(owner)
        .setSortitionSubmissionWindow(rotationTestWindow);
      await makeRequest();

      const interfoldAddress = await interfold.getAddress();
      const refundManagerAddress = await e3RefundManager.getAddress();
      const registryAddress = await registry.getAddress();
      const bondingAddress = await bondingRegistry.getAddress();

      const policy = await e3RefundManager.getE3PolicySnapshot(0);
      expect(policy.interfold).to.equal(interfoldAddress);
      expect(policy.registry).to.equal(registryAddress);
      expect(policy.bondingRegistry).to.equal(bondingAddress);
      const dependencies = await slashingManager.getE3Dependencies(0);
      expect(dependencies.bonding).to.equal(bondingAddress);
      expect(dependencies.registry).to.equal(registryAddress);
      expect(dependencies.interfoldContract).to.equal(interfoldAddress);
      expect(dependencies.refundManager).to.equal(refundManagerAddress);

      const rotatedRegistry = await requester.getAddress();
      const rotatedBonding = await computeProvider.getAddress();
      const rotatedRefundManager = await treasury.getAddress();
      const rotatedSlashingManager = await owner.getAddress();

      // Rotate every global dependency after the E3 has been requested. EOAs are
      // deliberate canaries: any accidental read through a live global pointer
      // will fail instead of silently succeeding through another deployment.
      await interfold.connect(owner).setCiphernodeRegistry(rotatedRegistry);
      await interfold.connect(owner).setBondingRegistry(rotatedBonding);
      await interfold.connect(owner).setE3RefundManager(rotatedRefundManager);
      await interfold.connect(owner).setSlashingManager(rotatedSlashingManager);
      await registry.connect(owner).setInterfold(rotatedRegistry);
      await registry.connect(owner).setBondingRegistry(rotatedBonding);
      await registry.connect(owner).setSlashingManager(rotatedSlashingManager);
      await bondingRegistry
        .connect(owner)
        .setSlashingManager(rotatedSlashingManager);
      await e3RefundManager.connect(owner).setInterfold(rotatedRegistry);
      await slashingManager.connect(owner).setBondingRegistry(rotatedBonding);
      await slashingManager
        .connect(owner)
        .setCiphernodeRegistry(rotatedRegistry);
      await slashingManager.connect(owner).setInterfold(rotatedRegistry);
      await slashingManager
        .connect(owner)
        .setE3RefundManager(rotatedRefundManager);

      // Committee selection still reads eligibility and ticket checkpoints from
      // the original bonding registry, then calls back into the original Interfold.
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(rotationTestWindow + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      await registry.publishCommittee(
        0,
        publicKey,
        ethers.keccak256(publicKey),
        encodeMockDkgProof(ethers.keccak256(publicKey)),
        "0x01",
      );

      // Slashing also stays bound to the original registry, bonding, Interfold,
      // and refund manager even though all four global pointers were rotated.
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        0,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      const refundBalanceBefore =
        await usdcToken.balanceOf(refundManagerAddress);
      await slashingManager.proposeSlash(
        0,
        await operator1.getAddress(),
        proof,
      );
      expect(
        await bondingRegistry.isAuthorizedSlashingManager(
          await slashingManager.getAddress(),
        ),
      ).to.equal(true);
      expect(await usdcToken.balanceOf(refundManagerAddress)).to.be.gt(
        refundBalanceBefore,
      );

      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));
      await interfold.publishCiphertextOutput(
        0,
        "0x" + "ab".repeat(100),
        ethers.keccak256("0x" + "ab".repeat(100)),
        "0x1337",
      );
      await interfold.publishPlaintextOutput(
        0,
        "0x" + "cd".repeat(100),
        "0x1337",
      );

      expect(await interfold.getE3Stage(0)).to.equal(5); // Complete
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

      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

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
        registry.publishCommittee(
          0,
          publicKey,
          pkCommitment,
          encodeMockDkgProof(pkCommitment),
          "0x01",
        ),
      )
        .to.emit(interfold, "CommitteeFormed")
        .withArgs(0);
    });

    it("rejects committee publication after the DKG deadline", async function () {
      const { interfold, registry, finalizeReadyCommittee } =
        await loadFixture(setup);
      await finalizeReadyCommittee();

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      const { dkgDeadline } = await interfold.getDeadlines(0);
      await time.increaseTo(dkgDeadline + 1n);

      await expect(
        registry.publishCommittee(
          0,
          publicKey,
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
      await registry.connect(operator1).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);

      await registry.finalizeCommittee(0);

      await interfold.processE3Failure(0);
      const distribution = await e3RefundManager.getRefundDistribution(0);
      expect(distribution.honestNodeAmount).to.equal(0);
    });

    it("rolls back failure processing when the registry lookup reverts", async function () {
      const sys = await deployInterfoldSystem({
        useMockCiphernodeRegistry: true,
        setupOperators: 0,
        wireSlashingManager: false,
      });
      const registry = sys.mockCiphernodeRegistry!;
      await makeRequest(sys.interfold, sys.usdcToken, sys.request);
      const payment = await sys.interfold.e3Payments(0);
      const registryAddress = await registry.getAddress();

      await networkHelpers.setBalance(registryAddress, ethers.parseEther("1"));
      await networkHelpers.impersonateAccount(registryAddress);
      await sys.interfold
        .connect(await ethers.getSigner(registryAddress))
        .onE3Failed(0, 8);
      await networkHelpers.stopImpersonatingAccount(registryAddress);
      await registry.setRevertActiveCommitteeNodes(true);

      await expect(
        sys.interfold.processE3Failure(0),
      ).to.be.revertedWithCustomError(registry, "ActiveCommitteeLookupFailed");
      expect(await sys.interfold.e3Payments(0)).to.equal(payment);
      const distribution = await sys.e3RefundManager.getRefundDistribution(0);
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
        licensePenalty: ethers.parseEther("100"),
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
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

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

      // 4. Slash operator1 via proposeSlash (Lane A) — real on-chain flow.
      //    The manager reserves the slash, then atomically routes the reserved
      //    underlying through Interfold into E3RefundManager escrow.
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

      // 6. Base refunds stay denominated in the E3 fee token; the slash is a
      //    separate claim in its actual underlying token.
      const distributionAfter = await e3RefundManager.getRefundDistribution(0);
      expect(distributionAfter.requesterAmount).to.equal(
        distributionBefore.requesterAmount,
      );
      expect(distributionAfter.honestNodeAmount).to.equal(
        distributionBefore.honestNodeAmount,
      );
      const usdcAddress = await usdcToken.getAddress();
      const requesterSlashClaim = await e3RefundManager.pendingSlashedClaim(
        0,
        usdcAddress,
        await requester.getAddress(),
      );
      expect(requesterSlashClaim).to.equal(0);
      expect(distributionAfter.totalSlashed).to.equal(actualSlashedAmount);

      const honestSlashClaims = await e3RefundManager.pendingSlashedClaim(
        0,
        usdcAddress,
        await computeProvider.getAddress(),
      );
      expect(honestSlashClaims).to.equal(actualSlashedAmount);
      for (const node of [operator1, operator2, operator3]) {
        expect(
          await e3RefundManager.pendingSlashedClaim(
            0,
            usdcAddress,
            await node.getAddress(),
          ),
        ).to.equal(0);
      }

      // 7. The requester pulls only the fault-attributed base refund.
      const requesterBalanceBefore = await usdcToken.balanceOf(
        await requester.getAddress(),
      );
      await e3RefundManager.connect(requester).claimRequesterRefund(0);
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
        licensePenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: true,
        failureReason: 0,
      });

      await makeRequest(requester, 0);
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      await registry.publishCommittee(
        0,
        publicKey,
        ethers.keccak256(publicKey),
        encodeMockDkgProof(ethers.keccak256(publicKey)),
        "0x01",
      );

      const e3 = await interfold.getE3(0);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      const blacklistToken = usdcToken as unknown as MockBlacklistUSDC;
      const refundManagerAddress = await e3RefundManager.getAddress();
      await blacklistToken.blacklist(refundManagerAddress);

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        0,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await expect(
        slashingManager.proposeSlash(0, await operator1.getAddress(), proof),
      ).to.emit(slashingManager, "SlashRoutePending");

      const pending = await slashingManager.getPendingSlashRoute(0);
      expect(pending.pending).to.equal(true);
      expect(pending.e3Id).to.equal(0);
      expect(pending.token).to.equal(await usdcToken.getAddress());
      expect(pending.amount).to.be.gt(0);
      expect(await bondingRegistry.reservedSlashedTicketBalance()).to.equal(
        pending.amount,
      );
      expect(await bondingRegistry.slashedTicketBalance()).to.equal(
        pending.amount,
      );

      await expect(
        bondingRegistry.connect(owner).withdrawSlashedFunds(pending.amount, 0),
      ).to.be.revertedWithCustomError(bondingRegistry, "ReservedSlashedFunds");

      await blacklistToken.unblacklist(refundManagerAddress);
      const refundBalanceBefore =
        await usdcToken.balanceOf(refundManagerAddress);
      await expect(slashingManager.connect(requester).retrySlashRoute(0))
        .to.emit(slashingManager, "SlashRouteCompleted")
        .withArgs(0, 0, await usdcToken.getAddress(), pending.amount)
        .and.to.emit(interfold, "SlashedFundsEscrowed")
        .withArgs(0, await usdcToken.getAddress(), pending.amount);

      expect(
        (await usdcToken.balanceOf(refundManagerAddress)) - refundBalanceBefore,
      ).to.equal(pending.amount);
      expect((await slashingManager.getPendingSlashRoute(0)).pending).to.equal(
        false,
      );
      expect(await bondingRegistry.reservedSlashedTicketBalance()).to.equal(0);
      expect(await bondingRegistry.slashedTicketBalance()).to.equal(0);
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
        licensePenalty: ethers.parseEther("100"),
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
      await interfold.connect(owner).setFeeToken(await feeToken.getAddress());

      await makeRequest(requester, 0, feeToken);
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      await registry.publishCommittee(
        0,
        publicKey,
        ethers.keccak256(publicKey),
        encodeMockDkgProof(ethers.keccak256(publicKey)),
        "0x01",
      );

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

      const underlyingAddress = await ticketUnderlying.getAddress();
      const feeTokenAddress = await feeToken.getAddress();
      const actualSlash = ethers.parseUnits("50", 6);
      expect(
        await e3RefundManager.pendingSlashedFunds(0, underlyingAddress),
      ).to.equal(actualSlash);

      const e3 = await interfold.getE3(0);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      // The fee-token settlement cannot consume or relabel the distinct
      // ticket underlying. Anyone can settle that recorded token explicitly.
      expect(
        await e3RefundManager.pendingSlashedFunds(0, underlyingAddress),
      ).to.equal(actualSlash);
      await e3RefundManager
        .connect(operator3)
        .settleSlashedFunds(0, underlyingAddress);

      const distribution = await e3RefundManager.getRefundDistribution(0);
      expect(distribution.feeToken).to.equal(feeTokenAddress);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
          feeTokenAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);

      const bondOwnerAddress = await computeProvider.getAddress();
      const totalSlashCredits = await e3RefundManager.pendingSlashedClaim(
        0,
        underlyingAddress,
        bondOwnerAddress,
      );
      expect(totalSlashCredits).to.equal(actualSlash);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
          underlyingAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
          underlyingAddress,
          await operator1.getAddress(),
        ),
      ).to.equal(0);
      expect(totalSlashCredits).to.be.gt(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
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
      await e3RefundManager.connect(requester).claimRequesterRefund(0);
      await e3RefundManager
        .connect(computeProvider)
        .claimSlashedFunds(0, underlyingAddress);

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
        licensePenalty: ethers.parseEther("100"),
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
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      // 2. Fail via compute timeout
      const e3 = await interfold.getE3(0);
      const computeDeadline =
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow;
      await time.increaseTo(computeDeadline + 1);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      // 3. Record the base distribution before slash.
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
      expect(distribution.honestNodeAmount).to.equal(honestNodeAmountBefore);
      const usdcAddress = await usdcToken.getAddress();
      const bondOwnerAddress = await computeProvider.getAddress();
      const ownerSlashClaim = await e3RefundManager.pendingSlashedClaim(
        0,
        usdcAddress,
        bondOwnerAddress,
      );
      expect(ownerSlashClaim).to.be.gt(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
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
          .claimHonestNodeReward(0, await operator2.getAddress()),
      ).to.be.revertedWithCustomError(e3RefundManager, "Unauthorized");
      await e3RefundManager
        .connect(computeProvider)
        .claimHonestNodeReward(0, await operator2.getAddress());
      await e3RefundManager
        .connect(computeProvider)
        .claimSlashedFunds(0, usdcAddress);
      const ownerBalanceAfter = await usdcToken.balanceOf(bondOwnerAddress);

      const perNodeAmount =
        distribution.honestNodeAmount / BigInt(distribution.honestNodeCount);
      expect(ownerBalanceAfter - ownerBalanceBefore).to.equal(
        perNodeAmount + ownerSlashClaim,
      );
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
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      const distributionBefore = await e3RefundManager.getRefundDistribution(0);
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
        .escrowSlashedFunds(0, await usdcToken.getAddress(), slashedAmount);
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [
        originalInterfold,
      ]);

      const distributionAfter = await e3RefundManager.getRefundDistribution(0);
      const tokenAddress = await usdcToken.getAddress();

      expect(distributionAfter.requesterAmount).to.equal(
        distributionBefore.originalPayment,
      );
      expect(distributionAfter.honestNodeAmount).to.equal(0);
      expect(distributionAfter.protocolAmount).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
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
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);
      await time.increase(defaultTimeoutConfig.dkgWindow + 1);
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      const distribution = await e3RefundManager.getRefundDistribution(0);
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
        .escrowSlashedFunds(0, usdcAddress, firstSlash);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
          usdcAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);

      await e3RefundManager
        .connect(interfoldSigner)
        .escrowSlashedFunds(0, usdcAddress, secondSlash);
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [
        originalInterfold,
      ]);

      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
          usdcAddress,
          await requester.getAddress(),
        ),
      ).to.equal(0);

      const honestSlashClaims = await e3RefundManager.pendingSlashedClaim(
        0,
        usdcAddress,
        await computeProvider.getAddress(),
      );
      expect(honestSlashClaims).to.equal(totalSlash);
      expect(
        (await e3RefundManager.getRefundDistribution(0)).totalSlashed,
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
      await interfold.markE3Failed(0);

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
        .escrowSlashedFunds(0, await usdcToken.getAddress(), slashedAmount);
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [
        originalInterfold,
      ]);

      // Distribution should not exist yet
      const distBefore = await e3RefundManager.getRefundDistribution(0);
      expect(distBefore.calculated).to.be.false;

      // Now process the failure — pending funds should be applied
      await interfold.processE3Failure(0);

      const distAfter = await e3RefundManager.getRefundDistribution(0);
      expect(distAfter.calculated).to.be.true;
      const usdcAddress = await usdcToken.getAddress();
      expect(
        await e3RefundManager.pendingSlashedFunds(0, usdcAddress),
      ).to.equal(0);
      expect(
        await e3RefundManager.pendingSlashedClaim(
          0,
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

      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);
      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );
      const e3 = await interfold.getE3(0);
      await time.increaseTo(
        Number(e3.inputWindow[1]) + defaultTimeoutConfig.computeWindow + 1,
      );
      await interfold.markE3Failed(0);
      await interfold.processE3Failure(0);

      await e3RefundManager.connect(operator1).claimRequesterRefund(0);
      expect(
        await e3RefundManager.hasRequesterClaimed(
          0,
          await operator1.getAddress(),
        ),
      ).to.equal(true);
      expect(
        await e3RefundManager.hasHonestNodeClaimed(
          0,
          await operator1.getAddress(),
        ),
      ).to.equal(false);

      await e3RefundManager
        .connect(computeProvider)
        .claimHonestNodeReward(0, await operator1.getAddress());
      expect(
        await e3RefundManager.hasHonestNodeClaimed(
          0,
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
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

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
      expect(distribution.requesterAmount).to.equal(
        (distribution.originalPayment * 5500n) / 10000n,
      );
      expect(distribution.honestNodeAmount).to.equal(
        (distribution.originalPayment * 4000n) / 10000n,
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
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      stage = await interfold.getE3Stage(0);
      expect(stage).to.equal(3); // KeyPublished

      // 3. Publish ciphertext output
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await interfold.publishCiphertextOutput(
        0,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proof,
      );
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
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
      await registry.finalizeCommittee(0);

      const publicKey = "0x1234567890abcdef1234567890abcdef";
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

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
      await interfold.publishCiphertextOutput(
        0,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proofBytes,
      );
      expect(await interfold.getE3Stage(0)).to.equal(4); // CiphertextReady

      // Record the E3 payment (normal rewards) before completion zeroes it
      const e3Payment = await interfold.e3Payments(0);

      // Record balances before plaintext publish (which triggers pull credits).
      const treasuryAddress = await treasury.getAddress();
      const treasuryBalanceBefore = await usdcToken.balanceOf(treasuryAddress);
      const bondOwnerAddress = await computeProvider.getAddress();
      const bondOwnerBalanceBefore =
        await usdcToken.balanceOf(bondOwnerAddress);

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

      // Normal rewards and slashed-fund rewards are both owner-routed pull
      // payments. This test claims only the slashed-fund share.
      void e3Payment;

      await e3RefundManager
        .connect(computeProvider)
        .claimSlashedFunds(0, usdcAddress);
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
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      expect(await interfold.getE3Stage(0)).to.equal(3); // KeyPublished

      // 3. Publish ciphertext output (after input deadline)
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await interfold.publishCiphertextOutput(
        0,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proof,
      );
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
      await registry.publishCommittee(
        0,
        publicKey,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );

      // Publish outputs
      const e3 = await interfold.getE3(0);
      await time.increaseTo(Number(e3.inputWindow[1]));

      const ciphertextOutput = "0x" + "ab".repeat(100);
      const proof = "0x1337";
      await interfold.publishCiphertextOutput(
        0,
        ciphertextOutput,
        ethers.keccak256(ciphertextOutput),
        proof,
      );

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
