// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Tests for committee expulsion, viability checks, and E3 failure on threshold breach.
 *
 * Verifies:
 * - Committee members are expelled via proposeSlash when affectsCommittee=true
 * - The E3 continues as long as active members >= threshold M
 * - The E3 fails when active members drop below threshold M
 * - Rewards exclude expelled members
 * - Idempotent expulsion (re-slashing same node doesn't double-count)
 */
import { expect } from "chai";
import type { Signer } from "ethers";

import {
  ACTIVE_CRYPTO_CONFIG_ID,
  COMMITTEE_SIZE_MINIMUM,
  COMMITTEE_THRESHOLDS_ONCHAIN,
  LARGE_TIMEOUT_CONFIG,
  ONE_DAY,
  deployInterfoldSystem,
  encodeMockDkgProof,
  ethers,
  networkHelpers,
  publishAvailableCiphertextOutput,
  signAndEncodeAttestation,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("Committee Expulsion & Fault Tolerance", function () {
  let firstE3Id: bigint;
  const INSUFFICIENT_COMMITTEE_MEMBERS = 2;
  // Lane A reasons are derived on-chain as keccak256(abi.encodePacked(proofType))
  const REASON_PT_0 = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));
  const REASON_PT_7 = ethers.keccak256(ethers.solidityPacked(["uint256"], [7]));

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const setup = async () => {
    const signers = await ethers.getSigners();
    const [
      owner,
      requester,
      treasury,
      operator1,
      operator2,
      operator3,
      operator4,
    ] = signers;
    const requesterAddress = await requester.getAddress();

    const sys = await deployInterfoldSystem({
      timeoutConfig: LARGE_TIMEOUT_CONFIG,
      committeeThresholds: COMMITTEE_THRESHOLDS_ONCHAIN.map(
        ([size, [min, max]]) =>
          [size, [min, max]] as [number, [number, number]],
      ),
      deployCircuitVerifier: true,
      setupOperators: 0,
      slashedFundsTreasury: treasury,
      mintUsdcTo: [],
    });
    const {
      interfold,
      ciphernodeRegistry: registry,
      slashingManager,
      bondingRegistry,
      ciphernodeBondToken: foldToken,
      ticketToken,
      usdcToken,
      nodeReleaseRegistry,
      mocks,
    } = sys;
    const mockVerifier = mocks.circuitVerifier!;
    const e3Program = mocks.e3Program;
    const decryptionVerifier = mocks.decryptionVerifier;
    const interfoldAddress = await interfold.getAddress();
    firstE3Id = await interfold.nexte3Id();

    // Fund the requester (fixture's `mintUsdcTo: []` skipped this).
    await usdcToken.mint(requesterAddress, ethers.parseUnits("100000", 6));

    // ── Slash Policies ─────────────────────────────────────────────────────
    const baseSlashPolicy = {
      ticketPenalty: ethers.parseUnits("10", 6),
      ciphernodeBondPenalty: ethers.parseEther("50"),
      requiresProof: true,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: 0,
      enabled: true,
      affectsCommittee: true,
    };

    await slashingManager.setSlashPolicy(REASON_PT_0, {
      ...baseSlashPolicy,
      failureReason: INSUFFICIENT_COMMITTEE_MEMBERS,
    });
    await slashingManager.setSlashPolicy(REASON_PT_7, {
      ...baseSlashPolicy,
      failureReason: INSUFFICIENT_COMMITTEE_MEMBERS,
    });

    // ── Helpers ────────────────────────────────────────────────────────────
    async function setupOperator(operator: Signer) {
      const operatorAddress = await operator.getAddress();
      const bondOwnerAddress = await owner.getAddress();

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
        .connect(owner)
        .approve(await bondingRegistry.getAddress(), ethers.parseEther("2000"));
      await bondingRegistry
        .connect(owner)
        .bondCiphernodeFor(operatorAddress, ethers.parseEther("1000"));
      await bondingRegistry.connect(owner).registerOperatorFor(operatorAddress);

      const ticketAmount = ethers.parseUnits("100", 6);
      await usdcToken
        .connect(owner)
        .approve(await bondingRegistry.ticketToken(), ticketAmount);
      await bondingRegistry
        .connect(owner)
        .addTicketBalanceFor(operatorAddress, ticketAmount);
    }

    async function makeRequest(committeeSize: number = COMMITTEE_SIZE_MINIMUM) {
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
        expectedFeeToken: await usdcToken.getAddress(),
        expectedCryptoConfigId: ACTIVE_CRYPTO_CONFIG_ID,
        maxFee: ethers.MaxUint256,
      };

      const fee = await interfold.getE3Quote(requestParams);
      await usdcToken.connect(requester).approve(interfoldAddress, fee);
      await interfold.connect(requester).request(requestParams);
      await time.increase(1);
    }

    async function finalizeCommittee(e3Id: bigint, operators: Signer[]) {
      for (const op of operators)
        await registry.connect(op).submitTicket(e3Id, 1);

      const deadline = await registry.getCommitteeDeadline(e3Id);
      await time.setNextBlockTimestamp(deadline + 1n);
      await registry.finalizeCommittee(e3Id);
    }

    async function publishFinalizedCommittee(e3Id: bigint) {
      const publicKey = ethers.toUtf8Bytes("fake-public-key");
      const pkCommitment = ethers.keccak256(publicKey);
      await registry.publishCommittee(
        e3Id,
        pkCommitment,
        encodeMockDkgProof(pkCommitment),
        "0x01",
      );
    }

    async function finalizeCommitteeWithOperators(
      e3Id: bigint,
      operators: Signer[],
    ) {
      await finalizeCommittee(e3Id, operators);
      await publishFinalizedCommittee(e3Id);
    }

    async function expelBelowThreshold(e3Id: bigint, operators: Signer[]) {
      const managerAddress = await slashingManager.getAddress();
      await networkHelpers.impersonateAccount(managerAddress);
      await networkHelpers.setBalance(managerAddress, ethers.parseEther("1"));
      const managerSigner = await ethers.getSigner(managerAddress);

      for (const operator of operators) {
        await registry
          .connect(managerSigner)
          .expelCommitteeMember(
            e3Id,
            await operator.getAddress(),
            ethers.ZeroHash,
          );
      }

      await networkHelpers.stopImpersonatingAccount(managerAddress);
    }

    async function prepareMinimumCommittee(publish = true) {
      const operators = [operator1, operator2, operator3];
      for (const operator of operators) await setupOperator(operator);
      await makeRequest(0);
      await finalizeCommittee(firstE3Id, operators);
      if (publish) await publishFinalizedCommittee(firstE3Id);
    }

    async function slashFirstMember() {
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        await signAndEncodeAttestation(
          [operator2, operator3],
          firstE3Id,
          await operator1.getAddress(),
          await slashingManager.getAddress(),
        ),
      );
    }

    async function configureEvidencePolicy(label: string) {
      const reason = ethers.keccak256(ethers.toUtf8Bytes(label));
      await slashingManager.setSlashPolicy(reason, {
        ticketPenalty: ethers.parseUnits("10", 6),
        ciphernodeBondPenalty: ethers.parseEther("50"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 1,
        enabled: true,
        affectsCommittee: true,
        failureReason: INSUFFICIENT_COMMITTEE_MEMBERS,
      });
      await slashingManager.grantRole(
        await slashingManager.SLASHER_ROLE(),
        await owner.getAddress(),
      );
      return reason;
    }

    async function proposeThresholdBreach(reason: string) {
      const proposalId = await slashingManager.totalProposals();
      await slashingManager.proposeSlashEvidence(
        firstE3Id,
        await operator2.getAddress(),
        reason,
        ethers.toUtf8Bytes("evidence-data"),
      );
      await time.increase(2);
      return proposalId;
    }

    return {
      interfold,
      registry,
      slashingManager,
      bondingRegistry,
      mockVerifier,
      usdcToken,
      foldToken,
      ticketToken,
      nodeReleaseRegistry,
      owner,
      requester,
      treasury,
      operator1,
      operator2,
      operator3,
      operator4,
      setupOperator,
      makeRequest,
      finalizeCommittee,
      publishFinalizedCommittee,
      finalizeCommitteeWithOperators,
      expelBelowThreshold,
      prepareMinimumCommittee,
      slashFirstMember,
      configureEvidencePolicy,
      proposeThresholdBreach,
    };
  };

  describe("committee expulsion via proposeSlash", function () {
    it("should expel a committee member and emit CommitteeMemberExpelled", async function () {
      const {
        registry,
        slashingManager,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // Minimum → M=2, N=3
      await makeRequest(COMMITTEE_SIZE_MINIMUM);
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      const op1Address = await operator1.getAddress();

      // Verify member is active before slash
      expect(await registry.isCommitteeMemberActive(firstE3Id, op1Address)).to
        .be.true;
      expect(
        (await registry.getCommitteeViability(firstE3Id)).activeCount,
      ).to.equal(3);

      // Committee members attest that operator1 is faulty
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        op1Address,
        await slashingManager.getAddress(),
      );
      const tx = await slashingManager.proposeSlash(
        firstE3Id,
        op1Address,
        proof,
      );

      // Should emit CommitteeMemberExpelled
      await expect(tx)
        .to.emit(registry, "CommitteeMemberExpelled")
        .withArgs(firstE3Id, op1Address, REASON_PT_0, 2);

      // Should emit CommitteeViabilityUpdated
      await expect(tx)
        .to.emit(registry, "CommitteeViabilityUpdated")
        .withArgs(firstE3Id, 2, 2, true); // 2 >= 2 → viable

      // Verify member is no longer active
      expect(await registry.isCommitteeMemberActive(firstE3Id, op1Address)).to
        .be.false;
      expect(
        (await registry.getCommitteeViability(firstE3Id)).activeCount,
      ).to.equal(2);
    });

    it("should keep E3 alive when active members >= threshold", async function () {
      const {
        interfold,
        registry,
        slashingManager,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest(0); // M=2, N=3
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      // Slash one member — 3 active → 2 active, threshold is 2, still viable
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

      // E3 should NOT be failed — stage should still be Requested (1)
      // or whatever stage it was at, not Failed
      const stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.not.equal(6); // 6 = E3Stage.Failed

      // Active committee still has enough members
      const { activeCount, thresholdM } =
        await registry.getCommitteeViability(firstE3Id);
      expect(activeCount).to.equal(2);
      expect(thresholdM).to.equal(2); // M=2
    });

    it("should fail E3 when active members drop below threshold", async function () {
      const {
        interfold,
        slashingManager,
        owner,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // Add an evidence-based slash policy (Lane B) with no appeal window
      const REASON_EVIDENCE = ethers.keccak256(
        ethers.toUtf8Bytes("E3_EVIDENCE_SLASH"),
      );
      await slashingManager.setSlashPolicy(REASON_EVIDENCE, {
        ticketPenalty: ethers.parseUnits("10", 6),
        ciphernodeBondPenalty: ethers.parseEther("50"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 1, // Minimum appeal window (1 second)
        enabled: true,
        affectsCommittee: true,
        failureReason: INSUFFICIENT_COMMITTEE_MEMBERS,
      });

      // Grant SLASHER_ROLE to owner for Lane B
      const SLASHER_ROLE = await slashingManager.SLASHER_ROLE();
      await slashingManager.grantRole(SLASHER_ROLE, await owner.getAddress());

      await makeRequest(0); // M=2, N=3
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      // Lane A: Slash op1 with attestation from [op2, op3] — active 3→2, still >= M=2
      // Evidence is the preimage of dataHash; the contract enforces
      // `keccak256(evidence) == dataHash` and equal dataHashes across voters.
      const evidence1 = ethers.hexlify(ethers.toUtf8Bytes("data1"));
      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
        0,
        31337,
        evidence1,
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof,
      );

      let stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.not.equal(6); // Not failed yet

      // Lane B: Evidence-based slash of op2 (no attestation needed) — active 2→1 < M=2
      // Lane A can't trigger E3 failure alone because you always need M active
      // non-accused voters, but after the slash active must drop below M — a contradiction.
      // Lane B (SLASHER_ROLE) bypasses attestation requirements for this final slash.
      const nextProposalId = await slashingManager.totalProposals();
      await slashingManager.proposeSlashEvidence(
        firstE3Id,
        await operator2.getAddress(),
        REASON_EVIDENCE,
        ethers.toUtf8Bytes("evidence-data"),
      );

      // Wait for appeal window to pass, then execute
      await time.increase(2);
      const tx = await slashingManager.executeSlash(nextProposalId);

      // Should emit E3Failed event
      await expect(tx).to.emit(interfold, "E3Failed");

      // E3 should now be Failed
      stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(6); // E3Stage.Failed

      // Every threshold breach has the same supplier-paid reason.
      const reason = await interfold.getFailureReason(firstE3Id);
      expect(reason).to.equal(INSUFFICIENT_COMMITTEE_MEMBERS);
    });

    it("should handle idempotent expulsion (re-slashing same node)", async function () {
      const {
        registry,
        slashingManager,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest(0);
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      // Slash operator1 once
      const ev1 = ethers.hexlify(ethers.toUtf8Bytes("first"));
      const proof1 = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
        0,
        31337,
        ev1,
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof1,
      );
      expect(
        (await registry.getCommitteeViability(firstE3Id)).activeCount,
      ).to.equal(2);

      // Slash operator1 again for a different proof type to verify expulsion is idempotent.
      // Same (e3Id, operator, proofType) would revert DuplicateEvidence — that's correct.
      // Using proofType=7 (C6ThresholdShareDecryption) with REASON_PT_7 instead.
      const ev2 = ethers.hexlify(ethers.toUtf8Bytes("second"));
      const proof2 = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
        7, // C6ThresholdShareDecryption — different proofType
        31337,
        ev2,
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof2,
      );

      // Active count should still be 2 (idempotent expulsion)
      expect(
        (await registry.getCommitteeViability(firstE3Id)).activeCount,
      ).to.equal(2);
    });

    it("should exclude expelled members from getActiveCommitteeNodes", async function () {
      const {
        registry,
        slashingManager,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest(0);
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      // Before expulsion: all 3 should be in active nodes
      const [nodesBefore, scoresBefore] =
        await registry.getActiveCommitteeNodes(firstE3Id);
      expect(nodesBefore.length).to.equal(3);
      expect(scoresBefore.length).to.equal(3);
      expect(nodesBefore).to.include(await operator1.getAddress());

      const scoreByNode = new Map(
        nodesBefore.map((node, index) => [
          node.toLowerCase(),
          scoresBefore[index],
        ]),
      );

      // Expel operator1
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

      // After expulsion: only 2 should be active
      const [nodesAfter, scoresAfter] =
        await registry.getActiveCommitteeNodes(firstE3Id);
      expect(nodesAfter.length).to.equal(2);
      expect(scoresAfter.length).to.equal(2);
      expect(nodesAfter).to.not.include(await operator1.getAddress());
      expect(nodesAfter).to.include(await operator2.getAddress());
      expect(nodesAfter).to.include(await operator3.getAddress());
      scoresAfter.forEach((score, index) => {
        expect(score).to.equal(
          scoreByNode.get(nodesAfter[index].toLowerCase()),
        );
      });
    });
  });

  describe("E3 fails below threshold", function () {
    it("should fail E3 exactly at the threshold breach via Lane B", async function () {
      const {
        interfold,
        registry,
        slashingManager,
        owner,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      // Lane B evidence-based policy with no appeal window
      const REASON_EVIDENCE = ethers.keccak256(
        ethers.toUtf8Bytes("E3_EVIDENCE_SLASH"),
      );
      await slashingManager.setSlashPolicy(REASON_EVIDENCE, {
        ticketPenalty: ethers.parseUnits("10", 6),
        ciphernodeBondPenalty: ethers.parseEther("50"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 1, // Minimum appeal window (1 second)
        enabled: true,
        affectsCommittee: true,
        failureReason: INSUFFICIENT_COMMITTEE_MEMBERS,
      });
      const SLASHER_ROLE = await slashingManager.SLASHER_ROLE();
      await slashingManager.grantRole(SLASHER_ROLE, await owner.getAddress());

      await makeRequest(0); // M=2, N=3
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      // Step 1: Lane A slash op1 — still viable (3→2 active, >= M=2)
      const laneAProof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        laneAProof,
      );

      // Step 2: Lane A cannot slash op2 (only op3 can vote, 1 < M=2).
      // Lane B (SLASHER_ROLE) is required for the final expulsion.
      const nextProposalId = await slashingManager.totalProposals();
      await slashingManager.proposeSlashEvidence(
        firstE3Id,
        await operator2.getAddress(),
        REASON_EVIDENCE,
        ethers.toUtf8Bytes("evidence-data"),
      );

      // Wait for appeal window to pass, then execute
      await time.increase(2);
      const tx = await slashingManager.executeSlash(nextProposalId);

      await expect(tx).to.emit(interfold, "E3Failed");

      // Should emit CommitteeViabilityUpdated(viable=false)
      // activeCount drops to 1, which is < M=2
      await expect(tx)
        .to.emit(registry, "CommitteeViabilityUpdated")
        .withArgs(firstE3Id, 1, 2, false);

      const stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.equal(6); // Failed
    });

    it("stops proof-based expulsions at the viability threshold", async function () {
      const {
        interfold,
        slashingManager,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest(COMMITTEE_SIZE_MINIMUM);
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      // Expel one member. The two remaining members still meet H=2.
      const evExpelOp1 = ethers.hexlify(ethers.toUtf8Bytes("expel-op1"));
      const proof1 = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
        0,
        31337,
        evExpelOp1,
      );
      await slashingManager.proposeSlash(
        firstE3Id,
        await operator1.getAddress(),
        proof1,
      );

      const stage = await interfold.getE3Stage(firstE3Id);
      expect(stage).to.not.equal(6);

      // One non-accused signer cannot authorize another expulsion at H=2.
      await expect(
        slashingManager.proposeSlash(
          firstE3Id,
          await operator2.getAddress(),
          await signAndEncodeAttestation(
            [operator3],
            firstE3Id,
            await operator2.getAddress(),
            await slashingManager.getAddress(),
            0,
            31337,
            ethers.hexlify(ethers.toUtf8Bytes("expel-op2")),
          ),
        ),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "InsufficientAttestations",
      );

      const stageAfter = await interfold.getE3Stage(firstE3Id);
      expect(stageAfter).to.not.equal(6);
    });

    it("rolls back the slash when a nonterminal E3 cannot be failed", async function () {
      const {
        interfold,
        registry,
        slashingManager,
        bondingRegistry,
        operator2,
        prepareMinimumCommittee,
        slashFirstMember,
        configureEvidencePolicy,
        proposeThresholdBreach,
        nodeReleaseRegistry,
      } = await loadFixture(setup);

      const reason = await configureEvidencePolicy("ROLLBACK_EVIDENCE_SLASH");
      await prepareMinimumCommittee();
      await slashFirstMember();
      const proposalId = await proposeThresholdBreach(reason);

      const operator = await operator2.getAddress();
      const ticketsBefore = await bondingRegistry.getTicketBalance(operator);
      const ciphernodeBondBefore =
        await bondingRegistry.getCiphernodeBond(operator);
      const mock = await ethers.deployContract("MockFailingInterfold", [
        await nodeReleaseRegistry.getAddress(),
        await bondingRegistry.getAddress(),
      ]);
      await mock.waitForDeployment();
      await ethers.provider.send("hardhat_setCode", [
        await interfold.getAddress(),
        await ethers.provider.getCode(await mock.getAddress()),
      ]);
      const failingInterfold = await ethers.getContractAt(
        "MockFailingInterfold",
        await interfold.getAddress(),
      );

      await expect(
        slashingManager.executeSlash(proposalId),
      ).to.be.revertedWithCustomError(
        failingInterfold,
        "FailureCallbackRejected",
      );

      expect(
        (await registry.getCommitteeViability(firstE3Id)).activeCount,
      ).to.equal(2);
      expect(await bondingRegistry.getTicketBalance(operator)).to.equal(
        ticketsBefore,
      );
      expect(await bondingRegistry.getCiphernodeBond(operator)).to.equal(
        ciphernodeBondBefore,
      );
      expect((await slashingManager.getSlashProposal(proposalId)).executed).to
        .be.false;
    });

    it("allows threshold-reducing slashes after the E3 is terminal", async function () {
      const {
        interfold,
        registry,
        slashingManager,
        prepareMinimumCommittee,
        slashFirstMember,
        configureEvidencePolicy,
        proposeThresholdBreach,
      } = await loadFixture(setup);

      const reason = await configureEvidencePolicy("TERMINAL_EVIDENCE_SLASH");
      await prepareMinimumCommittee();
      await slashFirstMember();

      const registryAddress = await registry.getAddress();
      await networkHelpers.impersonateAccount(registryAddress);
      await networkHelpers.setBalance(registryAddress, ethers.parseEther("1"));
      await interfold
        .connect(await ethers.getSigner(registryAddress))
        .onE3Failed(firstE3Id, INSUFFICIENT_COMMITTEE_MEMBERS);
      await networkHelpers.stopImpersonatingAccount(registryAddress);

      const proposalId = await proposeThresholdBreach(reason);
      await slashingManager.executeSlash(proposalId);

      expect(await interfold.getE3Stage(firstE3Id)).to.equal(6);
      expect(
        (await registry.getCommitteeViability(firstE3Id)).activeCount,
      ).to.equal(1);
    });
  });

  describe("publication viability gates", function () {
    it("rejects committee-key publication below threshold", async function () {
      const {
        registry,
        operator1,
        operator2,
        prepareMinimumCommittee,
        expelBelowThreshold,
      } = await loadFixture(setup);

      await prepareMinimumCommittee(false);
      await expelBelowThreshold(firstE3Id, [operator1, operator2]);

      const publicKey = ethers.toUtf8Bytes("fake-public-key");
      const commitment = ethers.keccak256(publicKey);
      await expect(
        registry.publishCommittee(
          firstE3Id,
          commitment,
          encodeMockDkgProof(commitment),
          "0x01",
        ),
      ).to.be.revertedWithCustomError(registry, "ThresholdNotMet");
    });

    it("rejects ciphertext publication below threshold", async function () {
      const {
        interfold,
        registry,
        operator1,
        operator2,
        prepareMinimumCommittee,
        expelBelowThreshold,
      } = await loadFixture(setup);

      await prepareMinimumCommittee();
      await expelBelowThreshold(firstE3Id, [operator1, operator2]);
      await time.increaseTo(
        Number((await interfold.getE3(firstE3Id)).inputWindow[1]),
      );

      const ciphertext = "0x" + "ab".repeat(100);
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          firstE3Id,
          ciphertext,
          ethers.keccak256(ciphertext),
          "0x1337",
        ),
      ).to.be.revertedWithCustomError(registry, "ThresholdNotMet");
    });

    it("rejects plaintext publication below threshold", async function () {
      const {
        interfold,
        registry,
        operator1,
        operator2,
        prepareMinimumCommittee,
        expelBelowThreshold,
      } = await loadFixture(setup);

      await prepareMinimumCommittee();
      await time.increaseTo(
        Number((await interfold.getE3(firstE3Id)).inputWindow[1]),
      );

      const ciphertext = "0x" + "ab".repeat(100);
      await publishAvailableCiphertextOutput(
        interfold,
        firstE3Id,
        ciphertext,
        ethers.keccak256(ciphertext),
        "0x1337",
      );
      await expelBelowThreshold(firstE3Id, [operator1, operator2]);

      await expect(
        interfold.publishPlaintextOutput(
          firstE3Id,
          "0x" + "cd".repeat(100),
          "0x1337",
        ),
      ).to.be.revertedWithCustomError(registry, "ThresholdNotMet");
    });
  });

  describe("slash execution events", function () {
    it("should emit SlashExecuted on proof-based committee slash", async function () {
      const {
        slashingManager,
        operator1,
        operator2,
        operator3,
        setupOperator,
        makeRequest,
        finalizeCommitteeWithOperators,
      } = await loadFixture(setup);

      await setupOperator(operator1);
      await setupOperator(operator2);
      await setupOperator(operator3);

      await makeRequest(0);
      await finalizeCommitteeWithOperators(firstE3Id, [
        operator1,
        operator2,
        operator3,
      ]);

      const proof = await signAndEncodeAttestation(
        [operator2, operator3],
        firstE3Id,
        await operator1.getAddress(),
        await slashingManager.getAddress(),
      );
      const op1Addr = await operator1.getAddress();
      const tx = await slashingManager.proposeSlash(firstE3Id, op1Addr, proof);

      await expect(tx).to.emit(slashingManager, "SlashExecuted").withArgs(
        0, // proposalId
        firstE3Id,
        op1Addr,
        REASON_PT_0,
        ethers.parseUnits("10", 6), // ticketPenalty
        ethers.parseEther("50"), // ciphernodeBondPenalty
        true, // executed
        0, // lane: LaneA (attestation/proof-based via proposeSlash)
      );
    });
  });
});
