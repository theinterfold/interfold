// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import SlashingManagerModule from "../../ignition/modules/slashingManager";
import type { MockCircuitVerifier } from "../../types";
import type { SlashingManager } from "../../types/contracts/slashing/SlashingManager";
import {
  deployInterfoldSystem,
  ethers,
  ignition,
  networkHelpers,
  signAndEncodeAttestation,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("SlashingManager", function () {
  // Lane A reasons are derived on-chain as keccak256(abi.encodePacked(proofType))
  const REASON_PT_0 = ethers.keccak256(ethers.solidityPacked(["uint256"], [0]));
  const REASON_PT_1 = ethers.keccak256(ethers.solidityPacked(["uint256"], [1]));
  const REASON_INACTIVITY = ethers.encodeBytes32String("inactivity");

  const SLASHER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("SLASHER_ROLE"));
  const GOVERNANCE_ROLE = ethers.keccak256(
    ethers.toUtf8Bytes("GOVERNANCE_ROLE"),
  );
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;

  const APPEAL_WINDOW = 7 * 24 * 60 * 60;

  // Placeholder address for contracts not under test
  const addressOne = "0x0000000000000000000000000000000000000001";

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  /**
   * Encodes a minimal attestation evidence for tests that check early
   * failures (before abi.decode is reached).
   */
  function encodeDummyAttestation(proofType: number = 0): string {
    return abiCoder.encode(
      ["uint256", "address[]", "bool[]", "bytes32[]", "bytes[]"],
      [proofType, [], [], [], []],
    );
  }

  function buildProofPolicy(
    overrides: Partial<{
      ticketPenalty: bigint;
      licensePenalty: bigint;
      requiresProof: boolean;
      proofVerifier: string;
      banNode: boolean;
      appealWindow: number;
      enabled: boolean;
      affectsCommittee: boolean;
      failureReason: number;
    }> = {},
  ) {
    return {
      ticketPenalty: ethers.parseUnits("50", 6),
      licensePenalty: ethers.parseEther("100"),
      requiresProof: true,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: 0,
      enabled: true,
      affectsCommittee: false,
      failureReason: 0,
      ...overrides,
    };
  }

  async function setupPolicies(
    slashingManager: SlashingManager,
    _mockVerifier?: MockCircuitVerifier,
  ) {
    const proofPolicy = buildProofPolicy();

    const evidencePolicy = {
      ticketPenalty: ethers.parseUnits("20", 6),
      licensePenalty: ethers.parseEther("50"),
      requiresProof: false,
      proofVerifier: ethers.ZeroAddress,
      banNode: false,
      appealWindow: APPEAL_WINDOW,
      enabled: true,
      affectsCommittee: false,
      failureReason: 0,
    };

    const banPolicy = buildProofPolicy({
      ticketPenalty: ethers.parseUnits("100", 6),
      licensePenalty: ethers.parseEther("500"),
      banNode: true,
    });

    await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);
    await slashingManager.setSlashPolicy(REASON_INACTIVITY, evidencePolicy);
    await slashingManager.setSlashPolicy(REASON_PT_1, banPolicy);
  }

  async function setup() {
    const signers = await ethers.getSigners();
    const [
      owner,
      slasher,
      proposer,
      operator,
      notTheOwner,
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
      usdcToken,
      mocks,
      mockCiphernodeRegistry: mockCiphernodeRegistryOpt,
    } = sys;
    const mockCiphernodeRegistry = mockCiphernodeRegistryOpt!;
    const _mockVerifier = mocks.circuitVerifier!;
    const mockCiphernodeRegistryAddress =
      await mockCiphernodeRegistry.getAddress();

    await interfoldToken.mint(
      operatorAddress,
      ethers.parseEther("2000"),
      ethers.encodeBytes32String("Test allocation"),
    );
    await slashingManager.addSlasher(await slasher.getAddress());
    await slashingManager.setCiphernodeRegistry(mockCiphernodeRegistryAddress);
    await slashingManager.setInterfold(addressOne);
    await slashingManager.setE3RefundManager(addressOne);

    return {
      owner,
      slasher,
      proposer,
      operator,
      operatorAddress,
      notTheOwner,
      voter1,
      voter2,
      voter3,
      slashingManager,
      bondingRegistry,
      interfoldToken,
      ticketToken,
      usdcToken,
      _mockVerifier,
      mockCiphernodeRegistry,
    };
  }

  describe("constructor / initialization", function () {
    it("should set the admin role correctly", async function () {
      const { slashingManager, owner } = await loadFixture(setup);

      expect(
        await slashingManager.hasRole(
          DEFAULT_ADMIN_ROLE,
          await owner.getAddress(),
        ),
      ).to.be.true;
      expect(
        await slashingManager.hasRole(
          GOVERNANCE_ROLE,
          await owner.getAddress(),
        ),
      ).to.be.true;
    });

    it("should set the bonding registry correctly", async function () {
      const { slashingManager, bondingRegistry } = await loadFixture(setup);

      expect(await slashingManager.bondingRegistry()).to.equal(
        await bondingRegistry.getAddress(),
      );
    });

    it("should revert if admin is zero address", async function () {
      await expect(
        ignition.deploy(SlashingManagerModule, {
          parameters: {
            SlashingManager: {
              admin: ethers.ZeroAddress,
              bondingRegistry: ethers.ZeroAddress,
              ciphernodeRegistry: ethers.ZeroAddress,
              interfold: ethers.ZeroAddress,
            },
          },
        }),
      ).to.be.rejected;
    });
  });

  describe("setSlashPolicy()", function () {
    it("should set a valid proof-based slash policy", async function () {
      const { slashingManager, _mockVerifier } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: await _mockVerifier.getAddress(),
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(slashingManager.setSlashPolicy(REASON_PT_0, policy))
        .to.emit(slashingManager, "SlashPolicyUpdated")
        .withArgs(REASON_PT_0, Object.values(policy));

      const storedPolicy = await slashingManager.getSlashPolicy(REASON_PT_0);
      expect(storedPolicy.ticketPenalty).to.equal(policy.ticketPenalty);
      expect(storedPolicy.licensePenalty).to.equal(policy.licensePenalty);
      expect(storedPolicy.requiresProof).to.equal(policy.requiresProof);
      expect(storedPolicy.enabled).to.equal(policy.enabled);
    });

    it("should set an evidence-based policy (no proof required)", async function () {
      const { slashingManager } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("20", 6),
        licensePenalty: ethers.parseEther("50"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: APPEAL_WINDOW,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(slashingManager.setSlashPolicy(REASON_INACTIVITY, policy))
        .to.emit(slashingManager, "SlashPolicyUpdated")
        .withArgs(REASON_INACTIVITY, Object.values(policy));
    });

    it("should revert if caller is not governance", async function () {
      const { slashingManager, notTheOwner } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: APPEAL_WINDOW,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(
        slashingManager
          .connect(notTheOwner)
          .setSlashPolicy(REASON_PT_0, policy),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("should revert if reason is zero", async function () {
      const { slashingManager } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: APPEAL_WINDOW,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(
        slashingManager.setSlashPolicy(ethers.ZeroHash, policy),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidPolicy");
    });

    // M-14: the `enabled` field on `SlashPolicy` is now informational only —
    // the on-chain validator no longer rejects policies based on this flag.
    // The whole-policy disable path is provided via reason removal/zeroing
    // in governance, not via this boolean. We assert the call succeeds.
    it("should accept policy with enabled=false (M-14 field is informational)", async function () {
      const { slashingManager } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: APPEAL_WINDOW,
        enabled: false,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(slashingManager.setSlashPolicy(REASON_PT_0, policy)).to.emit(
        slashingManager,
        "SlashPolicyUpdated",
      );
    });

    it("should revert if no penalties are set", async function () {
      const { slashingManager } = await loadFixture(setup);

      const policy = {
        ticketPenalty: 0,
        licensePenalty: 0,
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: APPEAL_WINDOW,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(
        slashingManager.setSlashPolicy(REASON_PT_0, policy),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidPolicy");
    });

    it("should allow proof-based policy without verifier (attestation model)", async function () {
      const { slashingManager } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(slashingManager.setSlashPolicy(REASON_PT_0, policy))
        .to.emit(slashingManager, "SlashPolicyUpdated")
        .withArgs(REASON_PT_0, Object.values(policy));
    });

    // Lane A (proof-based) policies may opt into a challenge window:
    // setting both `requiresProof=true` and a non-zero
    // `appealWindow` is now valid — `proposeSlash` will defer execution to
    // allow the operator to file an appeal.
    it("should accept proof-required policy with non-zero appeal window (Lane A challenge window)", async function () {
      const { slashingManager, _mockVerifier } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: await _mockVerifier.getAddress(),
        banNode: false,
        appealWindow: APPEAL_WINDOW,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(slashingManager.setSlashPolicy(REASON_PT_0, policy)).to.emit(
        slashingManager,
        "SlashPolicyUpdated",
      );
    });

    it("should revert if no proof required but no appeal window", async function () {
      const { slashingManager } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: false,
        proofVerifier: ethers.ZeroAddress,
        banNode: false,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await expect(
        slashingManager.setSlashPolicy(REASON_PT_0, policy),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidPolicy");
    });
  });

  describe("role management", function () {
    it("should add and remove slasher role", async function () {
      const { slashingManager, notTheOwner } = await loadFixture(setup);

      await slashingManager.addSlasher(await notTheOwner.getAddress());
      expect(
        await slashingManager.hasRole(
          SLASHER_ROLE,
          await notTheOwner.getAddress(),
        ),
      ).to.be.true;

      await slashingManager.removeSlasher(await notTheOwner.getAddress());
      expect(
        await slashingManager.hasRole(
          SLASHER_ROLE,
          await notTheOwner.getAddress(),
        ),
      ).to.be.false;
    });

    it("should revert if non-admin tries to add slasher", async function () {
      const { slashingManager, notTheOwner } = await loadFixture(setup);

      await expect(
        slashingManager
          .connect(notTheOwner)
          .addSlasher(await notTheOwner.getAddress()),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("should revert if zero address is added as slasher", async function () {
      const { slashingManager } = await loadFixture(setup);

      await expect(
        slashingManager.addSlasher(ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(slashingManager, "ZeroAddress");
    });
  });

  describe("proposeSlash() — Lane A (proof-based, permissionless)", function () {
    it("should propose and auto-execute slash with committee attestation", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      // Set up committee membership: operator must be a member, voters attest the operator is faulty
      const e3Id = 0;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(e3Id, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(e3Id, 2);

      // Committee members sign attestation votes
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        e3Id,
        operatorAddress,
        await slashingManager.getAddress(),
      );

      // Anyone can submit the signed attestation evidence (permissionless for Lane A)
      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(e3Id, operatorAddress, proof),
      ).to.emit(slashingManager, "SlashProposed");

      // Proof-based slashes auto-execute
      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.operator).to.equal(operatorAddress);
      expect(proposal.reason).to.equal(REASON_PT_0);
      expect(proposal.proofVerified).to.be.true;
      expect(proposal.executed).to.be.true;
      expect(proposal.proposer).to.equal(await proposer.getAddress());
    });

    it("should revert if committee attestation has insufficient votes", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      // Threshold is 2 but only 1 vote provided
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);

      const proof = await signAndEncodeAttestation(
        [voter1], // only 1 voter, need 2
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "InsufficientAttestations",
      );
    });

    it("should revert if vote signature is invalid", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        notTheOwner,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);

      // Build attestation manually with voter2's address but notTheOwner's
      // signature. The helper cannot forge identity mismatches because it
      // derives voter addresses from each signer's getAddress().
      const chainId = 31337;
      const verifyingContract = await slashingManager.getAddress();
      const accusationId = ethers.keccak256(
        ethers.solidityPacked(
          ["uint256", "uint256", "address", "uint256"],
          [chainId, 0, operatorAddress, 0],
        ),
      );
      const deadline = ethers.MaxUint256;
      const evidence = ethers.hexlify(ethers.toUtf8Bytes("invalid-signature"));
      const evidenceHash = ethers.keccak256(evidence);

      // Sort voters ascending
      const sortedVoters = [voter1Addr, voter2Addr].sort((a, b) =>
        a.toLowerCase() < b.toLowerCase() ? -1 : 1,
      );
      const sortedSigners = sortedVoters.map((addr) =>
        addr.toLowerCase() === voter1Addr.toLowerCase() ? voter1 : voter2,
      );

      const domain = {
        name: "InterfoldSlashing",
        version: "1",
        chainId,
        verifyingContract,
      };
      const types = {
        AccusationVote: [
          { name: "e3Id", type: "uint256" },
          { name: "accusationId", type: "bytes32" },
          { name: "voter", type: "address" },
          { name: "dataHash", type: "bytes32" },
          { name: "deadline", type: "uint256" },
        ],
      };

      const voters: string[] = [];
      const dataHashes: string[] = [];
      const signatures: string[] = [];

      // Keep `dataHash == keccak256(evidence)` so this test isolates
      // signature forgery and reverts with InvalidVoteSignature.
      for (let i = 0; i < sortedVoters.length; i++) {
        const voterAddr = sortedVoters[i];
        voters.push(voterAddr);
        dataHashes.push(evidenceHash);

        // For the second voter, use notTheOwner to sign (wrong signer)
        const signerToUse =
          i === sortedVoters.length - 1 ? notTheOwner : sortedSigners[i];
        const value = {
          e3Id: 0,
          accusationId,
          voter: voterAddr,
          dataHash: evidenceHash,
          deadline,
        };
        const signature = await signerToUse.signTypedData(domain, types, value);
        signatures.push(signature);
      }

      const proof = abiCoder.encode(
        ["uint256", "address[]", "bytes32[]", "bytes", "uint256", "bytes[]"],
        [0, voters, dataHashes, evidence, deadline, signatures],
      );

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidVoteSignature");
    });

    it("should revert if voter is not in committee", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      // Only voter1 is a committee member, but voter2 also signs
      const voter1Addr = await voter1.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 1);

      const proof = await signAndEncodeAttestation(
        [voter1, voter2], // voter2 is NOT in committee
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "VoterNotInCommittee");
    });

    it("should revert if evidence preimage does not match signed dataHash", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      const e3Id = 0;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(e3Id, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(e3Id, 2);

      const evidence = ethers.hexlify(
        ethers.toUtf8Bytes("mismatched-preimage"),
      );
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        e3Id,
        operatorAddress,
        await slashingManager.getAddress(),
        0,
        31337,
        evidence,
        ethers.MaxUint256,
        ethers.ZeroHash, // deliberately mismatched vs keccak256(evidence)
      );

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(e3Id, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidProof");
    });

    it("should revert if attestation deadline has expired", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      const e3Id = 0;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(e3Id, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(e3Id, 2);

      const latest = await ethers.provider.getBlock("latest");
      const expiredDeadline = BigInt((latest?.timestamp ?? 0) - 1);
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        e3Id,
        operatorAddress,
        await slashingManager.getAddress(),
        0,
        31337,
        ethers.ZeroHash,
        expiredDeadline,
      );

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(e3Id, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "SignatureExpired");
    });

    it("should revert if operator is zero address", async function () {
      const { slashingManager, proposer } = await loadFixture(setup);

      await setupPolicies(slashingManager);

      const proof = encodeDummyAttestation();

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, ethers.ZeroAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "ZeroAddress");
    });

    it("should revert if slash reason is disabled", async function () {
      const { slashingManager, proposer, operatorAddress } =
        await loadFixture(setup);

      const proof = encodeDummyAttestation();

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "SlashReasonDisabled");
    });

    it("should revert if proof is empty", async function () {
      const { slashingManager, proposer, operatorAddress } =
        await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, "0x"),
      ).to.be.revertedWithCustomError(slashingManager, "ProofRequired");
    });

    it("should reject duplicate evidence", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);
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
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      // Same proof for same e3Id/operator/reason should be rejected
      await expect(
        slashingManager
          .connect(proposer)
          .proposeSlash(0, operatorAddress, proof),
      ).to.be.revertedWithCustomError(slashingManager, "DuplicateEvidence");
    });

    it("should increment totalProposals", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      await setupPolicies(slashingManager);

      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);
      await mockCiphernodeRegistry.setCommitteeNodes(1, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(1, 2);

      expect(await slashingManager.totalProposals()).to.equal(0);

      const proof1 = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof1);

      expect(await slashingManager.totalProposals()).to.equal(1);

      const proof2 = await signAndEncodeAttestation(
        [voter1, voter2],
        1,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await slashingManager
        .connect(proposer)
        .proposeSlash(1, operatorAddress, proof2);

      expect(await slashingManager.totalProposals()).to.equal(2);
    });

    it("should ban node when policy requires it", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      await setupPolicies(slashingManager);

      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);

      expect(await slashingManager.isBanned(operatorAddress)).to.be.false;

      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
        1, // proofType=1 maps to REASON_PT_1 (ban policy)
      );
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      // banNode=true → auto-executed → node is now banned
      expect(await slashingManager.isBanned(operatorAddress)).to.be.true;
    });

    it("should propose slash via DKG partyId attribution", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      const e3Id = 0;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(e3Id, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(e3Id, 2);
      await (mockCiphernodeRegistry as any).setDkgAnchors(
        e3Id,
        [0],
        [ethers.id("sk-0")],
        [ethers.id("esm-0")],
      );

      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        e3Id,
        operatorAddress,
        await slashingManager.getAddress(),
      );

      await expect(
        (slashingManager as any)
          .connect(proposer)
          .proposeSlashByDkgParty(e3Id, 0, proof),
      ).to.emit(slashingManager, "SlashProposed");
    });

    it("should revert if partyId is not in stored DKG anchors", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      const proofPolicy = buildProofPolicy();
      await slashingManager.setSlashPolicy(REASON_PT_0, proofPolicy);

      const e3Id = 0;
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(e3Id, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(e3Id, 2);
      await (mockCiphernodeRegistry as any).setDkgAnchors(
        e3Id,
        [1],
        [ethers.id("sk-1")],
        [ethers.id("esm-1")],
      );

      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        e3Id,
        operatorAddress,
        await slashingManager.getAddress(),
      );

      await expect(
        (slashingManager as any)
          .connect(proposer)
          .proposeSlashByDkgParty(e3Id, 0, proof),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "PartyIdNotInDkgAnchors",
      );
    });
  });

  describe("proposeSlashEvidence() — Lane B (evidence-based, SLASHER_ROLE)", function () {
    it("should propose evidence-based slash with appeal window", async function () {
      const { slashingManager, slasher, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      const evidence = ethers.toUtf8Bytes("operator was inactive during E3");
      const e3Id = 0;

      await expect(
        slashingManager
          .connect(slasher)
          .proposeSlashEvidence(
            e3Id,
            operatorAddress,
            REASON_INACTIVITY,
            evidence,
          ),
      ).to.emit(slashingManager, "SlashProposed");

      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.operator).to.equal(operatorAddress);
      expect(proposal.reason).to.equal(REASON_INACTIVITY);
      expect(proposal.proofVerified).to.be.false;
      expect(proposal.executed).to.be.false;
      expect(proposal.proposer).to.equal(await slasher.getAddress());
      expect(proposal.executableAt).to.be.gt(proposal.proposedAt);
    });

    it("should revert if caller is not slasher", async function () {
      const { slashingManager, notTheOwner, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      const evidence = ethers.toUtf8Bytes("evidence");

      await expect(
        slashingManager
          .connect(notTheOwner)
          .proposeSlashEvidence(
            0,
            operatorAddress,
            REASON_INACTIVITY,
            evidence,
          ),
      ).to.be.revertedWithCustomError(slashingManager, "Unauthorized");
    });

    it("should revert if operator is zero address", async function () {
      const { slashingManager, slasher } = await loadFixture(setup);

      await setupPolicies(slashingManager);

      await expect(
        slashingManager
          .connect(slasher)
          .proposeSlashEvidence(
            0,
            ethers.ZeroAddress,
            REASON_INACTIVITY,
            ethers.toUtf8Bytes(""),
          ),
      ).to.be.revertedWithCustomError(slashingManager, "ZeroAddress");
    });
  });

  describe("executeSlash() — Lane B execution", function () {
    it("should execute evidence-based slash after appeal window", async function () {
      const { slashingManager, slasher, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );

      // Should revert before appeal window expires
      await expect(
        slashingManager.executeSlash(0),
      ).to.be.revertedWithCustomError(slashingManager, "AppealWindowActive");

      // Fast forward past appeal window
      await time.increase(APPEAL_WINDOW + 1);

      await expect(slashingManager.executeSlash(0)).to.emit(
        slashingManager,
        "SlashExecuted",
      );

      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.executed).to.be.true;
    });

    it("should revert if proof-based slash tries to executeSlash separately", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      await setupPolicies(slashingManager);
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);

      // Proof-based slash auto-executes in proposeSlash
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      // Should revert because already executed
      await expect(
        slashingManager.executeSlash(0),
      ).to.be.revertedWithCustomError(slashingManager, "AlreadyExecuted");
    });

    it("should revert if proposal doesn't exist", async function () {
      const { slashingManager } = await loadFixture(setup);

      await expect(
        slashingManager.executeSlash(999),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidProposal");
    });

    it("should revert if already executed", async function () {
      const { slashingManager, slasher, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );

      await time.increase(APPEAL_WINDOW + 1);
      await slashingManager.executeSlash(0);

      await expect(
        slashingManager.executeSlash(0),
      ).to.be.revertedWithCustomError(slashingManager, "AlreadyExecuted");
    });
  });

  describe("appeal system", function () {
    it("should allow operator to file appeal on evidence-based slash", async function () {
      const { slashingManager, slasher, operator, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );

      const evidence = "I was not inactive, here's the proof...";

      await expect(slashingManager.connect(operator).fileAppeal(0, evidence))
        .to.emit(slashingManager, "AppealFiled")
        .withArgs(0, operatorAddress, REASON_INACTIVITY, evidence);

      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.appealed).to.be.true;
    });

    it("should revert if non-operator tries to appeal", async function () {
      const { slashingManager, slasher, notTheOwner, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );

      await expect(
        slashingManager.connect(notTheOwner).fileAppeal(0, "Not my appeal"),
      ).to.be.revertedWithCustomError(slashingManager, "Unauthorized");
    });

    it("should revert if appeal window expired", async function () {
      const { slashingManager, slasher, operator, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );

      await time.increase(APPEAL_WINDOW + 1);

      await expect(
        slashingManager.connect(operator).fileAppeal(0, "Too late"),
      ).to.be.revertedWithCustomError(slashingManager, "AppealWindowExpired");
    });

    it("should revert if already appealed", async function () {
      const { slashingManager, slasher, operator, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );

      await slashingManager.connect(operator).fileAppeal(0, "First appeal");

      await expect(
        slashingManager.connect(operator).fileAppeal(0, "Second appeal"),
      ).to.be.revertedWithCustomError(slashingManager, "AlreadyAppealed");
    });

    it("should revert if appealing proof-verified slash", async function () {
      const {
        slashingManager,
        proposer,
        operator,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      await setupPolicies(slashingManager);
      const voter1Addr = await voter1.getAddress();
      const voter2Addr = await voter2.getAddress();
      await mockCiphernodeRegistry.setCommitteeNodes(0, [
        operatorAddress,
        voter1Addr,
        voter2Addr,
      ]);
      await mockCiphernodeRegistry.setThreshold(0, 2);

      // Proof-based slash auto-executes with proofVerified=true
      const proof = await signAndEncodeAttestation(
        [voter1, voter2],
        0,
        operatorAddress,
        await slashingManager.getAddress(),
      );
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      // Cannot appeal proof-verified slashes whose policy has appealWindow == 0:
      // they auto-execute inside `proposeSlash`, so the proposal is already
      // marked executed by the time the accused tries to file an appeal.
      await expect(
        slashingManager.connect(operator).fileAppeal(0, "Cannot appeal proof"),
      ).to.be.revertedWithCustomError(slashingManager, "AlreadyExecuted");
    });

    it("should allow governance to resolve appeal (approve)", async function () {
      const { slashingManager, slasher, operator, owner, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );
      await slashingManager.connect(operator).fileAppeal(0, "Evidence");

      const resolution = "Appeal approved after review";

      await expect(
        slashingManager.connect(owner).resolveAppeal(0, true, resolution),
      )
        .to.emit(slashingManager, "AppealResolved")
        .withArgs(
          0,
          operatorAddress,
          true,
          await owner.getAddress(),
          resolution,
        );

      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.resolved).to.be.true;
      expect(proposal.appealUpheld).to.be.true;
    });

    it("should allow governance to resolve appeal (deny)", async function () {
      const { slashingManager, slasher, operator, owner, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );
      await slashingManager.connect(operator).fileAppeal(0, "Evidence");

      await slashingManager
        .connect(owner)
        .resolveAppeal(0, false, "Appeal denied");

      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.resolved).to.be.true;
      expect(proposal.appealUpheld).to.be.false;
    });

    it("should block execution if appeal is pending", async function () {
      const { slashingManager, slasher, operator, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );
      await slashingManager.connect(operator).fileAppeal(0, "Evidence");

      await time.increase(APPEAL_WINDOW + 1);

      await expect(
        slashingManager.executeSlash(0),
      ).to.be.revertedWithCustomError(slashingManager, "AppealPending");
    });

    it("should block execution if appeal was approved", async function () {
      const { slashingManager, slasher, operator, owner, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );
      await slashingManager.connect(operator).fileAppeal(0, "Evidence");
      await slashingManager.connect(owner).resolveAppeal(0, true, "Approved");

      await time.increase(APPEAL_WINDOW + 1);

      await expect(
        slashingManager.executeSlash(0),
      ).to.be.revertedWithCustomError(slashingManager, "AppealUpheld");
    });

    it("should allow execution if appeal was denied", async function () {
      const { slashingManager, slasher, operator, owner, operatorAddress } =
        await loadFixture(setup);

      await setupPolicies(slashingManager);

      await slashingManager
        .connect(slasher)
        .proposeSlashEvidence(
          0,
          operatorAddress,
          REASON_INACTIVITY,
          ethers.toUtf8Bytes("evidence"),
        );
      await slashingManager.connect(operator).fileAppeal(0, "Evidence");
      await slashingManager.connect(owner).resolveAppeal(0, false, "Denied");

      await time.increase(APPEAL_WINDOW + 1);

      await expect(slashingManager.executeSlash(0)).to.emit(
        slashingManager,
        "SlashExecuted",
      );
    });
  });

  describe("ban management (two-step M-15)", function () {
    it("should ban a node via two-step propose/confirm with distinct governance signers", async function () {
      const { slashingManager, owner, notTheOwner, operatorAddress } =
        await loadFixture(setup);

      // Grant GOVERNANCE_ROLE to a second account so we can satisfy the
      // "distinct proposer/confirmer" constraint.
      const GOVERNANCE_ROLE = await slashingManager.GOVERNANCE_ROLE();
      await slashingManager
        .connect(owner)
        .grantRole(GOVERNANCE_ROLE, await notTheOwner.getAddress());

      const reason = ethers.encodeBytes32String("manual_ban");

      await expect(
        slashingManager.connect(owner).proposeBan(operatorAddress, reason),
      )
        .to.emit(slashingManager, "BanProposed")
        .withArgs(operatorAddress, reason, await owner.getAddress());

      // Same proposer cannot confirm \u2014 enforces two-of-N.
      await expect(
        slashingManager.connect(owner).confirmBan(operatorAddress, reason),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "BanRequiresConfirmation",
      );

      await expect(
        slashingManager
          .connect(notTheOwner)
          .confirmBan(operatorAddress, reason),
      )
        .to.emit(slashingManager, "NodeBanUpdated")
        .withArgs(
          operatorAddress,
          true,
          reason,
          await notTheOwner.getAddress(),
        );

      expect(await slashingManager.isBanned(operatorAddress)).to.be.true;
    });

    it("should allow governance to unban via unbanNode() (single step)", async function () {
      const { slashingManager, owner, notTheOwner, operatorAddress } =
        await loadFixture(setup);

      const GOVERNANCE_ROLE = await slashingManager.GOVERNANCE_ROLE();
      await slashingManager
        .connect(owner)
        .grantRole(GOVERNANCE_ROLE, await notTheOwner.getAddress());

      const reason = ethers.encodeBytes32String("test");
      await slashingManager.connect(owner).proposeBan(operatorAddress, reason);
      await slashingManager
        .connect(notTheOwner)
        .confirmBan(operatorAddress, reason);
      expect(await slashingManager.isBanned(operatorAddress)).to.be.true;

      await expect(
        slashingManager.connect(owner).unbanNode(operatorAddress, reason),
      )
        .to.emit(slashingManager, "NodeBanUpdated")
        .withArgs(operatorAddress, false, reason, await owner.getAddress());

      expect(await slashingManager.isBanned(operatorAddress)).to.be.false;
    });

    it("should allow governance to cancel a pending ban proposal", async function () {
      const { slashingManager, owner, operatorAddress } =
        await loadFixture(setup);

      const reason = ethers.encodeBytes32String("manual_ban");
      await slashingManager.connect(owner).proposeBan(operatorAddress, reason);

      await expect(slashingManager.connect(owner).cancelBan(operatorAddress))
        .to.emit(slashingManager, "BanCancelled")
        .withArgs(operatorAddress, await owner.getAddress());

      // After cancel, confirm should revert NoPendingBan.
      await expect(
        slashingManager.connect(owner).confirmBan(operatorAddress, reason),
      ).to.be.revertedWithCustomError(slashingManager, "NoPendingBan");
    });

    it("should revert updateBanStatus(true,...) (legacy single-step ban path is locked)", async function () {
      const { slashingManager, owner, operatorAddress } =
        await loadFixture(setup);

      await expect(
        slashingManager
          .connect(owner)
          .updateBanStatus(
            operatorAddress,
            true,
            ethers.encodeBytes32String("test"),
          ),
      ).to.be.revertedWithCustomError(
        slashingManager,
        "BanRequiresConfirmation",
      );
    });

    it("should revert if non-governance tries to ban", async function () {
      const { slashingManager, notTheOwner, operatorAddress } =
        await loadFixture(setup);

      await expect(
        slashingManager
          .connect(notTheOwner)
          .proposeBan(operatorAddress, ethers.encodeBytes32String("test")),
      ).to.be.revertedWithCustomError(slashingManager, "Unauthorized");
    });
  });

  describe("view functions", function () {
    it("should return correct slash policy", async function () {
      const { slashingManager, _mockVerifier } = await loadFixture(setup);

      const policy = {
        ticketPenalty: ethers.parseUnits("50", 6),
        licensePenalty: ethers.parseEther("100"),
        requiresProof: true,
        proofVerifier: await _mockVerifier.getAddress(),
        banNode: true,
        appealWindow: 0,
        enabled: true,
        affectsCommittee: false,
        failureReason: 0,
      };

      await slashingManager.setSlashPolicy(REASON_PT_0, policy);

      const retrieved = await slashingManager.getSlashPolicy(REASON_PT_0);
      expect(retrieved.ticketPenalty).to.equal(policy.ticketPenalty);
      expect(retrieved.licensePenalty).to.equal(policy.licensePenalty);
      expect(retrieved.requiresProof).to.equal(policy.requiresProof);
      expect(retrieved.proofVerifier).to.equal(policy.proofVerifier);
      expect(retrieved.banNode).to.equal(policy.banNode);
      expect(retrieved.appealWindow).to.equal(policy.appealWindow);
      expect(retrieved.enabled).to.equal(policy.enabled);
      expect(retrieved.affectsCommittee).to.equal(policy.affectsCommittee);
      expect(retrieved.failureReason).to.equal(policy.failureReason);
    });

    it("should return correct slash proposal", async function () {
      const {
        slashingManager,
        proposer,
        operatorAddress,
        voter1,
        voter2,
        mockCiphernodeRegistry,
      } = await loadFixture(setup);

      await setupPolicies(slashingManager);
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
      await slashingManager
        .connect(proposer)
        .proposeSlash(0, operatorAddress, proof);

      const proposal = await slashingManager.getSlashProposal(0);
      expect(proposal.operator).to.equal(operatorAddress);
      expect(proposal.reason).to.equal(REASON_PT_0);
      expect(proposal.ticketAmount).to.equal(ethers.parseUnits("50", 6));
      expect(proposal.licenseAmount).to.equal(ethers.parseEther("100"));
      expect(proposal.proposer).to.equal(await proposer.getAddress());
      expect(proposal.proofHash).to.equal(ethers.keccak256(proof));
      expect(proposal.proofVerified).to.be.true;
      expect(proposal.executed).to.be.true;
    });

    it("should revert for invalid proposal ID", async function () {
      const { slashingManager } = await loadFixture(setup);

      await expect(
        slashingManager.getSlashProposal(999),
      ).to.be.revertedWithCustomError(slashingManager, "InvalidProposal");
    });
  });
});
