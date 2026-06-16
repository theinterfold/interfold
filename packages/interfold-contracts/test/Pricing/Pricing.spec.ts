// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  DATA as data,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  PROOF as proof,
  setupAndPublishCommittee,
} from "../fixtures";

const { loadFixture, time, mine } = networkHelpers;

describe("E3 Pricing", function () {
  // Default pricing config matching initialize() defaults
  const defaultPricingConfig = {
    keyGenFixedPerNode: 100000n,
    keyGenPerEncryptionProof: 50000n,
    coordinationPerPair: 10000n,
    availabilityPerNodePerSec: 50n,
    decryptionPerNode: 300000n,
    publicationBase: 1000000n,
    verificationPerProof: 5000n,
    protocolTreasury: ethers.ZeroAddress,
    marginBps: 1500,
    protocolShareBps: 0,
    dkgUtilizationBps: 2500,
    computeUtilizationBps: 5000,
    decryptUtilizationBps: 2500,
    minCommitteeSize: 0,
    minThreshold: 0,
  };

  // Convert ethers Result to a plain object that can be spread
  const toPlainConfig = (pc: any) => ({
    keyGenFixedPerNode: pc.keyGenFixedPerNode,
    keyGenPerEncryptionProof: pc.keyGenPerEncryptionProof,
    coordinationPerPair: pc.coordinationPerPair,
    availabilityPerNodePerSec: pc.availabilityPerNodePerSec,
    decryptionPerNode: pc.decryptionPerNode,
    publicationBase: pc.publicationBase,
    verificationPerProof: pc.verificationPerProof,
    protocolTreasury: pc.protocolTreasury,
    marginBps: pc.marginBps,
    protocolShareBps: pc.protocolShareBps,
    dkgUtilizationBps: pc.dkgUtilizationBps,
    computeUtilizationBps: pc.computeUtilizationBps,
    decryptUtilizationBps: pc.decryptUtilizationBps,
    minCommitteeSize: pc.minCommitteeSize,
    minThreshold: pc.minThreshold,
  });

  const inputWindowDuration = 300;
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const setup = async () => {
    // Pricing.spec.ts historically used signers[5] as the treasury.
    const signers = await ethers.getSigners();
    const treasurySigner = signers[5];
    const sys = await deployInterfoldSystem({
      treasury: treasurySigner,
      wireSlashingManager: false,
    });
    await mine(1);
    return {
      owner: sys.owner,
      notTheOwner: sys.notTheOwner,
      operator1: sys.operator1!,
      operator2: sys.operator2!,
      operator3: sys.operator3!,
      treasury: treasurySigner,
      interfold: sys.interfold,
      ciphernodeRegistryContract: sys.ciphernodeRegistry,
      bondingRegistry: sys.bondingRegistry,
      licenseToken: sys.licenseToken,
      ticketToken: sys.ticketToken,
      usdcToken: sys.usdcToken,
      slashingManager: sys.slashingManager,
      e3RefundManager: sys.e3RefundManager,
      request: sys.request,
      mocks: sys.mocks,
    };
  };

  // ──────────────────────────────────────────────────────────────────────────
  //  getE3Quote() — Parametric Fee Calculation
  // ──────────────────────────────────────────────────────────────────────────

  describe("getE3Quote()", function () {
    it("returns a fee based on BaseCosts, committee size, and duration", async function () {
      const { interfold, request } = await loadFixture(setup);

      const fee = await interfold.getE3Quote(request);
      // Fee must be > 0 with default baseCosts
      expect(fee).to.be.gt(0);
    });

    it("computes fee correctly using the parametric formula", async function () {
      const { interfold, request, ciphernodeRegistryContract } =
        await loadFixture(setup);

      // Get the resolved threshold for Minimum (committeeSize = 0) → [1, 3]
      const n = 3n; // total committee
      const m = 1n; // quorum

      // Get pricing config
      const pc = await interfold.getPricingConfig();

      // Get timeout config
      const config = await interfold.getTimeoutConfig();
      const sortitionWindow =
        await ciphernodeRegistryContract.sortitionSubmissionWindow();
      const duration =
        sortitionWindow +
        (BigInt(request.inputWindow[1]) - BigInt(request.inputWindow[0])) +
        // M-06: sum BPS-weighted windows first then divide once. With the
        // default config (windows=3600, bps=2500/5000/2500) the per-term and
        // sum-then-divide formulas coincide, but this matches the on-chain
        // implementation and the dedicated DurationPrecision tests.
        (config.dkgWindow * BigInt(pc.dkgUtilizationBps) +
          config.computeWindow * BigInt(pc.computeUtilizationBps) +
          config.decryptionWindow * BigInt(pc.decryptUtilizationBps)) /
          10000n;

      // Calculate expected fee (proof-aware): proofsPerNode = 14 + 4 × (N-1)
      const proofsPerNode = 14n + 4n * (n - 1n);
      let baseFee = pc.keyGenFixedPerNode * n;
      baseFee += pc.keyGenPerEncryptionProof * n * proofsPerNode;
      if (n > 1n) baseFee += (pc.coordinationPerPair * n * (n - 1n)) / 2n;
      baseFee += pc.verificationPerProof * n * proofsPerNode;
      baseFee += pc.availabilityPerNodePerSec * n * duration;
      baseFee += pc.decryptionPerNode * m;
      if (m > 1n) baseFee += (pc.coordinationPerPair * m * (m - 1n)) / 2n;
      baseFee += pc.publicationBase;

      const marginBps = pc.marginBps;
      const expectedFee = (baseFee * (10000n + BigInt(marginBps))) / 10000n;

      const actualFee = await interfold.getE3Quote(request);
      expect(actualFee).to.equal(expectedFee);
    });

    it("fee increases with larger committee size", async function () {
      const { interfold, request } = await loadFixture(setup);

      const minimumFee = await interfold.getE3Quote(request);

      // Build request with Micro committee (larger)
      const now = await time.latest();
      const microRequest = {
        ...request,
        committeeSize: 1, // Micro → [4, 9]
        inputWindow: [now + 10, now + inputWindowDuration] as [number, number],
      };
      const microFee = await interfold.getE3Quote(microRequest);

      expect(microFee).to.be.gt(minimumFee);
    });

    it("fee increases with longer input window", async function () {
      const { interfold, request } = await loadFixture(setup);

      const shortFee = await interfold.getE3Quote(request);

      const now = await time.latest();
      const longRequest = {
        ...request,
        inputWindow: [now + 10, now + 3600] as [number, number], // 1 hour vs 5min
      };
      const longFee = await interfold.getE3Quote(longRequest);

      expect(longFee).to.be.gt(shortFee);
    });

    it("fee reflects margin changes", async function () {
      const { interfold, request } = await loadFixture(setup);

      const fee10Pct = await interfold.getE3Quote(request);

      // Set margin to 20%
      const pc = toPlainConfig(await interfold.getPricingConfig());
      await interfold.setPricingConfig({ ...pc, marginBps: 2000 });
      const fee20Pct = await interfold.getE3Quote(request);

      expect(fee20Pct).to.be.gt(fee10Pct);

      // Set margin to 0%
      const pc2 = toPlainConfig(await interfold.getPricingConfig());
      await interfold.setPricingConfig({ ...pc2, marginBps: 0 });
      const feeZero = await interfold.getE3Quote(request);

      expect(feeZero).to.be.lt(fee10Pct);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  //  setPricingConfig() — Governance
  // ──────────────────────────────────────────────────────────────────────────

  describe("setPricingConfig()", function () {
    it("reverts if not called by owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);
      await expect(
        interfold.connect(notTheOwner).setPricingConfig(defaultPricingConfig),
      ).to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount");
    });

    it("updates config and emits event", async function () {
      const { interfold } = await loadFixture(setup);
      const newConfig = {
        ...defaultPricingConfig,
        keyGenFixedPerNode: 100000n,
        keyGenPerEncryptionProof: 50000n,
        coordinationPerPair: 10000n,
        availabilityPerNodePerSec: 40n,
        decryptionPerNode: 300000n,
        publicationBase: 1000000n,
      };

      await expect(interfold.setPricingConfig(newConfig)).to.emit(
        interfold,
        "PricingConfigUpdated",
      );

      const stored = await interfold.getPricingConfig();
      expect(stored.keyGenFixedPerNode).to.equal(100000n);
      expect(stored.keyGenPerEncryptionProof).to.equal(50000n);
      expect(stored.coordinationPerPair).to.equal(10000n);
      expect(stored.availabilityPerNodePerSec).to.equal(40n);
      expect(stored.decryptionPerNode).to.equal(300000n);
      expect(stored.publicationBase).to.equal(1000000n);
    });

    it("changes the fee returned by getE3Quote", async function () {
      const { interfold, request } = await loadFixture(setup);

      const feeBefore = await interfold.getE3Quote(request);

      // Double base costs
      await interfold.setPricingConfig({
        ...defaultPricingConfig,
        keyGenFixedPerNode: 200000n,
        keyGenPerEncryptionProof: 100000n,
        coordinationPerPair: 20000n,
        availabilityPerNodePerSec: 100n,
        decryptionPerNode: 600000n,
        publicationBase: 2000000n,
      });

      const feeAfter = await interfold.getE3Quote(request);
      expect(feeAfter).to.be.gt(feeBefore);
    });

    it("reverts if margin exceeds 100%", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(
        interfold.setPricingConfig({
          ...defaultPricingConfig,
          marginBps: 10001,
        }),
      ).to.be.revertedWithCustomError(interfold, "BpsExceedsMax");
    });

    it("allows setting margin to 0", async function () {
      const { interfold } = await loadFixture(setup);
      await interfold.setPricingConfig({
        ...defaultPricingConfig,
        marginBps: 0,
      });
      const pc = await interfold.getPricingConfig();
      expect(pc.marginBps).to.equal(0);
    });

    it("reverts if protocolShareBps exceeds 100%", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(
        interfold.setPricingConfig({
          ...defaultPricingConfig,
          protocolShareBps: 10001,
        }),
      ).to.be.revertedWithCustomError(interfold, "BpsExceedsMax");
    });

    it("reverts if minCommitteeSize < minThreshold", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(
        interfold.setPricingConfig({
          ...defaultPricingConfig,
          minCommitteeSize: 2,
          minThreshold: 5,
        }),
      ).to.be.revertedWithCustomError(interfold, "MinSizeBelowMinThreshold");
    });

    it("enforces bounds on setCommitteeThresholds", async function () {
      const { interfold } = await loadFixture(setup);

      // Set minimum bounds via pricing config
      await interfold.setPricingConfig({
        ...defaultPricingConfig,
        minCommitteeSize: 5,
        minThreshold: 3,
      });

      // Should fail: committee size 4 < min 5
      await expect(
        interfold.setCommitteeThresholds(0, [3, 4]),
      ).to.be.revertedWithCustomError(interfold, "BelowMinCommitteeSize");

      // Should fail: threshold 2 < min 3
      await expect(
        interfold.setCommitteeThresholds(0, [2, 6]),
      ).to.be.revertedWithCustomError(interfold, "BelowMinThreshold");

      // Should succeed: meets both minimums
      await expect(
        interfold.setCommitteeThresholds(0, [3, 5]),
      ).to.not.be.revert(ethers);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  //  Protocol Treasury Share on Reward Distribution
  // ──────────────────────────────────────────────────────────────────────────

  describe("Protocol treasury share on success", function () {
    it("sends 100% to CNs when protocolShareBps is 0 (default)", async function () {
      const {
        interfold,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks: { decryptionVerifier, e3Program },
      } = await loadFixture(setup);

      // Build a fresh request with current timestamps
      const now = await time.latest();
      const freshRequest = {
        committeeSize: 0,
        inputWindow: [now + 100, now + inputWindowDuration + 100] as [
          number,
          number,
        ],
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

      // Make request with large approval to avoid fee mismatch
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      await interfold.request(freshRequest);
      const e3Id = 0;
      const fee = await interfold.e3Payments(e3Id);

      // Setup committee
      const nodes = [
        await operator1.getAddress(),
        await operator2.getAddress(),
        await operator3.getAddress(),
      ];
      await setupAndPublishCommittee(
        ciphernodeRegistryContract,
        e3Id,
        "0x1234",
        [operator1, operator2, operator3],
      );

      // Publish ciphertext
      await time.increase(inputWindowDuration + 200);
      await interfold.publishCiphertextOutput(e3Id, data, proof);

      // Record operator balances before distribution
      const op1Before = await usdcToken.balanceOf(nodes[0]);
      const op2Before = await usdcToken.balanceOf(nodes[1]);
      const op3Before = await usdcToken.balanceOf(nodes[2]);

      // Publish plaintext (triggers _distributeRewards)
      await interfold.publishPlaintextOutput(e3Id, data, proof);

      // Pull-payment: each operator claims their reward.
      for (const op of [operator1, operator2, operator3]) {
        await interfold.connect(op).claimReward(e3Id);
      }

      const op1After = await usdcToken.balanceOf(nodes[0]);
      const op2After = await usdcToken.balanceOf(nodes[1]);
      const op3After = await usdcToken.balanceOf(nodes[2]);

      // All fee distributed to operators (100%, no protocol share)
      const totalDistributed =
        op1After - op1Before + (op2After - op2Before) + (op3After - op3Before);
      expect(totalDistributed).to.equal(fee);
    });

    it("splits fee between CNs and treasury when protocolShareBps > 0", async function () {
      const {
        interfold,
        usdcToken,
        ciphernodeRegistryContract,
        treasury,
        operator1,
        operator2,
        operator3,
        mocks: { decryptionVerifier, e3Program },
      } = await loadFixture(setup);

      // Configure 20% protocol share
      const treasuryAddr = await treasury.getAddress();
      await interfold.setPricingConfig({
        ...defaultPricingConfig,
        protocolTreasury: treasuryAddr,
        protocolShareBps: 2000,
      });

      // Build a fresh request with current timestamps
      const now = await time.latest();
      const freshRequest = {
        committeeSize: 0,
        inputWindow: [now + 100, now + inputWindowDuration + 100] as [
          number,
          number,
        ],
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

      // Make request with large approval
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      await interfold.request(freshRequest);
      const e3Id = 0;
      const fee = await interfold.e3Payments(e3Id);

      // Setup committee
      const nodes = [
        await operator1.getAddress(),
        await operator2.getAddress(),
        await operator3.getAddress(),
      ];
      await setupAndPublishCommittee(
        ciphernodeRegistryContract,
        e3Id,
        "0x1234",
        [operator1, operator2, operator3],
      );

      // Publish outputs
      await time.increase(inputWindowDuration + 200);
      await interfold.publishCiphertextOutput(e3Id, data, proof);

      const treasuryBefore = await usdcToken.balanceOf(treasuryAddr);
      const op1Before = await usdcToken.balanceOf(nodes[0]);
      const op2Before = await usdcToken.balanceOf(nodes[1]);
      const op3Before = await usdcToken.balanceOf(nodes[2]);

      await interfold.publishPlaintextOutput(e3Id, data, proof);

      // Pull-payment: treasury & operators claim.
      await interfold
        .connect(treasury)
        .treasuryClaim(await usdcToken.getAddress());
      for (const op of [operator1, operator2, operator3]) {
        await interfold.connect(op).claimReward(e3Id);
      }

      const treasuryAfter = await usdcToken.balanceOf(treasuryAddr);
      const op1After = await usdcToken.balanceOf(nodes[0]);
      const op2After = await usdcToken.balanceOf(nodes[1]);
      const op3After = await usdcToken.balanceOf(nodes[2]);

      const expectedProtocol = (fee * 2000n) / 10000n;
      const expectedCN = fee - expectedProtocol;
      const totalOpDistributed =
        op1After - op1Before + (op2After - op2Before) + (op3After - op3Before);

      expect(treasuryAfter - treasuryBefore).to.equal(expectedProtocol);
      expect(totalOpDistributed).to.equal(expectedCN);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  //  Default Pricing Parameters (set in initialize)
  // ──────────────────────────────────────────────────────────────────────────

  describe("Default pricing parameters", function () {
    it("has correct default pricing config from initialize", async function () {
      const { interfold } = await loadFixture(setup);
      const pc = await interfold.getPricingConfig();
      expect(pc.keyGenFixedPerNode).to.equal(100000);
      expect(pc.keyGenPerEncryptionProof).to.equal(50000);
      expect(pc.coordinationPerPair).to.equal(10000);
      expect(pc.availabilityPerNodePerSec).to.equal(50);
      expect(pc.decryptionPerNode).to.equal(300000);
      expect(pc.publicationBase).to.equal(1000000);
      expect(pc.verificationPerProof).to.equal(5000);
      expect(pc.marginBps).to.equal(1500);
      expect(pc.protocolShareBps).to.equal(0);
      expect(pc.dkgUtilizationBps).to.equal(2500);
      expect(pc.computeUtilizationBps).to.equal(5000);
      expect(pc.decryptUtilizationBps).to.equal(2500);
      expect(pc.protocolTreasury).to.equal(ethers.ZeroAddress);
      expect(pc.minCommitteeSize).to.equal(0);
      expect(pc.minThreshold).to.equal(0);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  //  E3 Request with Parametric Pricing (end-to-end)
  // ──────────────────────────────────────────────────────────────────────────

  describe("End-to-end request with parametric pricing", function () {
    it("charges the computed fee and completes successfully", async function () {
      const { interfold, usdcToken, request, owner } = await loadFixture(setup);

      const fee = await interfold.getE3Quote(request);
      const ownerAddr = await owner.getAddress();
      const balanceBefore = await usdcToken.balanceOf(ownerAddr);

      await usdcToken.approve(await interfold.getAddress(), fee);
      await interfold.request(request);

      const balanceAfter = await usdcToken.balanceOf(ownerAddr);
      expect(balanceBefore - balanceAfter).to.equal(fee);
    });

    it("reverts if USDC allowance is less than computed fee", async function () {
      const { interfold, usdcToken, request } = await loadFixture(setup);

      // Approve only 1 unit
      await usdcToken.approve(await interfold.getAddress(), 1);

      await expect(interfold.request(request)).to.be.revertedWithCustomError(
        usdcToken,
        "ERC20InsufficientAllowance",
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  //  M-06 — Duration precision (sum-then-divide, not per-term truncation)
  //
  //  With per-term truncation a configuration like windows=2s and utilization
  //  bps=3000 each rounds every term to zero (`2 * 3000 / 10000 == 0`),
  //  losing 1.8 seconds of weight. Sum-then-divide preserves the full
  //  weighted contribution: `(2*3000 + 2*3000 + 2*3000) / 10000 == 1`.
  // ──────────────────────────────────────────────────────────────────────────

  describe("M-06 — duration precision", function () {
    it("sums weighted timeouts before dividing by BPS_BASE", async function () {
      const { interfold, request, ciphernodeRegistryContract, owner } =
        await loadFixture(setup);

      // Configure windows + utilization bps that would round to zero under
      // the old per-term formula but yield exactly 1 extra second under the
      // new sum-then-divide formula.
      await interfold.connect(owner).setTimeoutConfig({
        dkgWindow: 2,
        computeWindow: 2,
        decryptionWindow: 2,
      });

      const pc = await interfold.getPricingConfig();
      await interfold.connect(owner).setPricingConfig({
        ...toPlainConfig(pc),
        dkgUtilizationBps: 3000,
        computeUtilizationBps: 3000,
        decryptUtilizationBps: 3000,
      });

      const sortitionWindow =
        await ciphernodeRegistryContract.sortitionSubmissionWindow();
      const inputWindowSecs =
        BigInt(request.inputWindow[1]) - BigInt(request.inputWindow[0]);

      // New (correct) formula: sum then divide.
      const newDuration =
        sortitionWindow +
        inputWindowSecs +
        (2n * 3000n + 2n * 3000n + 2n * 3000n) / 10000n; // = +1

      // Old (buggy) per-term formula would have produced this:
      const oldDuration =
        sortitionWindow +
        inputWindowSecs +
        (2n * 3000n) / 10000n + // 0
        (2n * 3000n) / 10000n + // 0
        (2n * 3000n) / 10000n; // 0

      expect(newDuration - oldDuration).to.equal(1n);

      // Compute the expected fee using the new duration.
      const pc2 = await interfold.getPricingConfig();
      const n = 3n;
      const m = 1n;
      const proofsPerNode = 14n + 4n * (n - 1n);
      let baseFee = pc2.keyGenFixedPerNode * n;
      baseFee += pc2.keyGenPerEncryptionProof * n * proofsPerNode;
      if (n > 1n) baseFee += (pc2.coordinationPerPair * n * (n - 1n)) / 2n;
      baseFee += pc2.verificationPerProof * n * proofsPerNode;
      baseFee += pc2.availabilityPerNodePerSec * n * newDuration;
      baseFee += pc2.decryptionPerNode * m;
      if (m > 1n) baseFee += (pc2.coordinationPerPair * m * (m - 1n)) / 2n;
      baseFee += pc2.publicationBase;
      const expectedFee = (baseFee * (10000n + BigInt(pc2.marginBps))) / 10000n;

      // Quote against the same request — only the timeout config changed.
      const actualFee = await interfold.getE3Quote(request);
      expect(actualFee).to.equal(expectedFee);

      // The fee under the old (per-term) formula would have been smaller by
      // exactly `availabilityPerNodePerSec * n * 1s * marginMultiplier`.
      let oldBaseFee = pc2.keyGenFixedPerNode * n;
      oldBaseFee += pc2.keyGenPerEncryptionProof * n * proofsPerNode;
      if (n > 1n) oldBaseFee += (pc2.coordinationPerPair * n * (n - 1n)) / 2n;
      oldBaseFee += pc2.verificationPerProof * n * proofsPerNode;
      oldBaseFee += pc2.availabilityPerNodePerSec * n * oldDuration;
      oldBaseFee += pc2.decryptionPerNode * m;
      if (m > 1n) oldBaseFee += (pc2.coordinationPerPair * m * (m - 1n)) / 2n;
      oldBaseFee += pc2.publicationBase;
      const oldFee = (oldBaseFee * (10000n + BigInt(pc2.marginBps))) / 10000n;

      // The new formula must price strictly higher when the old one truncated.
      expect(actualFee).to.be.gt(oldFee);
    });
  });
});
