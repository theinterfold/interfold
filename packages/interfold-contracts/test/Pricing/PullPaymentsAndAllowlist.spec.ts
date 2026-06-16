// SPDX-License-Identifier: LGPL-3.0-only
//
// Pull-payment + fee-token allow-list integration tests.
import { expect } from "chai";
import type { Signer } from "ethers";

import type { MockBlacklistUSDC } from "../../types";
import {
  SORTITION_SUBMISSION_WINDOW,
  DATA as data,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  PROOF as proof,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("Interfold — pull payments + fee-token allow-list", function () {
  const inputWindowDuration = 300;
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const setupAndPublishCommittee = async (
    registry: any,
    e3Id: number,
    publicKey: string,
    operators: Signer[],
  ) => {
    for (const operator of operators) {
      await registry.connect(operator).submitTicket(e3Id, 1);
    }
    await time.increase(SORTITION_SUBMISSION_WINDOW + 1);
    await registry.finalizeCommittee(e3Id);
    const pkCommitment = ethers.keccak256(publicKey);
    await registry.publishCommittee(e3Id, publicKey, pkCommitment, "0x", "0x");
  };

  // Two fixtures: one using vanilla USDC (allow-list tests),
  // one using MockBlacklistUSDC as the fee token (blacklist isolation tests).
  const makeFixture = (useBlacklistToken: boolean) => async () => {
    const sys = await deployInterfoldSystem({
      committeeThresholds: [[0, [1, 3]]],
      useBlacklistFeeToken: useBlacklistToken,
    });
    const {
      owner,
      operator1: operator1Maybe,
      operator2: operator2Maybe,
      operator3: operator3Maybe,
      interfold,
      ciphernodeRegistry: ciphernodeRegistryContract,
      bondingRegistry,
      slashingManager,
      e3RefundManager,
      usdcToken: feeToken,
      mocks: { e3Program, decryptionVerifier },
    } = sys;
    const operator1 = operator1Maybe!;
    const operator2 = operator2Maybe!;
    const operator3 = operator3Maybe!;
    const [, , , , , treasury] = await ethers.getSigners();
    const treasuryAddress = await treasury.getAddress();

    // Configure protocol share so treasury actually receives credits
    await interfold.setPricingConfig({
      keyGenFixedPerNode: 100000n,
      keyGenPerEncryptionProof: 50000n,
      coordinationPerPair: 10000n,
      availabilityPerNodePerSec: 50n,
      decryptionPerNode: 300000n,
      publicationBase: 1000000n,
      verificationPerProof: 5000n,
      protocolTreasury: treasuryAddress,
      marginBps: 1500,
      protocolShareBps: 2000, // 20% to treasury
      dkgUtilizationBps: 2500,
      computeUtilizationBps: 5000,
      decryptUtilizationBps: 2500,
      minCommitteeSize: 0,
      minThreshold: 0,
    });

    const now = await time.latest();
    const request = {
      committeeSize: 0,
      inputWindow: [now + 10, now + inputWindowDuration] as [number, number],
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

    return {
      owner,
      operator1,
      operator2,
      operator3,
      treasury,
      interfold,
      ciphernodeRegistryContract,
      bondingRegistry,
      feeToken,
      slashingManager,
      e3RefundManager,
      request,
    };
  };

  const fixturePlain = () => makeFixture(false)();
  const fixtureBlacklist = () => makeFixture(true)();

  const runRequestAndPublish = async (ctx: any) => {
    const {
      interfold,
      operator1,
      operator2,
      operator3,
      ciphernodeRegistryContract,
      feeToken,
      request,
    } = ctx;
    await feeToken.approve(await interfold.getAddress(), ethers.MaxUint256);
    await interfold.request(request);
    const e3Id = 0;
    const nodes = [
      await operator1.getAddress(),
      await operator2.getAddress(),
      await operator3.getAddress(),
    ];
    await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, "0x1234", [
      operator1,
      operator2,
      operator3,
    ]);
    await time.increase(inputWindowDuration + 200);
    await interfold.publishCiphertextOutput(e3Id, data, proof);
    await interfold.publishPlaintextOutput(e3Id, data, proof);
    return { e3Id, nodes };
  };

  // ─────────────────────────────────────────────────────────────────────────
  // H-01 — per-operator pull rewards
  // ─────────────────────────────────────────────────────────────────────────

  describe("H-01 — pull rewards", function () {
    it("each operator can independently claim and double-claim reverts", async function () {
      const ctx = await loadFixture(fixturePlain);
      const { interfold, feeToken, operator1, operator2, operator3 } = ctx;
      const { e3Id, nodes } = await runRequestAndPublish(ctx);

      for (let i = 0; i < 3; i++) {
        const op = [operator1, operator2, operator3][i];
        const pending = await interfold.pendingReward(e3Id, nodes[i]);
        expect(pending).to.be.gt(0);
        const before = await feeToken.balanceOf(nodes[i]);
        await interfold.connect(op).claimReward(e3Id);
        const after = await feeToken.balanceOf(nodes[i]);
        expect(after - before).to.equal(pending);
        expect(await interfold.pendingReward(e3Id, nodes[i])).to.equal(0n);
        await expect(
          interfold.connect(op).claimReward(e3Id),
        ).to.be.revertedWithCustomError(interfold, "NothingToClaim");
      }
    });

    it("claimRewards batches across E3 ids", async function () {
      const ctx = await loadFixture(fixturePlain);
      const { interfold, feeToken, operator1, request } = ctx;
      // Two sequential E3s for the same committee.
      await runRequestAndPublish(ctx);
      const now = await time.latest();
      const req2 = {
        ...request,
        inputWindow: [now + 10, now + inputWindowDuration] as [number, number],
      };
      await interfold.request(req2);
      const e3Id2 = 1;
      await setupAndPublishCommittee(
        ctx.ciphernodeRegistryContract,
        e3Id2,
        "0x5678",
        [ctx.operator1, ctx.operator2, ctx.operator3],
      );
      await time.increase(inputWindowDuration + 200);
      await interfold.publishCiphertextOutput(e3Id2, data, proof);
      await interfold.publishPlaintextOutput(e3Id2, data, proof);

      const op1Addr = await operator1.getAddress();
      const expected =
        (await interfold.pendingReward(0, op1Addr)) +
        (await interfold.pendingReward(1, op1Addr));
      const before = await feeToken.balanceOf(op1Addr);
      await interfold.connect(operator1).claimRewards([0, 1]);
      const after = await feeToken.balanceOf(op1Addr);
      expect(after - before).to.equal(expected);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // M-02 — treasury pull (Interfold) + blacklist isolation
  // ─────────────────────────────────────────────────────────────────────────

  describe("M-02 — treasury pull isolates failures", function () {
    it("blacklisting treasury does not brick publishPlaintextOutput; other claimants unaffected", async function () {
      const ctx = await loadFixture(fixtureBlacklist);
      const { interfold, feeToken, treasury, operator1, operator2, operator3 } =
        ctx;
      const treasuryAddr = await treasury.getAddress();
      // Blacklist treasury BEFORE the run.
      const blacklistToken = feeToken as unknown as MockBlacklistUSDC;
      await blacklistToken.blacklist(treasuryAddr);

      const { e3Id, nodes } = await runRequestAndPublish(ctx);

      // Operators can still claim despite treasury being blacklisted.
      for (let i = 0; i < 3; i++) {
        const op = [operator1, operator2, operator3][i];
        const before = await feeToken.balanceOf(nodes[i]);
        await interfold.connect(op).claimReward(e3Id);
        expect(await feeToken.balanceOf(nodes[i])).to.be.gt(before);
      }

      // Treasury has credits but the pull reverts because token blocks the transfer.
      const tokenAddr = await feeToken.getAddress();
      expect(
        await interfold.pendingTreasuryClaim(treasuryAddr, tokenAddr),
      ).to.be.gt(0);
      await expect(
        interfold.connect(treasury).treasuryClaim(tokenAddr),
      ).to.be.revertedWithCustomError(feeToken, "Blacklisted");

      // After unblacklisting, treasury can claim what it accrued.
      await blacklistToken.unblacklist(treasuryAddr);
      const credit = await interfold.pendingTreasuryClaim(
        treasuryAddr,
        tokenAddr,
      );
      const before = await feeToken.balanceOf(treasuryAddr);
      await interfold.connect(treasury).treasuryClaim(tokenAddr);
      expect((await feeToken.balanceOf(treasuryAddr)) - before).to.equal(
        credit,
      );
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // M-10 — fee-token allow-list
  // ─────────────────────────────────────────────────────────────────────────

  describe("M-10 — fee-token allow-list gates request()", function () {
    it("request reverts FeeTokenNotAllowed when active fee token is de-allow-listed", async function () {
      const ctx = await loadFixture(fixturePlain);
      const { interfold, feeToken, request } = ctx;
      await feeToken.approve(await interfold.getAddress(), ethers.MaxUint256);

      // Disable current fee token via allow-list (token still set on Interfold).
      await interfold.setFeeTokenAllowed(await feeToken.getAddress(), false);
      expect(
        await interfold.isFeeTokenAllowed(await feeToken.getAddress()),
      ).to.eq(false);

      const now = await time.latest();
      const fresh = {
        ...request,
        inputWindow: [now + 10, now + inputWindowDuration] as [number, number],
      };
      await expect(interfold.request(fresh)).to.be.revertedWithCustomError(
        interfold,
        "FeeTokenNotAllowed",
      );

      // Re-allow restores request().
      await interfold.setFeeTokenAllowed(await feeToken.getAddress(), true);
      await interfold.request(fresh); // should not revert
    });
  });
});
