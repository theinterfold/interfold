// SPDX-License-Identifier: LGPL-3.0-only
//
// Per-E3 dust rotation in `_distributeRewards`.
//
// With integer-division splitting, each E3's per-node remainder
// (`cnAmount % committeeSize`) was historically stuffed into the last
// committee slot, biasing rewards toward whichever operator landed there.
// The fix rotates the dust slot deterministically by `e3Id % n`, so the
// bias averages out across requests with the same committee membership.
import { expect } from "chai";
import type { Signer } from "ethers";

import {
  SORTITION_SUBMISSION_WINDOW,
  DATA as data,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  PROOF as proof,
} from "../fixtures";

const { loadFixture, time } = networkHelpers;

describe("Pricing — per-E3 dust rotation across consecutive E3s", function () {
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

  const setup = async () => {
    const sys = await deployInterfoldSystem({
      mintUsdcTo: [],
      committeeThresholds: [[0, [1, 3]]],
    });
    const {
      owner,
      operator1: operator1Maybe,
      operator2: operator2Maybe,
      operator3: operator3Maybe,
      interfold,
      ciphernodeRegistry: ciphernodeRegistryContract,
      usdcToken: feeToken,
      mocks: { e3Program, decryptionVerifier },
    } = sys;
    const operator1 = operator1Maybe!;
    const operator2 = operator2Maybe!;
    const operator3 = operator3Maybe!;
    const [, , , , , treasury] = await ethers.getSigners();
    const treasuryAddress = await treasury.getAddress();
    const ownerAddress = await owner.getAddress();

    // Pricing — pick params that yield a per-node cnAmount remainder ≠ 0
    // for committeeSize=3 so the dust rotation is observable. The values
    // here were chosen empirically: stripping `protocolShareBps=0` and
    // setting `keyGenFixedPerNode=1` causes the fee to land on a value
    // whose `cnAmount % 3 != 0`.
    await interfold.setPricingConfig({
      keyGenFixedPerNode: 1n,
      keyGenPerEncryptionProof: 0n,
      coordinationPerPair: 0n,
      availabilityPerNodePerSec: 0n,
      decryptionPerNode: 0n,
      publicationBase: 1n, // total base = 3*1 + 1 = 4 → 4 % 3 = 1
      verificationPerProof: 0n,
      protocolTreasury: treasuryAddress,
      marginBps: 0,
      protocolShareBps: 0,
      dkgUtilizationBps: 2500,
      computeUtilizationBps: 5000,
      decryptUtilizationBps: 2500,
      minCommitteeSize: 0,
      minThreshold: 0,
    });

    await feeToken.mint(ownerAddress, ethers.parseUnits("1000000", 6));

    const makeRequest = () => {
      const now0 = Math.floor(Date.now() / 1000);
      return {
        committeeSize: 0,
        inputWindow: [now0 + 10, now0 + inputWindowDuration] as [
          number,
          number,
        ],
        e3Program: e3Program.getAddress() as unknown as string,
        paramSet: 0,
        computeProviderParams: abiCoder.encode(
          ["address"],
          [decryptionVerifier.getAddress()],
        ),
        customParams: abiCoder.encode(
          ["address"],
          ["0x1234567890123456789012345678901234567890"],
        ),
        proofAggregationEnabled: false,
      } as any;
    };

    const makeAndRun = async (e3Id: number) => {
      const now = await time.latest();
      const req = {
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
      await feeToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      await interfold.request(req);
      // topNodes are sorted by ascending address; operator3 < operator1 < operator2
      const nodes = [
        await operator3.getAddress(),
        await operator1.getAddress(),
        await operator2.getAddress(),
      ];
      await setupAndPublishCommittee(
        ciphernodeRegistryContract,
        e3Id,
        e3Id === 0 ? "0x1234" : "0x5678",
        [operator1, operator2, operator3],
      );
      await time.increase(inputWindowDuration + 200);
      await interfold.publishCiphertextOutput(e3Id, data, proof);
      await interfold.publishPlaintextOutput(e3Id, data, proof);
      return nodes;
    };

    return {
      owner,
      operator1,
      operator2,
      operator3,
      interfold,
      ciphernodeRegistryContract,
      feeToken,
      makeRequest,
      makeAndRun,
    };
  };

  it("rotates the per-E3 dust slot deterministically by e3Id", async function () {
    const ctx = await loadFixture(setup);
    const { interfold, makeAndRun } = ctx;

    const nodes = await makeAndRun(0);
    const pending0 = await Promise.all(
      nodes.map((n) => interfold.pendingReward(0, n)),
    );

    const nodes2 = await makeAndRun(1);
    expect(nodes2).to.deep.equal(nodes);
    const pending1 = await Promise.all(
      nodes.map((n) => interfold.pendingReward(1, n)),
    );

    // Sanity: cnAmount per E3 should not be divisible by 3 with the chosen
    // pricing — i.e. at least one node received strictly more than another.
    const max0 = pending0.reduce((a, b) => (a > b ? a : b));
    const min0 = pending0.reduce((a, b) => (a < b ? a : b));
    expect(max0, "test config must produce non-zero dust").to.be.gt(min0);

    // The dust slot for e3Id=0 must be slot 0; for e3Id=1, slot 1.
    const dustSlot0 = pending0.findIndex((p) => p === max0);
    const max1 = pending1.reduce((a, b) => (a > b ? a : b));
    const dustSlot1 = pending1.findIndex((p) => p === max1);

    expect(dustSlot0).to.equal(0);
    expect(dustSlot1).to.equal(1);

    // The shortfall (per-node payout) should be identical across both E3s
    // for the non-dust slots — the formula only changed who got the dust.
    const per0 = pending0[(0 + 1) % 3]; // a non-dust slot for e3Id=0
    const per1 = pending1[(1 + 1) % 3]; // a non-dust slot for e3Id=1
    expect(per0).to.equal(per1);
  });
});
